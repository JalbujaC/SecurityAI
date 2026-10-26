"""Phase 1–2 acceptance tests. Fully offline; mock the LLM."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from http_traffic.importers import import_capture
from http_traffic.normalize import normalize_exchange
from http_traffic.signals import derive_signals, prioritize
from http_traffic.store import TrafficStore
from http_traffic.analyzer import TrafficAnalyzer
from models.clients import ModelClient
from models.schemas import ModelRequest, ModelResponse
from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator


@pytest.fixture
def scope():
    return ScopeValidator(ScopeConfig(allowed_domains=['example.com'], excluded_domains=['private.example.com']))


def make_exchange(url='https://example.com/api/orders/4821?token=extremely-secret', status=200, response_body='{"owner_id":17,"email":"private@example.com"}', **kwargs):
    return normalize_exchange(
        method=kwargs.get('method', 'GET'), url=url,
        request_headers=[{'name': 'Authorization', 'value': 'Bearer DO-NOT-LEAK'},
                         {'name': 'Cookie', 'value': 'sid=secret-value'}],
        response_headers=[{'name': 'Content-Type', 'value': 'application/json'}],
        status=status, response_body=response_body, source_ref='entry:1', source_format='har')


def test_redaction_no_header_body_or_query_values():
    record = make_exchange()
    raw = json.dumps(record)
    for secret in ('extremely-secret', 'DO-NOT-LEAK', 'secret-value', 'private@example.com'):
        assert secret not in raw
    assert record['has_authorization']
    assert record['has_cookie']
    assert record['query_names'] == ['token']
    assert 'owner_id' in record['response_json_fields']
    assert '{id}' in record['url']


def test_url_with_userinfo_rejected():
    with pytest.raises(ValueError):
        make_exchange(url='https://alice:supersecret@example.com/data')


def test_har_import_scoped_and_deduplicated(tmp_path, scope):
    entry = {'request': {'method': 'GET', 'url': 'https://example.com/api/orders/11?id=secret', 'headers': []},
             'response': {'status': 200, 'headers': [], 'content': {'text': '{"owner_id":1}'}}}
    out_scope = {'request': {'method': 'GET', 'url': 'https://example.org/sensitive', 'headers': []},
                 'response': {'status': 200, 'headers': [], 'content': {'text': 'secret'}}}
    excluded = {'request': {'method': 'GET', 'url': 'https://private.example.com/sensitive', 'headers': []},
                 'response': {'status': 200, 'headers': [], 'content': {'text': 'secret'}}}
    file = tmp_path / 'traffic.har'
    file.write_text(json.dumps({'log': {'entries': [entry, entry, out_scope, excluded]}}))
    records, stats = import_capture(file, scope)
    assert len(records) == 1
    assert stats == {'total': 4, 'accepted': 1, 'out_of_scope': 2, 'malformed': 0, 'duplicates': 1}
    assert 'secret' not in json.dumps(records)


def test_har_base64_response_payload(tmp_path, scope):
    data = base64.b64encode(b'{"api_key":"NEVERSTORE"}').decode('ascii')
    path = tmp_path / 'b64.har'
    path.write_text(json.dumps({'log': {'entries': [
        {'request': {'method': 'GET', 'url': 'https://example.com/api/me'},
         'response': {'status': 200, 'content': {'text': data, 'encoding': 'base64'}}}
    ]}}))
    recs, _ = import_capture(path, scope)
    assert recs[0]['response_json_fields'] == ['api_key']
    assert 'NEVERSTORE' not in json.dumps(recs)


def test_burp_base64_xml_import(tmp_path, scope):
    req = base64.b64encode(b'GET /api/users/123 HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer PRIVATE\r\n\r\n').decode()
    resp = base64.b64encode(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"email":"PRIVATE@example.com"}').decode()
    path = tmp_path / 'burp.xml'
    path.write_text(f'<items><item><url>https://example.com/api/users/123</url><method>GET</method><status>200</status><request base64="true">{req}</request><response base64="true">{resp}</response></item></items>')
    recs, stats = import_capture(path, scope)
    assert stats['accepted'] == 1
    assert recs[0]['has_authorization']
    assert 'PRIVATE' not in json.dumps(recs)


def test_burp_xml_entities_rejected(tmp_path, scope):
    path = tmp_path / 'malicious.xml'
    path.write_text('<!DOCTYPE items [<!ENTITY x "injection">]><items></items>')
    with pytest.raises(ValueError, match='DTD'):
        import_capture(path, scope)


def test_capture_size_guard(tmp_path, scope, monkeypatch):
    file = tmp_path / 'big.har'
    file.write_bytes(b'{}')
    from http_traffic import importers
    monkeypatch.setattr(importers, 'MAX_CAPTURE_BYTES', 1)
    with pytest.raises(ValueError, match='40 MiB'):
        import_capture(file, scope)


def test_store_deduplicates_and_persists(tmp_path):
    store = TrafficStore(tmp_path / 'traffic')
    rec = make_exchange()
    assert store.add_exchanges([rec, rec]) == 1
    assert store.add_exchanges([rec]) == 0
    assert store.load_exchanges() == [rec]
    serialized = store.exchanges_path.read_text()
    assert 'private@example.com' not in serialized


def test_object_reference_is_not_validation():
    rec = make_exchange()
    signals = derive_signals([rec])
    assert {s['code'] for s in signals} >= {'OBJECT_REFERENCE', 'SENSITIVE_FIELD_NAMES'}
    assert all('validated' not in signal for signal in signals)
    assert prioritize([rec], signals) == [rec]


def test_status_variation_grouping():
    ok = make_exchange(url='https://example.com/api/orders/4821', status=200)
    denied = make_exchange(url='https://example.com/api/orders/4822', status=403)
    signals = derive_signals([ok, denied])
    assert 'STATUS_VARIATION' in {s['code'] for s in signals}


class FakeModel(ModelClient):
    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.calls.append(request)
        return ModelResponse(content=json.dumps(self.responder(request)), model='offline-test')


def _hypothesis(rec, signal):
    return {'title': 'Review object authorization', 'vulnerability_class': 'IDOR_BOLA_CANDIDATE',
            'confidence': 0.6, 'exchange_ids': [rec['exchange_id']],
            'signal_ids': [signal['signal_id']], 'rationale': 'An object reference was observed.',
            'verification_gap': 'No second authorization context exists.',
            'safe_next_step': 'Human reviewer checks program authorization and test-account ownership.'}


def test_model_accepts_grounded_review_hypothesis():
    rec = make_exchange()
    signal = derive_signals([rec])[0]
    model = FakeModel(lambda _: {'hypotheses': [_hypothesis(rec, signal)]})
    hypotheses, stats = TrafficAnalyzer(model).analyze([rec])
    assert stats['hypotheses_accepted'] == 1
    assert hypotheses[0]['status'] == 'review_hypothesis'
    assert hypotheses[0]['validation_status'] == 'unverified'
    assert hypotheses[0]['exchange_ids'] == [rec['exchange_id']]
    # Captured secret values never appear in Qwen prompts.
    prompt = '\n'.join(m.content for m in model.calls[0].messages)
    assert 'DO-NOT-LEAK' not in prompt
    assert 'private@example.com' not in prompt


def test_model_fake_ids_rejected():
    rec = make_exchange()
    model = FakeModel(lambda _: {'hypotheses': [{**_hypothesis(rec, derive_signals([rec])[0]), 'exchange_ids': ['invented']}]})
    candidates, stats = TrafficAnalyzer(model).analyze([rec])
    assert not candidates
    assert stats['hypotheses_discarded'] == 1


def test_model_fake_signal_rejected():
    rec = make_exchange()
    model = FakeModel(lambda _: {'hypotheses': [{**_hypothesis(rec, derive_signals([rec])[0]), 'signal_ids': ['fake']}]})
    assert TrafficAnalyzer(model).analyze([rec])[0] == []


def test_model_invalid_json_retries_then_fails_closed():
    rec = make_exchange()
    model = FakeModel(lambda _: {'not_hypotheses': []})
    found, stats = TrafficAnalyzer(model).analyze([rec])
    assert found == []
    assert stats['batches_failed'] == 1
    assert len(model.calls) == 2


def test_no_signals_no_model_calls():
    rec = make_exchange(url='https://example.com/status', response_body='{}')
    model = FakeModel(lambda _: {'hypotheses': []})
    found, stats = TrafficAnalyzer(model).analyze([rec])
    assert found == []
    assert stats['batches_attempted'] == 0
    assert not model.calls


def test_all_hypotheses_are_local_review_only(tmp_path):
    rec = make_exchange()
    signal = derive_signals([rec])[0]
    model = FakeModel(lambda _: {'hypotheses': [_hypothesis(rec, signal)]})
    records, _ = TrafficAnalyzer(model).analyze([rec])
    store = TrafficStore(tmp_path)
    assert store.add_hypotheses(records) == 1
    assert store.add_hypotheses(records) == 0
    assert store.load_hypotheses()[0]['validation_status'] == 'unverified'


def test_single_digit_object_id_redacted():
    rec = make_exchange(url='https://example.com/orders/7')
    assert rec['url'] == 'https://example.com/orders/{id}'


def test_import_fails_closed_on_malformed_url(tmp_path, scope):
    path = tmp_path / 'bad.har'
    path.write_text(json.dumps({'log': {'entries': [
        {'request': {'method': 'GET', 'url': 'file:///etc/passwd'}, 'response': {'status': 200}},
        {'request': {'method': 'GET', 'url': 'https://alice:pwd@example.com/private'}, 'response': {'status': 200}},
    ]}}))
    recs, stats = import_capture(path, scope)
    assert recs == []
    assert stats['malformed'] == 2


def test_llm_runtime_failure_is_inconclusive():
    rec = make_exchange()
    class BrokenModel(ModelClient):
        def generate(self, request: ModelRequest):
            raise ConnectionError('Model not running')
    candidates, stats = TrafficAnalyzer(BrokenModel()).analyze([rec])
    assert candidates == []
    assert stats['batches_failed'] == 1
