"""Offline phase 3/4 regressions. No actual HTTP requests or Ollama calls."""
import json
from pathlib import Path

import pytest

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from scope.targets import TargetManager
from storage.evidence_store import EvidenceStore
from storage.finding_store import FindingStore
from http_traffic.normalize import normalize_exchange
from http_traffic.store import TrafficStore
from http_traffic.signals import derive_signals
from http_traffic.compare import compare_exchanges, compare_by_id
from http_traffic.replay import ReplayExecutor, persist_replay
from http_traffic.integration import TrafficBridge


def validator():
    return ScopeValidator(ScopeConfig(allowed_domains=['example.com'], excluded_domains=['private.example.com']))


def record(status=200, *, url='https://example.com/api/orders/4821', response='{"owner_id":17,"email":"private@example.com"}'):
    return normalize_exchange(method='GET', url=url, request_headers=[],
                              response_headers=[{'name':'Content-Type','value':'application/json'}],
                              status=status, response_body=response, source_format='HAR')


def plan(url='https://example.com/api/orders/4821', method='GET'):
    return {'version': 1, 'case_id': 'cross_account_order', 'url': url, 'method': method,
            'contexts': {'owner': {'bearer_env': 'SECURITYAI_OWNER_TOKEN'},
                         'peer': {'bearer_env': 'SECURITYAI_PEER_TOKEN'}},
            'steps': [{'label':'owner_baseline','context':'owner','expected_access':'allow'},
                      {'label':'peer_probe','context':'peer','expected_access':'deny'}]}


def test_compare_reports_structural_differences_only():
    left, right = record(200), record(403, response='{"error":"not_authorized"}')
    result = compare_exchanges(left, right)
    assert result['changes']['status'] == [200, 403]
    assert result['verification_status'] == 'unverified'
    assert 'IDOR' in result['interpretation']


def test_compare_rejects_unrelated_routes():
    with pytest.raises(ValueError, match='different endpoint'):
        compare_exchanges(record(), record(url='https://example.com/api/users/12'))


def test_compare_rejects_fabricated_ids():
    with pytest.raises(KeyError):
        compare_by_id([record()], 'fake', 'also_fake')


def test_replay_is_explicitly_approved(monkeypatch):
    ran = []
    runner = ReplayExecutor(validator(), transport=lambda *a: ran.append(a),
                            resolver=lambda h: ['93.184.216.34'], spacing=0)
    with pytest.raises(PermissionError, match='approval'):
        runner.execute(plan())
    with pytest.raises(PermissionError, match='approval'):
        runner.execute(plan(), approved_case_id='wrong', authorization_confirmed=True)
    assert not ran


@pytest.mark.parametrize('bad', [
    {'url': 'http://example.com/orders/1'},
    {'url': 'https://private.example.com/orders/1'},
    {'url': 'https://localhost/orders/1'},
    {'url': 'https://example.com:8443/orders/1'},
    {'url': 'https://example.com/a#frag'},
    {'method': 'POST'}, {'method': 'DELETE'},
])
def test_replay_rejects_unsafe_request(bad):
    broken = plan()
    broken.update(bad)
    runner = ReplayExecutor(validator(), transport=lambda *a: None,
                            resolver=lambda h: ['93.184.216.34'], spacing=0)
    with pytest.raises((ValueError, PermissionError)):
        runner.execute(broken, approved_case_id=broken['case_id'], authorization_confirmed=True)


def test_replay_requires_two_contexts():
    broken = plan()
    del broken['contexts']['peer']
    with pytest.raises(ValueError, match='2..3'):
        ReplayExecutor(validator(), transport=lambda *a: None).execute(
            broken, approved_case_id=broken['case_id'], authorization_confirmed=True)


def test_replay_no_secret_persistence_and_flags_unexpected_200(monkeypatch, tmp_path):
    monkeypatch.setenv('SECURITYAI_OWNER_TOKEN', 'high-secret-owner-token')
    monkeypatch.setenv('SECURITYAI_PEER_TOKEN', 'high-secret-peer-token')
    captured = []

    def transport(method, url, headers, timeout):
        captured.append(dict(headers))
        status = 200
        return status, [{'name':'Content-Type','value':'application/json'}], b'{"owner_id": 17, "email": "private@example.com"}'

    run = ReplayExecutor(validator(), transport=transport, resolver=lambda _: ['93.184.216.34'], spacing=0).execute(
        plan(), approved_case_id='cross_account_order', authorization_confirmed=True)
    assert len(captured) == 2
    assert captured[0]['Authorization'] == 'Bearer high-secret-owner-token'
    assert captured[1]['Authorization'] == 'Bearer high-secret-peer-token'
    assert run['verification_status'] == 'unverified'
    assert run['comparisons'][0]['review_flags'] == ['unexpected_success_for_denied_context']
    store = TrafficStore(tmp_path / 'traffic')
    assert persist_replay(store, run) >= 1
    data = ''.join(p.read_text(encoding='utf-8') for p in store.directory.glob('*.json'))
    for secret in ('high-secret-owner-token', 'high-secret-peer-token', 'private@example.com'):
        assert secret not in data
    assert 'validated' not in data


def test_replay_rejects_private_resolved_ips(monkeypatch):
    monkeypatch.setenv('SECURITYAI_OWNER_TOKEN', 'abc')
    monkeypatch.setenv('SECURITYAI_PEER_TOKEN', 'xyz')
    from http_traffic.replay import _resolve_public
    import socket
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [(None,None,None,None,('10.0.0.1',443))])
    with pytest.raises(PermissionError, match='non-public'):
        _resolve_public('example.com')


def test_bridge_is_passive_and_evidence_linked(tmp_path):
    store = TrafficStore(tmp_path / 'traffic')
    ex = record()
    store.add_exchanges([ex])
    signals = derive_signals([ex]); assert signals
    hypo = {'hypothesis_id':'caseA','status':'review_hypothesis',
            'validation_status':'unverified', 'exchange_ids':[ex['exchange_id']],
            'signal_ids':[signals[0]['signal_id']], 'confidence':0.96,
            'title':'Review possible object authorization',
            'vulnerability_class':'IDOR_BOLA_CANDIDATE',
            'rationale':'Object identifier observed, access controls untested',
            'verification_gap':'Need owner and peer-controlled comparison',
            'safe_next_step':'Human-authorized comparison'}
    store.add_hypotheses([hypo])
    evidence_store = EvidenceStore(str(tmp_path/'evidence.json'))
    finding_store = FindingStore(str(tmp_path/'findings.json'))
    target_manager = TargetManager(validator())
    target_manager.add_root('example.com')
    bridge = TrafficBridge(scope_validator=validator(), evidence_store=evidence_store,
                           finding_store=finding_store, target_manager=target_manager)
    passive = bridge.integrate(store)
    assert passive.imported_exchanges == 1
    assert evidence_store.count() == 1
    assert finding_store.count() == 0
    assert not passive.seeded_hosts
    linked = bridge.integrate(store, promote_hypotheses=True)
    assert finding_store.count() == 1
    f = finding_store.all()[0]
    assert f.status == 'hypothesis'
    assert f.confidence == 0.59
    assert f.evidence_ids and evidence_store.get(f.evidence_ids[0]).tool_name == 'http_traffic'
    assert bridge.integrate(store, promote_hypotheses=True).new_findings == 0
    assert 'private@example.com' not in (tmp_path/'evidence.json').read_text(encoding='utf8')


def test_bridge_rechecks_scope_and_signal_ids(tmp_path):
    store = TrafficStore(tmp_path/'traffic')
    good = record()
    bad = record(url='https://private.example.com/api/orders/1')
    store.add_exchanges([good, bad])
    store.add_hypotheses([{'hypothesis_id':'f','status':'review_hypothesis','validation_status':'unverified',
                           'exchange_ids':[good['exchange_id']], 'signal_ids':['invented'],
                           'title':'Invalid evidence', 'vulnerability_class':'IDOR_BOLA_CANDIDATE',
                           'confidence':0.9, 'rationale':'r', 'verification_gap':'g'}])
    evidence_store = EvidenceStore()
    finding_store = FindingStore()
    bridge = TrafficBridge(scope_validator=validator(), evidence_store=evidence_store,
                           finding_store=finding_store)
    summary = bridge.integrate(store, promote_hypotheses=True)
    assert summary.imported_exchanges == 1
    assert finding_store.count() == 0


def test_coordinator_patch_is_idempotent():
    import importlib.util
    path = Path(__file__).parents[1] / 'apply.py'
    spec = importlib.util.spec_from_file_location('securityai_http13_apply', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sample = ('    def run(\n        self,\n        observation: str,\n'
              '        available_tools: list[str],\n        max_steps: int = 5,\n'
              '    ) -> list[ExecutionRecord]:\n'
              '        evidence: list[str] = []\n        evidence_ids: list[str] = []')
    new = module.patch_coordinator(sample)
    assert 'seed_evidence_ids: list[str] | None' in new
    assert 'list(seed_evidence or [])' in new
    assert module.patch_coordinator(new) == new


def test_replay_comparison_enters_evidence_store_without_validation(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITYAI_OWNER_TOKEN', 'owner-test-secret')
    monkeypatch.setenv('SECURITYAI_PEER_TOKEN', 'peer-test-secret')
    def transport(method, url, headers, timeout):
        owner = headers['Authorization'] == 'Bearer owner-test-secret'
        body = b'{"owner_id":1}' if owner else b'{"message":"denied"}'
        return (200 if owner else 403), [{'name':'Content-Type','value':'application/json'}], body
    run = ReplayExecutor(validator(), transport=transport,
                         resolver=lambda h: ['93.184.216.34'], spacing=0).execute(
                             plan(), approved_case_id='cross_account_order', authorization_confirmed=True)
    store = TrafficStore(tmp_path / 'traffic')
    persist_replay(store, run)
    e_store, f_store = EvidenceStore(), FindingStore()
    seed = TrafficBridge(scope_validator=validator(), evidence_store=e_store,
                         finding_store=f_store).integrate(store)
    assert seed.replay_comparisons == 1
    assert any(r.tool_name == 'http_traffic_comparison' for r in e_store._records)
    assert f_store.count() == 0
    assert 'unverified' in str(e_store._records[-1].output)
