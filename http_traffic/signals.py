"""Conservative deterministic review hints. No finding is proof of a vulnerability."""
from __future__ import annotations
import hashlib
import re

_OBJECT_PARAMS = {'id', 'user_id', 'account_id', 'order_id', 'org_id', 'organization_id', 'tenant_id', 'document_id', 'invoice_id', 'file_id', 'resource_id'}
_PRIVATE_FIELDS = {'email', 'phone', 'address', 'dob', 'birthdate', 'ssn', 'access_token', 'refresh_token', 'api_key', 'secret', 'password', 'card_number', 'owner_id', 'user_id'}
_ADMIN = re.compile(r'(?:^|/)(?:admin|internal|manage|staff)(?:/|$)', re.I)


def derive_signals(exchanges: list[dict]) -> list[dict]:
    signals = []
    groups: dict[str, list[dict]] = {}
    for record in exchanges:
        groups.setdefault(f"{record['method']}|{record['endpoint_key']}", []).append(record)
        fields = {path.split('.')[-1].replace('[]', '') for path in record['response_json_fields']}
        request_fields = {path.split('.')[-1].replace('[]', '') for path in record['request_json_fields']}
        query = set(record['query_names'])
        path = record['url'].split('?', 1)[0].lower()
        flags = set(record['response_flags'])
        codes = set()
        if '{id}' in path or _OBJECT_PARAMS.intersection(query | request_fields):
            codes.add('OBJECT_REFERENCE')
        if fields & _PRIVATE_FIELDS:
            codes.add('SENSITIVE_FIELD_NAMES')
        if 'stack_trace_pattern' in flags:
            codes.add('ERROR_DETAIL_PATTERN')
        if 'credential_like_pattern' in flags:
            codes.add('CREDENTIAL_LIKE_PATTERN')
        if record['cors_allow_origin'] == '*' and record['cors_allow_credentials']:
            codes.add('CORS_REVIEW')
        if 'public' in record['cache_policy'] and fields & _PRIVATE_FIELDS:
            codes.add('CACHE_REVIEW')
        if _ADMIN.search(path) and record['status'] in range(200, 300):
            codes.add('PRIVILEGED_ROUTE_OBSERVED')
        for code in sorted(codes):
            signals.append(_signal(code, [record['exchange_id']]))
    for records in groups.values():
        if len(records) >= 2 and len({r['status'] for r in records}) > 1:
            signals.append(_signal('STATUS_VARIATION', [r['exchange_id'] for r in records][:20]))
    # Deduplicate signals, sorted for consistent batch selection.
    return list({signal['signal_id']: signal for signal in signals}.values())


def _signal(code: str, exchange_ids: list[str]) -> dict:
    ids = sorted(set(exchange_ids))
    raw = '|'.join([code, *ids])
    return {
        'signal_id': hashlib.sha256(raw.encode('utf-8')).hexdigest()[:18],
        'code': code,
        'exchange_ids': ids,
        'meaning': {
            'OBJECT_REFERENCE': 'Object identifier is present; authorization enforcement is untested.',
            'SENSITIVE_FIELD_NAMES': 'Response JSON includes privacy-related field names; content and authorization are unverified.',
            'ERROR_DETAIL_PATTERN': 'Response text resembles a stack trace or detailed runtime error.',
            'CREDENTIAL_LIKE_PATTERN': 'Response contains a secret-like string pattern; authenticity and sensitivity unverified.',
            'CORS_REVIEW': 'Response combines wildcard origin with credential support; browser exploitability unverified.',
            'CACHE_REVIEW': 'Response has public cache directive and private-sounding fields; actual caching unverified.',
            'PRIVILEGED_ROUTE_OBSERVED': 'Privileged-looking route responded successfully; authorization is unverified.',
            'STATUS_VARIATION': 'Related exchanges returned different status codes; inputs/authentication may explain it.',
        }[code],
    }


def prioritize(exchanges: list[dict], signals: list[dict], *, limit: int = 200) -> list[dict]:
    counts: dict[str, int] = {}
    for signal in signals:
        for eid in signal['exchange_ids']:
            counts[eid] = counts.get(eid, 0) + 1
    return sorted(
        (record for record in exchanges if record['exchange_id'] in counts),
        key=lambda r: (-counts[r['exchange_id']], r['endpoint_key'], r['exchange_id']),
    )[:limit]
