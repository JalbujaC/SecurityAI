"""Explicit, bounded, scope-checked HTTP replay for user-owned test contexts.

Not reachable by the LLM, planner or tool registry. No raw bodies or secrets persist.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import time
from pathlib import Path
from urllib.parse import urlsplit

from http_traffic.normalize import normalize_exchange, safe_url
from http_traffic.store import _save_json
from http_traffic.compare import compare_exchanges

_LABEL = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{0,39}$')
_ENV = re.compile(r'^SECURITYAI_[A-Z0-9_]{3,80}$')
_MAX_BYTES = 65536


def _validate_plan(data: object, scope_validator) -> dict:
    if not isinstance(data, dict) or data.get('version') != 1:
        raise ValueError('Replay plan must be version 1 JSON object')
    case_id = data.get('case_id')
    if not isinstance(case_id, str) or not _LABEL.fullmatch(case_id):
        raise ValueError('Invalid case_id')
    url = data.get('url')
    if not isinstance(url, str) or len(url) > 1800:
        raise ValueError('Missing or excessive replay URL')
    parts = urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError('Replay requires HTTPS URL without userinfo or fragment')
    if parts.port not in (None, 443):
        raise ValueError('Replay only permits HTTPS port 443')
    if any(x in url for x in ('\r', '\n', '\\')):
        raise ValueError('Unsafe URL characters')
    safe_url(url)  # URI shape validation
    scope_validator.validate(url)
    if data.get('method') != 'GET':
        raise ValueError('Only explicit GET replay is supported in v1.3')
    contexts = data.get('contexts')
    steps = data.get('steps')
    if not isinstance(contexts, dict) or not 2 <= len(contexts) <= 3:
        raise ValueError('Define 2..3 named credential contexts')
    for name, credentials in contexts.items():
        if not isinstance(name, str) or not _LABEL.fullmatch(name) or not isinstance(credentials, dict):
            raise ValueError('Invalid credential context')
        if set(credentials) - {'bearer_env', 'cookie_env'}:
            raise ValueError('Credential contexts accept only bearer_env/cookie_env')
        if len(credentials) > 1:
            raise ValueError('Use one credential source per context')
        for env_name in credentials.values():
            if not isinstance(env_name, str) or not _ENV.fullmatch(env_name):
                raise ValueError('Credentials must refer to SECURITYAI_* environment variables')
    if not isinstance(steps, list) or not 2 <= len(steps) <= 4:
        raise ValueError('Replay requires 2..4 explicit steps')
    labels = set()
    for step in steps:
        if not isinstance(step, dict) or set(step) != {'label', 'context', 'expected_access'}:
            raise ValueError('Each step needs only label, context, expected_access')
        label = step.get('label')
        if not isinstance(label, str) or not _LABEL.fullmatch(label) or label in labels:
            raise ValueError('Step labels must be unique and well formed')
        labels.add(label)
        if step['context'] not in contexts or step['expected_access'] not in ('allow', 'deny'):
            raise ValueError('Unknown context or expected access')
    if len({s['context'] for s in steps}) < 2:
        raise ValueError('Cross-context replay requires two distinct contexts')
    if not any(s['expected_access'] == 'allow' for s in steps):
        raise ValueError('At least one positive-control step is required')
    if not any(s['expected_access'] == 'deny' for s in steps):
        raise ValueError('At least one negative-control step is required')
    return data


def _resolve_public(hostname: str) -> list[str]:
    addresses = {row[4][0] for row in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise PermissionError('Replay DNS resolved to an invalid or non-public address')
    return sorted(addresses)


def _default_transport(method: str, url: str, headers: dict, timeout: int) -> tuple[int, list[dict], bytes]:
    import requests
    try:
        return _perform_request(requests, method, url, headers, timeout)
    except requests.RequestException as exc:
        # Avoid including query parameters and potentially sensitive URLs in logs.
        raise ValueError(f'Approved replay network error: {type(exc).__name__}') from exc


def _perform_request(requests, method: str, url: str, headers: dict, timeout: int) -> tuple[int, list[dict], bytes]:
    with requests.Session() as session:
        session.trust_env = False  # no ambient proxy or netrc credentials
        session.headers.clear()
        with session.request(method=method, url=url, headers=headers, timeout=timeout,
                             allow_redirects=False, stream=True, verify=True) as response:
            buf = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                buf.extend(chunk)
                if len(buf) > _MAX_BYTES:
                    raise ValueError('Response exceeds bounded replay limit')
            return response.status_code, [dict(name=k, value=v) for k, v in response.headers.items()], bytes(buf)


class ReplayExecutor:
    def __init__(self, scope_validator, *, transport=None, resolver=None, timeout: int = 12, spacing: float = 1.0):
        if not 1 <= timeout <= 20:
            raise ValueError('Timeout must be within 1..20 seconds')
        if not 0 <= spacing <= 10:
            raise ValueError('Replay spacing must be between 0 and 10 seconds')
        self.spacing = spacing
        self.scope_validator = scope_validator
        self.transport = transport or _default_transport
        self.resolver = resolver or _resolve_public
        self.timeout = timeout

    def execute(self, plan: dict, *, approved_case_id: str | None = None,
                authorization_confirmed: bool = False) -> dict:
        plan = _validate_plan(plan, self.scope_validator)
        if not authorization_confirmed or approved_case_id != plan['case_id']:
            raise PermissionError('Explicit case-ID approval and authorization acknowledgement required')
        hostname = urlsplit(plan['url']).hostname
        results = []
        for idx, step in enumerate(plan['steps']):
            if idx and self.spacing:
                time.sleep(self.spacing)
            # Repeat scope+DNS checks immediately before every individual replay.
            self.scope_validator.validate(plan['url'])
            addresses = self.resolver(hostname)
            if not addresses or any(not ipaddress.ip_address(addr).is_global for addr in addresses):
                raise PermissionError('Replay resolved to invalid or non-public address')
            credentials = plan['contexts'][step['context']]
            headers = {'Accept': 'application/json', 'User-Agent': 'SecurityAI-approved-replay/1.3'}
            if 'bearer_env' in credentials:
                secret = os.environ.get(credentials['bearer_env'], '')
                if not secret or any(x in secret for x in '\r\n'):
                    raise ValueError('Invalid/missing bearer environment secret')
                headers['Authorization'] = 'Bearer ' + secret
            elif 'cookie_env' in credentials:
                secret = os.environ.get(credentials['cookie_env'], '')
                if not secret or any(x in secret for x in '\r\n'):
                    raise ValueError('Invalid/missing cookie environment secret')
                headers['Cookie'] = secret
            status, resp_headers, body = self.transport('GET', plan['url'], headers, self.timeout)
            if not isinstance(body, bytes) or len(body) > _MAX_BYTES:
                raise ValueError('Replay body must be bounded bytes')
            record = normalize_exchange(
                method='GET', url=plan['url'],
                request_headers=[{'name': k, 'value': v} for k, v in headers.items()],
                response_headers=resp_headers, status=status,
                response_body=body.decode('utf-8', errors='replace'),
                source_ref=plan['case_id'], source_format='approved-replay',
            )
            results.append({'label': step['label'], 'context': step['context'],
                            'expected_access': step['expected_access'],
                            'status': record['status'], 'exchange_id': record['exchange_id'],
                            'record': record, 'outcome': 'requires_human_review'})
        comparisons = []
        # All plan steps use the same URL/method, so compare structurally.
        first = results[0]
        for second in results[1:]:
            pair = compare_exchanges(first['record'], second['record'])
            pair['first_label'] = first['label']
            pair['second_label'] = second['label']
            pair['review_flags'] = (
                ['unexpected_success_for_denied_context']
                if second['expected_access'] == 'deny' and 200 <= second['status'] < 300
                else []
            )
            comparisons.append(pair)
        return {'case_id': plan['case_id'], 'verification_status': 'unverified',
                'results': results, 'comparisons': comparisons,
                'limits': {'method': 'GET', 'max_bytes': _MAX_BYTES, 'redirects_followed': False}}


def persist_replay(store, replay: dict) -> int:
    """Only structural results are written; all raw creds/bodies were discarded."""
    added = store.add_exchanges([item['record'] for item in replay['results']])
    path = store.directory / 'replay_results.json'
    existing = json.loads(path.read_text(encoding='utf-8')) if path.exists() else []
    sanitized = {
        'case_id': replay['case_id'], 'verification_status': replay['verification_status'],
        'results': [{k: v for k, v in item.items() if k != 'record'} for item in replay['results']],
        'comparisons': replay['comparisons'], 'limits': replay['limits'],
    }
    existing = [item for item in existing if item.get('case_id') != replay['case_id']]
    existing.append(sanitized)
    _save_json(path, existing)
    return added


def load_replay_plan(path: Path) -> dict:
    if path.suffix.lower() != '.json' or path.stat().st_size > 20000:
        raise ValueError('Replay plan must be a small JSON file')
    return json.loads(path.read_text(encoding='utf-8'))
