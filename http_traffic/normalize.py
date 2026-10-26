"""Data-minimizing HTTP exchange normalization. No raw values persist."""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

MAX_BODY_CHARS = 98304
MAX_JSON_PATHS = 70
MAX_PATH_DEPTH = 5
_ID = re.compile(r"^(?:\d{2,}|[0-9a-f]{8}-[0-9a-f-]{20,}|[a-zA-Z0-9_-]{28,})$", re.I)
_SAFE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,50}$")
_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)
_TRACE = re.compile(r"Traceback \(most recent call last\)|(?:Exception|Error):.*(?: at |line \d+)|stack trace|at [a-zA-Z_$.]+\([^\n]+:\d+", re.I)
_SECRETS = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)\b")


def safe_name(value: object) -> str:
    """Only retain bounded structural field names, never unknown key values."""
    value = str(value)
    return value.lower() if _SAFE_NAME.fullmatch(value) else '[nonstandard-key]'


def safe_url(raw: str) -> tuple[str, str, list[str]]:
    """Return redacted URL, endpoint group key and query *names* only."""
    parts = urlsplit(raw)
    if parts.scheme.lower() not in {'http', 'https'} or not parts.hostname:
        raise ValueError('Expected an absolute HTTP(S) URL')
    if parts.username or parts.password:
        raise ValueError('URLs containing userinfo are not supported')
    host = parts.hostname.lower()
    port = f':{parts.port}' if parts.port else ''
    names = sorted({safe_name(key) for key, _ in parse_qsl(parts.query, keep_blank_values=True)})[:35]
    path_parts = []
    object_segments = {'users', 'user', 'orders', 'order', 'accounts', 'account', 'invoices', 'invoice', 'documents', 'document', 'files', 'file', 'customers', 'customer', 'resources', 'resource'}
    previous = ''
    for part in parts.path.split('/'):
        if not part:
            path_parts.append('')
        elif _ID.fullmatch(part) or (previous in object_segments and part) or '@' in part or len(part) > 80:
            path_parts.append('{id}')
        else:
            # Only retain conservative endpoint path characters. Never persist encoded values.
            cleaned = re.sub(r'[^A-Za-z0-9_.{}~-]', '_', part)
            path_parts.append(cleaned[:70])
        previous = part.lower()
    path = '/'.join(path_parts) or '/'
    if not path.startswith('/'):
        path = '/' + path
    query = '&'.join(f'{name}=[REDACTED]' for name in names)
    redacted = urlunsplit((parts.scheme.lower(), host + port, path, query, ''))
    group_key = f'{parts.scheme.lower()}://{host}{port}{path}?{",".join(names)}'
    return redacted, group_key, names


def _header_names(headers: list[dict]) -> list[str]:
    return sorted({safe_name(item.get('name', '')) for item in headers if isinstance(item, dict)})[:70]


def _header_value(headers: list[dict], name: str) -> str:
    for item in headers:
        if isinstance(item, dict) and str(item.get('name', '')).lower() == name:
            return str(item.get('value', ''))[:1500]
    return ''


def _json_paths(obj: object, path: str = '', depth: int = 0, result: list[str] | None = None) -> list[str]:
    if result is None:
        result = []
    if depth > MAX_PATH_DEPTH or len(result) >= MAX_JSON_PATHS:
        return result
    if isinstance(obj, dict):
        for name, value in list(obj.items())[:80]:
            field = safe_name(name)
            new_path = f'{path}.{field}' if path else field
            if new_path not in result:
                result.append(new_path)
            _json_paths(value, new_path, depth + 1, result)
            if len(result) >= MAX_JSON_PATHS:
                break
    elif isinstance(obj, list) and obj:
        _json_paths(obj[0], f'{path}[]', depth + 1, result)
    return result[:MAX_JSON_PATHS]


def _body_signals(body: str, mime: str) -> tuple[list[str], list[str]]:
    snippet = body[:MAX_BODY_CHARS]
    observations = []
    if _TRACE.search(snippet):
        observations.append('stack_trace_pattern')
    if _SECRETS.search(snippet):
        observations.append('credential_like_pattern')
    if _EMAIL.search(snippet):
        observations.append('email_like_pattern')
    paths: list[str] = []
    if 'json' in mime.lower() or snippet.lstrip().startswith(('{', '[')):
        try:
            paths = _json_paths(json.loads(snippet))
        except (ValueError, TypeError, RecursionError):
            pass
    return sorted(observations), sorted(set(paths))


def normalize_exchange(
    *, method: str, url: str, request_headers: list[dict], response_headers: list[dict],
    status: int, request_body: str = '', response_body: str = '', source_ref: str = '',
    source_format: str = '',
) -> dict:
    redacted_url, endpoint_key, query_names = safe_url(url)
    req = request_headers or []
    resp = response_headers or []
    method = method.upper().strip()[:16]
    if not re.fullmatch(r'[A-Z]{1,16}', method):
        method = 'OTHER'
    req_mime = _header_value(req, 'content-type').split(';', 1)[0].lower()
    resp_mime = _header_value(resp, 'content-type').split(';', 1)[0].lower()
    req_flags, request_fields = _body_signals(request_body, req_mime)
    resp_flags, response_fields = _body_signals(response_body, resp_mime)
    # Do not persist request-body content signals: request can contain user-supplied secrets.
    cors_origin = _header_value(resp, 'access-control-allow-origin').strip()
    cache = _header_value(resp, 'cache-control').lower()
    set_cookies = [str(x.get('value', '')).lower() for x in resp if isinstance(x, dict) and str(x.get('name', '')).lower() == 'set-cookie']
    record = {
        'method': method,
        'url': redacted_url,
        'endpoint_key': endpoint_key,
        'query_names': query_names,
        'request_header_names': _header_names(req),
        'request_content_type': req_mime[:70],
        'has_authorization': bool(_header_value(req, 'authorization')),
        'has_cookie': bool(_header_value(req, 'cookie')),
        'request_json_fields': request_fields,
        'status': max(0, min(999, int(status or 0))),
        'response_header_names': _header_names(resp),
        'response_content_type': resp_mime[:70],
        'response_json_fields': response_fields,
        'response_flags': resp_flags,
        'cors_allow_origin': '*' if cors_origin == '*' else ('null' if cors_origin.lower() == 'null' else ('specific' if cors_origin else 'absent')),
        'cors_allow_credentials': _header_value(resp, 'access-control-allow-credentials').lower().strip() == 'true',
        'cache_policy': [x for x in ('public', 'private', 'no-store', 'no-cache') if x in cache],
        'sets_cookie': bool(set_cookies),
        'cookie_flags': {
            'all_secure': bool(set_cookies) and all(re.search(r'(?:^|;)\s*secure(?:;|$)', s) for s in set_cookies),
            'all_httponly': bool(set_cookies) and all(re.search(r'(?:^|;)\s*httponly(?:;|$)', s) for s in set_cookies),
        },
        'source_format': source_format,
        'source_ref': source_ref[:48],
    }
    # Unique only over sanitized content; raw requests, responses and secrets are never stored.
    canonical = json.dumps({k: v for k, v in record.items() if k not in {'source_format', 'source_ref'}}, sort_keys=True, separators=(',', ':'))
    record['exchange_id'] = hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:20]
    return record
