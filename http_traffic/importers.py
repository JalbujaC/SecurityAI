"""Offline HAR and Burp Suite XML importers. NO HTTP traffic is transmitted."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from .normalize import MAX_BODY_CHARS, normalize_exchange

MAX_CAPTURE_BYTES = 40 * 1024 * 1024
MAX_EXCHANGES = 10000
MAX_BURP_MESSAGE_CHARS = 600000


def _headers_from_mapping(items: list[dict]) -> list[dict]:
    return [dict(name=str(item.get('name', '')), value=str(item.get('value', '')))
            for item in items if isinstance(item, dict)][:200]


def _har_body(node: dict) -> str:
    if not isinstance(node, dict):
        return ''
    data = node.get('text', '')
    if not isinstance(data, str):
        return ''
    if node.get('encoding') == 'base64':
        # Limit decoding overhead. Binary content never needs analysis.
        if len(data) > (MAX_BODY_CHARS * 2):
            return ''
        try:
            return base64.b64decode(data, validate=True).decode('utf-8', errors='replace')[:MAX_BODY_CHARS]
        except (ValueError, UnicodeError):
            return ''
    return data[:MAX_BODY_CHARS]


def _read_har(data: bytes):
    root = json.loads(data)
    if not isinstance(root, dict) or not isinstance(root.get('log'), dict):
        raise ValueError('Not a valid HAR document')
    entries = root['log'].get('entries')
    if not isinstance(entries, list):
        raise ValueError('Not a valid HAR (log.entries must be a list)')
    for index, entry in enumerate(entries[:MAX_EXCHANGES], 1):
        entry = entry if isinstance(entry, dict) else {}
        req = entry.get('request') if isinstance(entry.get('request'), dict) else {}
        resp = entry.get('response') if isinstance(entry.get('response'), dict) else {}
        url = req.get('url', '')
        content = resp.get('content') or {}
        yield dict(
            method=req.get('method', 'GET'), url=url,
            request_headers=_headers_from_mapping(req.get('headers') or []),
            response_headers=_headers_from_mapping(resp.get('headers') or []),
            status=resp.get('status', 0),
            request_body=_har_body((req.get('postData') or {})),
            response_body=_har_body(content),
            source_ref=f'entry:{index}', source_format='har',
        )


def _burp_payload(element):
    if element is None:
        return ''
    value = element.text or ''
    if element.get('base64', '').lower() == 'true':
        if len(value) > MAX_BURP_MESSAGE_CHARS * 2:
            return ''
        try:
            return base64.b64decode(value, validate=True).decode('utf-8', errors='replace')[:MAX_BURP_MESSAGE_CHARS]
        except (ValueError, UnicodeError):
            return ''
    return value[:MAX_BURP_MESSAGE_CHARS]


def _split_message(message: str) -> tuple[str, list[dict], str]:
    if '\r\n\r\n' in message:
        head, body = message.split('\r\n\r\n', 1)
    elif '\n\n' in message:
        head, body = message.split('\n\n', 1)
    else:
        head, body = message, ''
    lines = head.splitlines()
    initial = lines[0] if lines else ''
    headers = []
    for line in lines[1:200]:
        if ':' in line and not line.startswith((' ', '\t')):
            key, value = line.split(':', 1)
            headers.append({'name': key.strip(), 'value': value.strip()})
    return initial, headers, body[:MAX_BODY_CHARS]


def _read_burp(data: bytes):
    # Block DTD/entity declarations, which are unnecessary for Burp exports.
    if b'<!doctype' in data.lower() or b'<!entity' in data.lower():
        raise ValueError('XML DTD/entity declarations are not allowed')
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError('Malformed Burp XML') from exc
    if root.tag.lower() != 'items':
        raise ValueError('Expected Burp Suite XML root <items>')
    for index, item in enumerate(root.findall('item')[:MAX_EXCHANGES], 1):
        request_first, request_headers, request_body = _split_message(_burp_payload(item.find('request')))
        response_first, response_headers, response_body = _split_message(_burp_payload(item.find('response')))
        url = item.findtext('url', default='')
        method = item.findtext('method', default='') or request_first.split(' ', 1)[0]
        status = item.findtext('status', default='0')
        if not status or not status.isdigit():
            parts = response_first.split(' ')
            status = parts[1] if len(parts) > 1 and parts[1].isdigit() else 0
        yield dict(
            method=method, url=url, request_headers=request_headers,
            response_headers=response_headers, status=int(status),
            request_body=request_body, response_body=response_body,
            source_ref=f'item:{index}', source_format='burp_xml',
        )


def import_capture(path: str | Path, scope_validator, *, max_entries: int = MAX_EXCHANGES) -> tuple[list[dict], dict]:
    """Only read local bytes; skip all out-of-scope HTTP exchanges."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > MAX_CAPTURE_BYTES:
        raise ValueError('Capture exceeds 40 MiB safety limit; split into smaller files')
    if max_entries < 1 or max_entries > MAX_EXCHANGES:
        raise ValueError(f'max_entries must be 1..{MAX_EXCHANGES}')
    data = path.read_bytes()
    ext = path.suffix.lower()
    if ext == '.har' or (ext == '.json' and data.lstrip().startswith(b'{')):
        stream = _read_har(data)
    elif ext == '.xml':
        stream = _read_burp(data)
    else:
        raise ValueError('Only .har, .json HAR, and Burp Suite .xml exports are supported')
    stats = {'total': 0, 'accepted': 0, 'out_of_scope': 0, 'malformed': 0, 'duplicates': 0}
    records = []
    seen = set()
    for entry in stream:
        if stats['total'] >= max_entries:
            break
        stats['total'] += 1
        try:
            # Scope check before writing ANY representation to disk.
            url = entry['url']
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
                stats['malformed'] += 1
                continue
            if not scope_validator.is_allowed(url):
                stats['out_of_scope'] += 1
                continue
            record = normalize_exchange(**entry)
        except (ValueError, TypeError, AttributeError, OverflowError):
            stats['malformed'] += 1
            continue
        if record['exchange_id'] in seen:
            stats['duplicates'] += 1
            continue
        seen.add(record['exchange_id'])
        records.append(record)
        stats['accepted'] += 1
    return records, stats
