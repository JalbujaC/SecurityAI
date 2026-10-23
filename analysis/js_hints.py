"""Offline JS endpoint hints only. Never fetch or execute discovered URLs."""
import re
from urllib.parse import urljoin, urlsplit

_PATTERN = re.compile(r'''["']((?:/api/|/v[0-9]+/)[a-zA-Z0-9_./{}?&=%-]{2,180})["']''')

def extract_endpoint_hints(script: str, base_url: str, scope_validator=None, limit: int = 30) -> list[str]:
    if not urlsplit(base_url).scheme:
        return []
    found = set()
    for match in _PATTERN.finditer(script):
        endpoint = urljoin(base_url, match.group(1))
        if scope_validator is not None and not scope_validator.is_allowed(endpoint):
            continue
        found.add(endpoint)
        if len(found) >= limit:
            break
    return sorted(found)
