"""Deterministic, explainable observation identity and coverage summaries."""
import hashlib
import json
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


def normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        return url.strip()
    hostname = parts.hostname.lower()
    port = f':{parts.port}' if parts.port else ''
    path = parts.path.rstrip('/') or '/'
    # Parameter values are deliberately retained; only order normalized.
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((parts.scheme.lower(), hostname + port, path, query, ''))


def observation_fingerprint(tool: str, target: str, observation: dict) -> str:
    payload = {
        'tool': tool,
        'target': normalize_url(target),
        'observation': observation,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:20]


def summarize_result(result) -> dict:
    """Success with zero observations is NEGATIVE evidence, not a finding."""
    if not result.success:
        return {'classification': 'tool_failure', 'count': 0}
    output = result.output if isinstance(result.output, dict) else {}
    count = output.get('count')
    if not isinstance(count, int):
        count = next((len(output[k]) for k in ('findings','results','endpoints','urls','records','ports','subdomains')
                      if isinstance(output.get(k), list)), 0)
    return {'classification': 'observations' if count else 'negative_observation',
            'count': count}
