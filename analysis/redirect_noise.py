"""Conservative redirect grouping for reconnaissance triage.

Grouping is informational only. A login redirect is not an auth bypass.
"""
from collections import defaultdict
from urllib.parse import urlparse


def redirect_groups(findings: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for item in findings:
        if not isinstance(item, dict):
            continue
        status = item.get('status', item.get('status_code'))
        location = item.get('redirect_location') or item.get('redirectlocation')
        if status not in (301, 302, 303, 307, 308) or not isinstance(location, str):
            continue
        parsed = urlparse(location)
        # Query strings and fragments often vary per request; group by route.
        key = (status, parsed.netloc.lower(), parsed.path.rstrip('/') or '/')
        groups[key].append(str(item.get('url') or ''))
    return [
        {'status_code': status, 'redirect_host': host, 'redirect_path': path,
         'count': len(urls), 'example_urls': sorted(set(urls))[:3],
         'classification': 'redirect_observation_not_vulnerability'}
        for (status, host, path), urls in sorted(groups.items())
    ]
