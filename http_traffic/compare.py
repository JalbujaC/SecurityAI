"""Conservative comparison of *redacted* HTTP exchanges.

No claim of unauthorized access follows from status/shape differences alone.
"""
from __future__ import annotations


def compare_exchanges(first: dict, second: dict) -> dict:
    for ex in (first, second):
        if not isinstance(ex, dict) or not ex.get('exchange_id') or not ex.get('endpoint_key'):
            raise ValueError('Two normalized exchanges are required')
    same_endpoint = (first['endpoint_key'] == second['endpoint_key']
                     and first.get('method') == second.get('method'))
    if not same_endpoint:
        raise ValueError('Cannot compare different endpoint groups or methods')
    left = set(first.get('response_json_fields') or [])
    right = set(second.get('response_json_fields') or [])
    flags_left = set(first.get('response_flags') or [])
    flags_right = set(second.get('response_flags') or [])
    changes = {}
    if first.get('status') != second.get('status'):
        changes['status'] = [first.get('status'), second.get('status')]
    if left != right:
        changes['json_field_names'] = {'only_first': sorted(left - right)[:30],
                                       'only_second': sorted(right - left)[:30]}
    if flags_left != flags_right:
        changes['response_flags'] = {'only_first': sorted(flags_left - flags_right),
                                     'only_second': sorted(flags_right - flags_left)}
    for name in ('response_content_type', 'cors_allow_origin',
                 'cors_allow_credentials', 'cache_policy', 'sets_cookie'):
        if first.get(name) != second.get(name):
            changes[name] = [first.get(name), second.get(name)]
    return {
        'comparison_status': 'observed_difference' if changes else 'same_redacted_structure',
        'verification_status': 'unverified',
        'same_endpoint': True,
        'first_exchange_id': first['exchange_id'],
        'second_exchange_id': second['exchange_id'],
        'changes': changes,
        'interpretation': 'A status/shape difference is not proof of IDOR or broken access control.',
    }


def compare_by_id(exchanges: list[dict], first_id: str, second_id: str) -> dict:
    lookup = {x.get('exchange_id'): x for x in exchanges}
    if first_id not in lookup or second_id not in lookup:
        raise KeyError('Exchange ID not found in scoped store')
    return compare_exchanges(lookup[first_id], lookup[second_id])
