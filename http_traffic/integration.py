"""Opt-in bridge from sanitized traffic to SecurityAI's evidence/finding lifecycle.

Never registers replay with the autonomous tool registry. Never validates findings.
"""
from __future__ import annotations

import math
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from http_traffic.normalize import safe_url, safe_name
from http_traffic.compare import compare_exchanges
from http_traffic.signals import derive_signals
from storage.evidence import EvidenceRecord
from storage.findings import FindingRecord
from tools.schemas import ToolResult
from agent.finding_builder import FindingBuilder


@dataclass
class TrafficSeed:
    seed_evidence: list[str] = field(default_factory=list)
    seed_evidence_ids: list[str] = field(default_factory=list)
    imported_exchanges: int = 0
    new_findings: int = 0
    seeded_hosts: int = 0
    replay_comparisons: int = 0


class TrafficBridge:
    def __init__(self, *, scope_validator, evidence_store, finding_store, target_manager=None):
        self.scope_validator = scope_validator
        self.evidence_store = evidence_store
        self.finding_store = finding_store
        self.target_manager = target_manager

    def integrate(self, store, *, promote_hypotheses: bool = False,
                  seed_hosts: bool = False, max_exchanges: int = 400) -> TrafficSeed:
        if not 1 <= max_exchanges <= 2000:
            raise ValueError('Invalid traffic integration limit')
        result = TrafficSeed()
        records = []
        for record in store.load_exchanges():
            if not isinstance(record, dict):
                continue
            try:
                method = record['method']
                raw_url = record['url']
                if method not in ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'):
                    continue
                self.scope_validator.validate(raw_url)
                sanitized_url, _, names = safe_url(raw_url)
                if record.get('exchange_id') is None or not isinstance(record['exchange_id'], str):
                    continue
                if len(record['exchange_id']) != 20 or not all(c in '0123456789abcdef' for c in record['exchange_id']):
                    continue
                if not isinstance(record.get('status'), int):
                    continue
                records.append((record, sanitized_url, names))
                if len(records) >= max_exchanges:
                    break
            except (ValueError, PermissionError, KeyError, TypeError):
                continue
        if not records:
            return result
        original_records = [record for record, _, _ in records]
        signals = derive_signals(original_records)
        signal_map = {signal['signal_id']: signal for signal in signals}
        signals_by_exchange = {}
        for signal in signals:
            for eid in signal['exchange_ids']:
                signals_by_exchange.setdefault(eid, []).append(signal['code'])
        exchange_ids = set()
        evidence_by_exchange = {}
        seen_hosts = set()
        for record, url, names in records:
            eid = record['exchange_id']
            if eid in exchange_ids:
                continue
            exchange_ids.add(eid)
            host = urlsplit(url).hostname
            fields = [safe_name(path) for path in (record.get('response_json_fields') or [])[:35]]
            payload = {
                'exchange_id': eid, 'method': record['method'], 'redacted_url': url,
                'status': record['status'], 'query_names': names,
                'response_fields': fields,
                'review_signals': sorted(set(signals_by_exchange.get(eid, []))),
                'classification': 'redacted_http_observation_not_verified',
            }
            evidence = EvidenceRecord.from_tool_result(ToolResult(
                tool_name='http_traffic', target=host, success=True, output=payload))
            self.evidence_store.add(evidence)
            evidence_by_exchange[eid] = evidence.evidence_id
            if seed_hosts and self.target_manager is not None and host not in seen_hosts:
                self.target_manager.add_discovered(host, source='http_traffic_import')
                seen_hosts.add(host)
                result.seeded_hosts += 1
        result.imported_exchanges = len(exchange_ids)
        comparison_links: list[tuple[set[str], str]] = []
        replay_file = store.directory / 'replay_results.json'
        if replay_file.exists() and replay_file.stat().st_size <= 2_000_000:
            try:
                runs = json.loads(replay_file.read_text(encoding='utf-8'))
            except (ValueError, OSError):
                runs = []
            lookup = {record['exchange_id']: record for record, _, _ in records}
            for run in runs[:50] if isinstance(runs, list) else []:
                if not isinstance(run, dict) or run.get('verification_status') != 'unverified':
                    continue
                for entry in (run.get('comparisons') or [])[:20]:
                    if not isinstance(entry, dict):
                        continue
                    a, b = entry.get('first_exchange_id'), entry.get('second_exchange_id')
                    if not isinstance(a, str) or not isinstance(b, str):
                        continue
                    if a not in lookup or b not in lookup:
                        continue
                    try:
                        compared = compare_exchanges(lookup[a], lookup[b])
                    except ValueError:
                        continue
                    # Recalculate differences only from safely stored normalized records.
                    compared['classification'] = 'unverified_response_comparison'
                    evidence = EvidenceRecord.from_tool_result(ToolResult(
                        tool_name='http_traffic_comparison',
                        target=urlsplit(lookup[a]['url']).hostname,
                        success=True, output=compared))
                    self.evidence_store.add(evidence)
                    comparison_links.append(({a, b}, evidence.evidence_id))
                    result.replay_comparisons += 1
        result.seed_evidence_ids = list(dict.fromkeys(
            list(evidence_by_exchange.values()) + [eid for _, eid in comparison_links]))
        # Only concise factual context enters planner, never stored response text or credentials.
        result.seed_evidence = [
            'Passive, redacted HTTP evidence (not proof of vulnerability): '
            f'{len(exchange_ids)} in-scope exchanges; signal types: '
            f'{", ".join(sorted({s["code"] for s in signals})) or "none"}; '
            'refer to existing EvidenceStore for exchange-level facts. '
            f'{result.replay_comparisons} unverified response comparisons; '
            'Do not treat observed status or field names as a validated finding.'
        ]
        if not promote_hypotheses:
            return result
        for item in store.load_hypotheses():
            if not isinstance(item, dict) or item.get('validation_status') != 'unverified':
                continue
            if item.get('status') != 'review_hypothesis':
                continue
            ids = item.get('exchange_ids')
            sids = item.get('signal_ids')
            if (not isinstance(ids, list) or not ids
                    or any(not isinstance(eid, str) for eid in ids)
                    or not set(ids).issubset(exchange_ids)):
                continue
            if (not isinstance(sids, list) or not sids
                    or any(not isinstance(sid, str) or sid not in signal_map for sid in sids)):
                continue
            linked = {eid for sid in sids for eid in signal_map[sid]['exchange_ids']}
            if not set(ids).issubset(linked):
                continue
            title = item.get('title')
            cls = item.get('vulnerability_class')
            if not isinstance(title, str) or not 2 <= len(title.strip()) <= 160:
                continue
            if cls not in {
                'IDOR_BOLA_CANDIDATE', 'ACCESS_CONTROL_CANDIDATE', 'SENSITIVE_DATA_REVIEW',
                'ERROR_DISCLOSURE_REVIEW', 'CORS_REVIEW', 'CACHE_REVIEW',
                'AUTH_BEHAVIOR_REVIEW', 'OTHER_REVIEW',
            }:
                continue
            try:
                score = float(item.get('confidence', 0.0))
                if not math.isfinite(score) or not 0 <= score <= 1:
                    continue
            except (TypeError, ValueError):
                continue
            # In-scope hypothesis; no model assessment can become 'validated' here.
            target = urlsplit(next(url for r, url, _ in records if r['exchange_id'] == ids[0])).hostname
            fid = FindingBuilder.fingerprint(
                target=target, vulnerability_class=cls,
                hypothesis=f'{item.get("hypothesis_id", "")}:{title}')
            rationale = str(item.get('rationale') or '')[:400]
            gap = str(item.get('verification_gap') or '')[:300]
            summary = f'{rationale} | Verification gap: {gap} | Traffic exchange IDs: {", ".join(ids[:10])}'
            before = self.finding_store.count()
            linked_ids = [evidence_by_exchange[eid] for eid in ids]
            for compared_ids, comparison_eid in comparison_links:
                if compared_ids.issubset(set(ids)):
                    linked_ids.append(comparison_eid)
            self.finding_store.add_or_merge(FindingRecord(
                finding_id=fid, title=title, target=target, vulnerability_class=cls,
                status='hypothesis', summary=summary,
                evidence_ids=list(dict.fromkeys(linked_ids)),
                confidence=min(score, 0.59)))
            if self.finding_store.count() > before:
                result.new_findings += 1
        return result


def seed_from_environment(system: dict, target: str) -> dict:
    """Call only when SECURITYAI_TRAFFIC_PROJECT is explicitly set in main.py."""
    import os
    from traffic_analysis import _scoped_store
    project = os.environ['SECURITYAI_TRAFFIC_PROJECT']
    store = _scoped_store([target], project)
    if not store.exchanges_path.exists():
        raise FileNotFoundError(f'No traffic exchanges found at {store.exchanges_path}')
    bridge = TrafficBridge(
        scope_validator=system['registry'].scope_validator,
        evidence_store=system['evidence_store'],
        finding_store=system['finding_store'],
        target_manager=system['target_manager'])
    seed = bridge.integrate(
        store,
        promote_hypotheses=os.environ.get('SECURITYAI_TRAFFIC_PROMOTE', '') == '1',
        seed_hosts=os.environ.get('SECURITYAI_TRAFFIC_SEED_HOSTS', '') == '1')
    print(f'[TRAFFIC] {seed.imported_exchanges} exchanges linked, '
          f'{seed.new_findings} new review hypotheses, {seed.seeded_hosts} opt-in hosts')
    return {'seed_evidence': seed.seed_evidence, 'seed_evidence_ids': seed.seed_evidence_ids}
