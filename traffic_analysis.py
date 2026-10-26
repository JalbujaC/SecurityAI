"""SecurityAI v1.3: passive traffic analysis, offline comparison and explicit replay.

Only the replay operation performs target HTTP requests, with human approval.
"""
from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from http_traffic.importers import import_capture
from http_traffic.store import TrafficStore
from http_traffic.signals import derive_signals
from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator


def _scoped_store(scopes: list[str], project: str) -> TrafficStore:
    labels = sorted({scope.lower().strip() for scope in scopes})
    if not all(re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+', label) for label in labels):
        raise ValueError('--scope requires exact domain names (e.g. example.com)')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', project):
        raise ValueError('--project must be 1..40 alphanumeric, hyphen, underscore characters')
    digest = hashlib.sha256('|'.join(labels).encode('utf-8')).hexdigest()[:10]
    return TrafficStore(Path('data') / 'traffic' / f'{project.lower()}-{digest}')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Offline redacted HTTP traffic intelligence (SecurityAI v1.2)')
    parser.add_argument('operation', choices=['import', 'analyze', 'inspect', 'compare', 'replay'])
    parser.add_argument('--scope', action='append', required=True, help='Explicitly authorized domain, repeatable')
    parser.add_argument('--exclude', action='append', default=[], help='Excluded domain, repeatable')
    parser.add_argument('--project', default='research', help='Local store label, not a domain')
    parser.add_argument('--input', type=Path, help='Existing .har, JSON HAR or Burp .xml file')
    parser.add_argument('--model', default='qwen3:8b', help='Locally installed Ollama model')
    parser.add_argument('--batch-size', type=int, default=8)
    parser.add_argument('--max-batches', type=int, default=25)
    parser.add_argument('--first', help='First stored exchange ID for compare')
    parser.add_argument('--second', help='Second stored exchange ID for compare')
    parser.add_argument('--plan', type=Path, help='Explicit human-authored HTTPS replay JSON')
    parser.add_argument('--approve-replay', help='Exact case_id approving this replay')
    parser.add_argument('--authorization-confirmed', action='store_true',
                        help='Acknowledge target/program authorization and ownership of test contexts')
    args = parser.parse_args(argv)

    try:
        store = _scoped_store(args.scope, args.project)
        validator = ScopeValidator(ScopeConfig(allowed_domains=args.scope, excluded_domains=args.exclude))
        if args.operation == 'import':
            if args.input is None:
                parser.error('import requires --input')
            records, stats = import_capture(args.input, validator)
            saved = store.add_exchanges(records)
            print(f'Imported: {stats}; new redacted exchanges persisted: {saved}')
            print(f'Store: {store.exchanges_path}')
        elif args.operation == 'inspect':
            records = [r for r in store.load_exchanges() if validator.is_allowed(r.get('url', ''))]
            signals = derive_signals(records)
            print(f'Store: {store.directory}; exchanges: {len(records)}; deterministic signals: {len(signals)}')
            for code in sorted({s['code'] for s in signals}):
                print(f'  {code}: {sum(s["code"] == code for s in signals)}')
            print(f'Review hypotheses stored: {len(store.load_hypotheses())}')
        elif args.operation == 'compare':
            from http_traffic.compare import compare_by_id
            if not args.first or not args.second:
                parser.error('compare requires --first and --second exchange IDs')
            records = [r for r in store.load_exchanges() if validator.is_allowed(r.get('url', ''))]
            import json
            print(json.dumps(compare_by_id(records, args.first, args.second), indent=2))
        elif args.operation == 'replay':
            if args.plan is None:
                parser.error('replay requires --plan')
            from http_traffic.replay import ReplayExecutor, persist_replay, load_replay_plan
            plan = load_replay_plan(args.plan)
            result = ReplayExecutor(validator).execute(
                plan, approved_case_id=args.approve_replay,
                authorization_confirmed=args.authorization_confirmed)
            added = persist_replay(store, result)
            print(f'Controlled replay completed. New redacted exchanges: {added}; '
                  f'comparison records: {len(result["comparisons"])}')
            print(f'Unverified replay audit: {store.directory / "replay_results.json"}')
        else:
            records = [r for r in store.load_exchanges() if validator.is_allowed(r.get('url', ''))]
            if not records:
                print('No imported exchanges. Run import first.')
                return 1
            # Lazy import: passive import works without Ollama or requests installed.
            from models.ollama import OllamaClient
            from http_traffic.analyzer import TrafficAnalyzer
            analyzer = TrafficAnalyzer(
                OllamaClient(model_name=args.model, base_url='http://127.0.0.1:11434', timeout=300),
                batch_size=args.batch_size, max_batches=args.max_batches,
            )
            hypotheses, stats = analyzer.analyze(records)
            saved = store.add_hypotheses(hypotheses)
            print(f'Analysis summary: {stats}')
            print(f'New unverified review hypotheses saved: {saved}')
            print(f'Store: {store.hypotheses_path}')
        return 0
    except (ValueError, OSError, PermissionError, KeyError) as exc:
        print(f'Traffic pipeline error: {exc}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
