"""Atomic storage of *redacted* capture observations and analysis candidates."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile


def _save_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix='.securityai-', suffix='.tmp', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


class TrafficStore:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.exchanges_path = self.directory / 'exchanges.json'
        self.hypotheses_path = self.directory / 'hypotheses.json'

    def load_exchanges(self) -> list[dict]:
        if not self.exchanges_path.exists():
            return []
        data = json.loads(self.exchanges_path.read_text(encoding='utf-8'))
        if not isinstance(data, list):
            raise ValueError('Invalid traffic exchange store')
        return data

    def add_exchanges(self, records: list[dict]) -> int:
        unique = {record['exchange_id']: record for record in self.load_exchanges()}
        previous = len(unique)
        for record in records:
            unique.setdefault(record['exchange_id'], record)
        _save_json(self.exchanges_path, list(unique.values()))
        return len(unique) - previous

    def load_hypotheses(self) -> list[dict]:
        if not self.hypotheses_path.exists():
            return []
        data = json.loads(self.hypotheses_path.read_text(encoding='utf-8'))
        if not isinstance(data, list):
            raise ValueError('Invalid traffic hypotheses store')
        return data

    def add_hypotheses(self, candidates: list[dict]) -> int:
        unique = {item['hypothesis_id']: item for item in self.load_hypotheses()}
        prior = len(unique)
        for item in candidates:
            if item['hypothesis_id'] in unique:
                current = unique[item['hypothesis_id']]
                current['exchange_ids'] = sorted(set(current['exchange_ids'] + item['exchange_ids']))
                current['signal_ids'] = sorted(set(current['signal_ids'] + item['signal_ids']))
            else:
                unique[item['hypothesis_id']] = item
        _save_json(self.hypotheses_path, list(unique.values()))
        return len(unique) - prior
