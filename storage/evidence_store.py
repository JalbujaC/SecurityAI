import json
from dataclasses import asdict
from pathlib import Path
from storage.evidence import EvidenceRecord


class EvidenceStore:
    def __init__(self, path: str | None = None):
        self._records: list[EvidenceRecord] = []
        self.path = Path(path) if path else None

    def add(self, record: EvidenceRecord) -> None:
        if record.evidence_id and any(item.evidence_id == record.evidence_id for item in self._records):
            return
        self._records.append(record)
        if self.path:
            self.save()

    def all(self) -> list[EvidenceRecord]:
        return list(self._records)

    def count(self) -> int:
        return len(self._records)

    def get(self, evidence_id: str) -> EvidenceRecord:
        for record in self._records:
            if record.evidence_id == evidence_id:
                return record
        raise KeyError(f'Unknown evidence: {evidence_id}')

    def by_tool(self, tool_name: str) -> list[EvidenceRecord]:
        return [r for r in self._records if r.tool_name == tool_name]

    def by_target(self, target: str) -> list[EvidenceRecord]:
        return [r for r in self._records if r.target == target]

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([asdict(r) for r in self._records],
                                        indent=2, default=str), encoding='utf-8')

    def load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        raw = json.loads(self.path.read_text(encoding='utf-8'))
        self._records = []
        for item in raw:
            record = EvidenceRecord(**item)
            if record.evidence_id and any(r.evidence_id == record.evidence_id for r in self._records):
                continue
            self._records.append(record)
