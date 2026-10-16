import json
from dataclasses import asdict
from pathlib import Path

from storage.evidence import EvidenceRecord


class EvidenceStore:
    """
    Stores evidence collected during a SecurityAI run.

    Records are kept in memory and can optionally
    be persisted to a JSON file.
    """

    def __init__(
        self,
        path: str | None = None,
    ):
        self._records: list[EvidenceRecord] = []
        self.path = Path(path) if path else None

    def add(
        self,
        record: EvidenceRecord,
    ) -> None:
        self._records.append(record)

        if self.path is not None:
            self.save()

    def all(self) -> list[EvidenceRecord]:
        return list(self._records)

    def count(self) -> int:
        return len(self._records)

    def by_tool(
        self,
        tool_name: str,
    ) -> list[EvidenceRecord]:
        return [
            record
            for record in self._records
            if record.tool_name == tool_name
        ]

    def by_target(
        self,
        target: str,
    ) -> list[EvidenceRecord]:
        return [
            record
            for record in self._records
            if record.target == target
        ]

    def save(self) -> None:
        if self.path is None:
            return

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        data = [
            asdict(record)
            for record in self._records
        ]

        self.path.write_text(
            json.dumps(
                data,
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )

    def load(self) -> None:
        if self.path is None:
            return

        if not self.path.exists():
            return

        raw = json.loads(
            self.path.read_text(
                encoding="utf-8"
            )
        )

        self._records = [
            EvidenceRecord(**item)
            for item in raw
        ]