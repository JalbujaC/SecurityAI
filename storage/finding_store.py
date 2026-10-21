import json

from dataclasses import asdict
from pathlib import Path

from storage.findings import FindingRecord


class FindingStore:
    """
    Tracks vulnerability hypotheses and their state.

    This store does not create findings automatically.
    It only stores and updates them.
    """

    ALLOWED_TRANSITIONS: dict[str, set[str]] = {
        "hypothesis": {
            "needs_validation",
            "rejected",
        },
        "needs_validation": {
            "validated",
            "rejected",
        },
        "validated": {
            "report_candidate",
            "rejected",
        },
        "rejected": set(),
        "report_candidate": set(),
    }

    def __init__(self, path: str | None = None):
        self._findings: dict[str, FindingRecord] = {}
        self.path = Path(path) if path else None

    def add(
        self,
        finding: FindingRecord,
    ) -> None:
        if finding.finding_id in self._findings:
            raise ValueError(
                f"Finding already exists: {finding.finding_id}"
            )

        self._findings[
            finding.finding_id
        ] = finding

        if self.path is not None:
            self.save()


    def add_or_merge(
        self,
        finding: FindingRecord,
    ) -> FindingRecord:
        existing = self._findings.get(
            finding.finding_id
        )

        if existing is None:
            self._findings[
                finding.finding_id
            ] = finding

            return finding

        merged_evidence = list(
            dict.fromkeys(
                existing.evidence_ids
                + finding.evidence_ids
            )
        )

        existing.evidence_ids = (
            merged_evidence
        )

        existing.confidence = max(
            existing.confidence,
            finding.confidence,
        )

        if (
            finding.summary
            and not existing.summary
        ):
            existing.summary = (
                finding.summary
            )
        if self.path is not None:
            self.save()
        
        return existing

    def get(
        self,
        finding_id: str,
    ) -> FindingRecord:
        try:
            return self._findings[finding_id]
        except KeyError as exc:
            raise KeyError(
                f"Unknown finding: {finding_id}"
            ) from exc

    def all(self) -> list[FindingRecord]:
        return list(self._findings.values())

    def count(self) -> int:
        return len(self._findings)

    def by_status(
        self,
        status: str,
    ) -> list[FindingRecord]:
        return [
            finding
            for finding in self._findings.values()
            if finding.status == status
        ]

    def save(self) -> None:
        if self.path is None:
            return

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        data = [
            asdict(finding)
            for finding in self._findings.values()
        ]

        self.path.write_text(
            json.dumps(
                data,
                indent=2,
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

        self._findings = {
            item["finding_id"]: FindingRecord(
                **item
            )
            for item in raw
        }
        
    def update_status(
        self,
        finding_id: str,
        status: str,
    ) -> FindingRecord:
        finding = self.get(finding_id)

        current_status = finding.status

        if current_status not in self.ALLOWED_TRANSITIONS:
            raise ValueError(
                f"Unknown current finding status: {current_status}"
            )

        allowed = self.ALLOWED_TRANSITIONS[
            current_status
        ]

        if status not in allowed:
            raise ValueError(
                f"Invalid finding status transition: "
                f"{current_status} -> {status}"
            )

        finding.status = status
        if self.path is not None:
            self.save()
            
        return finding

    def mark_needs_validation(
        self,
        finding_id: str,
    ) -> FindingRecord:
        return self.update_status(
            finding_id,
            "needs_validation",
        )