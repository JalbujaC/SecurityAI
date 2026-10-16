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

    def __init__(self):
        self._findings: dict[str, FindingRecord] = {}

    def add(
        self,
        finding: FindingRecord,
    ) -> None:
        if finding.finding_id in self._findings:
            raise ValueError(
                f"Finding already exists: {finding.finding_id}"
            )

        self._findings[finding.finding_id] = finding

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

        return finding