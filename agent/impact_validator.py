from dataclasses import dataclass

from storage.findings import FindingRecord


@dataclass
class ImpactAssessment:
    finding_id: str
    has_security_impact: bool
    impact_summary: str


class ImpactValidator:
    """
    Determines whether a validated finding has
    meaningful security impact.

    For v1, this is explicit and deterministic.
    """

    @staticmethod
    def assess(
        finding: FindingRecord,
        impact_summary: str,
    ) -> ImpactAssessment:

        if finding.status != "validated":
            raise ValueError(
                "Impact can only be assessed "
                "for validated findings."
            )

        normalized = impact_summary.strip()

        if not normalized:
            return ImpactAssessment(
                finding_id=finding.finding_id,
                has_security_impact=False,
                impact_summary="",
            )

        return ImpactAssessment(
            finding_id=finding.finding_id,
            has_security_impact=True,
            impact_summary=normalized,
        )