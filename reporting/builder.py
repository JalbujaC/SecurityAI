from agent.impact_validator import ImpactAssessment
from reporting.candidate import ReportCandidate
from storage.findings import FindingRecord


class ReportCandidateBuilder:
    @staticmethod
    def build(
        finding: FindingRecord,
        impact: ImpactAssessment,
    ) -> ReportCandidate:

        if finding.status != "validated":
            raise ValueError(
                "Only validated findings can "
                "become report candidates."
            )

        if not impact.has_security_impact:
            raise ValueError(
                "Finding has no confirmed "
                "security impact."
            )

        return ReportCandidate(
            finding_id=finding.finding_id,
            title=finding.title,
            target=finding.target,
            vulnerability_class=(
                finding.vulnerability_class
            ),
            summary=finding.summary,
            impact=impact.impact_summary,
            confidence=finding.confidence,
            evidence_ids=list(
                finding.evidence_ids
            ),
        )