from agent.impact_validator import ImpactValidator
from reporting.builder import ReportCandidateBuilder
from reporting.candidate import ReportCandidate
from storage.finding_store import FindingStore


class HumanReviewGate:
    """
    Explicit human-controlled promotion gate.

    Nothing in the autonomous pipeline should call
    approve() automatically.
    """

    def __init__(
        self,
        finding_store: FindingStore,
    ):
        self.finding_store = finding_store

    def approve(
        self,
        finding_id: str,
        impact_summary: str,
    ) -> ReportCandidate:

        finding = self.finding_store.get(
            finding_id
        )

        if finding.status != "validated":
            raise ValueError(
                "Only validated findings can "
                "enter human review."
            )

        impact = ImpactValidator.assess(
            finding,
            impact_summary,
        )

        candidate = (
            ReportCandidateBuilder.build(
                finding,
                impact,
            )
        )

        self.finding_store.mark_report_candidate(
            finding_id
        )

        return candidate

    def reject(
        self,
        finding_id: str,
    ) -> None:

        finding = self.finding_store.get(
            finding_id
        )

        if finding.status != "validated":
            raise ValueError(
                "Only validated findings can "
                "be rejected during final review."
            )

        self.finding_store.update_status(
            finding_id,
            "rejected",
        )