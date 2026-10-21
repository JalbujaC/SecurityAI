import pytest

from agent.impact_validator import ImpactAssessment
from reporting.builder import ReportCandidateBuilder
from storage.findings import FindingRecord


def test_validated_finding_becomes_report_candidate():
    finding = FindingRecord(
        finding_id="abc123",
        title="Authorization issue",
        target="api.example.com",
        vulnerability_class="unclassified",
        status="validated",
        summary="Observed unauthorized behavior.",
        evidence_ids=[
            "evidence1",
            "evidence2",
        ],
        confidence=0.9,
    )

    impact = ImpactAssessment(
        finding_id="abc123",
        has_security_impact=True,
        impact_summary=(
            "Unauthorized access to another "
            "user's data."
        ),
    )

    candidate = (
        ReportCandidateBuilder.build(
            finding,
            impact,
        )
    )

    assert candidate.finding_id == "abc123"
    assert candidate.target == "api.example.com"
    assert candidate.evidence_ids == [
        "evidence1",
        "evidence2",
    ]


def test_no_impact_blocks_report_candidate():
    finding = FindingRecord(
        finding_id="abc123",
        title="Issue",
        target="example.com",
        vulnerability_class="unclassified",
        status="validated",
    )

    impact = ImpactAssessment(
        finding_id="abc123",
        has_security_impact=False,
        impact_summary="",
    )

    with pytest.raises(
        ValueError
    ):
        ReportCandidateBuilder.build(
            finding,
            impact,
        )