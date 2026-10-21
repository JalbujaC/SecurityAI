import pytest

from agent.impact_validator import ImpactValidator
from storage.findings import FindingRecord


def make_finding(
    status="validated",
):
    return FindingRecord(
        finding_id="abc123",
        title="Possible authorization issue",
        target="api.example.com",
        vulnerability_class="unclassified",
        status=status,
        summary="Observed behavior.",
        evidence_ids=[
            "evidence1"
        ],
        confidence=0.9,
    )


def test_validated_finding_with_impact():
    finding = make_finding()

    result = ImpactValidator.assess(
        finding,
        "Unauthorized access to another user's data.",
    )

    assert result.has_security_impact is True


def test_empty_impact_is_not_reportable():
    finding = make_finding()

    result = ImpactValidator.assess(
        finding,
        "",
    )

    assert result.has_security_impact is False


def test_unvalidated_finding_cannot_be_assessed():
    finding = make_finding(
        status="needs_validation"
    )

    with pytest.raises(
        ValueError
    ):
        ImpactValidator.assess(
            finding,
            "Potential impact.",
        )