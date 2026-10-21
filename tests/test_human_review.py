import pytest

from reporting.review import HumanReviewGate
from storage.finding_store import FindingStore
from storage.findings import FindingRecord


def make_store(
    status="validated",
):
    store = FindingStore()

    store.add(
        FindingRecord(
            finding_id="abc123",
            title="Authorization issue",
            target="api.example.com",
            vulnerability_class="unclassified",
            status=status,
            summary="Observed unauthorized behavior.",
            evidence_ids=[
                "evidence1"
            ],
            confidence=0.9,
        )
    )

    return store


def test_human_approval_creates_report_candidate():
    store = make_store()

    gate = HumanReviewGate(
        store
    )

    candidate = gate.approve(
        finding_id="abc123",
        impact_summary=(
            "Unauthorized access to "
            "another user's data."
        ),
    )

    assert (
        candidate.finding_id
        == "abc123"
    )

    assert (
        store.get(
            "abc123"
        ).status
        == "report_candidate"
    )


def test_empty_impact_blocks_approval():
    store = make_store()

    gate = HumanReviewGate(
        store
    )

    with pytest.raises(
        ValueError
    ):
        gate.approve(
            finding_id="abc123",
            impact_summary="",
        )

    assert (
        store.get(
            "abc123"
        ).status
        == "validated"
    )


def test_unvalidated_finding_cannot_be_approved():
    store = make_store(
        status="needs_validation"
    )

    gate = HumanReviewGate(
        store
    )

    with pytest.raises(
        ValueError
    ):
        gate.approve(
            finding_id="abc123",
            impact_summary="Confirmed impact.",
        )


def test_human_rejection_marks_finding_rejected():
    store = make_store()

    gate = HumanReviewGate(
        store
    )

    gate.reject(
        "abc123"
    )

    assert (
        store.get(
            "abc123"
        ).status
        == "rejected"
    )