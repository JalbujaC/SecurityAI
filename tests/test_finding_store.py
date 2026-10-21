import pytest

from storage.findings import FindingRecord
from storage.finding_store import FindingStore


def test_finding_store_adds_finding():
    store = FindingStore()

    finding = FindingRecord(
        finding_id="finding-001",
        title="Possible IDOR",
        target="api.example.com",
        vulnerability_class="idor",
        status="hypothesis",
        summary="Authorization behavior requires validation.",
        confidence=0.4,
    )

    store.add(finding)

    assert store.count() == 1
    assert store.get("finding-001") == finding


def test_duplicate_finding_id_is_rejected():
    store = FindingStore()

    finding = FindingRecord(
        finding_id="finding-001",
        title="Possible IDOR",
        target="api.example.com",
        vulnerability_class="idor",
        status="hypothesis",
    )

    store.add(finding)

    with pytest.raises(
        ValueError,
        match="Finding already exists",
    ):
        store.add(finding)


def test_findings_can_be_filtered_by_status():
    store = FindingStore()

    store.add(
        FindingRecord(
            finding_id="finding-001",
            title="Possible IDOR",
            target="api.example.com",
            vulnerability_class="idor",
            status="hypothesis",
        )
    )

    store.add(
        FindingRecord(
            finding_id="finding-002",
            title="Reflected XSS",
            target="www.example.com",
            vulnerability_class="xss",
            status="validated",
        )
    )

    hypotheses = store.by_status(
        "hypothesis"
    )

    assert len(hypotheses) == 1
    assert hypotheses[0].finding_id == "finding-001"


def test_finding_status_can_be_updated():
    store = FindingStore()

    store.add(
        FindingRecord(
            finding_id="finding-001",
            title="Possible IDOR",
            target="api.example.com",
            vulnerability_class="idor",
            status="hypothesis",
        )
    )

    updated = store.update_status(
        "finding-001",
        "needs_validation",
    )

    assert updated.status == "needs_validation"

    assert (
        store.get("finding-001").status
        == "needs_validation"
    )


def test_unknown_finding_is_rejected():
    store = FindingStore()

    with pytest.raises(
        KeyError,
        match="Unknown finding",
    ):
        store.get("missing")

def test_finding_cannot_skip_validation():
    store = FindingStore()

    store.add(
        FindingRecord(
            finding_id="finding-001",
            title="Possible IDOR",
            target="api.example.com",
            vulnerability_class="idor",
            status="hypothesis",
        )
    )

    with pytest.raises(
        ValueError,
        match="Invalid finding status transition",
    ):
        store.update_status(
            "finding-001",
            "report_candidate",
        )

def test_finding_can_follow_valid_lifecycle():
    store = FindingStore()

    store.add(
        FindingRecord(
            finding_id="finding-001",
            title="Possible IDOR",
            target="api.example.com",
            vulnerability_class="idor",
            status="hypothesis",
        )
    )

    store.update_status(
        "finding-001",
        "needs_validation",
    )

    store.update_status(
        "finding-001",
        "validated",
    )

    store.update_status(
        "finding-001",
        "report_candidate",
    )

    assert (
        store.get("finding-001").status
        == "report_candidate"
    )

def test_rejected_finding_cannot_be_reopened():
    store = FindingStore()

    store.add(
        FindingRecord(
            finding_id="finding-001",
            title="Possible IDOR",
            target="api.example.com",
            vulnerability_class="idor",
            status="hypothesis",
        )
    )

    store.update_status(
        "finding-001",
        "rejected",
    )

    with pytest.raises(
        ValueError,
        match="Invalid finding status transition",
    ):
        store.update_status(
            "finding-001",
            "needs_validation",
        )

from storage.findings import FindingRecord


def test_add_or_merge_adds_new_finding():
    store = FindingStore()

    finding = FindingRecord(
        finding_id="abc123",
        title="Possible issue",
        target="api.example.com",
        vulnerability_class="unclassified",
        status="hypothesis",
        summary="Test finding.",
        evidence_ids=[
            "evidence1"
        ],
        confidence=0.7,
    )

    result = store.add_or_merge(
        finding
    )

    assert store.count() == 1
    assert result.finding_id == "abc123"


def test_add_or_merge_deduplicates_finding():
    store = FindingStore()

    first = FindingRecord(
        finding_id="abc123",
        title="Possible issue",
        target="api.example.com",
        vulnerability_class="unclassified",
        status="hypothesis",
        evidence_ids=[
            "evidence1"
        ],
        confidence=0.6,
    )

    second = FindingRecord(
        finding_id="abc123",
        title="Possible issue",
        target="api.example.com",
        vulnerability_class="unclassified",
        status="hypothesis",
        evidence_ids=[
            "evidence2"
        ],
        confidence=0.8,
    )

    store.add_or_merge(
        first
    )

    result = store.add_or_merge(
        second
    )

    assert store.count() == 1

    assert result.confidence == 0.8

    assert result.evidence_ids == [
        "evidence1",
        "evidence2",
    ]


def test_add_or_merge_does_not_duplicate_evidence():
    store = FindingStore()

    first = FindingRecord(
        finding_id="abc123",
        title="Possible issue",
        target="api.example.com",
        vulnerability_class="unclassified",
        status="hypothesis",
        evidence_ids=[
            "evidence1"
        ],
        confidence=0.7,
    )

    second = FindingRecord(
        finding_id="abc123",
        title="Possible issue",
        target="api.example.com",
        vulnerability_class="unclassified",
        status="hypothesis",
        evidence_ids=[
            "evidence1"
        ],
        confidence=0.7,
    )

    store.add_or_merge(
        first
    )

    result = store.add_or_merge(
        second
    )

    assert result.evidence_ids == [
        "evidence1"
    ]