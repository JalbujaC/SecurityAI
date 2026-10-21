from storage.finding_store import FindingStore
from storage.findings import FindingRecord


def test_finding_store_saves_and_loads(
    tmp_path,
):
    path = tmp_path / "findings.json"

    store = FindingStore(
        path=str(path)
    )

    finding = FindingRecord(
        finding_id="abc123",
        title="Possible issue",
        target="api.example.com",
        vulnerability_class="unclassified",
        status="hypothesis",
        summary="Test.",
        evidence_ids=[
            "evidence1"
        ],
        confidence=0.8,
    )

    store.add(
        finding
    )

    restored = FindingStore(
        path=str(path)
    )

    restored.load()

    assert restored.count() == 1

    loaded = restored.get(
        "abc123"
    )

    assert loaded.title == "Possible issue"
    assert loaded.confidence == 0.8
    assert loaded.evidence_ids == [
        "evidence1"
    ]


def test_status_update_is_persisted(
    tmp_path,
):
    path = tmp_path / "findings.json"

    store = FindingStore(
        path=str(path)
    )

    finding = FindingRecord(
        finding_id="abc123",
        title="Possible issue",
        target="example.com",
        vulnerability_class="unclassified",
        status="hypothesis",
    )

    store.add(
        finding
    )

    store.update_status(
        "abc123",
        "needs_validation",
    )

    restored = FindingStore(
        path=str(path)
    )

    restored.load()

    assert (
        restored.get("abc123").status
        == "needs_validation"
    )