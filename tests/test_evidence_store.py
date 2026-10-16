from storage.evidence import EvidenceRecord
from storage.evidence_store import EvidenceStore
from tools.schemas import ToolResult


def test_evidence_record_from_tool_result():
    result = ToolResult(
        tool_name="httpx",
        target="example.com",
        success=True,
        output={
            "results": [
                {
                    "url": "https://example.com",
                    "status_code": 200,
                }
            ]
        },
        error=None,
    )

    record = EvidenceRecord.from_tool_result(
        result
    )

    assert record.tool_name == "httpx"
    assert record.target == "example.com"
    assert record.success is True
    assert record.output == result.output
    assert record.error is None
    assert record.collected_at


def test_evidence_store_adds_record():
    store = EvidenceStore()

    record = EvidenceRecord(
        tool_name="subfinder",
        target="example.com",
        success=True,
        output={
            "subdomains": [
                "api.example.com"
            ]
        },
        error=None,
        collected_at="2026-10-15T00:00:00+00:00",
    )

    store.add(record)

    assert store.count() == 1
    assert store.all()[0] == record


def test_evidence_store_filters_by_tool():
    store = EvidenceStore()

    store.add(
        EvidenceRecord(
            tool_name="httpx",
            target="example.com",
            success=True,
            output={},
            error=None,
            collected_at="test",
        )
    )

    store.add(
        EvidenceRecord(
            tool_name="subfinder",
            target="example.com",
            success=True,
            output={},
            error=None,
            collected_at="test",
        )
    )

    records = store.by_tool(
        "httpx"
    )

    assert len(records) == 1
    assert records[0].tool_name == "httpx"


def test_evidence_store_filters_by_target():
    store = EvidenceStore()

    store.add(
        EvidenceRecord(
            tool_name="httpx",
            target="api.example.com",
            success=True,
            output={},
            error=None,
            collected_at="test",
        )
    )

    store.add(
        EvidenceRecord(
            tool_name="httpx",
            target="www.example.com",
            success=True,
            output={},
            error=None,
            collected_at="test",
        )
    )

    records = store.by_target(
        "api.example.com"
    )

    assert len(records) == 1
    assert (
        records[0].target
        == "api.example.com"
    )

def test_evidence_store_persists_to_disk(tmp_path):
    path = tmp_path / "evidence.json"

    store = EvidenceStore(
        path=str(path)
    )

    record = EvidenceRecord(
        tool_name="httpx",
        target="example.com",
        success=True,
        output={
            "results": [
                {
                    "url": "https://example.com"
                }
            ]
        },
        error=None,
        collected_at="test",
    )

    store.add(record)

    assert path.exists()


def test_evidence_store_loads_from_disk(tmp_path):
    path = tmp_path / "evidence.json"

    store = EvidenceStore(
        path=str(path)
    )

    store.add(
        EvidenceRecord(
            tool_name="subfinder",
            target="example.com",
            success=True,
            output={
                "subdomains": [
                    "api.example.com"
                ]
            },
            error=None,
            collected_at="test",
        )
    )

    loaded_store = EvidenceStore(
        path=str(path)
    )

    loaded_store.load()

    assert loaded_store.count() == 1

    record = loaded_store.all()[0]

    assert record.tool_name == "subfinder"
    assert record.target == "example.com"