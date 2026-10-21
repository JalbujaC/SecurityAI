from storage.evidence import EvidenceRecord
from tools.schemas import ToolResult


def test_evidence_id_is_created():
    result = ToolResult(
        tool_name="httpx",
        target="example.com",
        success=True,
        output={
            "status_code": 200
        },
        error=None,
    )

    record = (
        EvidenceRecord.from_tool_result(
            result
        )
    )

    assert record.evidence_id
    assert len(record.evidence_id) == 16


def test_same_evidence_has_same_id():
    result = ToolResult(
        tool_name="httpx",
        target="example.com",
        success=True,
        output={
            "status_code": 200
        },
        error=None,
    )

    first = (
        EvidenceRecord.from_tool_result(
            result
        )
    )

    second = (
        EvidenceRecord.from_tool_result(
            result
        )
    )

    assert (
        first.evidence_id
        == second.evidence_id
    )


def test_different_evidence_has_different_id():
    first = EvidenceRecord.build_id(
        tool_name="httpx",
        target="example.com",
        success=True,
        output={"status_code": 200},
        error=None,
    )

    second = EvidenceRecord.build_id(
        tool_name="httpx",
        target="example.com",
        success=True,
        output={"status_code": 404},
        error=None,
    )

    assert first != second