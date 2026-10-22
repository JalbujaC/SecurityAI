from agent.validation_result import (
    ValidationResultInterpreter,
)
from tools.schemas import ToolResult


def test_explicit_positive_result_is_validated():
    result = ToolResult(
        tool_name="dalfox",
        target="https://example.com",
        success=True,
        output={
            "validated": True
        },
    )

    assert (
        ValidationResultInterpreter.interpret(
            result
        )
        == "validated"
    )


def test_explicit_negative_result_is_rejected():
    result = ToolResult(
        tool_name="nuclei",
        target="example.com",
        success=True,
        output={
            "validated": False
        },
    )

    assert (
        ValidationResultInterpreter.interpret(
            result
        )
        == "rejected"
    )


def test_nonempty_findings_are_inconclusive():
    result = ToolResult(
        tool_name="nuclei",
        target="example.com",
        success=True,
        output={
            "findings": [
                {
                    "template": "test"
                }
            ]
        },
    )

    assert (
        ValidationResultInterpreter.interpret(
            result
        )
        == "inconclusive"
    )


def test_empty_findings_are_inconclusive():
    result = ToolResult(
        tool_name="nuclei",
        target="example.com",
        success=True,
        output={
            "findings": []
        },
    )

    assert (
        ValidationResultInterpreter.interpret(
            result
        )
        == "inconclusive"
    )


def test_failed_tool_is_inconclusive():
    result = ToolResult(
        tool_name="nuclei",
        target="example.com",
        success=False,
        output=None,
        error="timeout",
    )

    assert (
        ValidationResultInterpreter.interpret(
            result
        )
        == "inconclusive"
    )