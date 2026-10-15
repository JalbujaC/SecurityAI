import pytest

from agent.action_validator import ActionValidator
from agent.executor import AgentExecutor
from models.schemas import AgentDecision, ToolAction
from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.mock import MockReconTool
from tools.registry import ToolRegistry


def build_executor():
    scope = ScopeConfig(
        allowed_domains=["example.com"],
    )

    scope_validator = ScopeValidator(scope)

    registry = ToolRegistry(
        scope_validator=scope_validator
    )

    registry.register(
        MockReconTool()
    )

    validator = ActionValidator(
        registry
    )

    executor = AgentExecutor(
        registry=registry,
        validator=validator,
    )

    return executor

def test_executor_runs_valid_tool_action():
    executor = build_executor()

    decision = AgentDecision(
        action="RUN_TOOL",
        reasoning="Gather reconnaissance.",
        tool_action=ToolAction(
            tool_name="mock_recon",
            target="example.com",
            arguments={},
            reason="Collect evidence.",
        ),
    )

    result = executor.execute(decision)

    assert result is not None
    assert result.success is True
    assert result.tool_name == "mock_recon"
    assert result.target == "example.com"

def test_executor_does_nothing_for_analyze():
    executor = build_executor()

    decision = AgentDecision(
        action="ANALYZE",
        reasoning="Enough evidence exists.",
        tool_action=None,
    )

    result = executor.execute(decision)

    assert result is None

def test_executor_does_nothing_for_stop():
    executor = build_executor()

    decision = AgentDecision(
        action="STOP",
        reasoning="No further action required.",
        tool_action=None,
    )

    result = executor.execute(decision)

    assert result is None

def test_executor_blocks_out_of_scope_target():
    executor = build_executor()

    decision = AgentDecision(
        action="RUN_TOOL",
        reasoning="Attempt reconnaissance.",
        tool_action=ToolAction(
            tool_name="mock_recon",
            target="evil.com",
            arguments={},
        ),
    )

    with pytest.raises(PermissionError):
        executor.execute(decision)


def test_executor_blocks_unknown_tool():
    executor = build_executor()

    decision = AgentDecision(
        action="RUN_TOOL",
        reasoning="Invalid tool.",
        tool_action=ToolAction(
            tool_name="powershell",
            target="example.com",
            arguments={},
        ),
    )

    with pytest.raises(ValueError):
        executor.execute(decision)


def test_executor_rejects_missing_tool_action():
    executor = build_executor()

    decision = AgentDecision(
        action="RUN_TOOL",
        reasoning="Missing data.",
        tool_action=None,
    )

    with pytest.raises(ValueError):
        executor.execute(decision)


