import pytest

from agent.action_validator import ActionValidator
from agent.executor import AgentExecutor
from models.schemas import AgentDecision, ToolAction
from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.mock import MockReconTool
from tools.registry import ToolRegistry

from tools.schemas import ToolResult
from tools.setup import build_tool_registry

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


def test_active_tool_is_blocked_without_external_approval(
    tmp_path,
):
    wordlist = tmp_path / "directories.txt"

    wordlist.write_text(
        "admin\napi\nlogin\n",
        encoding="utf-8",
    )

    scope = ScopeConfig(
        allowed_domains=["example.com"]
    )

    registry = build_tool_registry(
        scope_config=scope,
        ffuf_wordlist=str(wordlist),
    )

    validator = ActionValidator(
        registry
    )

    executor = AgentExecutor(
        registry=registry,
        validator=validator,
    )

    decision = AgentDecision(
        action="RUN_TOOL",
        reasoning="Validate XSS hypothesis.",
        tool_action=ToolAction(
            tool_name="dalfox",
            target="https://example.com",
        ),
    )

    with pytest.raises(
        PermissionError,
        match="requires explicit approval",
    ):
        executor.execute(
            decision
        )


def test_external_approval_allows_active_tool_validation(
    tmp_path,
    monkeypatch,
):
    wordlist = tmp_path / "directories.txt"

    wordlist.write_text(
        "admin\napi\nlogin\n",
        encoding="utf-8",
    )

    scope = ScopeConfig(
        allowed_domains=["example.com"]
    )

    registry = build_tool_registry(
        scope_config=scope,
        ffuf_wordlist=str(wordlist),
    )

    validator = ActionValidator(
        registry
    )

    executor = AgentExecutor(
        registry=registry,
        validator=validator,
    )

    decision = AgentDecision(
        action="RUN_TOOL",
        reasoning="Validate XSS hypothesis.",
        tool_action=ToolAction(
            tool_name="dalfox",
            target="https://example.com",
        ),
    )

    tool = registry.get(
        "dalfox"
    )

    def fake_run(request):
        return ToolResult(
            tool_name="dalfox",
            target=request.target,
            success=True,
            output={
                "findings": [],
                "count": 0,
            },
        )

    monkeypatch.setattr(
        tool,
        "run",
        fake_run,
    )

    result = executor.execute(
        decision,
        approved=True,
    )

    assert result is not None
    assert result.success is True
    assert result.tool_name == "dalfox"

