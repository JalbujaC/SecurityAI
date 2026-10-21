import pytest

from agent.action_validator import ActionValidator
from agent.executor import AgentExecutor
from agent.validation_executor import ValidationExecutor
from agent.validation_planner import ValidationPlan

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator

from tools.registry import ToolRegistry
from tools.schemas import ToolResult


class FakeTool:
    def __init__(
        self,
        name: str,
    ):
        self.name = name

    def run(
        self,
        request,
    ):
        return ToolResult(
            tool_name=self.name,
            target=request.target,
            success=True,
            output={
                "validated": True
            },
        )


def build_executor(
    tool_name: str,
):
    scope = ScopeConfig(
        allowed_domains=[
            "example.com"
        ]
    )

    validator = ScopeValidator(
        scope
    )

    registry = ToolRegistry(
        scope_validator=validator
    )

    registry.register(
        FakeTool(
            tool_name
        )
    )

    action_validator = ActionValidator(
        registry
    )

    executor = AgentExecutor(
        registry=registry,
        validator=action_validator,
    )

    return ValidationExecutor(
        executor
    )


def test_passive_validation_runs_without_approval():
    executor = build_executor(
        "nuclei"
    )

    plan = ValidationPlan(
        finding_id="abc123",
        target="example.com",
        tool_name="nuclei",
        reason="Validate finding.",
        requires_approval=False,
    )

    result = executor.execute(
        plan
    )

    assert result is not None
    assert result.success is True


def test_active_validation_requires_approval():
    executor = build_executor(
        "dalfox"
    )

    plan = ValidationPlan(
        finding_id="abc123",
        target="https://example.com",
        tool_name="dalfox",
        reason="Validate XSS.",
        requires_approval=True,
    )

    with pytest.raises(
        PermissionError
    ):
        executor.execute(
            plan
        )


def test_active_validation_runs_when_approved():
    executor = build_executor(
        "dalfox"
    )

    plan = ValidationPlan(
        finding_id="abc123",
        target="https://example.com",
        tool_name="dalfox",
        reason="Validate XSS.",
        requires_approval=True,
    )

    result = executor.execute(
        plan,
        approved=True,
    )

    assert result is not None
    assert result.success is True