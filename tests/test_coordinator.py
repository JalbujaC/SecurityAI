import json

from agent.action_validator import ActionValidator
from agent.coordinator import AgentCoordinator
from agent.executor import AgentExecutor
from agent.planner import AgentPlanner
from models.clients import ModelClient
from models.schemas import ModelRequest, ModelResponse
from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.mock import MockReconTool
from tools.registry import ToolRegistry


class CoordinatorTestModel(ModelClient):
    def generate(
        self,
        request: ModelRequest,
    ) -> ModelResponse:

        data = {
            "action": "RUN_TOOL",
            "reasoning": "Perform reconnaissance.",
            "tool_action": {
                "tool_name": "mock_recon",
                "target": "example.com",
                "arguments": {},
                "reason": "Gather evidence.",
            },
        }

        return ModelResponse(
            content=json.dumps(data),
            model="coordinator-test-model",
        )

def test_coordinator_runs_single_tool_cycle():
    scope = ScopeConfig(
        allowed_domains=["example.com"]
    )

    scope_validator = ScopeValidator(scope)

    registry = ToolRegistry(
        scope_validator=scope_validator
    )

    registry.register(
        MockReconTool()
    )

    planner = AgentPlanner(
        CoordinatorTestModel()
    )

    validator = ActionValidator(
        registry
    )

    executor = AgentExecutor(
        registry=registry,
        validator=validator,
    )

    coordinator = AgentCoordinator(
        planner=planner,
        executor=executor,
    )

    decision, result = coordinator.run_once(
        observation="Begin reconnaissance.",
        available_tools=registry.list_tools(),
    )

    assert decision.action == "RUN_TOOL"

    assert result is not None
    assert result.success is True
    assert result.tool_name == "mock_recon"

class MultiStepTestModel(ModelClient):
    def __init__(self):
        self.calls = 0

    def generate(
        self,
        request: ModelRequest,
    ) -> ModelResponse:

        self.calls += 1

        if self.calls == 1:
            data = {
                "action": "RUN_TOOL",
                "reasoning": "Gather initial evidence.",
                "tool_action": {
                    "tool_name": "mock_recon",
                    "target": "example.com",
                    "arguments": {},
                    "reason": "Perform reconnaissance.",
                },
            }

        else:
            data = {
                "action": "ANALYZE",
                "reasoning": "Enough evidence has been collected.",
                "tool_action": None,
            }

        return ModelResponse(
            content=json.dumps(data),
            model="multi-step-test-model",
        )

def test_coordinator_runs_multiple_steps():
    scope = ScopeConfig(
    allowed_domains=["example.com"]
    )
        
    scope_validator = ScopeValidator(scope)

    registry = ToolRegistry(
        scope_validator=scope_validator
    )

    registry.register(
        MockReconTool()
    )

    planner = AgentPlanner(
        MultiStepTestModel()
    )

    validator = ActionValidator(
        registry
    )

    executor = AgentExecutor(
        registry=registry,
        validator=validator,
    )

    coordinator = AgentCoordinator(
        planner=planner,
        executor=executor,
    )

    history = coordinator.run(
        observation="Begin reconnaissance.",
        available_tools=registry.list_tools(),
        max_steps=5,
    )

    assert len(history) == 2

    assert history[0].decision.action == "RUN_TOOL"
    assert history[0].result is not None

    assert history[1].decision.action == "ANALYZE" 

class NeverStopModel(ModelClient):
    def generate(
        self,
        request: ModelRequest,
    ) -> ModelResponse:

        data = {
            "action": "RUN_TOOL",
            "reasoning": "Keep gathering.",
            "tool_action": {
                "tool_name": "mock_recon",
                "target": "example.com",
                "arguments": {},
                "reason": "More reconnaissance.",
            },
        }

        return ModelResponse(
            content=json.dumps(data),
            model="never-stop-model",
        )

def test_coordinator_respects_max_steps():
    scope = ScopeConfig(
        allowed_domains=["example.com"]
    )

    scope_validator = ScopeValidator(scope)

    registry = ToolRegistry(
        scope_validator=scope_validator
    )

    registry.register(
        MockReconTool()
    )

    planner = AgentPlanner(
        NeverStopModel()
    )

    validator = ActionValidator(
        registry
    )

    executor = AgentExecutor(
        registry=registry,
        validator=validator,
    )

    coordinator = AgentCoordinator(
        planner=planner,
        executor=executor,
    )

    history = coordinator.run(
        observation="Test bounded execution.",
        available_tools=registry.list_tools(),
        max_steps=3,
    )

    assert len(history) == 3