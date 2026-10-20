import json

from agent.action_validator import ActionValidator
from agent.coordinator import AgentCoordinator
from agent.executor import AgentExecutor
from agent.planner import AgentPlanner

from models.clients import ModelClient
from models.schemas import ModelRequest, ModelResponse
from models.schemas import AnalysisResult

from scope.schemas import ScopeConfig
from scope.targets import TargetManager
from scope.validator import ScopeValidator

from storage import evidence_store
from tools.mock import MockReconTool
from tools.registry import ToolRegistry
from tools.schemas import ToolResult

from storage.evidence_store import EvidenceStore
from agent.core import SecurityAI


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
                "reasoning": (
                    "Enough evidence has been collected."
                ),
                "tool_action": None,
            }

        return ModelResponse(
            content=json.dumps(data),
            model="multi-step-test-model",
        )


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


def build_coordinator(
    model: ModelClient,
):
    scope = ScopeConfig(
        allowed_domains=["example.com"]
    )

    evidence_store = EvidenceStore()

    scope_validator = ScopeValidator(
        scope
    )

    registry = ToolRegistry(
        scope_validator=scope_validator
    )

    registry.register(
        MockReconTool()
    )

    target_manager = TargetManager(
        scope_validator=scope_validator
    )

    target_manager.add_root(
        "example.com"
    )

    planner = AgentPlanner(
        model
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
        target_manager=target_manager,
        evidence_store=evidence_store
    )

    return (
        coordinator,
        registry,
        target_manager,
        evidence_store
    )


def test_coordinator_runs_single_tool_cycle():
    coordinator, registry, target_manager, evidence_store = (
        build_coordinator(
            CoordinatorTestModel()
        )
    )

    target_map = (
        target_manager.planner_targets(
            registry.list_tools()
        )
    )

    decision, result = coordinator.run_once(
        observation="Begin reconnaissance.",
        available_tools=registry.list_tools(),
        target_map=target_map,
    )

    assert decision.action == "RUN_TOOL"

    assert result is not None
    assert result.success is True
    assert result.tool_name == "mock_recon"


def test_coordinator_runs_multiple_steps():
    coordinator, registry, _, _ = (
        build_coordinator(
            MultiStepTestModel()
        )
    )

    history = coordinator.run(
        observation="Begin reconnaissance.",
        available_tools=registry.list_tools(),
        max_steps=5,
    )

    assert len(history) == 2

    assert (
        history[0].decision.action
        == "RUN_TOOL"
    )

    assert history[0].result is not None

    assert (
        history[1].decision.action
        == "ANALYZE"
    )


def test_coordinator_respects_max_steps():
    coordinator, registry, _, _ = (
        build_coordinator(
            NeverStopModel()
        )
    )

    history = coordinator.run(
        observation="Test bounded execution.",
        available_tools=registry.list_tools(),
        max_steps=3,
    )

    assert len(history) == 3

    for record in history:
        assert (
            record.decision.action
            == "RUN_TOOL"
        )


def test_coordinator_builds_targets_from_manager():
    coordinator, registry, target_manager, evidence_store = (
        build_coordinator(
            CoordinatorTestModel()
        )
    )

    target_map = (
        target_manager.planner_targets(
            registry.list_tools()
        )
    )

    assert "mock_recon" in target_map

    assert target_map["mock_recon"] == [
        "example.com"
    ]


def test_target_manager_remains_available_after_run():
    coordinator, registry, target_manager, evidence_store = (
        build_coordinator(
            CoordinatorTestModel()
        )
    )

    coordinator.run(
        observation="Begin reconnaissance.",
        available_tools=registry.list_tools(),
        max_steps=1,
    )

    assert (
        "example.com"
        in target_manager.values()
    )

def test_coordinator_stores_tool_result_as_evidence():
    coordinator, registry, _, evidence_store = (
        build_coordinator(
            CoordinatorTestModel()
        )
    )

    coordinator.run(
        observation="Begin reconnaissance.",
        available_tools=registry.list_tools(),
        max_steps=1,
    )

    assert evidence_store.count() == 1

    record = evidence_store.all()[0]

    assert record.tool_name == "mock_recon"
    assert record.target == "example.com"
    assert record.success is True


def test_httpx_batch_is_bounded_and_prioritized(
    monkeypatch,
):
    scope = ScopeConfig(
        allowed_domains=[
            "example.com"
        ]
    )

    scope_validator = ScopeValidator(
        scope
    )

    target_manager = TargetManager(
        scope_validator=scope_validator
    )

    target_manager.add_root(
        "example.com"
    )

    for index in range(20):
        target_manager.add_discovered(
            f"host{index}.example.com",
            source="subfinder",
        )

    target_manager.add_discovered(
        "auth.example.com",
        source="subfinder",
    )

    registry = ToolRegistry(
        scope_validator=scope_validator
    )

    class FakeHttpxTool:
        name = "httpx"

        def run(
            self,
            request,
        ):
            return ToolResult(
                tool_name="httpx",
                target=request.target,
                success=True,
                output={
                    "targets_received": request.targets,
                    "results": [],
                    "count": 0,
                },
            )

    registry.register(
        FakeHttpxTool()
    )

    class HttpxDecisionModel(ModelClient):
        def generate(
            self,
            request,
        ):
            return ModelResponse(
                content=json.dumps(
                    {
                        "action": "RUN_TOOL",
                        "reasoning": "Probe web services.",
                        "tool_action": {
                            "tool_name": "httpx",
                            "target": "example.com",
                            "arguments": {},
                            "reason": "Identify live services.",
                        },
                    }
                ),
                model="test-model",
            )

    planner = AgentPlanner(
        HttpxDecisionModel()
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
        target_manager=target_manager,
    )

    target_map = (
        target_manager.planner_targets(
            registry.list_tools()
        )
    )

    decision, result = coordinator.run_once(
        observation="Test HTTPX batching.",
        available_tools=registry.list_tools(),
        target_map=target_map,
    )

    received = (
        result.output[
            "targets_received"
        ]
    )

    assert len(received) == 10

    assert (
        "auth.example.com"
        in received
    )

def test_httpx_second_batch_does_not_repeat_targets():
    scope = ScopeConfig(
        allowed_domains=[
            "example.com"
        ]
    )

    scope_validator = ScopeValidator(
        scope
    )

    target_manager = TargetManager(
        scope_validator=scope_validator
    )

    target_manager.add_root(
        "example.com"
    )

    for index in range(25):
        target_manager.add_discovered(
            f"host{index}.example.com",
            source="subfinder",
        )

    registry = ToolRegistry(
        scope_validator=scope_validator
    )

    class FakeHttpxTool:
        name = "httpx"

        def run(
            self,
            request,
        ):
            return ToolResult(
                tool_name="httpx",
                target=request.target,
                success=True,
                output={
                    "targets_received": list(
                        request.targets
                    ),
                    "results": [],
                    "count": 0,
                },
            )

    registry.register(
        FakeHttpxTool()
    )

    class AlwaysHttpxModel(ModelClient):
        def generate(
            self,
            request,
        ):
            return ModelResponse(
                content=json.dumps(
                    {
                        "action": "RUN_TOOL",
                        "reasoning": "Continue probing.",
                        "tool_action": {
                            "tool_name": "httpx",
                            "target": "example.com",
                            "arguments": {},
                            "reason": "Identify live services.",
                        },
                    }
                ),
                model="test-model",
            )

    planner = AgentPlanner(
        AlwaysHttpxModel()
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
        target_manager=target_manager,
    )

    target_map = (
        target_manager.planner_targets(
            registry.list_tools()
        )
    )

    _, first_result = coordinator.run_once(
        observation="Probe targets.",
        available_tools=registry.list_tools(),
        target_map=target_map,
    )

    _, second_result = coordinator.run_once(
        observation="Probe targets.",
        available_tools=registry.list_tools(),
        target_map=target_map,
    )

    first_targets = set(
        first_result.output[
            "targets_received"
        ]
    )

    second_targets = set(
        second_result.output[
            "targets_received"
        ]
    )

    assert len(first_targets) == 10
    assert len(second_targets) == 10

    assert first_targets.isdisjoint(
        second_targets
    )

def test_analyze_decision_invokes_security_analyzer():
    scope = ScopeConfig(
        allowed_domains=[
            "example.com"
        ]
    )

    scope_validator = ScopeValidator(
        scope
    )

    target_manager = TargetManager(
        scope_validator=scope_validator
    )

    target_manager.add_root(
        "example.com"
    )

    registry = ToolRegistry(
        scope_validator=scope_validator
    )

    class AnalyzeDecisionModel(ModelClient):
        def generate(
            self,
            request,
        ):
            return ModelResponse(
                content=json.dumps(
                    {
                        "action": "ANALYZE",
                        "reasoning": (
                            "Enough evidence exists "
                            "for structured analysis."
                        ),
                        "tool_action": None,
                    }
                ),
                model="planner-test",
            )

    class AnalysisModel(ModelClient):
        def generate(
            self,
            request,
        ):
            return ModelResponse(
                content=json.dumps(
                    {
                        "status": "HYPOTHESIS",
                        "summary": (
                            "A test observation "
                            "requires validation."
                        ),
                        "confidence": 0.4,
                        "evidence": [
                            "Observed HTTP response."
                        ],
                        "hypotheses": [
                            (
                                "A possible issue "
                                "may require validation."
                            )
                        ],
                        "recommended_next_step": (
                            "Perform a controlled "
                            "verification step."
                        ),
                    }
                ),
                model="analysis-test",
            )

    planner = AgentPlanner(
        AnalyzeDecisionModel()
    )

    validator = ActionValidator(
        registry
    )

    executor = AgentExecutor(
        registry=registry,
        validator=validator,
    )

    analyzer = SecurityAI(
        AnalysisModel()
    )

    coordinator = AgentCoordinator(
        planner=planner,
        executor=executor,
        target_manager=target_manager,
        analyzer=analyzer,
    )

    history = coordinator.run(
        observation=(
            "Analyze authorized target "
            "example.com."
        ),
        available_tools=[],
        max_steps=3,
    )

    assert len(history) == 1

    assert (
        history[0].decision.action
        == "ANALYZE"
    )

    assert isinstance(
        history[0].result,
        AnalysisResult,
    )

    assert (
        history[0].result.status
        == "HYPOTHESIS"
    )

    assert (
        history[0].result.confidence
        == 0.4
    )

    assert len(
        history[0].result.hypotheses
    ) == 1


def test_analyze_without_analyzer_stops_cleanly():
    scope = ScopeConfig(
        allowed_domains=[
            "example.com"
        ]
    )

    scope_validator = ScopeValidator(
        scope
    )

    registry = ToolRegistry(
        scope_validator=scope_validator
    )

    class AnalyzeDecisionModel(ModelClient):
        def generate(
            self,
            request,
        ):
            return ModelResponse(
                content=json.dumps(
                    {
                        "action": "ANALYZE",
                        "reasoning": "Analyze evidence.",
                        "tool_action": None,
                    }
                ),
                model="test-model",
            )

    planner = AgentPlanner(
        AnalyzeDecisionModel()
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
        observation="Test.",
        available_tools=[],
    )

    assert len(history) == 1
    assert history[0].decision.action == "ANALYZE"
    assert history[0].result is None