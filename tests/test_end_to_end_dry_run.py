import json

import pytest

from agent.action_validator import ActionValidator
from agent.coordinator import AgentCoordinator
from agent.executor import AgentExecutor
from agent.planner import AgentPlanner

from models.clients import ModelClient
from models.schemas import (
    AgentDecision,
    ModelRequest,
    ModelResponse,
    ToolAction,
)

from scope.schemas import ScopeConfig
from scope.targets import TargetManager
from scope.validator import ScopeValidator

from storage.evidence_store import EvidenceStore
from storage.finding_store import FindingStore
from storage.findings import FindingRecord

from tools.mock import MockReconTool
from tools.registry import ToolRegistry


class DryRunModel(ModelClient):
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
                "reasoning": "Collect initial evidence.",
                "tool_action": {
                    "tool_name": "mock_recon",
                    "target": "example.com",
                    "arguments": {},
                    "reason": "Gather scoped reconnaissance evidence.",
                },
            }

        else:
            data = {
                "action": "ANALYZE",
                "reasoning": "Evidence is ready for analysis.",
                "tool_action": None,
            }

        return ModelResponse(
            content=json.dumps(data),
            model="dry-run-model",
        )


def build_dry_run():
    scope_config = ScopeConfig(
        allowed_domains=["example.com"]
    )

    scope_validator = ScopeValidator(
        scope_config
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

    evidence_store = EvidenceStore()
    finding_store = FindingStore()

    planner = AgentPlanner(
        DryRunModel()
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
        evidence_store=evidence_store,
    )

    return (
        coordinator,
        registry,
        target_manager,
        evidence_store,
        finding_store,
    )


def test_end_to_end_dry_run():
    (
        coordinator,
        registry,
        target_manager,
        evidence_store,
        finding_store,
    ) = build_dry_run()

    history = coordinator.run(
        observation=(
            "Perform authorized dry-run reconnaissance "
            "against example.com."
        ),
        available_tools=registry.list_tools(),
        max_steps=3,
    )

    assert len(history) == 2

    assert (
        history[0].decision.action
        == "RUN_TOOL"
    )

    assert history[0].result is not None
    assert history[0].result.success is True

    assert (
        history[1].decision.action
        == "ANALYZE"
    )

    assert evidence_store.count() == 1

    evidence = evidence_store.all()[0]

    assert evidence.tool_name == "mock_recon"
    assert evidence.target == "example.com"

    assert (
        "example.com"
        in target_manager.values()
    )

    finding = FindingRecord(
        finding_id="finding-001",
        title="Dry-run security hypothesis",
        target="example.com",
        vulnerability_class="test",
        status="hypothesis",
        summary=(
            "Synthetic finding used only to verify "
            "finding lifecycle integration."
        ),
        confidence=0.25,
    )

    finding_store.add(
        finding
    )

    finding_store.update_status(
        "finding-001",
        "needs_validation",
    )

    finding_store.update_status(
        "finding-001",
        "validated",
    )

    finding_store.update_status(
        "finding-001",
        "report_candidate",
    )

    assert (
        finding_store.get(
            "finding-001"
        ).status
        == "report_candidate"
    )


def test_active_validation_cannot_bypass_approval(
    tmp_path,
):
    from tools.setup import build_tool_registry

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
        reasoning="Attempt active validation.",
        tool_action=ToolAction(
            tool_name="nuclei_dast",
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