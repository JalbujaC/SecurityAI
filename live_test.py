import json
from dataclasses import asdict

from reporting.review import HumanReviewGate
from agent.action_validator import ActionValidator
from agent.coordinator import AgentCoordinator
from agent.executor import AgentExecutor
from agent.planner import AgentPlanner
from agent.core import SecurityAI
from agent.validation_coordinator import ValidationCoordinator
from agent.validation_executor import ValidationExecutor
from models.ollama import OllamaClient

from scope.schemas import ScopeConfig
from scope.targets import TargetManager

from storage import finding_store
from storage.evidence_store import EvidenceStore

from tools.setup import build_tool_registry
from storage.finding_store import FindingStore
from storage.run_state import RunStateStore


TARGET = "hytale.com"

MAX_STEPS = 5

ACTIVE_APPROVAL_TOOLS = {
    "dalfox",
    "nuclei_dast",
}

ENABLE_HUMAN_REVIEW = False

IMPACT_SUMMARIES: dict[str, str] = {}

def main():
    scope = ScopeConfig(
        allowed_domains=[
            TARGET,
        ]
    )

    registry = build_tool_registry(
        scope_config=scope,
        ffuf_wordlist="data/wordlists/directories.txt",
    )

    # Do not expose approval-gated active tools
    # to autonomous planning during this run.
    available_tools = [
        tool
        for tool in registry.list_tools()
        if tool not in ACTIVE_APPROVAL_TOOLS
    ]

    target_manager = TargetManager(
        scope_validator=registry.scope_validator
    )

    evidence_store = EvidenceStore(
        path="data/evidence/live_test.json"
    )

    finding_store = FindingStore(
        path="data/findings/live_test.json"
    )

    finding_store.load()

    run_state_store = RunStateStore(
        path="data/state/live_test.json"
    )

    run_state_store.load(
        target_manager
    )

    # Re-assert the configured scope root after
    # restoring persisted discovered targets.
    target_manager.add_root(
        TARGET
    )
    model = OllamaClient(
        model_name="qwen3:8b",
        timeout=300,
    )
    analyzer = SecurityAI(
        model
    )

    planner = AgentPlanner(
        model=model
    )

    validator = ActionValidator(
        registry=registry
    )

    executor = AgentExecutor(
        registry=registry,
        validator=validator,
    )

    validation_executor = ValidationExecutor(
        executor
    )

    validation_coordinator = ValidationCoordinator(
        finding_store=finding_store,
        executor=validation_executor,
    )

    human_review = HumanReviewGate(
        finding_store
    )

    coordinator = AgentCoordinator(
        planner=planner,
        executor=executor,
        target_manager=target_manager,
        evidence_store=evidence_store,
        analyzer=analyzer,
        finding_store=finding_store
    )

    observation = (
        f"The authorized bug bounty scope contains {TARGET}. "
        "Perform reconnaissance using only the registered "
        "tools and targets supplied by the system. "
        "Use evidence from each completed step to determine the next "
        "justified action. Do not invent targets or tools."
    )

    history = coordinator.run(
        observation=observation,
        available_tools=available_tools,
        max_steps=MAX_STEPS,
    )

    for finding in finding_store.all():
        if finding.status != "hypothesis":
            continue

        result = validation_coordinator.validate(
            finding_id=finding.finding_id,
            available_tools=available_tools,
            approved=False,
        )

        if result is not None:
            print()
            print(
                f"Validation result for "
                f"{finding.finding_id}:"
            )
            print(result)


    report_candidates = []

    if ENABLE_HUMAN_REVIEW:
        for finding in finding_store.all():
            if finding.status != "validated":
                continue

            impact_summary = (
                IMPACT_SUMMARIES.get(
                    finding.finding_id
                )
            )

            if not impact_summary:
                continue

            candidate = human_review.approve(
                finding_id=finding.finding_id,
                impact_summary=impact_summary,
            )

            report_candidates.append(
                candidate
            )

    run_state_store.save(
        target_manager
    )

    if report_candidates:
        report_path = (
            "data/reports/live_test.json"
        )

        from pathlib import Path

        path = Path(
            report_path
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            json.dumps(
                [
                    asdict(candidate)
                    for candidate
                    in report_candidates
                ],
                indent=2,
            ),
            encoding="utf-8",
        )

    print()
    print("=" * 70)
    print("SECURITYAI LIVE TEST")
    print("=" * 70)

    for record in history:
        print()
        print("-" * 70)
        print(f"STEP {record.step}")
        print("-" * 70)

        print("Decision:")
        print(record.decision)

        print()

        print("Result:")
        print(record.result)

    print()
    print("=" * 70)
    print("RUN SUMMARY")
    print("=" * 70)

    print(f"Steps executed: {len(history)}")
    print(
        f"Evidence records stored: "
        f"{evidence_store.count()}"
    )

    print(
        f"Findings stored: "
        f"{finding_store.count()}"
    )

    print(
        f"Report candidates created: "
        f"{len(report_candidates)}"
    )

    if finding_store.count() > 0:
        print()
        print("Findings:")

        for finding in finding_store.all():
            print(
                f"- [{finding.status}] "
                f"{finding.finding_id} "
                f"{finding.title} "
                f"(target={finding.target}, "
                f"confidence={finding.confidence:.2f})"
            )

    print()
    print("Known targets:")

    for asset in target_manager.all():
        print(
            f"- [{asset.kind}] "
            f"{asset.value} "
            f"(source={asset.source})"
        )

    print()
    print(
        "Evidence file: "
        "data/evidence/live_test.json"
    )
    print(
        "Run state file: "
        "data/state/live_test.json"
    )

    if report_candidates:
        print(
            "Report candidate file: "
            "data/reports/live_test.json"
        )

if __name__ == "__main__":
    main()