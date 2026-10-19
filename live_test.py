from agent.action_validator import ActionValidator
from agent.coordinator import AgentCoordinator
from agent.executor import AgentExecutor
from agent.planner import AgentPlanner

from models.ollama import OllamaClient

from scope.schemas import ScopeConfig
from scope.targets import TargetManager

from storage.evidence_store import EvidenceStore

from tools.setup import build_tool_registry


TARGET = "hytale.com"

MAX_STEPS = 5

ACTIVE_APPROVAL_TOOLS = {
    "dalfox",
    "nuclei_dast",
}


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

    # Important: use the root domain here.
    target_manager.add_root(
        TARGET
    )

    evidence_store = EvidenceStore(
        path="data/evidence/live_test.json"
    )

    model = OllamaClient(
        model_name="qwen3:8b",
        timeout=300,
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

    coordinator = AgentCoordinator(
        planner=planner,
        executor=executor,
        target_manager=target_manager,
        evidence_store=evidence_store,
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


if __name__ == "__main__":
    main()