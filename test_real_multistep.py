from agent.action_validator import ActionValidator
from agent.coordinator import AgentCoordinator
from agent.executor import AgentExecutor
from agent.planner import AgentPlanner

from models.ollama import OllamaClient

from scope.schemas import ScopeConfig

from tools.setup import build_tool_registry


TARGET = "www.hytale.com"


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

    model = OllamaClient(
        model_name="qwen3:4b"
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
    )

    observation = (
        f"The authorized target is {TARGET}. "
        "Begin with conservative reconnaissance. "
        "Use the evidence collected from each step to decide "
        "what should happen next."
    )

    history = coordinator.run(
        observation=observation,
        available_tools=registry.list_tools(),
        allowed_targets=[TARGET],
        max_steps=2,
    )

    for record in history:
        print()
        print("=" * 60)
        print(f"STEP {record.step}")
        print("=" * 60)

        print("Decision:")
        print(record.decision)

        print()

        print("Result:")
        print(record.result)


if __name__ == "__main__":
    main()