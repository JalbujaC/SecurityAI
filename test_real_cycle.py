from agent.action_validator import ActionValidator
from agent.coordinator import AgentCoordinator
from agent.executor import AgentExecutor
from agent.planner import AgentPlanner

from models.ollama import OllamaClient

from scope.schemas import ScopeConfig

from tools.setup import build_tool_registry


TARGET = "hytale.com"


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

planner = AgentPlanner(model)

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

observation = (
    f"The authorized target is {TARGET}. "
    "No reconnaissance has been performed yet. "
    "Choose the safest appropriate first reconnaissance step."
)

decision, result = coordinator.run_once(
    observation=observation,
    available_tools=registry.list_tools(),
)

print("Decision:")
print(decision)

print()

print("Result:")
print(result)