from agent.action_validator import ActionValidator
from models.schemas import AgentDecision
from tools.registry import ToolRegistry
from tools.schemas import ToolRequest, ToolResult


class AgentExecutor:
    """
    Executes validated tool actions proposed by the planner.

    The model never interacts with subprocesses directly.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        validator: ActionValidator,
    ):
        self.registry = registry
        self.validator = validator

    def execute(
        self,
        decision: AgentDecision,
    ) -> ToolResult | None:

        if decision.action != "RUN_TOOL":
            return None

        if decision.tool_action is None:
            raise ValueError(
                "RUN_TOOL decision is missing tool_action."
            )

        # First security boundary.
        self.validator.validate(
            decision.tool_action
        )

        request = ToolRequest(
            tool_name=decision.tool_action.tool_name,
            target=decision.tool_action.target,
            arguments=decision.tool_action.arguments,
        )

        # Registry performs scope validation again.
        return self.registry.execute(request)