from agent.action_validator import ActionValidator
from models.schemas import AgentDecision
from tools.registry import ToolRegistry
from tools.schemas import ToolRequest, ToolResult

from dataclasses import replace

from agent.approval_policy import ApprovalPolicy


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
        approved: bool = False,
    ) -> ToolResult | None:

        if decision.action != "RUN_TOOL":
            return None

        if decision.tool_action is None:
            raise ValueError(
                "RUN_TOOL decision is missing tool_action."
            )

        tool_action = decision.tool_action

        if (
            approved
            and ApprovalPolicy.requires_approval(
                tool_action.tool_name
            )
        ):
            tool_action = replace(
                tool_action,
                approved=True,
            )

        self.validator.validate(
            tool_action
        )

        request = ToolRequest(
            tool_name=tool_action.tool_name,
            target=tool_action.target,
            arguments=tool_action.arguments,
        )

        return self.registry.execute(
            request
        )