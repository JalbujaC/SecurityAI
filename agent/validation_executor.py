from agent.executor import AgentExecutor
from agent.validation_planner import ValidationPlan
from models.schemas import AgentDecision, ToolAction
from tools.schemas import ToolResult


class ValidationExecutor:
    """
    Executes deterministic validation plans through
    the existing AgentExecutor safety boundary.
    """

    def __init__(
        self,
        executor: AgentExecutor,
    ):
        self.executor = executor

    def execute(
        self,
        plan: ValidationPlan,
        approved: bool = False,
    ) -> ToolResult | None:

        decision = AgentDecision(
            action="RUN_TOOL",
            reasoning=plan.reason,
            tool_action=ToolAction(
                tool_name=plan.tool_name,
                target=plan.target,
                arguments={},
                reason=plan.reason,
                approved=False,
            ),
        )

        return self.executor.execute(
            decision,
            approved=approved,
        )