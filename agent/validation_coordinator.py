from agent.validation_executor import ValidationExecutor
from agent.validation_planner import ValidationPlanner
from storage.finding_store import FindingStore
from tools.schemas import ToolResult

from agent.validation_result import (
    ValidationResultInterpreter,
)

class ValidationCoordinator:
    """
    Plans and executes validation for stored findings.
    """

    def __init__(
        self,
        finding_store: FindingStore,
        executor: ValidationExecutor,
    ):
        self.finding_store = finding_store
        self.executor = executor

    def validate(
        self,
        finding_id: str,
        available_tools: list[str],
        approved: bool = False,
    ) -> ToolResult | None:

        finding = self.finding_store.get(
            finding_id
        )

        if finding.status == "hypothesis":
            self.finding_store.mark_needs_validation(
                finding_id
            )

        elif finding.status != "needs_validation":
            raise ValueError(
                f"Finding cannot be validated "
                f"from status: {finding.status}"
            )

        plan = ValidationPlanner.plan(
            finding=finding,
            available_tools=available_tools,
        )

        if plan is None:
            return None

        result = self.executor.execute(
            plan=plan,
            approved=approved,
        )

        if result is None:
            return None

        outcome = (
            ValidationResultInterpreter.interpret(
                result
            )
        )

        if outcome == "validated":
            self.finding_store.update_status(
                finding_id,
                "validated",
            )

        elif outcome == "rejected":
            self.finding_store.update_status(
                finding_id,
                "rejected",
            )

        return result