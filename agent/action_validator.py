from models.schemas import ToolAction
from tools.registry import ToolRegistry
from tools.arguments import ToolArgumentPolicy
from agent.approval_policy import ApprovalPolicy

class ActionValidator:
    """
    Validates model-proposed actions before they can reach the execution layer
    """

    def __init__(self, registry: ToolRegistry):
        self.registry = registry

    def validate(self, action: ToolAction) -> None:
        if not action.tool_name:
            raise ValueError("Tool name is required.")
        if not action.target:
            raise ValueError("Target is required.")
        if action.tool_name not in self.registry.list_tools():
           raise ValueError(f"Unknown or unavailable tool: {action.tool_name}")

        ToolArgumentPolicy.validate(
        tool_name=action.tool_name,
        arguments=action.arguments,
    )
        if (
            ApprovalPolicy.requires_approval(
                action.tool_name
            )
            and not action.approved
        ):
            raise PermissionError(
                f"Tool requires explicit approval: "
                f"{action.tool_name}"
            )
        #Invokes the same deterministic scope system used by the registry
        self.registry.scope_validator.validate(action.target)
