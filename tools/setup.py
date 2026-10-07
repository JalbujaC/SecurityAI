from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator

from tools.registry import ToolRegistry
from tools.subfinder import SubfinderTool


def build_tool_registry(scope_config: ScopeConfig) -> ToolRegistry:
    validator = ScopeValidator(scope_config)

    registry = ToolRegistry(
        scope_validator=validator
    )

    registry.register(
        SubfinderTool(
            scope_validator=validator
        )
    )

    return registry