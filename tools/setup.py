from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator

from tools.registry import ToolRegistry
from tools.subfinder import SubfinderTool
from tools.httpx import HttpxTool
from tools.katana import KatanaTool

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
    registry.register(
            HttpxTool(
                scope_validator=validator
            )
        )
    registry.register(
            KatanaTool(
                scope_validator=validator
            )
        )

    return registry