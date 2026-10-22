from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult
from scope.validator import ScopeValidator


class ToolRegistry:
    def __init__(self, scope_validator: ScopeValidator):
        self.scope_validator = scope_validator
        self._tools: dict[str, SecurityTool] = {}

    def register(self, tool: SecurityTool) -> None:
        if tool.name in self._tools:
            raise ValueError(f'Tool already registered: {tool.name}')
        self._tools[tool.name] = tool

    def list_tools(self) -> list[str]:
        return sorted(self._tools)

    def get(self, tool_name: str) -> SecurityTool:
        try:
            return self._tools[tool_name]
        except KeyError as exc:
            raise KeyError(f'Unknown tool: {tool_name}') from exc

    def execute(self, request: ToolRequest) -> ToolResult:
        self.scope_validator.validate(request.target)
        # Batch scope must be checked at the same boundary, not just by a wrapper.
        for target in request.targets:
            self.scope_validator.validate(target)
        return self.get(request.tool_name).run(request)
