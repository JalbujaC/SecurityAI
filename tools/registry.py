import re

from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult
from scope.validator import ScopeValidator
from tools.subfinder import SubfinderTool

class ToolRegistry:
    def __init__(self, scope_validator: ScopeValidator):
        self.scope_validator = scope_validator
        self._tools: dict[str, SecurityTool] = {}

    def register(self, tool: SecurityTool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name}")

        self._tools[tool.name] = tool

    def list_tools(self) -> list[str]:
        return sorted(self._tools.keys())

    def get(self, tool_name: str) -> SecurityTool:
        try:
            return self._tools[tool_name]
        except KeyError as exc:
            raise KeyError(f"Unknown tool: {tool_name}") from exc

    def execute(self, request: ToolRequest) -> ToolRequest:
        self. scope_validator.validate(request.target)

        tool = self.get(request.tool_name)

        return tool.run(request)