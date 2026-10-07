from dataclasses import dataclass, field
from typing import Any

@dataclass
class ToolRequest:
    tool_name: str
    target: str
    arguments: dict[str, Any] = field(default_factory=dict)

@dataclass
class ToolResult:
    tool_name: str
    target: str
    success: bool
    output: Any = None
    error: str | None = None