from abc import ABC, abstractmethod

from tools.schemas import ToolRequest, ToolResult

class SecurityTool(ABC):
    name: str

    @abstractmethod
    def run(self, request: ToolRequest) -> ToolResult:
        raise NotImplementedError

    