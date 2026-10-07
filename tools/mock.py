from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult

class MockReconTool(SecurityTool):
    name = "mock_recon"

    def run(self, request: ToolRequest) -> ToolResult:
        return ToolResult(tool_name=self.name, target=request.target, success=True, output={"message": f"Mock reconnaissance completed for {request.target}"})
    