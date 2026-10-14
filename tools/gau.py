from http.client import CONTINUE
import json
from pydoc import text
import subprocess
from sys import stderr

from scope.validator import ScopeValidator
from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult

class GauTool(SecurityTool):
    name = "gau"

    def __init__(
            self,
            scope_validator: ScopeValidator,
            binary: str = "gau",
            timeout: int = 120,
            threads: int = 3
    ):
        self.scope_validator = scope_validator
        self.binary = binary
        self.timeout = timeout
        self.threads = threads

    def run(self, request: ToolRequest) -> ToolResult:
        command = [
            self.binary,
            "--json",
            "--subs",
            "--threads",
            str(self.threads),
            request.target
        ]

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error="gau execution timed out."
            )
        except OSError as exc:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=f"Unable to execute gau: {exc}"
            )

        if process.returncode != 0:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=process.stderr.strip() or "gau execution failed."
            )

        urls = []

        for line in process.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line)
            except json.json.JSONDecodeError:
                continue

            url = data.get("url")

            if not url:
                continue

            if not self.scope_validator.is_allowed(url):
                continue

            urls.append(url)

        urls = sorted(set(urls))

        return ToolResult(
            tool_name=self.name,
            target=request.target,
            success=True,
            output={
                "urls": urls,
                "count": len(urls),
            },
        )    

