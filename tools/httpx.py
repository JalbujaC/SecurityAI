import json
from re import sub
import subprocess
import time

from scope.validator import ScopeValidator
from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult


class HttpxTool(SecurityTool):
    name = "httpx"

    def __init__(self, scope_validator: ScopeValidator, binary: str = "httpx", timeout: int = 60):
        self.scope_validator = scope_validator
        self.binary = binary
        self.timeout = timeout

    def run(self, request: ToolRequest) -> ToolResult:
        command = [
            self.binary, 
            "-u",
            request.target,
            "-json",
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect"
        ]

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.name, 
                target=request.target,
                success=False,
                error="httpx execution timed out."
            )

        if process.returncode != 0:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=process.stderr.strip() or "httpx execution failed."
            )

        results = []

        for line in process.stdout.splitlines():
            line = line.strip()

            if not line: 
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = data.get("url")

            if not url:
                continue

            if not self.scope_validator.is_allowed(url):
                continue

            results.append(
                {
                    "url": url,
                    "status_code": data.get("status_code"),
                    "title": data.get("title"),
                    "technologies": data.get("tech", [])
                }
            )

        return ToolResult(
            tool_name=self.name,
            target=request.target,
            success=True,
            output={
                "results": results,
                "count": len(results)
            }
        )