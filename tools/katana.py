import json
import subprocess

from scope.validator import ScopeValidator
from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult


class KatanaTool(SecurityTool):
    name = "katana"

    def __init__(
            self, 
            scope_validator: ScopeValidator,
            binary: str = "katana",
            timeout: int = 120,
            depth: int = 2,
            rate_limit: int = 5
    ):
        self.scope_validator = scope_validator
        self.binary = binary
        self.timeout = timeout
        self.depth = depth
        self.rate_limit = rate_limit


    def run(self, request: ToolRequest) -> ToolResult:
        command = [
            self.binary,
            "-u",
            request.target,
            "-d",
            str(self.depth),
            "-rl",
            str(self.rate_limit),
            "-jsonl",
            "-silent"
        ]

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error="Katana execution timed out."
            )

        except OSError as exc:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=f"Unable to execute Katana: {exc}"
            )

        if process.returncode != 0:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=process.stderr.strip() or "Katana execution failed.",
            )

        endpoints = []
        stdout = process.stdout or ""
        for line in stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            try: 
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            endpoint = None

            request_data = data.get("request")

            if isinstance(request_data, dict):
                endpoint = request_data.get("endpoint")

            if not endpoint:
                endpoint = data.get("url")

            if not endpoint:
                continue

            if not self.scope_validator.is_allowed(endpoint):
                continue

            endpoints.append(endpoint)

        endpoints = sorted(set(endpoints))

        return ToolResult(
            tool_name=self.name,
            target=request.target,
            success=True,
            output={
                "endpoints": endpoints,
                "count": len(endpoints),
            },
        )