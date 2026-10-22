import json
import subprocess
from sys import stdout

from scope.validator import ScopeValidator
from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult

class DnsxTool(SecurityTool):
    name = "dnsx"

    def __init__(
        self,
        scope_validator: ScopeValidator,
        binary: str = "dnsx",
        timeout: int = 60,
        rate_limit: int = 20,
    ):
        self.scope_validator = scope_validator
        self.binary = binary
        self.timeout = timeout
        self.rate_limit = rate_limit

    def run(self, request: ToolRequest) -> ToolResult:
        command = [
            self.binary,
            "-d",
            request.target,
            "-a",
            "-json",
            "-silent",
            "-rl",
            str(self.rate_limit),
        ]

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error="dnsx execution timed out.",
            )

        except OSError as exc:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=f"Unable to execute dnsx: {exc}",
            )

        if process.returncode != 0:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=process.stderr.strip() or "dnsx execution failed.",
            )

        records = []
        stdout = process.stdout or ""
        for line in process.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = data.get("host")

            if not host:
                continue

            host = host.lower().strip()

            if not self.scope_validator.is_allowed(host):
                continue

            records.append(
                {
                    "host": host,
                    "a": data.get("a", []),
                    "aaaa": data.get("aaaa", []),
                    "cname": data.get("cname", []),
                    "resolver": data.get("resolver"),
                    "status_code": data.get("status_code"),
                }
            )

        return ToolResult(
            tool_name=self.name,
            target=request.target,
            success=True,
            output={
                "records": records,
                "count": len(records),
            },
        )