import json
from socket import timeout
import subprocess
import time

from scope.validator import ScopeValidator
from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult


class SubfinderTool(SecurityTool):
    name = "subfinder"

    def __init__(
            self, 
            scope_validator: ScopeValidator,
            binary: str = "subfinder",
            timeout: int = 120,
    ):
        self.scope_validator = scope_validator
        self.binary = binary
        self.timeout = timeout

    def run(self, request: ToolRequest) -> ToolResult:
        command = [self.binary, "-d", request.target, "-silent", "-json"]

        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.name, 
                target=request.target,
                success=False,
                error="Subfinder execution timed out."
            )
        except OSError as exc: 
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=f"Unable to execute subfinder: {exc}",
            )

        if process.returncode != 0:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=(
                    process.stderr.strip()
                    or "Subfinder execution failed."
                ),
            )

        subdomains = []

        for line in process.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue


            hostname = data.get("host")

            if not hostname:
                continue

            hostname = hostname.lower().strip()

            if self.scope_validator.is_allowed(hostname):
                subdomains.append(hostname)

        subdomains = sorted(set(subdomains))

        return ToolResult(
            tool_name=self.name,
            target=request.target,
            success=True,
            output={
                "subdomains": subdomains,
                "count": len(subdomains),
            },
        )