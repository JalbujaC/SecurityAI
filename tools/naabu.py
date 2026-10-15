import json
import subprocess

from scope.validator import ScopeValidator
from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult


class NaabuTool(SecurityTool):
    name = "naabu"

    def __init__(
            self,
            scope_validator: ScopeValidator,
            binary: str = "naabu",
            timeout: int = 120,
            rate_limit: int = 50,
            ports: str = "80,443,8080,8443"
    ):
        self.scope_validator = scope_validator
        self.binary = binary
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.ports = ports

    def run(self, request: ToolRequest) -> ToolResult:
        command = [
            self.binary,
            "-host",
            request.target,
            "-p",
            self.ports,
            "-rate",
            str(self.rate_limit),
            "-json",
            "-silent"
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
                error="Naabu execution timed out."
            )
        except OSError as exc:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=f"Unable to execute Naabu: {exc}"
            )

        if process.returncode != 0:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=process.stderr.strip() or "Naabu execution failed."
            )

        ports = []

        for line in process.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            try: 
                data = json.loads(line)
            except json.JSONDecodeError:
                continue


            host = data.get("host") or request.target
            ip = data.get("ip")
            port = data.get("port")

            if not self.scope_validator.is_allowed(host):
                continue

            if port is None:
                continue

            ports.append(
                {
                    "host": host,
                    "ip": ip,
                    "port": port
                }
            )
        return ToolResult(
            tool_name=self.name,
            target=request.target,
            success=True,
            output={
                "ports": ports,
                "count": len(ports),
            },
        )            