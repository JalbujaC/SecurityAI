import json
import subprocess

from scope.validator import ScopeValidator
from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult


class DalfoxTool(SecurityTool):
    name = "dalfox"

    def __init__(
        self,
        scope_validator: ScopeValidator,
        binary: str = "dalfox",
        timeout: int = 180,
        workers: int = 5,
        request_timeout: int = 10,
    ):
        self.scope_validator = scope_validator
        self.binary = binary
        self.timeout = timeout
        self.workers = workers
        self.request_timeout = request_timeout

    def run(self, request: ToolRequest) -> ToolResult:
        command = [
            self.binary,
            "scan",
            request.target,
            "--format",
            "jsonl",
            "--silence",
            "--no-color",
            "--workers",
            str(self.workers),
            "--timeout",
            str(self.request_timeout),
            "--only-poc",
            "v,r,a",
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
                error="Dalfox execution timed out.",
            )

        except OSError as exc:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=f"Unable to execute Dalfox: {exc}",
            )

        # Dalfox:
        # 0 = completed, no findings
        # 1 = completed, findings reported
        # 2 = runtime/config/input error
        if process.returncode not in (0, 1):
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=process.stderr.strip() or "Dalfox execution failed.",
            )

        findings = []

        for line in process.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = (
                data.get("url")
                or data.get("target")
                or data.get("poc")
            )

            if url and not self.scope_validator.is_allowed(url):
                continue

            findings.append(data)

        return ToolResult(
            tool_name=self.name,
            target=request.target,
            success=True,
            output={
                "findings": findings,
                "count": len(findings),
            },
        )