import json
from os import error
import subprocess
from sys import stdout

from scope.validator import ScopeValidator
from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult

class NucleiTool(SecurityTool):
    name = "nuclei"

    def __init__(
        self,
        scope_validator: ScopeValidator,
        binary: str = "nuclei",
        timeout: int = 360,
        rate_limit: int = 5,
        severities: str = "info,low,medium",
    ):
        self.scope_validator = scope_validator
        self.binary = binary
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.severities = severities

    def run(self, request: ToolRequest) -> ToolResult:
        command = [
            self.binary,
            "-u",
            request.target,
            "-jsonl",
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
                error="Nuclei execution timed out.",
            )

        except OSError as exc:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=f"Unable to execute Nuclei: {exc}",
            )

        if process.returncode != 0:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=process.stderr.strip() or "Nuclei execution failed.",
            )

        findings = []

        stdout = process.stdout or ""
        for line in stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            matched_at = data.get("matched-at") or data.get("host")

            if not matched_at:
                continue

            if not self.scope_validator.is_allowed(matched_at):
                continue

            info = data.get("info", {})

            findings.append(
                {
                    "template_id": data.get("template-id"),
                    "name": info.get("name"),
                    "severity": info.get("severity"),
                    "matched_at": matched_at,
                    "type": data.get("type"),
                    "matcher_name": data.get("matcher-name"),
                }
            )

        return ToolResult(
            tool_name=self.name,
            target=request.target,
            success=True,
            output={
                "findings": findings,
                "count": len(findings),
            },
        )