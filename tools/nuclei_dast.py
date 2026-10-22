import json
import re
import subprocess
from urllib.parse import urlparse

from scope.validator import ScopeValidator
from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult

class NucleiDastTool(SecurityTool):
    name = "nuclei_dast"

    def __init__(
            self,
            scope_validator: ScopeValidator,
            binary: str = "nuclei",
            timeout: int = 240,
            rate_limit: int = 3
    ):
        self.scope_validator = scope_validator
        self.binary = binary
        self.timeout = timeout
        self.rate_limit = rate_limit

    def _build_fuzz_scope(self, target: str) -> str:
        parsed = urlparse(target)

        if not parsed.scheme or not parsed.hostname:
            raise ValueError("Nuclei DAST target must be a full URL including scheme.")

        hostname = re.escape(parsed.hostname)
        return rf"^https?://{hostname}(?::\d+)?(?:/|$)"

    def run(self, request: ToolRequest) -> ToolResult:
        try:
            fuzz_scope = self._build_fuzz_scope(request.target)
        except ValueError as exc:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=str(exc)
            )

        command = [
            self.binary,
            "-u",
            request.target,
            "-dast",
            "-fuzz-aggression",
            "low",
            "-fuzz-scope",
            fuzz_scope,
            "-rate-limit",
            str(self.rate_limit),
            "-jsonl",
            "-silent",
            "-no-interactsh"
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
                error="Nuclei DAST execution timed out.",
            )

        except OSError as exc:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=f"Unable to execute Nuclei DAST: {exc}",
            )

        if process.returncode != 0:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=(
                    process.stderr.strip()
                    or "Nuclei DAST execution failed."
                ),
            )

        findings = []
        stdout = process.stdout or ""
        for line in process.stdout.splitlines():
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
                    "matcher_name": data.get("matcher-name"),
                    "type": data.get("type"),
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