import json
import subprocess
from pathlib import Path

from scope.validator import ScopeValidator
from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult


class FfufTool(SecurityTool):
    name = "ffuf"

    def __init__(
        self,
        scope_validator: ScopeValidator,
        wordlist: str,
        binary: str = "ffuf",
        timeout: int = 90,
        rate_limit: int = 5,
        threads: int = 5,
        max_time: int = 60,
    ):
        self.scope_validator = scope_validator
        self.wordlist = Path(wordlist)
        self.binary = binary
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.threads = threads
        self.max_time = max_time

    def run(self, request: ToolRequest) -> ToolResult:
        if not self.wordlist.exists():
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=f"Wordlist not found: {self.wordlist}",
            )

        target = request.target.rstrip("/")

        fuzz_url = f"{target}/FUZZ"

        command = [
            self.binary,
            "-w",
            str(self.wordlist),
            "-u",
            fuzz_url,
            "-json",
            "-s",
            "-noninteractive",
            "-rate",
            str(self.rate_limit),
            "-t",
            str(self.threads),
            "-maxtime",
            str(self.max_time),
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
                error="ffuf execution timed out.",
            )

        except OSError as exc:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=f"Unable to execute ffuf: {exc}",
            )

        if process.returncode != 0:
            return ToolResult(
                tool_name=self.name,
                target=request.target,
                success=False,
                error=process.stderr.strip() or "ffuf execution failed.",
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

            url = data.get("url")

            if not url:
                continue

            if not self.scope_validator.is_allowed(url):
                continue

            findings.append(
                {
                    "url": url,
                    "status": data.get("status"),
                    "length": data.get("length"),
                    "words": data.get("words"),
                    "lines": data.get("lines"),
                    "redirect_location": data.get("redirectlocation"),
                    "input": data.get("input", {}),
                }
            )

        from analysis.redirect_noise import redirect_groups
        return ToolResult(
            tool_name=self.name,
            target=request.target,
            success=True,
            output={
                "findings": findings,
                "count": len(findings),
                "redirect_groups": redirect_groups(findings),
            },
        )