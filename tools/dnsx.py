import json
import subprocess

from scope.validator import ScopeValidator
from tools.base import SecurityTool
from tools.schemas import ToolRequest, ToolResult


class DnsxTool(SecurityTool):
    name = 'dnsx'

    def __init__(self, scope_validator: ScopeValidator, binary: str = 'dnsx',
                 timeout: int = 180, rate_limit: int = 20):
        self.scope_validator = scope_validator
        self.binary = binary
        self.timeout = timeout
        self.rate_limit = rate_limit

    def run(self, request: ToolRequest) -> ToolResult:
        # dnsx -d is a brute-force mode requiring -w; use stdin for resolving hosts.
        command = [self.binary, '-a', '-json', '-silent', '-rl', str(self.rate_limit)]
        try:
            process = subprocess.run(
                command, input=request.target + '\n', capture_output=True,
                text=True, encoding='utf-8', errors='replace',
                timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired:
            return ToolResult(tool_name=self.name, target=request.target, success=False,
                              error='dnsx execution timed out.')
        except OSError as exc:
            return ToolResult(tool_name=self.name, target=request.target, success=False,
                              error=f'Unable to execute dnsx: {exc}')
        if process.returncode != 0:
            return ToolResult(tool_name=self.name, target=request.target, success=False,
                              error=(process.stderr or '').strip() or 'dnsx failed')
        records = []
        for line in (process.stdout or '').splitlines():
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(data, dict):
                continue
            host = data.get('host')
            if not host or not self.scope_validator.is_allowed(host):
                continue
            records.append({k: data.get(k) for k in
                            ('host', 'a', 'aaaa', 'cname', 'resolver', 'status_code')})
        return ToolResult(tool_name=self.name, target=request.target, success=True,
                          output={'records': records, 'count': len(records)})
