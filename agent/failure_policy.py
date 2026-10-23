"""Suspend noisy tools after repeated failures; never bypass scope/approval."""
from collections import defaultdict

class FailureCircuitBreaker:
    def __init__(self, threshold: int = 2):
        if threshold < 1:
            raise ValueError('threshold must be positive')
        self.threshold = threshold
        self._failures = defaultdict(int)
        self._suspended = set()

    def observe(self, tool: str, result) -> None:
        if tool in self._suspended:
            return
        if result is not None and not result.success:
            self._failures[tool] += 1
            if self._failures[tool] >= self.threshold:
                self._suspended.add(tool)
        elif result is not None and result.success:
            self._failures[tool] = 0

    def allowed(self, tool: str) -> bool:
        return tool not in self._suspended

    def suspended(self) -> set[str]:
        return set(self._suspended)
