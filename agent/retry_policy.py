from dataclasses import dataclass, field


@dataclass
class RetryPolicy:
    max_attempts: int = 2
    _attempts: dict[tuple[str, str], int] = field(
        default_factory=dict
    )

    def record_attempt(
        self,
        tool_name: str,
        target: str,
    ) -> int:
        key = (
            tool_name,
            target,
        )

        current = self._attempts.get(
            key,
            0,
        )

        current += 1

        self._attempts[
            key
        ] = current

        return current

    def attempts_for(
        self,
        tool_name: str,
        target: str,
    ) -> int:
        return self._attempts.get(
            (
                tool_name,
                target,
            ),
            0,
        )

    def can_retry(
        self,
        tool_name: str,
        target: str,
    ) -> bool:
        return (
            self.attempts_for(
                tool_name,
                target,
            )
            < self.max_attempts
        )