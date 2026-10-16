from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class EvidenceRecord:
    tool_name: str
    target: str
    success: bool
    output: Any
    error: str | None
    collected_at: str

    @classmethod
    def from_tool_result(
        cls,
        result,
    ) -> "EvidenceRecord":
        return cls(
            tool_name=result.tool_name,
            target=result.target,
            success=result.success,
            output=result.output,
            error=result.error,
            collected_at=datetime.now(
                timezone.utc
            ).isoformat(),
        )