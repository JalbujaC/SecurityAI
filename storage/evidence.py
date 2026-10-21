import hashlib
import json

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
    evidence_id: str = ""

    @classmethod
    def from_tool_result(
        cls,
        result,
    ) -> "EvidenceRecord":
        evidence_id = cls.build_id(
            tool_name=result.tool_name,
            target=result.target,
            success=result.success,
            output=result.output,
            error=result.error,
        )

        return cls(
            tool_name=result.tool_name,
            target=result.target,
            success=result.success,
            output=result.output,
            error=result.error,
            collected_at=datetime.now(
                timezone.utc
            ).isoformat(),
            evidence_id=evidence_id,
        )

    @staticmethod
    def build_id(
        tool_name: str,
        target: str,
        success: bool,
        output: Any,
        error: str | None,
    ) -> str:
        canonical = json.dumps(
            {
                "tool_name": tool_name,
                "target": target,
                "success": success,
                "output": output,
                "error": error,
            },
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        )

        digest = hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

        return digest[:16]