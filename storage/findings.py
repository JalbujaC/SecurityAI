from dataclasses import dataclass, field
from typing import Literal


FindingStatus = Literal[
    "hypothesis",
    "needs_validation",
    "validated",
    "rejected",
    "report_candidate",
]


@dataclass
class FindingRecord:
    finding_id: str
    title: str
    target: str
    vulnerability_class: str
    status: FindingStatus

    summary: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.0