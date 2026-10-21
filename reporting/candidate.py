from dataclasses import dataclass, field


@dataclass
class ReportCandidate:
    finding_id: str
    title: str
    target: str
    vulnerability_class: str
    summary: str
    impact: str
    confidence: float
    evidence_ids: list[str] = field(
        default_factory=list
    )