import hashlib
import re

from models.schemas import AnalysisResult
from storage.findings import FindingRecord


class FindingBuilder:
    """
    Converts sufficiently strong analysis hypotheses
    into deterministic FindingRecord objects.

    This does not validate vulnerabilities.
    New records always begin as hypotheses.
    """

    MIN_CONFIDENCE = 0.60

    @classmethod
    def from_analysis(
        cls,
        analysis: AnalysisResult,
        target: str,
        evidence_ids: list[str] | None = None
    ) -> list[FindingRecord]:

        if analysis.confidence < cls.MIN_CONFIDENCE:
            return []

        if not analysis.evidence:
            return []

        if not analysis.hypotheses:
            return []

        findings: list[FindingRecord] = []

        for hypothesis in analysis.hypotheses:
            hypothesis = hypothesis.strip()

            if not hypothesis:
                continue

            finding_id = cls.fingerprint(
                target=target,
                vulnerability_class="unclassified",
                hypothesis=hypothesis,
            )

            findings.append(
                FindingRecord(
                    finding_id=finding_id,
                    title=hypothesis,
                    target=target,
                    vulnerability_class="unclassified",
                    status="hypothesis",
                    summary=analysis.summary,
                    evidence_ids=list(
                        evidence_ids or []
                    ),
                    confidence=analysis.confidence,
                )
            )

        return findings

    @staticmethod
    def fingerprint(
        target: str,
        vulnerability_class: str,
        hypothesis: str,
    ) -> str:
        normalized_target = target.strip().lower()

        normalized_class = (
            vulnerability_class
            .strip()
            .lower()
        )

        normalized_hypothesis = re.sub(
            r"\s+",
            " ",
            hypothesis.strip().lower(),
        )

        canonical = "|".join(
            [
                normalized_target,
                normalized_class,
                normalized_hypothesis,
            ]
        )

        digest = hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

        return digest[:16]