from agent.finding_builder import FindingBuilder
from models.schemas import AnalysisResult


def make_analysis(
    confidence: float = 0.8,
    evidence: list[str] | None = None,
    hypotheses: list[str] | None = None,
) -> AnalysisResult:
    return AnalysisResult(
        status="HYPOTHESIS",
        summary="Observed behavior requires verification.",
        confidence=confidence,
        evidence=(
            evidence
            if evidence is not None
            else ["Observed response behavior."]
        ),
        hypotheses=(
            hypotheses
            if hypotheses is not None
            else ["Possible authorization issue."]
        ),
        recommended_next_step=(
            "Perform controlled verification."
        ),
    )


def test_strong_analysis_creates_finding():
    analysis = make_analysis()

    findings = FindingBuilder.from_analysis(
        analysis=analysis,
        target="api.example.com",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.target == "api.example.com"
    assert finding.status == "hypothesis"
    assert finding.confidence == 0.8
    assert (
        finding.vulnerability_class
        == "unclassified"
    )


def test_low_confidence_creates_no_finding():
    analysis = make_analysis(
        confidence=0.40
    )

    findings = FindingBuilder.from_analysis(
        analysis=analysis,
        target="api.example.com",
    )

    assert findings == []


def test_analysis_without_evidence_creates_no_finding():
    analysis = make_analysis(
        evidence=[]
    )

    findings = FindingBuilder.from_analysis(
        analysis=analysis,
        target="api.example.com",
    )

    assert findings == []


def test_analysis_without_hypothesis_creates_no_finding():
    analysis = make_analysis(
        hypotheses=[]
    )

    findings = FindingBuilder.from_analysis(
        analysis=analysis,
        target="api.example.com",
    )

    assert findings == []


def test_multiple_hypotheses_create_multiple_findings():
    analysis = make_analysis(
        hypotheses=[
            "Possible authorization issue.",
            "Possible redirect validation issue.",
        ]
    )

    findings = FindingBuilder.from_analysis(
        analysis=analysis,
        target="api.example.com",
    )

    assert len(findings) == 2


def test_fingerprint_is_deterministic():
    first = FindingBuilder.fingerprint(
        target="API.EXAMPLE.COM",
        vulnerability_class="Unclassified",
        hypothesis="Possible   authorization issue.",
    )

    second = FindingBuilder.fingerprint(
        target="api.example.com",
        vulnerability_class="unclassified",
        hypothesis="possible authorization issue.",
    )

    assert first == second


def test_different_hypotheses_have_different_fingerprints():
    first = FindingBuilder.fingerprint(
        target="api.example.com",
        vulnerability_class="unclassified",
        hypothesis="Possible authorization issue.",
    )

    second = FindingBuilder.fingerprint(
        target="api.example.com",
        vulnerability_class="unclassified",
        hypothesis="Possible redirect issue.",
    )

    assert first != second

def test_finding_receives_evidence_ids():
    analysis = make_analysis()

    findings = FindingBuilder.from_analysis(
        analysis=analysis,
        target="api.example.com",
        evidence_ids=[
            "evidence123",
            "evidence456",
        ],
    )

    assert len(findings) == 1

    assert findings[0].evidence_ids == [
        "evidence123",
        "evidence456",
    ]