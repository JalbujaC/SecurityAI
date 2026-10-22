import json

from dataclasses import asdict
from pathlib import Path


# ============================================================
# Agent
# ============================================================

from agent.action_validator import ActionValidator
from agent.coordinator import AgentCoordinator
from agent.core import SecurityAI
from agent.executor import AgentExecutor
from agent.planner import AgentPlanner

from agent.validation_coordinator import ValidationCoordinator
from agent.validation_executor import ValidationExecutor


# ============================================================
# Model
# ============================================================

from models.ollama import OllamaClient


# ============================================================
# Reporting
# ============================================================

from reporting.review import HumanReviewGate


# ============================================================
# Scope / Targets
# ============================================================

from scope.schemas import ScopeConfig
from scope.targets import TargetManager


# ============================================================
# Storage
# ============================================================

from storage.evidence_store import EvidenceStore
from storage.finding_store import FindingStore
from storage.run_state import RunStateStore


# ============================================================
# Tools
# ============================================================

from tools.setup import build_tool_registry


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_NAME = "qwen3:8b"

TARGET = "vinted.net"

MAX_STEPS = 50

FFUF_WORDLIST = "data/wordlists/directories.txt"


# Tools that must NEVER be exposed to autonomous planning.
ACTIVE_APPROVAL_TOOLS = {
    "dalfox",
    "nuclei_dast",
}


# ------------------------------------------------------------
# Explicit active-validation approval
# ------------------------------------------------------------
#
# Add a finding ID here only after manually reviewing it.
#
# Example:
#
# APPROVED_ACTIVE_VALIDATIONS = {
#     "0c2d74c532eab012",
# }
#
# Empty by default.

APPROVED_ACTIVE_VALIDATIONS: set[str] = set()


# ------------------------------------------------------------
# Explicit final human review
# ------------------------------------------------------------

ENABLE_HUMAN_REVIEW = False


# Human-written impact statements.
#
# Example:
#
# IMPACT_SUMMARIES = {
#     "0c2d74c532eab012": (
#         "An authenticated user can access another "
#         "user's private account data."
#     )
# }

IMPACT_SUMMARIES: dict[str, str] = {}


# ============================================================
# STORAGE PATHS
# ============================================================

# Keep each approved program's state isolated.
import re
RUN_KEY = re.sub(r"[^a-zA-Z0-9_.-]", "_", TARGET.lower())
EVIDENCE_PATH = f"data/evidence/{RUN_KEY}.json"
FINDINGS_PATH = f"data/findings/{RUN_KEY}.json"
STATE_PATH = f"data/state/{RUN_KEY}.json"
REPORT_PATH = f"data/reports/{RUN_KEY}.json"


# ============================================================
# BUILD SYSTEM
# ============================================================


def build_securityai():
    """
    Construct all SecurityAI v1 components.
    """

    # --------------------------------------------------------
    # Scope
    # --------------------------------------------------------

    scope = ScopeConfig(
        allowed_domains=[
            TARGET,
        ]
    )

    registry = build_tool_registry(
        scope_config=scope,
        ffuf_wordlist=FFUF_WORDLIST,
    )


    # --------------------------------------------------------
    # Target state
    # --------------------------------------------------------

    target_manager = TargetManager(
        scope_validator=registry.scope_validator
    )

    run_state_store = RunStateStore(
        path=STATE_PATH
    )

    # Restore previous discovered assets and attempted targets.
    run_state_store.load(
        target_manager
    )

    # Always reassert configured root scope after restoring state.
    target_manager.add_root(
        TARGET
    )


    # --------------------------------------------------------
    # Persistent evidence
    # --------------------------------------------------------

    evidence_store = EvidenceStore(
        path=EVIDENCE_PATH
    )

    # Restore historical evidence so finding evidence IDs
    # remain traceable across restarts.
    evidence_store.load()


    # --------------------------------------------------------
    # Persistent findings
    # --------------------------------------------------------

    finding_store = FindingStore(
        path=FINDINGS_PATH
    )

    finding_store.load()


    # --------------------------------------------------------
    # Local model
    # --------------------------------------------------------

    model = OllamaClient(
        model_name=MODEL_NAME,
        timeout=300,
    )


    # --------------------------------------------------------
    # Planner / analyzer
    # --------------------------------------------------------

    planner = AgentPlanner(
        model=model
    )

    analyzer = SecurityAI(
        model=model
    )


    # --------------------------------------------------------
    # Execution safety boundary
    # --------------------------------------------------------

    validator = ActionValidator(
        registry=registry
    )

    executor = AgentExecutor(
        registry=registry,
        validator=validator,
    )


    # --------------------------------------------------------
    # Main recon / analysis coordinator
    # --------------------------------------------------------

    coordinator = AgentCoordinator(
        planner=planner,
        executor=executor,
        target_manager=target_manager,
        evidence_store=evidence_store,
        analyzer=analyzer,
        finding_store=finding_store,
    )


    # --------------------------------------------------------
    # Validation pipeline
    # --------------------------------------------------------

    validation_executor = ValidationExecutor(
        executor=executor
    )

    validation_coordinator = ValidationCoordinator(
        finding_store=finding_store,
        executor=validation_executor,
    )


    # --------------------------------------------------------
    # Final human review
    # --------------------------------------------------------

    human_review = HumanReviewGate(
        finding_store=finding_store
    )


    return {
        "registry": registry,
        "target_manager": target_manager,
        "run_state_store": run_state_store,
        "evidence_store": evidence_store,
        "finding_store": finding_store,
        "coordinator": coordinator,
        "validation_coordinator": validation_coordinator,
        "human_review": human_review,
    }


# ============================================================
# RECON + ANALYSIS
# ============================================================


def run_recon(
    system: dict,
):
    registry = system["registry"]
    coordinator = system["coordinator"]

    # Active validation tools are intentionally hidden from
    # autonomous planning.
    autonomous_tools = [
        tool_name
        for tool_name in registry.list_tools()
        if tool_name not in ACTIVE_APPROVAL_TOOLS
    ]

    observation = (
        f"The authorized bug bounty scope contains {TARGET}. "
        "Perform conservative security reconnaissance using only "
        "registered tools and system-supplied targets. "
        "Use accumulated evidence to determine the next justified "
        "action. Do not invent targets, arguments, or tools. "
        "When evidence supports a concrete security hypothesis, "
        "hand it off for analysis."
    )

    return coordinator.run(
        observation=observation,
        available_tools=autonomous_tools,
        max_steps=MAX_STEPS,
    )


# ============================================================
# VALIDATION
# ============================================================


def run_validation(
    system: dict,
):
    registry = system["registry"]
    finding_store = system["finding_store"]
    validation_coordinator = (
        system["validation_coordinator"]
    )

    # Validation is allowed to consider the full registered
    # tool set because the approval boundary still exists in
    # AgentExecutor / ApprovalPolicy.
    validation_tools = registry.list_tools()

    results = []

    for finding in list(
        finding_store.all()
    ):
        if finding.status not in {
            "hypothesis",
            "needs_validation",
        }:
            continue

        approved = (
            finding.finding_id
            in APPROVED_ACTIVE_VALIDATIONS
        )

        try:
            result = (
                validation_coordinator.validate(
                    finding_id=finding.finding_id,
                    available_tools=validation_tools,
                    approved=approved,
                )
            )

        except PermissionError as exc:
            # This is expected when a validation plan requires
            # dalfox/nuclei_dast without explicit human approval.
            results.append(
                {
                    "finding_id": finding.finding_id,
                    "status": "approval_required",
                    "message": str(exc),
                }
            )

            continue

        except ValueError as exc:
            results.append(
                {
                    "finding_id": finding.finding_id,
                    "status": "validation_error",
                    "message": str(exc),
                }
            )

            continue

        if result is None:
            results.append(
                {
                    "finding_id": finding.finding_id,
                    "status": "no_validation_result",
                }
            )

            continue

        results.append(
            {
                "finding_id": finding.finding_id,
                "status": (
                    finding_store
                    .get(finding.finding_id)
                    .status
                ),
                "tool": result.tool_name,
                "success": result.success,
            }
        )

    return results


# ============================================================
# HUMAN REVIEW / REPORT CANDIDATES
# ============================================================


def run_human_review(
    system: dict,
):
    if not ENABLE_HUMAN_REVIEW:
        return []

    finding_store = system["finding_store"]
    human_review = system["human_review"]

    candidates = []

    for finding in list(
        finding_store.all()
    ):
        if finding.status != "validated":
            continue

        impact_summary = (
            IMPACT_SUMMARIES.get(
                finding.finding_id
            )
        )

        # No human-supplied impact statement =
        # no report promotion.
        if not impact_summary:
            continue

        candidate = human_review.approve(
            finding_id=finding.finding_id,
            impact_summary=impact_summary,
        )

        candidates.append(
            candidate
        )

    return candidates


# ============================================================
# REPORT PERSISTENCE
# ============================================================


def save_report_candidates(
    candidates,
):
    if not candidates:
        return

    path = Path(
        REPORT_PATH
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            [
                asdict(candidate)
                for candidate
                in candidates
            ],
            indent=2,
        ),
        encoding="utf-8",
    )


# ============================================================
# OUTPUT
# ============================================================


def print_run_history(
    history,
):
    print()
    print("=" * 70)
    print("SECURITYAI EXECUTION")
    print("=" * 70)

    for record in history:
        print()
        print("-" * 70)
        print(
            f"STEP {record.step}"
        )
        print("-" * 70)

        print("Decision:")
        print(
            record.decision
        )

        print()

        print("Result:")
        print(
            record.result
        )


def print_summary(
    system: dict,
    history,
    validation_results,
    report_candidates,
):
    evidence_store = system[
        "evidence_store"
    ]

    finding_store = system[
        "finding_store"
    ]

    target_manager = system[
        "target_manager"
    ]

    print()
    print("=" * 70)
    print("SECURITYAI V1 SUMMARY")
    print("=" * 70)

    print(
        f"Steps executed: "
        f"{len(history)}"
    )

    print(
        f"Known targets: "
        f"{len(target_manager.all())}"
    )

    print(
        f"Evidence records: "
        f"{evidence_store.count()}"
    )

    print(
        f"Findings stored: "
        f"{finding_store.count()}"
    )

    print(
        f"Report candidates: "
        f"{len(report_candidates)}"
    )


    # --------------------------------------------------------
    # Findings
    # --------------------------------------------------------

    if finding_store.count():
        print()
        print("Findings:")

        for finding in finding_store.all():
            print(
                f"- [{finding.status}] "
                f"{finding.finding_id} "
                f"{finding.title} "
                f"(target={finding.target}, "
                f"confidence="
                f"{finding.confidence:.2f})"
            )


    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if validation_results:
        print()
        print("Validation:")

        for item in validation_results:
            print(
                f"- {item}"
            )


    # --------------------------------------------------------
    # Files
    # --------------------------------------------------------

    print()
    print("Persistent data:")

    print(
        f"- Evidence: {EVIDENCE_PATH}"
    )

    print(
        f"- Findings: {FINDINGS_PATH}"
    )

    print(
        f"- Run state: {STATE_PATH}"
    )

    if report_candidates:
        print(
            f"- Reports: {REPORT_PATH}"
        )


# ============================================================
# MAIN
# ============================================================


def main():
    print(
        "[SECURITYAI] Starting SecurityAI v1..."
    )

    print(
        f"[SECURITYAI] Target: {TARGET}"
    )

    print(
        f"[SECURITYAI] Model: {MODEL_NAME}"
    )


    # --------------------------------------------------------
    # Initialize
    # --------------------------------------------------------

    system = build_securityai()


    # --------------------------------------------------------
    # Recon + analysis
    # --------------------------------------------------------

    history = run_recon(
        system
    )


    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    validation_results = (
        run_validation(
            system
        )
    )


    # --------------------------------------------------------
    # Explicit human review
    # --------------------------------------------------------

    report_candidates = (
        run_human_review(
            system
        )
    )


    # --------------------------------------------------------
    # Persist reports
    # --------------------------------------------------------

    save_report_candidates(
        report_candidates
    )


    # --------------------------------------------------------
    # Persist target / attempt state
    # --------------------------------------------------------

    system[
        "run_state_store"
    ].save(
        system[
            "target_manager"
        ]
    )


    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    print_run_history(
        history
    )

    print_summary(
        system=system,
        history=history,
        validation_results=validation_results,
        report_candidates=report_candidates,
    )


if __name__ == "__main__":
    main()