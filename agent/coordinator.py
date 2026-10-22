import json

from storage import finding_store
from storage.evidence import EvidenceRecord
from storage.evidence_store import EvidenceStore

from agent.executor import AgentExecutor
from agent.planner import AgentPlanner

from agent.finding_builder import FindingBuilder
from storage.finding_store import FindingStore

from tools.schemas import ToolResult
from scope.targets import TargetManager

from agent.core import SecurityAI
from models.schemas import (
    AgentDecision,
    AnalysisResult,
    ExecutionRecord
)

class AgentCoordinator:
    """
    Coordinates a single planning/execution cycle.

    This is intentionally NOT an autonomous loop.
    """

    HTTPX_BATCH_SIZE = 10   

    def __init__(
        self,
        planner: AgentPlanner,
        executor: AgentExecutor,
        target_manager: TargetManager | None = None,
        evidence_store: EvidenceStore | None = None,
        analyzer: SecurityAI | None = None,
        finding_store: FindingStore | None = None
    ):
        self.planner = planner
        self.executor = executor
        self.target_manager = target_manager
        self.evidence_store = evidence_store
        self.analyzer = analyzer
        self.finding_store = finding_store

    def run_once(
        self, observation: str, available_tools: list[str],
        evidence: list[str] | None = None,
        target_map: dict[str, list[str]] | None = None,
    ) -> tuple[AgentDecision, ToolResult | None]:
        decision = self.planner.decide(
            observation=observation, available_tools=available_tools,
            evidence=evidence, target_map=target_map)
        if decision.action != "RUN_TOOL" or decision.tool_action is None:
            return decision, None

        tool_name = decision.tool_action.tool_name
        if self.target_manager is not None:
            eligible = self.target_manager.unattempted_for(tool_name)
            if not eligible:
                # Never re-run a previously attempted tool/target combination.
                return AgentDecision(action="STOP", reasoning=(
                    f"No unattempted targets remain for {tool_name}"), tool_action=None), None
            from dataclasses import replace
            decision.tool_action = replace(decision.tool_action, target=eligible[0].value)
            execution_targets = ([asset.value for asset in eligible[:self.HTTPX_BATCH_SIZE]]
                                 if tool_name == "httpx" else None)
        else:
            execution_targets = None

        # Even a failing execution counts as attempted; failures are persisted.
        # Do not record blocked/invalid actions as attempts.
        result = self.executor.execute(decision, targets=execution_targets)
        if self.target_manager is not None and result is not None:
            self.target_manager.mark_attempted(
                tool_name, execution_targets or [decision.tool_action.target])
        return decision, result

    def run(
        self,
        observation: str,
        available_tools: list[str],
        max_steps: int = 5,
    ) -> list[ExecutionRecord]:

        history: list[ExecutionRecord] = []
        evidence: list[str] = []
        evidence_ids: list[str] = []
        seen_actions: set[tuple[str, str]] = set()

        for step in range(1, max_steps + 1):
            if self.target_manager is not None:
                target_map = (
                    self.target_manager.planner_targets(
                        available_tools
                    )
                )
            else:
                target_map = {}            
            
            decision, result = self.run_once(
                observation=observation,
                available_tools=available_tools,
                evidence=evidence,
                target_map=target_map
            )

            if decision.action == "RUN_TOOL" and decision.tool_action is not None:
                key = (decision.tool_action.tool_name, decision.tool_action.target)
                if key in seen_actions and decision.tool_action.tool_name != "httpx":
                    decision = AgentDecision(action="STOP", reasoning=(
                        "Repeated action without progress"), tool_action=None)
                    result = None
                else:
                    seen_actions.add(key)

            history.append(
                ExecutionRecord(
                    step=step,
                    decision=decision,
                    result=result,
                )
            )

            if decision.action == "STOP":
                break

            if decision.action == "ANALYZE":
                if self.analyzer is not None:
                    analysis_input = (
                        self._build_analysis_input(
                            observation=observation,
                            evidence=evidence,
                        )
                    )

                    analysis_result = (
                        self.analyzer.analyze(
                            analysis_input
                        )
                    )

                    history[-1].result = (
                        analysis_result
                    )

                    if self.finding_store is not None:
                        analysis_target = (
                            self._select_analysis_target(
                                history
                            )
                        )

                        findings = (
                            FindingBuilder.from_analysis(
                                analysis=analysis_result,
                                target=analysis_target,
                                evidence_ids=evidence_ids
                            )
                        )

                        for finding in findings:
                            self.finding_store.add_or_merge(
                                finding
                            )

                break

            if result is None:
                break

            if (
                self.evidence_store is not None
                and result is not None
            ):
                evidence_record = (
                    EvidenceRecord.from_tool_result(
                        result
                    )
                )

                self.evidence_store.add(
                    evidence_record
                )

                evidence_ids.append(
                    evidence_record.evidence_id
                )
                        
            if (
                self.target_manager is not None
                and result.success
                and isinstance(result.output, dict)
            ):
                self.target_manager.ingest_tool_result(
                    tool_name=result.tool_name,
                    output=result.output
                )
            evidence.append(
                self._summarize_result(result)
            )

        return history


    def _select_analysis_target(
        self,
        history: list[ExecutionRecord],
    ) -> str:
        for record in reversed(
            history[:-1]
        ):
            if isinstance(
                record.result,
                ToolResult,
            ):
                return record.result.target

        if self.target_manager is not None:
            roots = (
                self.target_manager.roots()
            )

            if roots:
                return roots[0].value

        return "unknown"


    def _build_analysis_input(
        self,
        observation: str,
        evidence: list[str],
    ) -> str:
        sections = [
            "Original research objective:",
            observation,
            "",
            "Collected evidence:",
        ]

        if evidence:
            sections.extend(
                evidence
            )
        else:
            sections.append(
                "No tool evidence was collected."
            )

        sections.extend(
            [
                "",
                (
                    "Analyze only the evidence above. "
                    "Do not treat scanner output, "
                    "technology identification, open "
                    "ports, redirects, discovered "
                    "endpoints, or unusual hostnames "
                    "as vulnerabilities by themselves."
                ),
            ]
        )

        return "\n".join(
            sections
        )

    def _summarize_result(
        self,
        result: ToolResult,
    ) -> str:

        if not result.success:
            return (
                f"Tool: {result.tool_name}\n"
                f"Target: {result.target}\n"
                f"Success: False\n"
                f"Error: {result.error}"
            )

        output = result.output or {}

        if result.tool_name == "subfinder":
            subdomains = output.get("subdomains", [])

            sample = subdomains[:15]

            return (
                f"Tool: subfinder\n"
                f"Target: {result.target}\n"
                f"Success: True\n"
                f"Subdomains found: {len(subdomains)}\n"
                f"Sample:\n"
                + "\n".join(
                    f"- {host}"
                    for host in sample
                )
            )

        if result.tool_name == "dnsx":
            records = output.get("records", [])

            sample = records[:10]

            return (
                f"Tool: dnsx\n"
                f"Target: {result.target}\n"
                f"Success: True\n"
                f"DNS records found: {len(records)}\n"
                f"Sample: {json.dumps(sample, default=str)}"
            )

        if result.tool_name == "httpx":
            results = output.get("results", [])

            sample = results[:10]

            return (
                f"Tool: httpx\n"
                f"Target: {result.target}\n"
                f"Success: True\n"
                f"Responsive HTTP targets: {len(results)}\n"
                f"Sample: {json.dumps(sample, default=str)}"
            )

        if result.tool_name in {
            "nuclei",
            "nuclei_dast",
            "dalfox",
            "ffuf",
        }:
            findings = output.get("findings", [])

            sample = findings[:10]

            return (
                f"Tool: {result.tool_name}\n"
                f"Target: {result.target}\n"
                f"Success: True\n"
                f"Findings: {len(findings)}\n"
                f"Sample: {json.dumps(sample, default=str)}"
            )

        if result.tool_name == "katana":
            endpoints = output.get("endpoints", [])

            return (
                f"Tool: katana\n"
                f"Target: {result.target}\n"
                f"Success: True\n"
                f"Endpoints found: {len(endpoints)}\n"
                f"Sample:\n"
                + "\n".join(
                    f"- {endpoint}"
                    for endpoint in endpoints[:15]
                )
            )

        if result.tool_name == "gau":
            urls = output.get("urls", [])

            return (
                f"Tool: gau\n"
                f"Target: {result.target}\n"
                f"Success: True\n"
                f"Historical URLs found: {len(urls)}\n"
                f"Sample:\n"
                + "\n".join(
                    f"- {url}"
                    for url in urls[:15]
                )
            )

        if result.tool_name == "naabu":
            ports = output.get("ports", [])

            return (
                f"Tool: naabu\n"
                f"Target: {result.target}\n"
                f"Success: True\n"
                f"Open ports found: {len(ports)}\n"
                f"Sample: {json.dumps(ports[:10], default=str)}"
            )

        return (
            f"Tool: {result.tool_name}\n"
            f"Target: {result.target}\n"
            f"Success: {result.success}\n"
            f"Summary: {json.dumps(output, default=str)[:1500]}"
        )