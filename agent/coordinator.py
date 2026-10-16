import json

from agent.executor import AgentExecutor
from agent.planner import AgentPlanner
from models.schemas import AgentDecision, ExecutionRecord
from tools.schemas import ToolResult
from scope.targets import TargetManager

class AgentCoordinator:
    """
    Coordinates a single planning/execution cycle.

    This is intentionally NOT an autonomous loop.
    """

    def __init__(
        self,
        planner: AgentPlanner,
        executor: AgentExecutor,
        target_manager: TargetManager | None = None 
    ):
        self.planner = planner
        self.executor = executor
        self.target_manager = target_manager

    def run_once(
        self,
        observation: str,
        available_tools: list[str],
        evidence: list[str] | None = None,
        target_map: dict[str, list[str]] | None = None
    ) -> tuple[AgentDecision, ToolResult | None]:

        decision = self.planner.decide(
            observation=observation,
            available_tools=available_tools,
            evidence=evidence,
            target_map=target_map
        )

        result = self.executor.execute(
            decision
        )

        return decision, result
    
    def run(
        self,
        observation: str,
        available_tools: list[str],
        max_steps: int = 5,
    ) -> list[ExecutionRecord]:

        history: list[ExecutionRecord] = []
        evidence: list[str] = []

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
                break

            if result is None:
                break
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