from dataclasses import dataclass

from storage.findings import FindingRecord


@dataclass
class ValidationPlan:
    finding_id: str
    target: str
    tool_name: str
    reason: str
    requires_approval: bool


class ValidationPlanner:
    """
    Creates conservative validation plans for findings.

    It never executes tools and never bypasses approval.
    """

    ACTIVE_TOOLS = {
        "dalfox",
        "nuclei_dast",
    }

    @classmethod
    def plan(
        cls,
        finding: FindingRecord,
        available_tools: list[str],
    ) -> ValidationPlan | None:

        title = finding.title.lower()

        tool_name = cls._select_tool(
            title=title,
            available_tools=available_tools,
        )

        if tool_name is None:
            return None

        return ValidationPlan(
            finding_id=finding.finding_id,
            target=finding.target,
            tool_name=tool_name,
            reason=(
                f"Validate finding: "
                f"{finding.title}"
            ),
            requires_approval=(
                tool_name in cls.ACTIVE_TOOLS
            ),
        )

    @staticmethod
    def _select_tool(
        title: str,
        available_tools: list[str],
    ) -> str | None:

        available = set(
            available_tools
        )

        if (
            any(
                keyword in title
                for keyword in {
                    "xss",
                    "cross-site scripting",
                }
            )
            and "dalfox" in available
        ):
            return "dalfox"

        if (
            any(
                keyword in title
                for keyword in {
                    "template",
                    "misconfiguration",
                    "exposure",
                    "known vulnerability",
                }
            )
            and "nuclei_dast" in available
        ):
            return "nuclei_dast"

        if "nuclei" in available:
            return "nuclei"

        return None