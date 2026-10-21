from typing import Literal

from tools.schemas import ToolResult


ValidationOutcome = Literal[
    "validated",
    "rejected",
    "inconclusive",
]


class ValidationResultInterpreter:
    """
    Converts validation tool output into a finding outcome.

    Successful tool execution alone is not validation.
    """

    @staticmethod
    def interpret(
        result: ToolResult,
    ) -> ValidationOutcome:

        if not result.success:
            return "inconclusive"

        output = result.output

        if not isinstance(
            output,
            dict,
        ):
            return "inconclusive"

        # Explicit deterministic signal used by
        # controlled validators/tests.
        if output.get("validated") is True:
            return "validated"

        if output.get("validated") is False:
            return "rejected"

        # Scanner/validator findings must contain
        # at least one concrete result.
        findings = output.get(
            "findings"
        )

        if (
            isinstance(findings, list)
            and len(findings) > 0
        ):
            return "validated"

        # Empty findings are not proof that the
        # hypothesis is false.
        return "inconclusive"