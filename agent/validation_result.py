from typing import Literal
from tools.schemas import ToolResult

ValidationOutcome = Literal['validated', 'rejected', 'inconclusive']


class ValidationResultInterpreter:
    """A scanner hit is a lead, not verified impact.

    Existing deterministic verified-result adapters/tests may use an explicit
    validated boolean. Raw Nuclei/Dalfox/FFUF findings never auto-validate.
    """

    @staticmethod
    def interpret(result: ToolResult) -> ValidationOutcome:
        if not result.success or not isinstance(result.output, dict):
            return 'inconclusive'
        if result.output.get('validated') is True:
            return 'validated'
        if result.output.get('validated') is False:
            return 'rejected'
        return 'inconclusive'
