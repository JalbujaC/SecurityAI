class ApprovalPolicy:
    """
    Defines which tools require explicit approval before execution.
    """

    REQUIRES_APPROVAL: set[str] = {
        "dalfox",
        "nuclei_dast",
    }

    @classmethod
    def requires_approval(
        cls,
        tool_name: str,
    ) -> bool:
        return tool_name in cls.REQUIRES_APPROVAL