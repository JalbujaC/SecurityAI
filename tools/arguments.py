from typing import Any


class ToolArgumentPolicy:
    """
    Defines which model-proposed arguments are permitted
    for each registered tool.
    """

    POLICIES: dict[str, set[str]] = {
        "subfinder": set(),
        "dnsx": set(),
        "httpx": set(),
        "katana": set(),
        "nuclei": set(),
        "ffuf": set(),
        "naabu": set(),
        "gau": set(),
        "dalfox": set(),
        "nuclei_dast": set(),
        "mock_recon": set()
    }

    @classmethod
    def validate(
        cls,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> None:
        if tool_name not in cls.POLICIES:
            raise ValueError(
                f"No argument policy exists for tool: {tool_name}"
            )

        allowed = cls.POLICIES[tool_name]

        unknown = set(arguments.keys()) - allowed

        if unknown:
            raise ValueError(
                f"Unsupported arguments for {tool_name}: "
                f"{sorted(unknown)}"
            )