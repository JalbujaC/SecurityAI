from scope.resource_policy import tool_target_allowed
from scope.targets import TargetAsset


class ToolTargetPolicy:
    POLICIES: dict[str, set[str]] = {
        "subfinder": {"root_domain"},
        "dnsx": {"root_domain", "host"},
        "httpx": {"root_domain", "host", "url"},
        "katana": {"url"},
        "nuclei": {"url"},
        "ffuf": {"url"},
        "naabu": {"root_domain", "host"},
        "gau": {"root_domain", "host"},
        "dalfox": {"url"},
        "nuclei_dast": {"url"},
        "mock_recon": {"root_domain", "host", "url"}
    }
    @classmethod
    def allowed_kinds(
        cls,
        tool_name: str,
    ) -> set[str]:
        try:
            return cls.POLICIES[tool_name]
        except KeyError as exc:
            raise ValueError(
                f"No target policy exists for tool: {tool_name}"
            ) from exc
        
    @classmethod
    def is_compatible(
        cls,
        tool_name: str,
        asset: TargetAsset,
    ) -> bool:
        return (
            asset.kind in cls.allowed_kinds(tool_name)
            and tool_target_allowed(tool_name, asset.value)
        )
    @classmethod
    def filter_assets(
        cls,
        tool_name: str,
        assets: list[TargetAsset],
    ) -> list[TargetAsset]:
        return [
            asset
            for asset in assets
            if cls.is_compatible(
                tool_name,
                asset,
            )
        ]