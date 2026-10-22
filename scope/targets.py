from dataclasses import dataclass
from typing import Literal

from scope.validator import ScopeValidator

TargetKind = Literal[
    "root_domain",
    "host",
    "url"
]

@dataclass(frozen=True)
class TargetAsset:
    value: str
    kind: TargetKind
    source: str

class TargetManager:
    """
    Maintains scope-validated targets.

    The model does not add or modify entries directly.
    """

    def __init__(
            self,
            scope_validator: ScopeValidator
    ):
        self.scope_validator = scope_validator
        self._targets: dict[str, TargetAsset] = {}
        self._attempted: dict[str, set[str]] = {}

    def add_root(
            self,
            target: str
    ) -> TargetAsset:
        self.scope_validator.validate(target)

        hostname = self.scope_validator.normalize_target(target)

        asset = TargetAsset(
            value=hostname,
            kind="root_domain",
            source="scope"
        )

        self._targets[asset.value] = asset

        return asset

    def add_discovered(
            self,
            target: str,
            source: str
    ) -> TargetAsset:
        self.scope_validator.validate(target)

        kind = self._classify(target)

        if kind == "url":
            value = target.strip()
        else:
            value = self.scope_validator.normalize_target(target)

        existing = self._targets.get(value)

        if (
            existing is not None
            and existing.kind == "root_domain"
        ):
            return existing
        
        asset = TargetAsset(
            value=value,
            kind=kind,
            source=source
        )

        self._targets[asset.value] = asset

        return asset

    def roots(self) -> list[TargetAsset]:
        return [
            asset
            for asset in self._targets.values()
            if asset.kind == "root_domain"
        ]
    
    def all(self) -> list[TargetAsset]:
        return list(self._targets.values())

    def values(self) -> list[str]:
        return [
            asset.value
            for asset in self._targets.values()
        ]

    def _classify(
            self,
            target: str
    ) -> TargetKind:
        if "://" in target:
            return "url"
        return "host"

    def ingest_tool_result(
        self,
        tool_name: str,
        output: dict,
    ) -> list[TargetAsset]:
        discovered: list[TargetAsset] = []

        if tool_name == "subfinder":
            for host in output.get("subdomains", []):
                discovered.append(
                    self.add_discovered(
                        host,
                        source="subfinder",
                    )
                )

        elif tool_name == "dnsx":
            for record in output.get("records", []):
                host = record.get("host")

                if host:
                    discovered.append(
                        self.add_discovered(
                            host,
                            source="dnsx",
                        )
                    )

        elif tool_name == "httpx":
            for result in output.get("results", []):
                url = result.get("url")

                if url:
                    discovered.append(
                        self.add_discovered(
                            url,
                            source="httpx",
                        )
                    )

        elif tool_name == "katana":
            for endpoint in output.get("endpoints", []):
                discovered.append(
                    self.add_discovered(
                        endpoint,
                        source="katana",
                    )
                )

        elif tool_name == "gau":
            for url in output.get("urls", []):
                discovered.append(
                    self.add_discovered(
                        url,
                        source="gau",
                    )
                )

        elif tool_name == "naabu":
            for record in output.get("ports", []):
                host = record.get("host")

                if host:
                    discovered.append(
                        self.add_discovered(
                            host,
                            source="naabu",
                        )
                    )

        return discovered
    
    def by_kind(
        self,
        kinds: set[str],
    ) -> list[TargetAsset]:
        return [
            asset
            for asset in self._targets.values()
            if asset.kind in kinds
        ]

    def eligible_for(
        self,
        tool_name: str,
    ) -> list[TargetAsset]:
        from scope.tool_targets import ToolTargetPolicy
        from scope.prioritizer import TargetPrioritizer

        assets = ToolTargetPolicy.filter_assets(
            tool_name,
            self.all()
        )

        return TargetPrioritizer.rank(
            assets
        )

    def planner_targets(
        self,
        tool_names: list[str],
    ) -> dict[str, list[str]]:
        target_map: dict[str, list[str]] = {}

        for tool_name in tool_names:
            assets = self.unattempted_for(tool_name)

            target_map[tool_name] = [
                asset.value
                for asset in assets
            ]

        return target_map

    def mark_attempted(
        self,
        tool_name: str,
        targets: list[str],
    ) -> None:
        attempted = self._attempted.setdefault(
            tool_name,
            set(),
        )

        attempted.update(
            targets
        )


    def was_attempted(
        self,
        tool_name: str,
        target: str,
    ) -> bool:
        return target in self._attempted.get(
            tool_name,
            set(),
        )


    def unattempted_for(
        self,
        tool_name: str,
    ) -> list[TargetAsset]:
        return [
            asset
            for asset in self.eligible_for(tool_name)
            if not self.was_attempted(
                tool_name,
                asset.value,
            )
        ]

    def export_state(self) -> dict:
        return {
            "targets": [
                {
                    "value": asset.value,
                    "kind": asset.kind,
                    "source": asset.source,
                }
                for asset in self._targets.values()
            ],
            "attempted": {
                tool_name: sorted(targets)
                for tool_name, targets
                in self._attempted.items()
            },
        }


    def import_state(
        self,
        state: dict,
    ) -> None:
        self._targets = {}
        self._attempted = {}

        for item in state.get(
            "targets",
            [],
        ):
            self.scope_validator.validate(
                item["value"]
            )

            asset = TargetAsset(
                value=item["value"],
                kind=item["kind"],
                source=item["source"],
            )

            self._targets[
                asset.value
            ] = asset

        for tool_name, targets in state.get(
            "attempted",
            {}
        ).items():
            safe = set()
            for target in targets:
                self.scope_validator.validate(target)
                safe.add(target)
            self._attempted[tool_name] = safe