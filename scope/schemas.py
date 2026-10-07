from dataclasses import dataclass, field

@dataclass
class ScopeConfig:
    allowed_domains: list[str] = field(default_factory=list)
    excluded_domains: list[str] = field(default_factory=list)

    