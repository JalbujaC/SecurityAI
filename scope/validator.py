from urllib.parse import urlparse
from scope.schemas import ScopeConfig

class ScopeValidator:
    """
    Determines the target scope and enforces it.

    The model must never decide whether a target is allowed.
    """


    def __init__(self, config:ScopeConfig):
        self.config = config

    def normalize_target(self, target: str) -> str:
        target = target.strip().lower()

        if "://" in target:
            parsed = urlparse(target)
            hostname = parsed.hostname

            if hostname is None:
                raise ValueError(f"Invalid target: {target}")

            return hostname
        return target.split("/")[0].split(":")[0]

    def is_excluded(self, target: str) -> bool:
        hostname = self.normalize_target(target)

        for excluded in self.config.excluded_domains:
            excluded = excluded.lower()

            if hostname == excluded:
                return True
            if hostname.endswith("." + excluded):
                return True
        return False

    def is_allowed(self, target: str) -> bool:
        hostname = self.normalize_target(target)

        if self.is_excluded(hostname):
            return False

        for allowed in self.config.allowed_domains:
            allowed = allowed.lower()

            if hostname == allowed:
                return True
            if hostname.endswith("." + allowed):
                return True
        return False

    def validate(self, target: str) -> None:
        if not self.is_allowed(target):
            raise PermissionError(f"Target is outside authorized scope: {target}")
    