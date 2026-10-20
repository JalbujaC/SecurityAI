from scope.targets import TargetAsset


class TargetPrioritizer:
    """
    Deterministically ranks discovered assets for reconnaissance.

    The model does not control priority scores.
    """

    HIGH_VALUE_KEYWORDS: set[str] = {
        "api",
        "auth",
        "account",
        "accounts",
        "admin",
        "login",
        "oauth",
        "payment",
        "payments",
        "store",
        "support",
        "developer",
        "docs",
        "service",
        "services",
    }

    LOWER_VALUE_KEYWORDS: set[str] = {
        "cdn",
        "static",
        "assets",
        "telemetry",
        "mail",
        "email",
        "emails",
    }

    @classmethod
    def score(
        cls,
        asset: TargetAsset,
    ) -> int:
        score = 0

        value = asset.value.lower()

        if asset.kind == "root_domain":
            score += 100

        elif asset.kind == "url":
            score += 60

        elif asset.kind == "host":
            score += 40

        labels = (
            value
            .replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
            .split(".")
        )

        for label in labels:
            if label in cls.HIGH_VALUE_KEYWORDS:
                score += 20

            if label in cls.LOWER_VALUE_KEYWORDS:
                score -= 10

        if "dev" in labels:
            score += 5

        if "test" in labels:
            score += 5

        return score

    @classmethod
    def rank(
        cls,
        assets: list[TargetAsset],
    ) -> list[TargetAsset]:
        return sorted(
            assets,
            key=lambda asset: (
                -cls.score(asset),
                asset.value,
            ),
        )