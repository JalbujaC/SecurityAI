from scope.prioritizer import TargetPrioritizer
from scope.targets import TargetAsset


def test_root_domain_scores_highest():
    root = TargetAsset(
        value="example.com",
        kind="root_domain",
        source="scope",
    )

    host = TargetAsset(
        value="www.example.com",
        kind="host",
        source="subfinder",
    )

    assert (
        TargetPrioritizer.score(root)
        > TargetPrioritizer.score(host)
    )


def test_interesting_host_scores_higher():
    auth = TargetAsset(
        value="auth.example.com",
        kind="host",
        source="subfinder",
    )

    static = TargetAsset(
        value="static.example.com",
        kind="host",
        source="subfinder",
    )

    assert (
        TargetPrioritizer.score(auth)
        > TargetPrioritizer.score(static)
    )


def test_rank_orders_high_priority_first():
    assets = [
        TargetAsset(
            value="static.example.com",
            kind="host",
            source="subfinder",
        ),
        TargetAsset(
            value="api.example.com",
            kind="host",
            source="subfinder",
        ),
        TargetAsset(
            value="auth.example.com",
            kind="host",
            source="subfinder",
        ),
    ]

    ranked = TargetPrioritizer.rank(
        assets
    )

    assert ranked[0].value in {
        "api.example.com",
        "auth.example.com",
    }

    assert (
        ranked[-1].value
        == "static.example.com"
    )


def test_ranking_is_deterministic():
    assets = [
        TargetAsset(
            value="beta.example.com",
            kind="host",
            source="subfinder",
        ),
        TargetAsset(
            value="alpha.example.com",
            kind="host",
            source="subfinder",
        ),
    ]

    first = TargetPrioritizer.rank(
        assets
    )

    second = TargetPrioritizer.rank(
        assets
    )

    assert first == second

    assert [
        asset.value
        for asset in first
    ] == [
        "alpha.example.com",
        "beta.example.com",
    ]