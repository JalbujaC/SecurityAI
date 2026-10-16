import pytest

from scope.schemas import ScopeConfig
from scope.targets import TargetManager
from scope.validator import ScopeValidator


@pytest.fixture
def manager():
    config = ScopeConfig(
        allowed_domains=["example.com"]
    )

    validator = ScopeValidator(config)

    return TargetManager(
        scope_validator=validator
    )


def test_root_target_is_registered(manager):
    asset = manager.add_root(
        "example.com"
    )

    assert asset.value == "example.com"
    assert asset.kind == "root_domain"
    assert asset.source == "scope"


def test_discovered_host_is_registered(manager):
    manager.add_root("example.com")

    asset = manager.add_discovered(
        "api.example.com",
        source="subfinder",
    )

    assert asset.value == "api.example.com"
    assert asset.kind == "host"
    assert asset.source == "subfinder"


def test_discovered_url_is_registered(manager):
    manager.add_root("example.com")

    asset = manager.add_discovered(
        "https://api.example.com/login",
        source="katana",
    )

    assert asset.value == "https://api.example.com/login"
    assert asset.kind == "url"


def test_out_of_scope_target_is_rejected(manager):
    with pytest.raises(PermissionError):
        manager.add_discovered(
            "evil.com",
            source="subfinder",
        )


def test_duplicate_target_is_not_duplicated(manager):
    manager.add_root("example.com")

    manager.add_discovered(
        "api.example.com",
        source="subfinder",
    )

    manager.add_discovered(
        "api.example.com",
        source="dnsx",
    )

    assert manager.values().count(
        "api.example.com"
    ) == 1

def test_ingest_subfinder_results(manager):
    manager.add_root("example.com")

    discovered = manager.ingest_tool_result(
        tool_name="subfinder",
        output={
            "subdomains": [
                "api.example.com",
                "admin.example.com",
            ]
        },
    )

    values = manager.values()

    assert "api.example.com" in values
    assert "admin.example.com" in values
    assert len(discovered) == 2

def test_ingest_httpx_results(manager):
    manager.add_root("example.com")

    discovered = manager.ingest_tool_result(
        tool_name="httpx",
        output={
            "results": [
                {
                    "url": "https://api.example.com",
                    "status_code": 200,
                }
            ]
        },
    )

    assert (
        "https://api.example.com"
        in manager.values()
    )

    assert discovered[0].kind == "url"

def test_ingest_rejects_out_of_scope_asset(manager):
    manager.add_root("example.com")

    with pytest.raises(PermissionError):
        manager.ingest_tool_result(
            tool_name="subfinder",
            output={
                "subdomains": [
                    "evil.com",
                ]
            },
        )

def test_eligible_targets_are_filtered_by_tool(manager):
    manager.add_root("example.com")

    manager.add_discovered(
        "api.example.com",
        source="subfinder",
    )

    manager.add_discovered(
        "https://api.example.com",
        source="httpx",
    )

    subfinder_targets = manager.eligible_for(
        "subfinder"
    )

    katana_targets = manager.eligible_for(
        "katana"
    )

    assert [
        asset.value
        for asset in subfinder_targets
    ] == ["example.com"]

    assert [
        asset.value
        for asset in katana_targets
    ] == ["https://api.example.com"]

def test_planner_targets_are_grouped_by_tool(manager):
    manager.add_root("example.com")

    manager.add_discovered(
        "api.example.com",
        source="subfinder",
    )

    manager.add_discovered(
        "https://api.example.com",
        source="httpx",
    )

    targets = manager.planner_targets(
        [
            "subfinder",
            "httpx",
            "katana",
        ]
    )

    assert targets["subfinder"] == [
        "example.com"
    ]

    assert "api.example.com" in targets["httpx"]

    assert (
        "https://api.example.com"
        in targets["katana"]
    )