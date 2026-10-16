import pytest

from scope.targets import TargetAsset
from scope.tool_targets import ToolTargetPolicy


def test_subfinder_accepts_only_root_domain():
    root = TargetAsset(
        value="example.com",
        kind="root_domain",
        source="scope",
    )

    host = TargetAsset(
        value="api.example.com",
        kind="host",
        source="subfinder",
    )

    assert ToolTargetPolicy.is_compatible(
        "subfinder",
        root,
    )

    assert not ToolTargetPolicy.is_compatible(
        "subfinder",
        host,
    )


def test_katana_requires_url():
    host = TargetAsset(
        value="api.example.com",
        kind="host",
        source="subfinder",
    )

    url = TargetAsset(
        value="https://api.example.com",
        kind="url",
        source="httpx",
    )

    assert not ToolTargetPolicy.is_compatible(
        "katana",
        host,
    )

    assert ToolTargetPolicy.is_compatible(
        "katana",
        url,
    )


def test_httpx_accepts_host_and_url():
    host = TargetAsset(
        value="api.example.com",
        kind="host",
        source="subfinder",
    )

    url = TargetAsset(
        value="https://api.example.com",
        kind="url",
        source="httpx",
    )

    assert ToolTargetPolicy.is_compatible(
        "httpx",
        host,
    )

    assert ToolTargetPolicy.is_compatible(
        "httpx",
        url,
    )


def test_unknown_tool_is_rejected():
    asset = TargetAsset(
        value="example.com",
        kind="root_domain",
        source="scope",
    )

    with pytest.raises(ValueError):
        ToolTargetPolicy.is_compatible(
            "unknown_tool",
            asset,
        )

