import pytest

from scope.schemas import ScopeConfig
from tools.schemas import ToolRequest
from tools.setup import build_tool_registry

def test_registry_contains_subfinder():
    config = ScopeConfig(
        allowed_domains=["example.com"]
    )

    registry = build_tool_registry(config)

    assert "subfinder" in registry.list_tools()

def test_registry_blocks_out_of_scope_subfinder_request():
    config = ScopeConfig(
        allowed_domains=["example.com"]
    )

    registry = build_tool_registry(config)

    request = ToolRequest(
        tool_name="subfinder",
        target="outside-scope.test",
    )

    with pytest.raises(PermissionError):
        registry.execute(request)