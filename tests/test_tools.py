import pytest

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator

from tools.mock import MockReconTool
from tools.registry import ToolRegistry
from tools.schemas import ToolRequest


@pytest.fixture
def registry():
    scope = ScopeConfig(
        allowed_domains=["example.com"],
    )

    validator = ScopeValidator(scope)

    tool_registry = ToolRegistry(
        scope_validator=validator
    )

    tool_registry.register(MockReconTool())

    return tool_registry


def test_tool_can_be_registered(registry):
    assert "mock_recon" in registry.list_tools()


def test_registered_tool_can_be_retrieved(registry):
    tool = registry.get("mock_recon")

    assert tool.name == "mock_recon"


def test_unknown_tool_is_rejected(registry):
    with pytest.raises(KeyError):
        registry.get("does_not_exist")


def test_duplicate_tool_registration_is_rejected(registry):
    with pytest.raises(ValueError):
        registry.register(MockReconTool())


def test_in_scope_tool_request_executes(registry):
    request = ToolRequest(
        tool_name="mock_recon",
        target="api.example.com",
    )

    result = registry.execute(request)

    assert result.success is True
    assert result.tool_name == "mock_recon"
    assert result.target == "api.example.com"


def test_out_of_scope_tool_request_is_rejected(registry):
    request = ToolRequest(
        tool_name="mock_recon",
        target="evil.com",
    )

    with pytest.raises(PermissionError):
        registry.execute(request)