import pytest

from agent.action_validator import ActionValidator
from models.schemas import ToolAction
from scope.schemas import ScopeConfig
from tools.setup import build_tool_registry

def build_validator(tmp_path):
    wordlist = tmp_path / "directories.txt"

    wordlist.write_text(
        "admin\napi\nlogin\n",
        encoding="utf-8",
    )

    scope = ScopeConfig(
        allowed_domains=["example.com"],
    )

    registry = build_tool_registry(
        scope_config=scope,
        ffuf_wordlist=str(wordlist),
    )

    return ActionValidator(registry)

def test_valid_tool_action_is_accepted(tmp_path):
    validator = build_validator(tmp_path)

    action = ToolAction(
        tool_name="subfinder",
        target="example.com",
        reason="Discover scoped subdomains.",
    )

    validator.validate(action)


def test_unknown_tool_is_rejected(tmp_path):
    validator = build_validator(tmp_path)

    action = ToolAction(
        tool_name="arbitrary_shell",
        target="example.com",
    )

    with pytest.raises(ValueError):
        validator.validate(action)


def test_out_of_scope_action_is_rejected(tmp_path):
    validator = build_validator(tmp_path)

    action = ToolAction(
        tool_name="httpx",
        target="evil.com",
    )

    with pytest.raises(PermissionError):
        validator.validate(action)


def test_missing_target_is_rejected(tmp_path):
    validator = build_validator(tmp_path)

    action = ToolAction(
        tool_name="subfinder",
        target="",
    )

    with pytest.raises(ValueError):
        validator.validate(action)

def test_model_cannot_request_unregistered_command(tmp_path):
    validator = build_validator(tmp_path)

    action = ToolAction(
        tool_name="powershell",
        target="example.com",
        arguments={
            "command": "whoami"
        },
    )

    with pytest.raises(ValueError):
        validator.validate(action)

def test_empty_arguments_are_allowed(tmp_path):
    validator = build_validator(tmp_path)

    action = ToolAction(
        tool_name="subfinder",
        target="example.com",
        arguments={},
    )

    validator.validate(action)

def test_unknown_tool_argument_is_rejected(tmp_path):
    validator = build_validator(tmp_path)

    action = ToolAction(
        tool_name="subfinder",
        target="example.com",
        arguments={
            "command": "whoami",
        },
    )

    with pytest.raises(ValueError):
        validator.validate(action)

def test_model_cannot_change_rate_limit(tmp_path):
    validator = build_validator(tmp_path)

    action = ToolAction(
        tool_name="httpx",
        target="example.com",
        arguments={
            "rate_limit": 10000,
        },
    )

    with pytest.raises(ValueError):
        validator.validate(action)