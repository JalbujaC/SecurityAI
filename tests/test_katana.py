import subprocess

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.katana import KatanaTool
from tools.schemas import ToolRequest


def build_tool():
    config = ScopeConfig(
        allowed_domains=["example.com"],
        excluded_domains=["internal.example.com"],
    )

    validator = ScopeValidator(config)

    return KatanaTool(
        scope_validator=validator
    )


def test_katana_parses_endpoints(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"request":{"endpoint":"https://example.com/"}}\n'
        '{"request":{"endpoint":"https://example.com/login"}}\n'
        '{"request":{"endpoint":"https://api.example.com/users"}}\n'
    )

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=fake_stdout,
        stderr="",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="katana",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 3
    assert "https://example.com/login" in result.output["endpoints"]
    assert "https://api.example.com/users" in result.output["endpoints"]


def test_katana_filters_out_of_scope_endpoints(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"request":{"endpoint":"https://example.com/login"}}\n'
        '{"request":{"endpoint":"https://internal.example.com/admin"}}\n'
        '{"request":{"endpoint":"https://evil.com/"}}\n'
    )

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=fake_stdout,
        stderr="",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="katana",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1
    assert result.output["endpoints"] == [
        "https://example.com/login"
    ]


def test_katana_deduplicates_endpoints(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"request":{"endpoint":"https://example.com/login"}}\n'
        '{"request":{"endpoint":"https://example.com/login"}}\n'
    )

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=fake_stdout,
        stderr="",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="katana",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1


def test_katana_handles_failure(monkeypatch):
    tool = build_tool()

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="katana error",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="katana",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert result.error == "katana error"


def test_katana_handles_timeout(monkeypatch):
    tool = build_tool()

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="katana",
            timeout=120,
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="katana",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert "timed out" in result.error.lower()