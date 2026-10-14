import subprocess

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.gau import GauTool
from tools.schemas import ToolRequest


def build_tool():
    config = ScopeConfig(
        allowed_domains=["example.com"],
        excluded_domains=["internal.example.com"],
    )

    validator = ScopeValidator(config)

    return GauTool(
        scope_validator=validator
    )


def test_gau_parses_urls(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"url":"https://example.com/login"}\n'
        '{"url":"https://api.example.com/users"}\n'
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
        tool_name="gau",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 2
    assert "https://example.com/login" in result.output["urls"]


def test_gau_filters_out_of_scope_urls(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"url":"https://example.com/login"}\n'
        '{"url":"https://evil.com/admin"}\n'
        '{"url":"https://internal.example.com/admin"}\n'
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
        tool_name="gau",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1
    assert result.output["urls"] == [
        "https://example.com/login"
    ]


def test_gau_deduplicates_urls(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"url":"https://example.com/login"}\n'
        '{"url":"https://example.com/login"}\n'
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
        tool_name="gau",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1


def test_gau_handles_failure(monkeypatch):
    tool = build_tool()

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="gau error",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="gau",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert result.error == "gau error"


def test_gau_handles_timeout(monkeypatch):
    tool = build_tool()

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="gau",
            timeout=120,
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="gau",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert "timed out" in result.error.lower()