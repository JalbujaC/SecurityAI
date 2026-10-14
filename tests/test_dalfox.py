import subprocess

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.dalfox import DalfoxTool
from tools.schemas import ToolRequest


def build_tool():
    config = ScopeConfig(
        allowed_domains=["example.com"],
        excluded_domains=["internal.example.com"],
    )

    validator = ScopeValidator(config)

    return DalfoxTool(
        scope_validator=validator
    )


def test_dalfox_parses_findings(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"type":"V",'
        '"url":"https://example.com/search?q=test",'
        '"param":"q"}\n'
    )

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout=fake_stdout,
        stderr="",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="dalfox",
        target="https://example.com/search?q=test",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1


def test_dalfox_accepts_no_findings(monkeypatch):
    tool = build_tool()

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="",
        stderr="",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="dalfox",
        target="https://example.com/search?q=test",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 0


def test_dalfox_filters_out_of_scope_findings(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"type":"V","url":"https://example.com/search?q=test"}\n'
        '{"type":"V","url":"https://evil.com/search?q=test"}\n'
    )

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout=fake_stdout,
        stderr="",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="dalfox",
        target="https://example.com/search?q=test",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1


def test_dalfox_handles_failure(monkeypatch):
    tool = build_tool()

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=2,
        stdout="",
        stderr="dalfox runtime error",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="dalfox",
        target="https://example.com/search?q=test",
    )

    result = tool.run(request)

    assert result.success is False
    assert result.error == "dalfox runtime error"


def test_dalfox_handles_timeout(monkeypatch):
    tool = build_tool()

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="dalfox",
            timeout=180,
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="dalfox",
        target="https://example.com/search?q=test",
    )

    result = tool.run(request)

    assert result.success is False
    assert "timed out" in result.error.lower()