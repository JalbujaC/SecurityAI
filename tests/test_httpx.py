import subprocess

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.httpx import HttpxTool
from tools.schemas import ToolRequest


def build_tool():
    config = ScopeConfig(
        allowed_domains=["example.com"],
        excluded_domains=["internal.example.com"],
    )

    validator = ScopeValidator(config)

    return HttpxTool(
        scope_validator=validator
    )


def test_httpx_parses_result(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"url":"https://api.example.com",'
        '"status_code":200,'
        '"title":"API",'
        '"tech":["nginx","React"]}\n'
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
        tool_name="httpx",
        target="api.example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1

    item = result.output["results"][0]

    assert item["url"] == "https://api.example.com"
    assert item["status_code"] == 200
    assert item["title"] == "API"
    assert "nginx" in item["technologies"]


def test_httpx_filters_out_of_scope_result(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"url":"https://evil.com","status_code":200}\n'
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
        tool_name="httpx",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 0


def test_httpx_handles_failure(monkeypatch):
    tool = build_tool()

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="httpx error",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="httpx",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert result.error == "httpx error"


def test_httpx_handles_timeout(monkeypatch):
    tool = build_tool()

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="httpx",
            timeout=60,
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="httpx",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert "timed out" in result.error.lower()