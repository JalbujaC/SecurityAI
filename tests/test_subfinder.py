import subprocess

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.schemas import ToolRequest
from tools.subfinder import SubfinderTool


def build_tool():
    config = ScopeConfig(
        allowed_domains=["example.com"],
        excluded_domains=["internal.example.com"],
    )

    validator = ScopeValidator(config)

    return SubfinderTool(
        scope_validator=validator
    )


def test_subfinder_parses_results(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"host":"api.example.com"}\n'
        '{"host":"www.example.com"}\n'
    )

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=fake_stdout,
        stderr="",
    )

    def fake_run(*args, **kwargs):
        return fake_process

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="subfinder",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 2
    assert "api.example.com" in result.output["subdomains"]
    assert "www.example.com" in result.output["subdomains"]


def test_subfinder_filters_out_of_scope_results(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"host":"api.example.com"}\n'
        '{"host":"internal.example.com"}\n'
        '{"host":"evil.com"}\n'
    )

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=fake_stdout,
        stderr="",
    )

    def fake_run(*args, **kwargs):
        return fake_process

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="subfinder",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1
    assert result.output["subdomains"] == [
        "api.example.com"
    ]


def test_subfinder_handles_failure(monkeypatch):
    tool = build_tool()

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="subfinder error",
    )

    def fake_run(*args, **kwargs):
        return fake_process

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="subfinder",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert result.error == "subfinder error"


def test_subfinder_handles_timeout(monkeypatch):
    tool = build_tool()

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="subfinder",
            timeout=120,
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="subfinder",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert "timed out" in result.error.lower()