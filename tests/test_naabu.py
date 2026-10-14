import subprocess

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.naabu import NaabuTool
from tools.schemas import ToolRequest


def build_tool():
    config = ScopeConfig(
        allowed_domains=["example.com"],
        excluded_domains=["internal.example.com"],
    )

    validator = ScopeValidator(config)

    return NaabuTool(
        scope_validator=validator
    )


def test_naabu_parses_open_ports(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"host":"example.com","ip":"1.2.3.4","port":80}\n'
        '{"host":"example.com","ip":"1.2.3.4","port":443}\n'
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
        tool_name="naabu",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 2

    assert result.output["ports"][0]["port"] == 80
    assert result.output["ports"][1]["port"] == 443


def test_naabu_filters_out_of_scope_hosts(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"host":"example.com","ip":"1.2.3.4","port":80}\n'
        '{"host":"evil.com","ip":"5.6.7.8","port":443}\n'
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
        tool_name="naabu",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1
    assert result.output["ports"][0]["host"] == "example.com"


def test_naabu_handles_failure(monkeypatch):
    tool = build_tool()

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="naabu error",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="naabu",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert result.error == "naabu error"


def test_naabu_handles_timeout(monkeypatch):
    tool = build_tool()

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="naabu",
            timeout=120,
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="naabu",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert "timed out" in result.error.lower()