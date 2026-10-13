import subprocess

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.dnsx import DnsxTool
from tools.schemas import ToolRequest


def build_tool():
    config = ScopeConfig(
        allowed_domains=["example.com"],
        excluded_domains=["internal.example.com"],
    )

    validator = ScopeValidator(config)

    return DnsxTool(
        scope_validator=validator
    )


def test_dnsx_parses_a_records(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"host":"api.example.com",'
        '"a":["1.2.3.4"],'
        '"resolver":"8.8.8.8:53",'
        '"status_code":"NOERROR"}\n'
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
        tool_name="dnsx",
        target="api.example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1

    record = result.output["records"][0]

    assert record["host"] == "api.example.com"
    assert record["a"] == ["1.2.3.4"]


def test_dnsx_filters_out_of_scope_hosts(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"host":"api.example.com","a":["1.2.3.4"]}\n'
        '{"host":"internal.example.com","a":["10.0.0.1"]}\n'
        '{"host":"evil.com","a":["5.6.7.8"]}\n'
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
        tool_name="dnsx",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1
    assert result.output["records"][0]["host"] == "api.example.com"


def test_dnsx_handles_failure(monkeypatch):
    tool = build_tool()

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="dnsx error",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="dnsx",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert result.error == "dnsx error"


def test_dnsx_handles_timeout(monkeypatch):
    tool = build_tool()

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="dnsx",
            timeout=60,
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="dnsx",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert "timed out" in result.error.lower()