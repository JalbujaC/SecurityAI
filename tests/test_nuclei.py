import subprocess

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.nuclei import NucleiTool
from tools.schemas import ToolRequest


def build_tool():
    config = ScopeConfig(
        allowed_domains=["example.com"],
        excluded_domains=["internal.example.com"],
    )

    validator = ScopeValidator(config)

    return NucleiTool(
        scope_validator=validator
    )


def test_nuclei_parses_findings(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"template-id":"missing-security-headers",'
        '"type":"http",'
        '"matched-at":"https://example.com",'
        '"matcher-name":"headers",'
        '"info":{"name":"Missing Security Headers","severity":"low"}}\n'
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
        tool_name="nuclei",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1

    finding = result.output["findings"][0]

    assert finding["template_id"] == "missing-security-headers"
    assert finding["severity"] == "low"
    assert finding["matched_at"] == "https://example.com"


def test_nuclei_filters_out_of_scope_findings(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"template-id":"test-1",'
        '"matched-at":"https://example.com",'
        '"info":{"name":"Test","severity":"low"}}\n'
        '{"template-id":"test-2",'
        '"matched-at":"https://evil.com",'
        '"info":{"name":"Test","severity":"low"}}\n'
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
        tool_name="nuclei",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1
    assert result.output["findings"][0]["matched_at"] == "https://example.com"


def test_nuclei_handles_failure(monkeypatch):
    tool = build_tool()

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="nuclei error",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="nuclei",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert result.error == "nuclei error"


def test_nuclei_handles_timeout(monkeypatch):
    tool = build_tool()

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="nuclei",
            timeout=180,
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="nuclei",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert "timed out" in result.error.lower()