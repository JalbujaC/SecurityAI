import subprocess

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.nuclei_dast import NucleiDastTool
from tools.schemas import ToolRequest


def build_tool():
    config = ScopeConfig(
        allowed_domains=["example.com"],
        excluded_domains=["internal.example.com"],
    )

    validator = ScopeValidator(config)

    return NucleiDastTool(
        scope_validator=validator
    )


def test_nuclei_dast_parses_findings(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"template-id":"dast-example",'
        '"matched-at":"https://example.com/search?q=test",'
        '"type":"http",'
        '"matcher-name":"body",'
        '"info":{"name":"DAST Finding","severity":"medium"}}\n'
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
        tool_name="nuclei_dast",
        target="https://example.com/search?q=test",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1
    assert result.output["findings"][0]["severity"] == "medium"


def test_nuclei_dast_filters_out_of_scope_findings(monkeypatch):
    tool = build_tool()

    fake_stdout = (
        '{"template-id":"one",'
        '"matched-at":"https://example.com/test",'
        '"info":{"name":"Test","severity":"low"}}\n'
        '{"template-id":"two",'
        '"matched-at":"https://evil.com/test",'
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
        tool_name="nuclei_dast",
        target="https://example.com/test",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1


def test_nuclei_dast_uses_safe_flags(monkeypatch):
    tool = build_tool()

    captured_command = []

    def fake_run(command, **kwargs):
        captured_command.extend(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="nuclei_dast",
        target="https://example.com/search",
    )

    result = tool.run(request)

    assert result.success is True
    assert "-dast" in captured_command
    assert "-fuzz-aggression" in captured_command
    assert "low" in captured_command
    assert "-fuzz-scope" in captured_command
    assert "-no-interactsh" in captured_command


def test_nuclei_dast_requires_full_url():
    tool = build_tool()

    request = ToolRequest(
        tool_name="nuclei_dast",
        target="example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert "full url" in result.error.lower()


def test_nuclei_dast_handles_failure(monkeypatch):
    tool = build_tool()

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="nuclei dast error",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="nuclei_dast",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert result.error == "nuclei dast error"


def test_nuclei_dast_handles_timeout(monkeypatch):
    tool = build_tool()

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="nuclei",
            timeout=240,
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="nuclei_dast",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert "timed out" in result.error.lower()