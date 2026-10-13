import subprocess

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.ffuf import FfufTool
from tools.schemas import ToolRequest


def build_tool(tmp_path):
    wordlist = tmp_path / "directories.txt"

    wordlist.write_text(
        "admin\napi\nlogin\n",
        encoding="utf-8",
    )

    config = ScopeConfig(
        allowed_domains=["example.com"],
        excluded_domains=["internal.example.com"],
    )

    validator = ScopeValidator(config)

    return FfufTool(
        scope_validator=validator,
        wordlist=str(wordlist),
    )


def test_ffuf_parses_findings(monkeypatch, tmp_path):
    tool = build_tool(tmp_path)

    fake_stdout = (
        '{"url":"https://example.com/admin",'
        '"status":200,'
        '"length":1024,'
        '"words":50,'
        '"lines":20,'
        '"input":{"FUZZ":"admin"}}\n'
        '{"url":"https://example.com/api",'
        '"status":301,'
        '"length":0,'
        '"words":0,'
        '"lines":0,'
        '"redirectlocation":"/api/",'
        '"input":{"FUZZ":"api"}}\n'
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
        tool_name="ffuf",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 2

    first = result.output["findings"][0]

    assert first["url"] == "https://example.com/admin"
    assert first["status"] == 200
    assert first["input"]["FUZZ"] == "admin"


def test_ffuf_filters_out_of_scope_results(monkeypatch, tmp_path):
    tool = build_tool(tmp_path)

    fake_stdout = (
        '{"url":"https://example.com/admin","status":200}\n'
        '{"url":"https://evil.com/admin","status":200}\n'
        '{"url":"https://internal.example.com/admin","status":200}\n'
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
        tool_name="ffuf",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is True
    assert result.output["count"] == 1
    assert result.output["findings"][0]["url"] == (
        "https://example.com/admin"
    )


def test_ffuf_handles_missing_wordlist(tmp_path):
    config = ScopeConfig(
        allowed_domains=["example.com"]
    )

    validator = ScopeValidator(config)

    tool = FfufTool(
        scope_validator=validator,
        wordlist=str(tmp_path / "missing.txt"),
    )

    request = ToolRequest(
        tool_name="ffuf",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert "wordlist not found" in result.error.lower()


def test_ffuf_handles_failure(monkeypatch, tmp_path):
    tool = build_tool(tmp_path)

    fake_process = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="",
        stderr="ffuf error",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: fake_process,
    )

    request = ToolRequest(
        tool_name="ffuf",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert result.error == "ffuf error"


def test_ffuf_handles_timeout(monkeypatch, tmp_path):
    tool = build_tool(tmp_path)

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="ffuf",
            timeout=90,
        )

    monkeypatch.setattr(
        subprocess,
        "run",
        fake_run,
    )

    request = ToolRequest(
        tool_name="ffuf",
        target="https://example.com",
    )

    result = tool.run(request)

    assert result.success is False
    assert "timed out" in result.error.lower()