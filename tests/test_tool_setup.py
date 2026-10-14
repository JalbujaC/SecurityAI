import pytest

from scope.schemas import ScopeConfig
from tools.schemas import ToolRequest
from tools.setup import build_tool_registry

def test_registry_contains_subfinder(tmp_path):
    wordlist = tmp_path / "directories.txt"

    wordlist.write_text(
        "admin\napi\nlogin\n",
        encoding="utf-8",
    )
    
    config = ScopeConfig(
        allowed_domains=["example.com"]
    )

    registry = build_tool_registry(config, ffuf_wordlist=str(wordlist))
    tools = registry.list_tools()


    assert "subfinder" in tools
    assert "httpx" in tools
    assert "katana" in tools
    assert "dnsx" in tools
    assert "nuclei" in tools
    assert "ffuf" in tools
    assert "naabu" in tools
    assert "gau" in tools
    assert "dalfox" in tools
    
def test_registry_blocks_out_of_scope_subfinder_request(tmp_path):
    wordlist = tmp_path / "directories.txt"
    
    wordlist.write_text(
        "admin\napi\nlogin\n", 
        encoding="utf-8",
        )
    
    
    config = ScopeConfig(
        allowed_domains=["example.com"]
    )

    registry = build_tool_registry(config, ffuf_wordlist=str(wordlist))

    request = ToolRequest(
        tool_name="subfinder",
        target="outside-scope.test",
    )

    with pytest.raises(PermissionError):
        registry.execute(request)