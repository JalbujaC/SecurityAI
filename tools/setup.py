from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator

from tools import nuclei
from tools.registry import ToolRegistry


from tools.subfinder import SubfinderTool
from tools.httpx import HttpxTool
from tools.katana import KatanaTool
from tools.dnsx import DnsxTool
from tools.nuclei import NucleiTool
from tools.ffuf import FfufTool
from tools.naabu import NaabuTool
from tools.gau import GauTool
from tools.dalfox import DalfoxTool
from tools.nuclei_dast import NucleiDastTool

def build_tool_registry(scope_config: ScopeConfig, ffuf_wordlist: str) -> ToolRegistry:
    validator = ScopeValidator(scope_config)

    registry = ToolRegistry(
        scope_validator=validator
    )

    registry.register(
        SubfinderTool(
            scope_validator=validator
        )
    )
    registry.register(
        HttpxTool(
            scope_validator=validator
        )
    )
    registry.register(
        KatanaTool(
            scope_validator=validator
        )
    )
    registry.register(
        DnsxTool(
            scope_validator=validator
        )
    )
    registry.register(
        NucleiTool(
            scope_validator=validator
        )
    )
    registry.register(
        FfufTool(
            scope_validator=validator,
            wordlist=ffuf_wordlist
        )
    )
    registry.register(
        NaabuTool(
            scope_validator=validator
        )
    )
    registry.register(
        GauTool(
            scope_validator=validator
        )
    )
    registry.register(
        DalfoxTool(
            scope_validator=validator
        )
    )
    registry.register(
        NucleiDastTool(
            scope_validator=validator
        )
    )
    return registry