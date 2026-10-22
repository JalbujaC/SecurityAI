import json
import subprocess

import pytest

from agent.planner import AgentPlanner
from agent.validation_result import ValidationResultInterpreter
from models.schemas import ModelResponse
from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator
from tools.dnsx import DnsxTool
from tools.registry import ToolRegistry
from tools.schemas import ToolRequest, ToolResult


class DummyModel:
    def __init__(self):
        self.calls = 0

    def generate(self, request):
        self.calls += 1
        content = '{"summary": "wrong schema"}' if self.calls == 1 else json.dumps({
            'action': 'RUN_TOOL', 'reasoning': 'Need HTTP',
            'tool_action': {'tool_name': 'httpx', 'target': 'evil.test', 'arguments': {'bad': 1}}})
        return ModelResponse(model='dummy', content=content)


def test_planner_repairs_shape_and_ignores_target():
    model = DummyModel()
    decision = AgentPlanner(model).decide('Observe', ['httpx'], target_map={'httpx': ['example.com']})
    assert model.calls == 2
    assert decision.tool_action.target == 'example.com'
    assert decision.tool_action.arguments == {}


def test_registry_rejects_out_of_scope_batch():
    validator = ScopeValidator(ScopeConfig(allowed_domains=['example.com']))
    registry = ToolRegistry(validator)
    with pytest.raises(PermissionError):
        registry.execute(ToolRequest(tool_name='httpx', target='example.com',
                                     targets=['other.test']))


def test_dnsx_uses_host_stdin_not_bruteforce(monkeypatch):
    validator = ScopeValidator(ScopeConfig(allowed_domains=['example.com']))
    captured = {}
    def fake_run(command, **kwargs):
        captured.update(command=command, kwargs=kwargs)
        return subprocess.CompletedProcess(command, 0,
                    stdout='{"host":"example.com","a":["127.0.0.1"]}\n', stderr='')
    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = DnsxTool(validator).run(ToolRequest(tool_name='dnsx', target='example.com'))
    assert '-d' not in captured['command']
    assert captured['kwargs']['input'] == 'example.com\n'
    assert result.output['count'] == 1


def test_scanner_match_is_not_confirmed_vulnerability():
    result = ToolResult(tool_name='nuclei', target='example.com', success=True,
                        output={'findings': [{'template_id': 'test'}]})
    assert ValidationResultInterpreter.interpret(result) == 'inconclusive'
