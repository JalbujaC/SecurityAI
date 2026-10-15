import json

import pytest

from agent.planner import AgentPlanner
from models.clients import ModelClient
from models.schemas import ModelRequest, ModelResponse


class DecisionModel(ModelClient):
    def __init__(self, data):
        self.data = data

    def generate(
        self,
        request: ModelRequest,
    ) -> ModelResponse:
        return ModelResponse(
            content=json.dumps(self.data),
            model="decision-test-model",
        )


def test_planner_returns_tool_action():
    model = DecisionModel(
        {
            "action": "RUN_TOOL",
            "reasoning": "Need subdomain discovery.",
            "tool_action": {
                "tool_name": "subfinder",
                "target": "example.com",
                "arguments": {},
                "reason": "Discover subdomains.",
            },
        }
    )

    planner = AgentPlanner(model)

    decision = planner.decide(
        observation="Begin reconnaissance on example.com",
        available_tools=[
            "subfinder",
            "dnsx",
            "httpx",
        ],
    )

    assert decision.action == "RUN_TOOL"
    assert decision.tool_action is not None
    assert decision.tool_action.tool_name == "subfinder"
    assert decision.tool_action.target == "example.com"


def test_planner_can_choose_analyze():
    model = DecisionModel(
        {
            "action": "ANALYZE",
            "reasoning": "Enough evidence is available.",
            "tool_action": None,
        }
    )

    planner = AgentPlanner(model)

    decision = planner.decide(
        observation="Existing evidence is ready for analysis.",
        available_tools=["httpx"],
    )

    assert decision.action == "ANALYZE"
    assert decision.tool_action is None


def test_planner_can_choose_stop():
    model = DecisionModel(
        {
            "action": "STOP",
            "reasoning": "No further action is justified.",
            "tool_action": None,
        }
    )

    planner = AgentPlanner(model)

    decision = planner.decide(
        observation="No additional investigation required.",
        available_tools=["subfinder"],
    )

    assert decision.action == "STOP"
    assert decision.tool_action is None


def test_planner_rejects_invalid_action():
    model = DecisionModel(
        {
            "action": "DELETE_SYSTEM",
            "reasoning": "Invalid action.",
            "tool_action": None,
        }
    )

    planner = AgentPlanner(model)

    with pytest.raises(ValueError):
        planner.decide(
            observation="Test",
            available_tools=["subfinder"],
        )


def test_run_tool_requires_tool_action():
    model = DecisionModel(
        {
            "action": "RUN_TOOL",
            "reasoning": "Run something.",
            "tool_action": None,
        }
    )

    planner = AgentPlanner(model)

    with pytest.raises(ValueError):
        planner.decide(
            observation="Test",
            available_tools=["subfinder"],
        )


def test_analyze_rejects_tool_action():
    model = DecisionModel(
        {
            "action": "ANALYZE",
            "reasoning": "Analyze evidence.",
            "tool_action": {
                "tool_name": "subfinder",
                "target": "example.com",
                "arguments": {},
                "reason": "Should not exist.",
            },
        }
    )

    planner = AgentPlanner(model)

    with pytest.raises(ValueError):
        planner.decide(
            observation="Test",
            available_tools=["subfinder"],
        )