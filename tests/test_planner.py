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
        target_map={
            "subfinder": ["example.com"],
            "dnsx": ["example.com"],
            "httpx": ["example.com"],
        },
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
        target_map={
            "httpx": ["example.com"],
        },
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
        target_map={
            "subfinder": ["example.com"],
        },
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
            target_map={
                "subfinder": ["example.com"],
            },
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
            target_map={
                "subfinder": ["example.com"],
            },
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
            target_map={
                "subfinder": ["example.com"],
            },
        )


def test_single_eligible_target_is_bound_deterministically():
    model = DecisionModel(
        {
            "action": "RUN_TOOL",
            "reasoning": "Probe target.",
            "tool_action": {
                "tool_name": "httpx",
                "target": "www.wrong:com",
                "arguments": {},
                "reason": "Probe HTTP.",
            },
        }
    )

    planner = AgentPlanner(model)

    decision = planner.decide(
        observation="Test deterministic target binding.",
        available_tools=["httpx"],
        target_map={
            "httpx": [
                "www.example.com",
            ]
        },
    )

    assert decision.tool_action is not None
    assert (
        decision.tool_action.target
        == "www.example.com"
    )


def test_multiple_targets_reject_invalid_model_target():
    model = DecisionModel(
        {
            "action": "RUN_TOOL",
            "reasoning": "Probe target.",
            "tool_action": {
                "tool_name": "httpx",
                "target": "evil.com",
                "arguments": {},
                "reason": "Probe HTTP.",
            },
        }
    )

    planner = AgentPlanner(model)

    with pytest.raises(
        ValueError,
        match="Model proposed invalid target",
    ):
        planner.decide(
            observation="Test target validation.",
            available_tools=["httpx"],
            target_map={
                "httpx": [
                    "example.com",
                    "api.example.com",
                ]
            },
        )


def test_tool_cannot_use_target_from_another_tools_pool():
    model = DecisionModel(
        {
            "action": "RUN_TOOL",
            "reasoning": "Crawl application.",
            "tool_action": {
                "tool_name": "katana",
                "target": "example.com",
                "arguments": {},
                "reason": "Discover endpoints.",
            },
        }
    )

    planner = AgentPlanner(model)

    with pytest.raises(
        ValueError,
        match="Model proposed invalid target",
    ):
        planner.decide(
            observation="Test tool target pairing.",
            available_tools=[
                "subfinder",
                "katana",
            ],
            target_map={
                "subfinder": [
                    "example.com",
                ],
                "katana": [
                    "https://example.com",
                    "https://api.example.com",
                ],
            },
        )


def test_tool_without_eligible_targets_is_rejected():
    model = DecisionModel(
        {
            "action": "RUN_TOOL",
            "reasoning": "Crawl target.",
            "tool_action": {
                "tool_name": "katana",
                "target": "https://example.com",
                "arguments": {},
                "reason": "Discover endpoints.",
            },
        }
    )

    planner = AgentPlanner(model)

    with pytest.raises(
        ValueError,
        match="No eligible targets available",
    ):
        planner.decide(
            observation="Test unavailable target type.",
            available_tools=["katana"],
            target_map={
                "katana": [],
            },
        )