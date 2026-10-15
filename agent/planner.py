import json

from models.clients import ModelClient
from models.schemas import (
    AgentDecision,
    ModelMessage,
    ModelRequest,
    ToolAction
)

class AgentPlanner:
    def __init__(self, model: ModelClient):
        self.model = model

    def decide(self, observation: str, available_tools: list[str], evidence: list[str] | None = None, allowed_targets: list[str] | None = None) -> AgentDecision:

        tools_text = ", ".join(sorted(available_tools))

        evidence = evidence or []
        allowed_targets = allowed_targets or []
        evidence_text = "\n".join(
            f"- {item}"
            for item in evidence
        )

        targets_text = ", ".join(allowed_targets)
        messages = [
            ModelMessage(
                role="system",
                content=(
                    "You are the planning component of SecurityAI, an assistant "
                    "for authorized bug bounty research.\n\n"
                    "You may only propose tools from this list:\n"
                    f"{tools_text}\n\n"
                    "You may ONLY select a target exactly as written in this list:\n"
                    f"{targets_text}\n\n"

                    "Do not modify, abbreviate, reconstruct, or invent target names. "
                    "Copy the selected target exactly.\n\n"
                    "You do NOT execute tools. You only propose the next action.\n"
                    "Return ONLY valid JSON. No markdown or commentary.\n\n"
                    "Allowed actions:\n"
                    '- "RUN_TOOL": gather additional evidence with one registered tool.\n'
                    '- "ANALYZE": use ONLY when enough evidence exists to hand off to the '
                    'vulnerability-analysis stage. Do not use ANALYZE merely to reason about '
                    'which reconnaissance step should happen next.\n'
                    '- "STOP": use only when no useful or justified next action remains.\n\n'

                    "If reconnaissance is incomplete and another registered tool can materially "
                    "improve coverage, choose RUN_TOOL.\n"
                    "{\n"
                    '  "action": "RUN_TOOL",\n'
                    '  "reasoning": "short reason",\n'
                    '  "tool_action": {\n'
                    '    "tool_name": "registered tool name",\n'
                    '    "target": "target",\n'
                    '    "arguments": {},\n'
                    '    "reason": "why this tool is useful"\n'
                    "  }\n"
                    "}\n\n"
                    "Examples:\n"
                    "- Open ports discovered but HTTP services not characterized -> RUN_TOOL httpx.\n"
                    "- Subdomains discovered but not resolved/probed -> RUN_TOOL dnsx or httpx.\n"
                    "- Live web service discovered but endpoints unknown -> RUN_TOOL katana or gau.\n"
                    "- Evidence already supports a concrete security hypothesis -> ANALYZE.\n\n"
                    "For ANALYZE or STOP, tool_action must be null.\n"
                    "Never invent shell commands or unregistered tools."
                    "Evidence may contain summarized results from previous tools. "
                    "Do not reproduce or restate the evidence in your response. "
                    "Use it only to decide the next action.\n\n"

                    "Your response object MUST contain the top-level key 'action'. "
                    "Never return a tool result or evidence object as your response.\n\n"
                ),
            ),
            ModelMessage(
                role="user",
                content=(
                    f"Original observation:\n{observation}\n\n"
                    f"Evidence collected so far:\n"
                    f"{evidence_text if evidence_text else 'None'}"
                )
            ),
        ]

        request = ModelRequest(
            messages=messages,
            temperature=0.1,
            max_tokens=800
        )

        response = self.model.generate(request)

        try:
            data = json.loads(response.content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Model returned invalid decision JSON: {response.content}") from exc

        return self._parse_decision(data, allowed_targets)
    
    def _parse_decision(self, data: dict, allowed_targets: list[str]) -> AgentDecision:
        action = data.get("action")

        if action not in {"RUN_TOOL", "ANALYZE", "STOP"}:
            raise ValueError(f"Invalid agent action: {action}")

        reasoning = data.get("reasoning", "")

        tool_data = data.get("tool_action")

        if action == "RUN_TOOL":
            if not isinstance(tool_data, dict):
                raise ValueError(
                    "RUN_TOOL requires tool_action."
                )

            model_target = tool_data.get("target", "")

            if len(allowed_targets) == 1:
                selected_target = allowed_targets[0]

            elif allowed_targets:
                if model_target not in allowed_targets:
                    raise ValueError(
                        f"Model proposed invalid target: {model_target}"
                    )

                selected_target = model_target

            else:
                selected_target = model_target


            tool_action = ToolAction(
                tool_name=tool_data.get("tool_name", ""),
                target=selected_target,
                arguments=tool_data.get("arguments", {}),
                reason=tool_data.get("reason", ""),
            )

        else:
            if tool_data is not None:
                raise ValueError(
                    f"{action} must not include tool_action."
                )

            tool_action = None
        return AgentDecision(
            action=action,
            reasoning=reasoning,
            tool_action=tool_action
        )