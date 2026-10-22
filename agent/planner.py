import json

from models.clients import ModelClient
from models.schemas import AgentDecision, ModelMessage, ModelRequest, ToolAction


class AgentPlanner:
    """LLM selects a registered tool; target binding remains deterministic."""

    def __init__(self, model: ModelClient):
        self.model = model

    def decide(self, observation: str, available_tools: list[str], evidence: list[str] | None = None,
               target_map: dict[str, list[str]] | None = None) -> AgentDecision:
        target_map = target_map or {}
        executable = {
            name: targets for name, targets in target_map.items()
            if name in available_tools and targets
        }
        tools_text = '\n'.join(f'- {name}: {len(targets)} eligible target(s)'
                               for name, targets in sorted(executable.items())) or 'None'
        # No huge lists of subdomains or model-selected targets.
        context = '\n'.join(str(item)[:1800] for item in (evidence or [])[-8:])[:9000]
        messages = [
            ModelMessage(role='system', content=(
                'You are the SecurityAI planner. You do not execute commands. '
                'Choose one of RUN_TOOL, ANALYZE or STOP. Available tools with targets:\n'
                f'{tools_text}\n'
                'For RUN_TOOL choose ONLY a tool listed above. The runtime selects its target. '
                'Set tool_action.target to an empty string and arguments to {}. '
                'Never invent tools or targets. Do not claim vulnerabilities from reconnaissance alone. '
                'Avoid repeating tool actions with no new evidence. '
                'Return ONLY JSON: {"action":"RUN_TOOL","reasoning":"...",'
                '"tool_action":{"tool_name":"...","target":"","arguments":{},"reason":"..."}}. '
                'For ANALYZE or STOP set tool_action to null. '
                'Choose ANALYZE only when there is concrete observed security-relevant behavior; '
                'choose STOP if no useful authorized next action remains.'
            )),
            ModelMessage(role='user', content=f'Objective: {observation}\nRecent evidence:\n{context or "None"}')
        ]
        result = None
        problem = ''
        for attempt in range(2):
            attempt_messages = list(messages)
            if attempt:
                attempt_messages.append(ModelMessage(
                    role='user', content=(
                        f'Your previous planner output was invalid: {problem}. '
                        'Return one valid JSON object with action RUN_TOOL, ANALYZE or STOP. '
                        'A RUN_TOOL must select an available tool with eligible targets. '
                        'No commands or model-selected target.'
                    )
                ))
            response = self.model.generate(ModelRequest(
                messages=attempt_messages, temperature=0.1 if not attempt else 0.0,
                max_tokens=600 if not attempt else 350))
            try:
                parsed = json.loads(response.content)
                result = self._parse_decision(parsed, executable)
                break
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                problem = str(exc)[:350]
        if result is None:
            # Fail closed, without executing a guessed tool or crashing the run.
            return AgentDecision(action='STOP', reasoning=f'Planner invalid after repair: {problem}', tool_action=None)
        return result

    def _parse_decision(self, data: dict, target_map: dict[str, list[str]]) -> AgentDecision:
        if not isinstance(data, dict):
            raise ValueError('Planner must return an object')
        action = data.get('action')
        if action not in {'RUN_TOOL', 'ANALYZE', 'STOP'}:
            raise ValueError(f'Invalid agent action: {action}')
        reasoning = str(data.get('reasoning') or '')[:800]
        tool_data = data.get('tool_action')
        if action != 'RUN_TOOL':
            if tool_data is not None:
                raise ValueError(f'{action} must not include tool_action')
            return AgentDecision(action=action, reasoning=reasoning, tool_action=None)
        if not isinstance(tool_data, dict):
            raise ValueError('RUN_TOOL requires tool_action')
        tool_name = tool_data.get('tool_name')
        eligible = target_map.get(tool_name, [])
        if not eligible:
            raise ValueError(f'No eligible targets available for tool: {tool_name}')
        return AgentDecision(
            action='RUN_TOOL', reasoning=reasoning,
            tool_action=ToolAction(
                tool_name=tool_name, target=eligible[0], arguments={},
                reason=str(tool_data.get('reason') or '')[:500], approved=False))
