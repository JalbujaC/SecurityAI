from typing import Any
from dataclasses import dataclass, field


@dataclass 
class ModelMessage:
    role: str
    content: str

@dataclass
class ModelRequest:
    messages: list[ModelMessage]
    temperature: float = 0.2
    max_tokens: int = 1024

@dataclass
class ModelResponse:
    content: str
    model: str
    raw: Any = None

@dataclass
class AnalysisResult:
    status: str
    summary: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    recommended_next_step: str = ""

@dataclass
class ToolAction:
    tool_name: str
    target: str
    arguments: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    approved: bool = False

@dataclass
class AgentDecision:
    action: str
    reasoning: str
    tool_action: ToolAction | None = None

@dataclass
class ExecutionRecord:
    step: int
    decision: AgentDecision
    result: Any = None


   