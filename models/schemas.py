from typing import Any
from dataclasses import dataclass, field

from analysis import hypotheses

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



   