from typing import Any
from dataclasses import dataclass

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

   