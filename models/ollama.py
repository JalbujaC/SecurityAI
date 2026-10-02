import requests

from models.clients import ModelClient
from models.schemas import ModelRequest, ModelResponse , ModelMessage


class OllamaClient(ModelClient):
    """
    ModelClient implementation for a local Ollama server.
    """

    def __init__(self, model_name: str = "qwen3:4b", base_url: str = "http://localhost:11434", timeout: int = 120):
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout


    def generate(self, request: ModelRequest) -> ModelResponse: 
        messages = [
            {
                "role": message.role,
                "content": message.content,
            }
            for message in request.messages
        ]

        payload = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
            "think": False,
            "format": "json",
            "options": {
                "temperature": request.temperature,
                "num_predict": request.max_tokens,
            },
        }

        response = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout)

        response.raise_for_status()

        data = response.json()

        return ModelResponse(content=data["message"]["content"], model=data["model"], raw=data)

