from models.clients import ModelClient
from models.schemas import ModelRequest, ModelMessage

class SecurityAI:
    """
    SecurityAI implementation of the ModelClient interface for security analysis.

    This model is intentionally unaware of the underlying model implementation.
    """

    def __init__(self, model: ModelClient):
        self.model = model

    def analyze(self, observation: str) -> str:

        messages = [
            ModelMessage(role="system", content=(
                    "You are BountyAI, an AI assistant for authorized "
                    "bug bounty research. Analyze observations conservatively. "
                    "Treat scanner output as evidence rather than confirmed "
                    "vulnerabilities. Never assume a vulnerability is proven "
                    "without sufficient evidence."
            )),
            ModelMessage(role="user", content=observation)
        ]

        request = ModelRequest(messages=messages, temperature=0.2, max_tokens=1024)
        response = self.model.generate(request)

        return response.content