import json

from models.clients import ModelClient
from models.schemas import ModelRequest, ModelResponse

class MockModel(ModelClient):
    """
    Mock implementation of the ModelClient interface for testing purposes.
    """

    def generate(self, request: ModelRequest) -> ModelResponse:
        user_message = request.messages[-1].content

        data = {
            "status": "HYPOTHESIS",
            "summary": "Observation requires further analysis.",
            "confidence": 0.25,
            "evidence": [user_message],
            "hypothesis": ["Further authorized verification may be warranted."],
            "recommended_next_step": ("Review the ovservation within the authorized scope."),
        }

        return ModelResponse(
            content=json.dumps(data),
            model="mock-model",
        )