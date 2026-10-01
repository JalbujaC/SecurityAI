from models.clients import ModelClient
from models.schemas import ModelRequest, ModelResponse

class MockModel(ModelClient):
    """
    Mock implementation of the ModelClient interface for testing purposes.
    """

    def generate(self, request: ModelRequest) -> ModelResponse:
        user_message = request.messages[-1].content

        response = (
            "This is an observation requiring further authorization analysis.\n\n"
            f"Observation received: {user_message}\n\n"
            "Status: HYPOTHESIS"
        )

        return ModelResponse(
            content=response,
            model="mock-model",
        )