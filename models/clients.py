from abc import ABC, abstractmethod
from models.schemas import ModelRequest, ModelResponse

class ModelClient(ABC):
    """
    Abstract interface for all AI model backends.

    The agent should depend on this interface rather than
    directly depending on Ollama, Qwen, llama.cpp, etc.
    """

    @abstractmethod
    def generate(self, request: ModelRequest) -> ModelResponse:
        """
        Generate a response from the model based on the given request.

        Args:
            request (ModelRequest): The request containing messages and parameters.
        """

        raise NotImplementedError
    