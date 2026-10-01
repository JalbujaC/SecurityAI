from agent.core import SecurityAI
from models.mock import MockModel
from models.schemas import ModelRequest, ModelMessage

def test_model_instantiation():
    model = MockModel()
    assert model is not None


def test_model_implements_generated():
    model = MockModel()
    request = ModelRequest(
        messages=[
            ModelMessage(role="user", content="Test observation for security analysis.")
        ],
        temperature=0.2,
        max_tokens=100,
    )

    response = model.generate(request)
    assert response is not None
    assert response.model == "mock-model"

def test_security_ai_instantiation():
    model = MockModel()
    agent = SecurityAI(model)
    assert agent is not None

def test_security_ai_analyze():
    model = MockModel()
    agent = SecurityAI(model)

    observation = "example.com exposes /api/users/{id}"
    response = agent.analyze(observation)

    assert response is not None
    assert "HYPOTHESIS" in response

def test_securtiy_ai_passes_observation_to_model():
    model = MockModel()
    agent = SecurityAI(model)

    observation = "example.com exposes /api/users/{id}"
    response = agent.analyze(observation)

    assert observation in response