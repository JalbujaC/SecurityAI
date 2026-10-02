from unittest import result

from agent.core import SecurityAI
from models.mock import MockModel
from models.schemas import ModelRequest, ModelMessage, AnalysisResult

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

    observation = "example.com exposes /api/users/{id}"
    result = agent.analyze(observation)
    
def test_security_ai_analyze():
    model = MockModel()
    agent = SecurityAI(model)

    observation = "example.com exposes /api/users/{id}"

    result = agent.analyze(observation)

    assert isinstance(result, AnalysisResult)
    assert result.status == "HYPOTHESIS"
    assert result.summary

def test_securtiy_ai_passes_observation_to_model():
    model = MockModel()
    agent = SecurityAI(model)

    observation = "example.com exposes /api/users/{id}"
    result = agent.analyze(observation)

    assert observation in result.evidence

def test_analysis_confidence_is_valid():
    model = MockModel()
    agent = SecurityAI(model)

    result = agent.analyze("example.com exposes /admin")
    assert 0.0 <= result.confidence <= 1.0

def test_analysis_Result_contains_lists():
    model = MockModel()
    agent = SecurityAI(model)

    result = agent.analyze("example.com exposes /admin")
    assert isinstance(result.evidence, list)
    assert isinstance(result.hypotheses, list)