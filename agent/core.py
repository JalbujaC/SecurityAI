from models.clients import ModelClient
from models.schemas import AnalysisResult, ModelMessage, ModelRequest
import json

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
                    "You are SecurityAI, an AI assistant for authorized "
                    "bug bounty research. Analyze observations conservatively. "
                    "Scanner output and discovered endpoints are evidence, not confirmed vulnerabilities. "
                    "Return ONLY valid JSON. Do not include markdown, code fences, or additional commentary. Never assume a vulnerability is proven "
                    "without sufficient evidence. "
                    "Use this exact structure:\n"
                    "{\n"
                    "status: HYPOTHESIS, \n"
                    "summary: short factual summary \n"
                    "confidence: 0.0, \n"
                    "evidence: [directly observed facts only]"
                    "hypotheses: [possible issues requiring verification]"
                    "recommended_next_Steps: one safe verification step"
                    "}\n\n"
                    "confidence must be between 0.0 and 1.0"
            )),
            ModelMessage(role="user", content=observation)
        ]

        request = ModelRequest(messages=messages, temperature=0.1, max_tokens=1024)
        response = self.model.generate(request)


    
        try:
            data = json.loads(response.content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Model returned invalid JSON: {response.content}") from exc

        confidence = float(data["confidence"])
        if not 0.0 <= confidence <= 1.0:
            raise ValueError(f"Invalid confidence value: {confidence}")

        return AnalysisResult(
            status=data["status"],
            summary=data["summary"],
            confidence=confidence,
            evidence=data.get("evidence", []),
            hypotheses=data.get("hypotheses", []),
            recommended_next_step=data.get("recommended_next_step", ""),
        )