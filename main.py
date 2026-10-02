from agent.core import SecurityAI
from models.ollama import OllamaClient

def main():
    model = OllamaClient(model_name="qwen3:4b")
    agent = SecurityAI(model)

    print()
    print("[SECURITY AI] Starting SecurityAI...")

    print(f"[SECURITY AI] Initializing {model.model_name}...")
    print()

    observation = "example.com exposes /api/users/{id}"

    print("User:")
    print(observation)
    print()

    print("Agent:")

    result = agent.analyze(observation)

    print(f"Status: {result.status}")
    print(f"Confidence: {result.confidence:.2f}")
    print()
    print(f"Summary: {result.summary}")
    print()
    print("Evidence:")
    for item in result.evidence:
        print(f" - {item}")

    print()
    print("Hypothese:")
    for item in result.hypotheses:
        print(f" - {item}")
    print()
    print(f"Next step: {result.recommended_next_step}")


if __name__ == "__main__":
    main()


