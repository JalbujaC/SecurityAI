from agent.core import SecurityAI
from models.mock import MockModel

def main():
    model = MockModel()
    agent = SecurityAI(model)

    print()
    print("[SECURITY AI] Starting SecurityAI...")

    print("[SECURITY AI] Initializing {model.__class__.__name__}...")
    print()

    observation = "example.com exposes /api/users/{id}"

    print("User:")
    print(observation)
    print()

    print("Agent:")

    response = agent.analyze(observation)

    print(response)


if __name__ == "__main__":
    main()


