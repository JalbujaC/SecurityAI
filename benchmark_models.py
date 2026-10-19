import time

from models.ollama import OllamaClient
from models.schemas import (
    ModelMessage,
    ModelRequest,
)


MODELS = [
    "qwen3:4b",
    "qwen3:8b",
]


def benchmark_model(
    model_name: str,
):
    model = OllamaClient(
        model_name=model_name,
        timeout=300,
    )

    request = ModelRequest(
        messages=[
            ModelMessage(
                role="system",
                content=(
                    "You are a cybersecurity planning assistant. "
                    "Return only valid JSON."
                ),
            ),
            ModelMessage(
                role="user",
                content=(
                    "An authorized web target responds with HTTP 302, "
                    "uses Cloudflare, and exposes ports 80, 443, and 8443. "
                    "Choose the safest logical next reconnaissance step. "
                    "Return JSON with keys action, reasoning, and tool."
                ),
            ),
        ],
        temperature=0.1,
        max_tokens=500,
    )

    start = time.perf_counter()

    response = model.generate(
        request
    )

    elapsed = time.perf_counter() - start

    print()
    print("=" * 60)
    print(f"MODEL: {model_name}")
    print("=" * 60)

    print(
        f"Elapsed: {elapsed:.2f} seconds"
    )

    print()
    print("Response:")
    print(response.content)

    if response.raw:
        print()

        prompt_tokens = response.raw.get(
            "prompt_eval_count"
        )

        generated_tokens = response.raw.get(
            "eval_count"
        )

        eval_duration = response.raw.get(
            "eval_duration"
        )

        print(
            f"Prompt tokens: {prompt_tokens}"
        )

        print(
            f"Generated tokens: {generated_tokens}"
        )

        if (
            generated_tokens
            and eval_duration
        ):
            seconds = (
                eval_duration
                / 1_000_000_000
            )

            if seconds > 0:
                tokens_per_second = (
                    generated_tokens
                    / seconds
                )

                print(
                    "Generation speed: "
                    f"{tokens_per_second:.2f} tok/s"
                )


def main():
    for model_name in MODELS:
        try:
            benchmark_model(
                model_name
            )

        except Exception as exc:
            print()
            print(
                f"{model_name} FAILED: {exc}"
            )


if __name__ == "__main__":
    main()