from agent.retry_policy import RetryPolicy


def test_retry_policy_allows_two_attempts():
    policy = RetryPolicy(
        max_attempts=2
    )

    assert policy.can_retry(
        "gau",
        "example.com",
    )

    policy.record_attempt(
        "gau",
        "example.com",
    )

    assert policy.can_retry(
        "gau",
        "example.com",
    )

    policy.record_attempt(
        "gau",
        "example.com",
    )

    assert not policy.can_retry(
        "gau",
        "example.com",
    )


def test_retry_state_is_per_tool_and_target():
    policy = RetryPolicy(
        max_attempts=2
    )

    policy.record_attempt(
        "gau",
        "example.com",
    )

    assert (
        policy.attempts_for(
            "gau",
            "example.com",
        )
        == 1
    )

    assert (
        policy.attempts_for(
            "nuclei",
            "example.com",
        )
        == 0
    )

    assert (
        policy.attempts_for(
            "gau",
            "api.example.com",
        )
        == 0
    )