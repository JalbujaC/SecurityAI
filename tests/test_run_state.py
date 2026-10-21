from scope.schemas import ScopeConfig
from scope.targets import TargetManager
from scope.validator import ScopeValidator
from storage.run_state import RunStateStore


def test_run_state_restores_targets_and_attempts(
    tmp_path,
):
    scope = ScopeConfig(
        allowed_domains=[
            "example.com"
        ]
    )

    validator = ScopeValidator(
        scope
    )

    manager = TargetManager(
        validator
    )

    manager.add_root(
        "example.com"
    )

    manager.add_discovered(
        "api.example.com",
        source="subfinder",
    )

    manager.mark_attempted(
        "httpx",
        [
            "api.example.com",
        ],
    )

    state_store = RunStateStore(
        path=str(
            tmp_path / "state.json"
        )
    )

    state_store.save(
        manager
    )

    restored = TargetManager(
        validator
    )

    state_store.load(
        restored
    )

    assert (
        "example.com"
        in restored.values()
    )

    assert (
        "api.example.com"
        in restored.values()
    )

    assert restored.was_attempted(
        "httpx",
        "api.example.com",
    )