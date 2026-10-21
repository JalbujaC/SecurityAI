from agent.validation_coordinator import (
    ValidationCoordinator,
)
from storage.finding_store import FindingStore
from storage.findings import FindingRecord
from tools.schemas import ToolResult


class FakeValidationExecutor:
    def __init__(self):
        self.received_plan = None
        self.received_approved = None

    def execute(
        self,
        plan,
        approved=False,
    ):
        self.received_plan = plan
        self.received_approved = approved

        return ToolResult(
            tool_name=plan.tool_name,
            target=plan.target,
            success=True,
            output={
                "validated": True
            }, 
        )


def test_validation_moves_hypothesis_to_needs_validation():
    store = FindingStore()

    store.add(
        FindingRecord(
            finding_id="abc123",
            title="Possible issue",
            target="example.com",
            vulnerability_class="unclassified",
            status="hypothesis",
        )
    )

    executor = FakeValidationExecutor()

    coordinator = ValidationCoordinator(
        finding_store=store,
        executor=executor,
    )

    result = coordinator.validate(
        finding_id="abc123",
        available_tools=[
            "nuclei"
        ],
    )

    assert result is not None

    assert (
        store.get(
            "abc123"
        ).status
        == "validated"
    )


def test_validation_returns_none_without_tool():
    store = FindingStore()

    store.add(
        FindingRecord(
            finding_id="abc123",
            title="Possible issue",
            target="example.com",
            vulnerability_class="unclassified",
            status="hypothesis",
        )
    )

    executor = FakeValidationExecutor()

    coordinator = ValidationCoordinator(
        finding_store=store,
        executor=executor,
    )

    result = coordinator.validate(
        finding_id="abc123",
        available_tools=[],
    )

    assert result is None

def test_inconclusive_validation_remains_needs_validation():
    store = FindingStore()

    store.add(
        FindingRecord(
            finding_id="abc123",
            title="Possible issue",
            target="example.com",
            vulnerability_class="unclassified",
            status="hypothesis",
        )
    )

    class InconclusiveExecutor:
        def execute(
            self,
            plan,
            approved=False,
        ):
            return ToolResult(
                tool_name=plan.tool_name,
                target=plan.target,
                success=True,
                output={
                    "findings": []
                },
            )

    coordinator = ValidationCoordinator(
        finding_store=store,
        executor=InconclusiveExecutor(),
    )

    result = coordinator.validate(
        finding_id="abc123",
        available_tools=[
            "nuclei"
        ],
    )

    assert result is not None

    assert (
        store.get(
            "abc123"
        ).status
        == "needs_validation"
    )


def test_negative_validation_rejects_finding():
    store = FindingStore()

    store.add(
        FindingRecord(
            finding_id="abc123",
            title="Possible issue",
            target="example.com",
            vulnerability_class="unclassified",
            status="hypothesis",
        )
    )

    class NegativeExecutor:
        def execute(
            self,
            plan,
            approved=False,
        ):
            return ToolResult(
                tool_name=plan.tool_name,
                target=plan.target,
                success=True,
                output={
                    "validated": False
                },
            )

    coordinator = ValidationCoordinator(
        finding_store=store,
        executor=NegativeExecutor(),
    )

    coordinator.validate(
        finding_id="abc123",
        available_tools=[
            "nuclei"
        ],
    )

    assert (
        store.get(
            "abc123"
        ).status
        == "rejected"
    )

def test_validation_stops_after_max_attempts():
    store = FindingStore()

    store.add(
        FindingRecord(
            finding_id="abc123",
            title="Possible issue",
            target="example.com",
            vulnerability_class="unclassified",
            status="hypothesis",
        )
    )

    class FailingExecutor:
        def __init__(self):
            self.calls = 0

        def execute(
            self,
            plan,
            approved=False,
        ):
            self.calls += 1

            return ToolResult(
                tool_name=plan.tool_name,
                target=plan.target,
                success=False,
                output=None,
                error="timeout",
            )

    executor = FailingExecutor()

    coordinator = ValidationCoordinator(
        finding_store=store,
        executor=executor,
    )

    coordinator.validate(
        finding_id="abc123",
        available_tools=[
            "nuclei"
        ],
    )

    coordinator.validate(
        finding_id="abc123",
        available_tools=[
            "nuclei"
        ],
    )

    result = coordinator.validate(
        finding_id="abc123",
        available_tools=[
            "nuclei"
        ],
    )

    assert result is None

    assert executor.calls == 2