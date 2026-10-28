"""The execution service, the adapters, and the ledger that makes a retry safe.

This is where the phase's central sentence is tested: **only an ``ALLOW`` decision
reaches an adapter.** The service is exercised directly, with a recording adapter, so
"the adapter was called exactly once" is a count rather than an inference — and the
same service is then run against the real repository, so what the ledger records is
asserted about the database.

Three groups:

- **the enforcement point** — refusals, mismatches and failures, with call counts;
- **idempotency** — a replay returns the recorded outcome and does not run again, and a
  key that cannot be reused is refused rather than answered;
- **the reference adapter and the ledger's own constraints** — determinism, the closed
  finding vocabulary, and the ``CHECK``s that make an impossible row unrepresentable.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from actions_fixture import count_executions, purge_executions
from aicore_api.auth.authorization import AuthorizationDecision, DecisionReason
from aicore_api.auth.policy import combine
from aicore_api.core.actions import (
    AGENT_POSTURE_CHECK,
    ActionDefinition,
    ActionRegistry,
    ActionRequest,
    ActionSensitivity,
    ActionTarget,
    ExecutionStatus,
)
from aicore_api.core.assets import AssetStatus, Environment, RiskClassification
from aicore_api.core.execution import (
    ActionExecutionService,
    ExecutionFailedError,
    ExecutionLedger,
    ExecutionRecord,
    ExecutionRefusedError,
    IdempotencyConflictError,
)
from aicore_api.core.executors import (
    DEFAULT_EXECUTORS,
    FINDING_HIGH_RISK,
    FINDING_NEW_REGISTRATION,
    FINDING_PRODUCTION_AUTONOMOUS,
    FINDING_SUSPENDED_ASSET,
    FINDING_UNCLASSIFIED_RISK,
    ActionExecutionError,
    ActionExecutor,
    ActionExecutorRegistry,
    ActionInvocation,
    ActionOutcome,
    AgentRegistryExecutor,
    ExecutorRegistryError,
    PostureAssessment,
)
from aicore_api.core.firewall import FirewallConfigurationError, FirewallOutcome, decide
from aicore_api.core.permissions import Action, Permission, Resource
from aicore_api.core.policy import ConditionField, ContextValue, PolicyDefinition, PolicyEffect
from aicore_api.core.policy_engine import PolicyContext, evaluate_policies
from aicore_api.db.repositories.action_executions import ActionExecutionRepository
from aicore_api.db.tenancy import bind_tenant
from identity_fixture import Identity, IdentityFactory

INVOKED_AT = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


# ── A recording adapter, and a catalogue that reaches it ─────────────────────


class RecordingExecutor(ActionExecutor):
    """An adapter that records what it was given, and can be told to fail.

    The test double lives at the adapter boundary on purpose: it is the one thing in
    the pipeline no assertion should have to work around, so it is injected through the
    service's constructor — the same seam the application uses — rather than by
    patching a module attribute.
    """

    executor_id = "test_recorder"

    def __init__(self, *, failure: str | None = None, explode: bool = False) -> None:
        self.calls: list[ActionInvocation] = []
        self._failure = failure
        self._explode = explode

    def execute(self, invocation: ActionInvocation) -> ActionOutcome:
        self.calls.append(invocation)
        if self._failure is not None:
            raise ActionExecutionError(self._failure)
        if self._explode:
            raise ZeroDivisionError("an adapter bug, not a refusal")
        return ActionOutcome(
            summary=f"{invocation.action_id} recorded the target",
            findings=("recorded",),
            details={"adapter": self.executor_id},
        )


TEST_DEFINITION: ActionDefinition = dataclasses.replace(
    AGENT_POSTURE_CHECK, action_id="agent.test_check", executor_id=RecordingExecutor.executor_id
)
TEST_REGISTRY = ActionRegistry((TEST_DEFINITION,), executor_ids=(RecordingExecutor.executor_id,))


@dataclass
class InMemoryLedger:
    """An :class:`ExecutionLedger` in a dictionary.

    Exists so the service's bookkeeping can be exercised without a database, and so the
    counts below are about the service rather than about a transaction.
    """

    organization_id: uuid.UUID
    records: dict[str, ExecutionRecord] = field(default_factory=dict)

    def find_by_key(self, idempotency_key: str) -> ExecutionRecord | None:
        return self.records.get(idempotency_key)

    def reserve(
        self,
        *,
        idempotency_key: str,
        action_id: str,
        target_id: uuid.UUID,
        request_fingerprint: str,
    ) -> ExecutionRecord:
        if idempotency_key in self.records:
            raise IdempotencyConflictError("this idempotency key is already reserved")
        record = ExecutionRecord(
            id=uuid.uuid4(),
            organization_id=self.organization_id,
            idempotency_key=idempotency_key,
            action_id=action_id,
            target_id=target_id,
            request_fingerprint=request_fingerprint,
            status=ExecutionStatus.RESERVED,
            outcome=None,
            error_code=None,
            created_at=INVOKED_AT,
            completed_at=None,
        )
        self.records[idempotency_key] = record
        return record

    def record_outcome(
        self,
        record: ExecutionRecord,
        *,
        status: ExecutionStatus,
        outcome: Mapping[str, object] | None,
        error_code: str | None,
        completed_at: datetime,
    ) -> ExecutionRecord:
        updated = dataclasses.replace(
            record,
            status=status,
            outcome=outcome,
            error_code=error_code,
            completed_at=completed_at,
        )
        self.records[record.idempotency_key] = updated
        return updated


def _request(
    organization_id: uuid.UUID,
    *,
    idempotency_key: str = "key-0001",
    target_id: uuid.UUID | None = None,
    arguments: Mapping[str, object] | None = None,
) -> ActionRequest:
    """A validated request for the test action."""
    return ActionRequest.build(
        definition=TEST_DEFINITION,
        organization_id=organization_id,
        principal_id=uuid.uuid4(),
        membership_id=uuid.uuid4(),
        target_id=target_id or uuid.uuid4(),
        environment=Environment.PRODUCTION,
        arguments=dict(arguments or {}),
        correlation_id="execution-test-request",
        idempotency_key=idempotency_key,
    )


def _target(request: ActionRequest) -> ActionTarget:
    return ActionTarget(
        resource=Resource.AGENT,
        identifier=request.target_id,
        facts={ConditionField.ENVIRONMENT: Environment.PRODUCTION.value},
    )


def _decision(
    request: ActionRequest,
    *,
    authorize: bool = True,
    effect: PolicyEffect | None = None,
    target: ActionTarget | None = None,
):
    """A decision produced by the real firewall, from real phase 5 and 6 answers."""
    organization_id = request.organization_id
    authorization = AuthorizationDecision(
        allowed=authorize,
        reason=DecisionReason.ALLOWED if authorize else DecisionReason.MISSING_PERMISSION,
        permission=Permission.ACTION_EXECUTE,
        organization_id=organization_id,
        role_code="owner",
        membership_id=uuid.uuid4(),
    )
    context = PolicyContext(
        organization_id=organization_id,
        resource=Resource.ACTION,
        action=Action.EXECUTE,
        facts={ConditionField.ENVIRONMENT: Environment.PRODUCTION.value},
    )
    definitions = (
        []
        if effect is None
        else [
            PolicyDefinition(
                policy_id=uuid.uuid4(),
                version=1,
                name="Test policy",
                priority=100,
                effect=effect,
                resource=Resource.ACTION,
                action=Action.EXECUTE,
                conditions=(),
            )
        ]
    )
    policy = evaluate_policies(definitions, context, evaluated_at=INVOKED_AT)
    return decide(
        request=request,
        definition=TEST_DEFINITION,
        target=target if target is not None else _target(request),
        authorization=authorization,
        policy=combine(authorization, policy),
    )


def _service(recorder: RecordingExecutor, ledger: ExecutionLedger) -> ActionExecutionService:
    return ActionExecutionService(
        registry=TEST_REGISTRY,
        executors=ActionExecutorRegistry((recorder,)),
        ledger=ledger,
    )


# ── The enforcement point ────────────────────────────────────────────────────


def test_an_allowed_action_is_executed_exactly_once() -> None:
    """CASE A at the service boundary: one decision, one adapter call, one record."""
    organization_id = uuid.uuid4()
    request = _request(organization_id)
    recorder = RecordingExecutor()
    ledger = InMemoryLedger(organization_id)
    service = _service(recorder, ledger)

    result = service.execute(
        decision=_decision(request),
        request=request,
        definition=TEST_DEFINITION,
        target=_target(request),
        invoked_at=INVOKED_AT,
    )

    assert len(recorder.calls) == 1
    assert result.replayed is False
    assert result.adapter == RecordingExecutor.executor_id
    assert result.executed_at == INVOKED_AT
    assert len(result.digest) == 64
    assert result.outcome.findings == ("recorded",)

    # The adapter saw the resolved invocation, and nothing else.
    invocation = recorder.calls[0]
    assert invocation.organization_id == organization_id
    assert invocation.target.identifier == request.target_id
    assert invocation.correlation_id == request.correlation_id
    assert invocation.arguments == request.arguments

    record = ledger.records[request.idempotency_key]
    assert record.status is ExecutionStatus.EXECUTED
    assert record.completed_at == INVOKED_AT
    assert record.outcome is not None
    assert record.error_code is None


@pytest.mark.parametrize("effect", [PolicyEffect.DENY, PolicyEffect.REQUIRE_APPROVAL])
def test_a_decision_that_is_not_an_allow_never_reaches_the_adapter(effect: PolicyEffect) -> None:
    """CASE C and CASE D at the service boundary: refused, and nothing is recorded.

    The service is handed the refusal *deliberately* — a caller that skipped the
    firewall's own refusal — because the property under test is that the service
    refuses on its own account. A decision that is not ``ALLOW`` must not reach an
    adapter even if a future route forgets to check first.
    """
    organization_id = uuid.uuid4()
    request = _request(organization_id)
    recorder = RecordingExecutor()
    ledger = InMemoryLedger(organization_id)
    decision = _decision(request, effect=effect)
    assert decision.outcome is not FirewallOutcome.ALLOW

    with pytest.raises(ExecutionRefusedError) as refusal:
        _service(recorder, ledger).execute(
            decision=decision,
            request=request,
            definition=TEST_DEFINITION,
            target=_target(request),
            invoked_at=INVOKED_AT,
        )

    assert recorder.calls == []
    assert ledger.records == {}
    assert refusal.value.decision is decision


def test_a_phase_five_denial_never_reaches_the_adapter() -> None:
    """CASE B at the service boundary: an authorization denial is not executable."""
    organization_id = uuid.uuid4()
    request = _request(organization_id)
    recorder = RecordingExecutor()
    ledger = InMemoryLedger(organization_id)
    decision = _decision(request, authorize=False)

    with pytest.raises(ExecutionRefusedError):
        _service(recorder, ledger).execute(
            decision=decision,
            request=request,
            definition=TEST_DEFINITION,
            target=_target(request),
            invoked_at=INVOKED_AT,
        )

    assert recorder.calls == []
    assert ledger.records == {}


def test_the_service_refuses_values_that_do_not_describe_one_request() -> None:
    """A mismatch between the decision, the request, the definition and the target.

    Each of these would execute the wrong thing, so none of them is a refusal the
    client could act on — they fail loudly, before any write.
    """
    organization_id = uuid.uuid4()
    request = _request(organization_id)
    recorder = RecordingExecutor()
    ledger = InMemoryLedger(organization_id)
    service = _service(recorder, ledger)
    decision = _decision(request)

    with pytest.raises(FirewallConfigurationError):
        service.execute(
            decision=decision,
            request=_request(uuid.uuid4()),
            definition=TEST_DEFINITION,
            target=_target(request),
            invoked_at=INVOKED_AT,
        )
    with pytest.raises(FirewallConfigurationError):
        service.execute(
            decision=decision,
            request=request,
            definition=dataclasses.replace(TEST_DEFINITION, action_id="agent.elsewhere"),
            target=_target(request),
            invoked_at=INVOKED_AT,
        )
    with pytest.raises(FirewallConfigurationError):
        service.execute(
            decision=decision,
            request=request,
            definition=AGENT_POSTURE_CHECK,
            target=_target(request),
            invoked_at=INVOKED_AT,
        )
    with pytest.raises(FirewallConfigurationError):
        service.execute(
            decision=decision,
            request=request,
            definition=TEST_DEFINITION,
            target=ActionTarget(resource=Resource.AGENT, identifier=uuid.uuid4()),
            invoked_at=INVOKED_AT,
        )

    assert recorder.calls == []
    assert ledger.records == {}


def test_an_adapter_that_fails_is_recorded_and_not_retried_under_the_same_key() -> None:
    """A failure is an outcome, and the key stays claimed.

    The action may have had effects this build cannot see, so "retry the same key"
    must not mean "run it again". The client's way forward is a new key — which is a
    new request, and a new decision.
    """
    organization_id = uuid.uuid4()
    request = _request(organization_id)
    recorder = RecordingExecutor(failure="the target is not in a state this action can read")
    ledger = InMemoryLedger(organization_id)
    service = _service(recorder, ledger)

    with pytest.raises(ExecutionFailedError):
        service.execute(
            decision=_decision(request),
            request=request,
            definition=TEST_DEFINITION,
            target=_target(request),
            invoked_at=INVOKED_AT,
        )

    assert len(recorder.calls) == 1
    record = ledger.records[request.idempotency_key]
    assert record.status is ExecutionStatus.FAILED
    assert record.outcome is None
    assert record.error_code == "execution_failed"

    # The same key now refuses instead of re-running the action.
    with pytest.raises(IdempotencyConflictError):
        service.execute(
            decision=_decision(request),
            request=request,
            definition=TEST_DEFINITION,
            target=_target(request),
            invoked_at=INVOKED_AT,
        )
    assert len(recorder.calls) == 1


def test_an_unexpected_adapter_error_is_recorded_before_it_propagates() -> None:
    """A bug in an adapter stays a 500, and it still cannot be retried into a re-run."""
    organization_id = uuid.uuid4()
    request = _request(organization_id)
    recorder = RecordingExecutor(explode=True)
    ledger = InMemoryLedger(organization_id)
    service = _service(recorder, ledger)

    with pytest.raises(ZeroDivisionError):
        service.execute(
            decision=_decision(request),
            request=request,
            definition=TEST_DEFINITION,
            target=_target(request),
            invoked_at=INVOKED_AT,
        )

    record = ledger.records[request.idempotency_key]
    assert record.status is ExecutionStatus.FAILED
    assert record.error_code == "internal_error"


# ── Idempotency ──────────────────────────────────────────────────────────────


def test_the_same_request_with_the_same_key_is_replayed_and_not_re_run() -> None:
    """The retry case: the answer is the recorded one, and the adapter is not called."""
    organization_id = uuid.uuid4()
    request = _request(organization_id)
    recorder = RecordingExecutor()
    ledger = InMemoryLedger(organization_id)
    service = _service(recorder, ledger)

    first = service.execute(
        decision=_decision(request),
        request=request,
        definition=TEST_DEFINITION,
        target=_target(request),
        invoked_at=INVOKED_AT,
    )
    # The client retries the *same* request: same target, same arguments, same key.
    second = service.execute(
        decision=_decision(request),
        request=request,
        definition=TEST_DEFINITION,
        target=_target(request),
        invoked_at=INVOKED_AT,
    )

    assert len(recorder.calls) == 1
    assert first.replayed is False
    assert second.replayed is True
    assert second.execution_id == first.execution_id
    assert second.outcome.summary == first.outcome.summary
    assert second.outcome.findings == first.outcome.findings
    assert second.digest == first.digest


def test_a_key_reused_for_a_different_request_is_refused() -> None:
    """One key, one request: reusing it for something else is a 409, not an answer."""
    organization_id = uuid.uuid4()
    target_id = uuid.uuid4()
    first_request = _request(organization_id, target_id=target_id, idempotency_key="shared-key")
    other_request = _request(
        organization_id,
        target_id=target_id,
        arguments={"report_detail": "full"},
        idempotency_key="shared-key",
    )
    recorder = RecordingExecutor()
    ledger = InMemoryLedger(organization_id)
    service = _service(recorder, ledger)

    service.execute(
        decision=_decision(first_request),
        request=first_request,
        definition=TEST_DEFINITION,
        target=_target(first_request),
        invoked_at=INVOKED_AT,
    )

    with pytest.raises(IdempotencyConflictError):
        service.execute(
            decision=_decision(other_request),
            request=other_request,
            definition=TEST_DEFINITION,
            target=_target(other_request),
            invoked_at=INVOKED_AT,
        )

    assert len(recorder.calls) == 1


def test_a_reservation_that_never_completed_is_refused_rather_than_re_run() -> None:
    """The crash case: the key was claimed and the action's outcome is unknown."""
    organization_id = uuid.uuid4()
    request = _request(organization_id)
    recorder = RecordingExecutor()
    ledger = InMemoryLedger(organization_id)
    service = _service(recorder, ledger)
    ledger.reserve(
        idempotency_key=request.idempotency_key,
        action_id=request.action_id,
        target_id=request.target_id,
        request_fingerprint=request.fingerprint,
    )

    with pytest.raises(IdempotencyConflictError):
        service.execute(
            decision=_decision(request),
            request=request,
            definition=TEST_DEFINITION,
            target=_target(request),
            invoked_at=INVOKED_AT,
        )

    assert recorder.calls == []


# ── The registries, and the shape of what an adapter receives ────────────────


def test_the_adapter_registry_refuses_an_unknown_executor() -> None:
    """An action whose adapter is missing could be authorized and never run."""
    registry = ActionExecutorRegistry((RecordingExecutor(),))

    with pytest.raises(ExecutorRegistryError) as refusal:
        registry.resolve(dataclasses.replace(TEST_DEFINITION, executor_id="not_registered"))
    assert "not_registered" in str(refusal.value)
    assert registry.get("not_registered") is None


def test_the_adapter_registry_refuses_two_adapters_with_one_identifier() -> None:
    """One identifier reaches exactly one adapter."""
    with pytest.raises(ExecutorRegistryError):
        ActionExecutorRegistry((RecordingExecutor(), RecordingExecutor()))


def test_an_adapter_without_a_usable_identifier_cannot_be_defined() -> None:
    """The identifier is declared by the class, and checked when the class is made."""

    with pytest.raises(ExecutorRegistryError):

        class _Unnamed(ActionExecutor):
            def execute(self, invocation: ActionInvocation) -> ActionOutcome:
                return ActionOutcome(summary="unreachable")

    with pytest.raises(ExecutorRegistryError):

        class _BadlyNamed(ActionExecutor):
            executor_id = "Not.An.Identifier"

            def execute(self, invocation: ActionInvocation) -> ActionOutcome:
                return ActionOutcome(summary="unreachable")


def test_the_service_refuses_to_be_built_on_a_broken_catalogue() -> None:
    """Construction is where a missing adapter is a deployment failure, not a request."""
    with pytest.raises(ExecutorRegistryError):
        ActionExecutionService(
            registry=ActionRegistry(
                (dataclasses.replace(TEST_DEFINITION, executor_id="missing_adapter"),),
                executor_ids=("missing_adapter",),
            ),
            executors=ActionExecutorRegistry((RecordingExecutor(),)),
            ledger=InMemoryLedger(uuid.uuid4()),
        )


def test_an_invocation_carries_no_capability_beyond_its_arguments() -> None:
    """No session, no engine, no credential, no path, no URL: the adapter's whole world.

    Asserted as a field set, because this is the boundary that makes "an adapter cannot
    query another tenant" true by construction rather than by restraint.
    """
    fields = set(ActionInvocation.__dataclass_fields__)
    assert fields == {
        "organization_id",
        "action_id",
        "target",
        "environment",
        "arguments",
        "principal_id",
        "membership_id",
        "agent_id",
        "correlation_id",
        "invoked_at",
    }
    forbidden = {
        "session",
        "db",
        "engine",
        "connection",
        "cursor",
        "token",
        "credential",
        "secret",
        "password",
        "path",
        "file",
        "url",
        "uri",
        "endpoint",
        "host",
        "callback",
        "executor",
        "module",
    }
    assert not fields & forbidden


def test_an_invocation_does_not_render_the_arguments_it_carries() -> None:
    """The repr names the arguments; it never prints their values."""
    organization_id = uuid.uuid4()
    request = _request(organization_id, arguments={"report_detail": "full"})
    invocation = ActionInvocation(
        organization_id=organization_id,
        action_id=request.action_id,
        target=_target(request),
        environment=request.environment,
        arguments=request.arguments,
        principal_id=request.principal_id,
        membership_id=request.membership_id,
        agent_id=None,
        correlation_id=request.correlation_id,
        invoked_at=INVOKED_AT,
    )

    assert invocation.argument_names == ("report_detail",)
    assert invocation.argument_values() == {"report_detail": "full"}
    assert "report_detail" in repr(invocation)
    assert "full" not in repr(invocation)


# ── The reference adapter ────────────────────────────────────────────────────


def _invocation(
    *,
    facts: Mapping[ConditionField, ContextValue],
    action_id: str = AGENT_POSTURE_CHECK.action_id,
    report_detail: str = "summary",
    arguments: object | None = None,
) -> ActionInvocation:
    """An invocation for the reference adapter, over facts a row could attest."""
    target = ActionTarget(
        resource=Resource.AGENT,
        identifier=uuid.uuid4(),
        facts={
            ConditionField.ENVIRONMENT: Environment.PRODUCTION.value,
            **facts,
        },
    )
    parsed = AGENT_POSTURE_CHECK.parse_arguments({"report_detail": report_detail})
    return ActionInvocation(
        organization_id=uuid.uuid4(),
        action_id=action_id,
        target=target,
        environment=Environment.PRODUCTION,
        arguments=parsed if arguments is None else arguments,  # type: ignore[arg-type]
        principal_id=uuid.uuid4(),
        membership_id=uuid.uuid4(),
        agent_id=None,
        correlation_id="reference-adapter-test",
        invoked_at=INVOKED_AT,
    )


def test_the_reference_adapter_is_deterministic() -> None:
    """The same facts always produce the same outcome, findings, details and verdict."""
    facts = {
        ConditionField.RISK_CLASSIFICATION: RiskClassification.HIGH.value,
        ConditionField.RESOURCE_STATUS: AssetStatus.ACTIVE.value,
        ConditionField.AGENT_AGE_DAYS: 400,
    }
    adapter = AgentRegistryExecutor()

    first = adapter.execute(_invocation(facts=facts, report_detail="full"))
    second = adapter.execute(_invocation(facts=facts, report_detail="full"))

    assert first == second
    assert first.findings == (FINDING_HIGH_RISK,)
    assert first.details["assessment"] == PostureAssessment.ATTENTION.value
    assert "facts" in first.details
    # The facts it reports back are the ones it was given, in a stable order.
    assert list(first.details["facts"]) == sorted(first.details["facts"])


@pytest.mark.parametrize(
    ("facts", "expected_findings", "assessment"),
    [
        (
            {
                ConditionField.RISK_CLASSIFICATION: RiskClassification.CRITICAL.value,
                ConditionField.RESOURCE_STATUS: AssetStatus.ACTIVE.value,
                ConditionField.AGENT_AGE_DAYS: 200,
            },
            (FINDING_HIGH_RISK,),
            PostureAssessment.ATTENTION,
        ),
        (
            {
                ConditionField.RISK_CLASSIFICATION: RiskClassification.UNASSESSED.value,
                ConditionField.RESOURCE_STATUS: AssetStatus.ACTIVE.value,
                ConditionField.AGENT_AGE_DAYS: 200,
            },
            (FINDING_UNCLASSIFIED_RISK,),
            PostureAssessment.STANDARD,
        ),
        (
            {
                ConditionField.RISK_CLASSIFICATION: RiskClassification.LOW.value,
                ConditionField.RESOURCE_STATUS: AssetStatus.SUSPENDED.value,
                ConditionField.AGENT_AGE_DAYS: 200,
            },
            (FINDING_SUSPENDED_ASSET,),
            PostureAssessment.ATTENTION,
        ),
        (
            {
                ConditionField.RISK_CLASSIFICATION: RiskClassification.LOW.value,
                ConditionField.RESOURCE_STATUS: AssetStatus.ACTIVE.value,
                ConditionField.AGENT_CATEGORY: "autonomous",
                ConditionField.AGENT_AGE_DAYS: 200,
            },
            (FINDING_PRODUCTION_AUTONOMOUS,),
            PostureAssessment.ELEVATED,
        ),
        (
            {
                ConditionField.RISK_CLASSIFICATION: RiskClassification.LOW.value,
                ConditionField.RESOURCE_STATUS: AssetStatus.ACTIVE.value,
                ConditionField.AGENT_AGE_DAYS: 2,
            },
            (FINDING_NEW_REGISTRATION,),
            PostureAssessment.ELEVATED,
        ),
        (
            {
                ConditionField.RISK_CLASSIFICATION: RiskClassification.LOW.value,
                ConditionField.RESOURCE_STATUS: AssetStatus.ACTIVE.value,
                ConditionField.AGENT_AGE_DAYS: 200,
            },
            (),
            PostureAssessment.STANDARD,
        ),
    ],
)
def test_the_reference_adapter_reports_a_closed_set_of_findings(
    facts: Mapping[ConditionField, object], expected_findings: tuple[str, ...], assessment: object
) -> None:
    """One row per rule, so a rule that stops firing is a failing test rather than a silence."""
    outcome = AgentRegistryExecutor().execute(_invocation(facts=facts))

    assert outcome.findings == expected_findings
    assert outcome.details["assessment"] == assessment
    assert outcome.summary.startswith(AGENT_POSTURE_CHECK.action_id)
    assert "facts" not in outcome.details, "summary detail does not echo the record"


def test_the_reference_adapter_refuses_arguments_that_are_not_its_own() -> None:
    """An adapter that guessed at arguments it does not recognize would be unreviewable."""
    with pytest.raises(ActionExecutionError):
        AgentRegistryExecutor().execute(_invocation(facts={}, arguments=ActionOutcome(summary="x")))


def test_a_target_whose_facts_are_incomplete_is_still_assessed() -> None:
    """A field the record cannot attest is absent, and an absent field is not a finding."""
    outcome = AgentRegistryExecutor().execute(_invocation(facts={}))
    assert outcome.details["assessment"] == PostureAssessment.STANDARD.value


# ── The ledger, against the real database ────────────────────────────────────


@pytest.fixture
def ledger_organization(
    integration_engine: Engine, owner_identity: Identity
) -> Iterator[uuid.UUID]:
    """A committed tenant for the ledger tests, cleaned up afterwards.

    The repository commits (a reservation must be visible to a concurrent retry), so
    the rows a test writes outlive its transaction and have to be removed explicitly —
    before the identity fixture removes the organization, which references them.
    """
    yield owner_identity.organization_id
    purge_executions(integration_engine, owner_identity.organization_id)


def _reserve(session: Session, organization_id: uuid.UUID) -> tuple[ActionExecutionRepository, str]:
    repository = ActionExecutionRepository(session, organization_id)
    key = f"ledger-{uuid.uuid4().hex[:12]}"
    repository.reserve(
        idempotency_key=key,
        action_id=AGENT_POSTURE_CHECK.action_id,
        target_id=uuid.uuid4(),
        request_fingerprint="a" * 64,
    )
    return repository, key


def test_a_reservation_is_readable_and_can_be_completed(
    integration_session: Session, integration_engine: Engine, ledger_organization: uuid.UUID
) -> None:
    """The repository's three operations, in the order the service uses them."""
    repository, key = _reserve(integration_session, ledger_organization)

    reserved = repository.find_by_key(key)
    assert reserved is not None
    assert reserved.status is ExecutionStatus.RESERVED
    assert reserved.completed_at is None
    assert reserved.outcome is None

    completed = repository.record_outcome(
        reserved,
        status=ExecutionStatus.EXECUTED,
        outcome={"summary": "recorded", "findings": [], "details": {}},
        error_code=None,
        completed_at=INVOKED_AT,
    )

    assert completed.status is ExecutionStatus.EXECUTED
    assert completed.completed_at is not None
    assert completed.outcome == {"summary": "recorded", "findings": [], "details": {}}

    again = repository.find_by_key(key)
    assert again is not None
    assert again.outcome == completed.outcome
    assert count_executions(integration_engine, ledger_organization) == 1


def test_a_second_reservation_of_one_key_is_refused_by_the_database(
    integration_session: Session, ledger_organization: uuid.UUID
) -> None:
    """The unique constraint is the concurrency control: no lock, no coordination."""
    _, key = _reserve(integration_session, ledger_organization)

    with pytest.raises(IdempotencyConflictError):
        ActionExecutionRepository(integration_session, ledger_organization).reserve(
            idempotency_key=key,
            action_id=AGENT_POSTURE_CHECK.action_id,
            target_id=uuid.uuid4(),
            request_fingerprint="b" * 64,
        )


def test_the_same_key_in_another_organization_is_a_different_key(
    integration_session: Session,
    ledger_organization: uuid.UUID,
    identity_factory: IdentityFactory,
    integration_engine: Engine,
) -> None:
    """Keys are per tenant, and a lookup cannot see another tenant's row.

    An idempotency key is chosen by the client, so a shared keyspace would let one
    organization's retry collide with — or read — another's.
    """
    _, key = _reserve(integration_session, ledger_organization)

    other = identity_factory(role_code="owner")
    try:
        other_repository = ActionExecutionRepository(integration_session, other.organization_id)
        assert other_repository.find_by_key(key) is None
        other_repository.reserve(
            idempotency_key=key,
            action_id=AGENT_POSTURE_CHECK.action_id,
            target_id=uuid.uuid4(),
            request_fingerprint="c" * 64,
        )
        assert other_repository.find_by_key(key) is not None
    finally:
        purge_executions(integration_engine, other.organization_id)


@pytest.mark.parametrize(
    ("statement", "values"),
    [
        # An execution without an outcome.
        (
            "INSERT INTO aicore.action_executions (organization_id, idempotency_key, action_id,"
            " target_id, request_fingerprint, status) VALUES (:organization_id, :key, :action_id,"
            " :target_id, :fingerprint, 'executed')",
            {"fingerprint": "d" * 64},
        ),
        # A reservation that claims to have completed.
        (
            "INSERT INTO aicore.action_executions (organization_id, idempotency_key, action_id,"
            " target_id, request_fingerprint, status, completed_at) VALUES (:organization_id,"
            " :key, :action_id, :target_id, :fingerprint, 'reserved', now())",
            {"fingerprint": "e" * 64},
        ),
        # A failure with an outcome.
        (
            "INSERT INTO aicore.action_executions (organization_id, idempotency_key, action_id,"
            " target_id, request_fingerprint, status, outcome, error_code, completed_at) VALUES"
            " (:organization_id, :key, :action_id, :target_id, :fingerprint, 'failed', '{}'::jsonb,"
            " 'x', now())",
            {"fingerprint": "f" * 64},
        ),
        # A status this build does not have.
        (
            "INSERT INTO aicore.action_executions (organization_id, idempotency_key, action_id,"
            " target_id, request_fingerprint, status) VALUES (:organization_id, :key, :action_id,"
            " :target_id, :fingerprint, 'unknown')",
            {"fingerprint": "0" * 64},
        ),
        # A fingerprint that is not a digest.
        (
            "INSERT INTO aicore.action_executions (organization_id, idempotency_key, action_id,"
            " target_id, request_fingerprint, status) VALUES (:organization_id, :key, :action_id,"
            " :target_id, 'short', 'reserved')",
            {},
        ),
        # A key that is not an opaque token.
        (
            "INSERT INTO aicore.action_executions (organization_id, idempotency_key, action_id,"
            " target_id, request_fingerprint, status) VALUES (:organization_id, 'not a key',"
            " :action_id, :target_id, :fingerprint, 'reserved')",
            {"fingerprint": "1" * 64},
        ),
    ],
)
def test_the_ledger_refuses_a_row_that_cannot_be_true(
    integration_session: Session,
    ledger_organization: uuid.UUID,
    statement: str,
    values: Mapping[str, str],
) -> None:
    """The constraints, exercised: an impossible row is not representable.

    Written as raw SQL on purpose — the application is designed never to attempt any of
    these, so the only way to know the database refuses them is to ask it directly.
    """
    with bind_tenant(ledger_organization):
        with pytest.raises(IntegrityError):
            integration_session.execute(
                text(statement),
                {
                    "organization_id": str(ledger_organization),
                    "key": f"bad-{uuid.uuid4().hex[:8]}",
                    "action_id": AGENT_POSTURE_CHECK.action_id,
                    "target_id": str(uuid.uuid4()),
                    **values,
                },
            )
        integration_session.rollback()


def test_the_service_uses_the_real_ledger_end_to_end(
    integration_session: Session, integration_engine: Engine, ledger_organization: uuid.UUID
) -> None:
    """The same "exactly once" property, with the repository underneath the service."""
    request = _request(ledger_organization)
    recorder = RecordingExecutor()
    service = ActionExecutionService(
        registry=TEST_REGISTRY,
        executors=ActionExecutorRegistry((recorder,)),
        ledger=ActionExecutionRepository(integration_session, ledger_organization),
    )

    first = service.execute(
        decision=_decision(request),
        request=request,
        definition=TEST_DEFINITION,
        target=_target(request),
        invoked_at=INVOKED_AT,
    )
    # The client retries the *same* request: same target, same arguments, same key.
    second = service.execute(
        decision=_decision(request),
        request=request,
        definition=TEST_DEFINITION,
        target=_target(request),
        invoked_at=INVOKED_AT,
    )

    assert len(recorder.calls) == 1
    assert first.replayed is False
    assert second.replayed is True
    assert count_executions(integration_engine, ledger_organization) == 1


def test_the_previous_revision_cannot_represent_an_action_target(
    integration_session: Session, policies, ledger_organization: uuid.UUID
) -> None:
    """Why the downgrade refuses rather than deletes: revision 0005's constraint would fail.

    A policy targeting ``action.execute`` can exist while revision 0006 is applied — it
    is a valid definition of this build — and the previous revision's ``CHECK`` cannot
    hold it. The migration relies on exactly this: it re-adds the old constraint and
    lets PostgreSQL refuse. Asserted here so the mechanism is not merely assumed.
    """
    policies.create(
        "Execution guard",
        resource="action",
        action="execute",
        effect="deny",
        conditions=[],
    )

    with bind_tenant(ledger_organization):
        with pytest.raises(IntegrityError):
            integration_session.execute(
                text(
                    "ALTER TABLE aicore.policy_versions ADD CONSTRAINT "
                    "ck_policy_versions_action_valid_roundtrip "
                    "CHECK (action IN ('create', 'delete', 'manage', 'read', 'update'))"
                )
            )
        integration_session.rollback()


def test_the_reference_adapter_is_in_the_catalogue_this_build_serves() -> None:
    """The definition the API resolves and the adapter it reaches are one pairing."""
    adapter = DEFAULT_EXECUTORS.resolve(AGENT_POSTURE_CHECK)

    assert isinstance(adapter, AgentRegistryExecutor)
    assert AGENT_POSTURE_CHECK.sensitivity is ActionSensitivity.ROUTINE
