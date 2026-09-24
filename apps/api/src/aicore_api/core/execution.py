"""The execution service: the only code in this build that runs an action.

It exists to make one sentence true in a way a test can check:

    **Only an ``ALLOW`` decision reaches an executor.**

Everything else in this module is bookkeeping around that. The service takes the
firewall's decision, the request it was made about, the definition it named and the
target it addressed; it re-checks the decision instead of trusting its caller; and it
refuses — before touching anything — unless the outcome is exactly ``ALLOW``. A future
code path that skips the firewall therefore fails closed: it cannot execute, only
fail.

**Idempotency without a second execution.** A caller retrying a request whose answer
it never saw is the exact situation an execution path must survive, so the request
carries a key, and the ledger claims it:

1. the key is looked up; a completed record with the same fingerprint is *replayed* —
   the recorded outcome is returned and the adapter is not called again;
2. otherwise the key is reserved with an INSERT guarded by a unique constraint, so two
   concurrent requests cannot both proceed (no lock, no coordination, no distributed
   anything — the database's constraint is the arbiter);
3. only then is the adapter invoked, and the outcome recorded against the reservation.

A reservation whose adapter failed stays incomplete: the action may have had effects
this build cannot see, so retrying that key is refused (409) rather than re-run. The
ledger is **not** an audit trail — it records no actor, no rationale and no refusal,
and exists only so a retry returns the same answer instead of running the action
twice. Recording what happened, for whom and whether it was allowed is Phase 8's
system, and this phase does not build it.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from aicore_api.core.actions import (
    ActionDefinition,
    ActionRegistry,
    ActionRequest,
    ActionTarget,
    ExecutionStatus,
    canonical_json,
)
from aicore_api.core.domain_errors import ConflictError
from aicore_api.core.events import ACTION_EXECUTED, DomainEvent, emit_event
from aicore_api.core.executors import (
    ActionExecutionError,
    ActionExecutorRegistry,
    ActionInvocation,
    ActionOutcome,
)
from aicore_api.core.firewall import FirewallConfigurationError, FirewallDecision, FirewallOutcome

__all__ = [
    "ActionExecutionResult",
    "ActionExecutionService",
    "ExecutionFailedError",
    "ExecutionLedger",
    "ExecutionRecord",
    "ExecutionRefusedError",
    "ExecutionStatus",
    "IdempotencyConflictError",
]

logger = logging.getLogger(__name__)

#: How many characters of an adapter's own message are kept in the log line. An
#: adapter's message is this build's own code text, never a client's input, and the
#: cap keeps a runaway message from filling a log.
_MAX_LOGGED_MESSAGE = 200


class ExecutionRefusedError(RuntimeError):
    """The service was handed a decision that is not ``ALLOW``.

    The enforcement point, expressed as an error: if the pipeline ever calls the
    service with a ``DENY`` or ``REQUIRE_APPROVAL`` decision, the action does not run
    and the caller gets this. The route translates it into the same structured refusal
    the firewall would have produced, so the two paths cannot disagree.
    """

    def __init__(self, decision: FirewallDecision) -> None:
        super().__init__(
            f"the firewall decided {decision.outcome.value} for action "
            f"{decision.action_id!r}; it is not executed"
        )
        self.decision = decision


class ExecutionFailedError(RuntimeError):
    """An adapter was reached and did not complete the action.

    Distinct from a refusal: the decision was ``ALLOW``, the action was admitted, and
    the work failed. The API answers 500 with a code and no detail — an adapter's
    internals are not a client's business — while the log line carries the reason for
    whoever operates the service.
    """


class IdempotencyConflictError(ConflictError):
    """The idempotency key cannot be reused for the request the caller just sent.

    Three cases, one answer: the key already ran a *different* request, a request with
    this key is still in progress, or a previous attempt with this key failed. In all
    three the caller's retry must not execute the action, and the way forward is a new
    key.
    """


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    """One row of the idempotency ledger, as the service sees it."""

    id: uuid.UUID
    organization_id: uuid.UUID
    idempotency_key: str
    action_id: str
    target_id: uuid.UUID
    request_fingerprint: str
    status: ExecutionStatus
    outcome: Mapping[str, Any] | None
    error_code: str | None
    created_at: datetime
    completed_at: datetime | None

    @property
    def replayable(self) -> bool:
        """Whether this record holds a completed outcome that can be returned again."""
        return self.status is ExecutionStatus.EXECUTED and self.outcome is not None


class ExecutionLedger(Protocol):
    """What the service needs from storage, and nothing more.

    A protocol rather than a repository: the service is not a database client, and the
    tests that prove "the adapter runs exactly once" use an in-memory implementation of
    this interface instead of a second database.
    """

    def find_by_key(self, idempotency_key: str) -> ExecutionRecord | None:
        """The record that holds ``idempotency_key`` in this organization, if any."""

    def reserve(
        self,
        *,
        idempotency_key: str,
        action_id: str,
        target_id: uuid.UUID,
        request_fingerprint: str,
    ) -> ExecutionRecord:
        """Claim the key, or raise :class:`IdempotencyConflictError` if it is taken."""

    def record_outcome(
        self,
        record: ExecutionRecord,
        *,
        status: ExecutionStatus,
        outcome: Mapping[str, Any] | None,
        error_code: str | None,
        completed_at: datetime,
    ) -> ExecutionRecord:
        """Write the ending of a reserved execution and hand back the stored row."""


def _digest(definition: ActionDefinition, target: ActionTarget, payload: Mapping[str, Any]) -> str:
    """A stable digest of one execution's reported outcome.

    Covers the action and the target as well as the outcome, so two different
    executions that happen to report identical prose do not share a digest. Nothing
    about the caller is included: a digest identifies *what was done*, not who asked.
    """
    return hashlib.sha256(
        canonical_json(
            {
                "action": definition.action_id,
                "target": str(target.identifier),
                "outcome": dict(payload),
            }
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ActionExecutionResult:
    """A completed (or replayed) execution: everything the API reports, and nothing else.

    Deliberately does not carry the firewall decision: the route that called the
    service has just computed one, and a second copy here could only disagree with it.
    """

    execution_id: uuid.UUID
    definition: ActionDefinition
    outcome: ActionOutcome
    adapter: str
    digest: str
    executed_at: datetime
    replayed: bool

    @property
    def action_id(self) -> str:
        """The action that ran."""
        return self.definition.action_id

    @property
    def outcome_payload(self) -> dict[str, Any]:
        """The outcome as the response publishes it, without the ledger's own fields."""
        return self.outcome.payload()


def _require(condition: object, message: str) -> None:
    """Fail loudly when the service is handed an inconsistent set of values."""
    if not condition:
        raise FirewallConfigurationError(message)


class ActionExecutionService:
    """Runs an action, but only when the firewall's outcome is ``ALLOW``.

    Constructed once per process from the catalogue and the adapters this build has.
    Every consistency question is answered here — this is the last place that can
    refuse — so the checks are explicit rather than assumed, and the construction
    itself verifies that every registered action has an adapter.
    """

    def __init__(
        self,
        *,
        registry: ActionRegistry,
        executors: ActionExecutorRegistry,
        ledger: ExecutionLedger,
    ) -> None:
        for definition in registry.definitions():
            # At startup, not at request time: an action whose adapter is missing is a
            # broken deployment, and it must be broken loudly.
            executors.resolve(definition)
        for executor_id in registry.executor_ids():
            _require(
                executor_id in executors,
                f"the catalogue names executor {executor_id!r}, which the adapter registry does "
                "not have",
            )
        self._registry = registry
        self._executors = executors
        self._ledger = ledger

    @property
    def registry(self) -> ActionRegistry:
        """The catalogue this service serves."""
        return self._registry

    @property
    def executors(self) -> ActionExecutorRegistry:
        """The adapters this service may reach."""
        return self._executors

    def execute(
        self,
        *,
        decision: FirewallDecision,
        request: ActionRequest,
        definition: ActionDefinition,
        target: ActionTarget,
        invoked_at: datetime,
    ) -> ActionExecutionResult:
        """Run the action ``decision`` allowed, exactly once.

        Raises rather than returning for every case that is not an execution:
        :class:`ExecutionRefusedError` when the decision is not ``ALLOW``,
        :class:`IdempotencyConflictError` when the key cannot be reused,
        :class:`ExecutionFailedError` when the adapter failed. There is no return value
        that means "not run", because a caller that had to check for one would
        eventually forget to.
        """
        # 1. The enforcement point. Re-checked, not trusted: the route already refused
        #    a non-ALLOW decision, and this is the line that makes that a property of
        #    the service rather than of its caller.
        if decision.outcome is not FirewallOutcome.ALLOW:
            raise ExecutionRefusedError(decision)

        # 2. Everything below must describe one request. Mismatches are programming
        #    errors and are refused loudly, before any write.
        _require(
            decision.action_id == request.action_id and decision.action_id == definition.action_id,
            "the decision, the request and the definition name different actions",
        )
        _require(
            decision.organization_id == request.organization_id,
            "the decision is about a different organization than the request",
        )
        _require(
            self._registry.get(definition.action_id) is definition,
            f"action {definition.action_id!r} is not the definition this service serves",
        )
        _require(
            target.identifier == request.target_id
            and target.resource is definition.target_resource,
            "the target is not the row the request names, or not the kind the action addresses",
        )

        # 3. Idempotency. A replay is returned, never re-run.
        replay = self._replay(request)
        if replay is not None:
            return replay

        record = self._ledger.reserve(
            idempotency_key=request.idempotency_key,
            action_id=request.action_id,
            target_id=request.target_id,
            request_fingerprint=request.fingerprint,
        )

        # 4. The adapter, which is the only thing in this module that does work.
        executor = self._executors.resolve(definition)
        invocation = ActionInvocation(
            organization_id=request.organization_id,
            action_id=request.action_id,
            target=target,
            environment=request.environment,
            arguments=request.arguments,
            principal_id=request.principal_id,
            membership_id=request.membership_id,
            agent_id=request.agent_id,
            correlation_id=request.correlation_id,
            invoked_at=invoked_at,
        )
        try:
            outcome = executor.execute(invocation)
        except ActionExecutionError as exc:
            logger.warning(
                "action %s failed (correlation_id=%s, execution_id=%s): %s",
                request.action_id,
                request.correlation_id,
                record.id,
                str(exc)[:_MAX_LOGGED_MESSAGE],
            )
            self._ledger.record_outcome(
                record,
                status=ExecutionStatus.FAILED,
                outcome=None,
                error_code="execution_failed",
                completed_at=invoked_at,
            )
            raise ExecutionFailedError(
                f"action {request.action_id!r} was admitted but could not be completed"
            ) from exc
        except Exception:
            # An unexpected failure is a bug, and the global handler answers it as a
            # generic 500. The reservation is finalized first so a retry cannot re-run
            # an action whose outcome is unknown.
            logger.exception(
                "action %s raised unexpectedly (correlation_id=%s, execution_id=%s)",
                request.action_id,
                request.correlation_id,
                record.id,
            )
            self._ledger.record_outcome(
                record,
                status=ExecutionStatus.FAILED,
                outcome=None,
                error_code="internal_error",
                completed_at=invoked_at,
            )
            raise

        # 5. Record the outcome, then report it.
        payload = outcome.payload()
        digest = _digest(definition, target, payload)
        stored = self._ledger.record_outcome(
            record,
            status=ExecutionStatus.EXECUTED,
            outcome={**payload, "adapter": executor.executor_id, "digest": digest},
            error_code=None,
            completed_at=invoked_at,
        )
        emit_event(
            DomainEvent(
                name=ACTION_EXECUTED,
                organization_id=request.organization_id,
                resource_type="action_execution",
                resource_id=stored.id,
                actor_membership_id=request.membership_id,
                occurred_at=invoked_at,
                data={
                    "action_id": request.action_id,
                    "target_resource": target.resource.value,
                    "decision": decision.outcome.value,
                    "adapter": executor.executor_id,
                    "finding_count": len(outcome.findings),
                    "digest": digest,
                },
            )
        )
        return ActionExecutionResult(
            execution_id=stored.id,
            definition=definition,
            outcome=outcome,
            adapter=executor.executor_id,
            digest=digest,
            executed_at=invoked_at,
            replayed=False,
        )

    def _replay(self, request: ActionRequest) -> ActionExecutionResult | None:
        """Return the recorded execution for this key, or refuse the reuse of it.

        ``None`` means "this key has not been used": the caller reserves it and
        proceeds. Anything else is either a replay of the identical request or a
        refusal — there is no path here that runs an action twice.
        """
        existing = self._ledger.find_by_key(request.idempotency_key)
        if existing is None:
            return None
        if existing.request_fingerprint != request.fingerprint:
            raise IdempotencyConflictError(
                "this idempotency key was already used for a different request; use a new key"
            )
        if existing.replayable:
            stored = existing.outcome or {}
            definition = self._registry.resolve(existing.action_id)
            return ActionExecutionResult(
                execution_id=existing.id,
                definition=definition,
                outcome=ActionOutcome(
                    summary=str(stored.get("summary", "")),
                    findings=tuple(str(finding) for finding in stored.get("findings", ())),
                    details=dict(stored.get("details", {})),
                ),
                adapter=str(stored.get("adapter", definition.executor_id)),
                digest=str(stored.get("digest", "")),
                executed_at=existing.completed_at or existing.created_at,
                replayed=True,
            )
        raise IdempotencyConflictError(
            "a previous request with this idempotency key did not complete; use a new key"
        )
