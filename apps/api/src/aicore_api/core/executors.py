"""Action executors: the adapters an ``ALLOW`` decision may reach.

An executor — an adapter — is the only code in this build that carries out an action,
and this module is the whole of the boundary around it.

**An adapter receives a resolved invocation and nothing else.**
:class:`ActionInvocation` carries the organization, the action, the target's attested
facts, the validated arguments and the identifiers the decision was made from. It
carries *no* session, no engine, no connection, no credential, no path and no URL: an
adapter therefore cannot query another tenant, cannot read a file, cannot open a
socket — not because it is trusted not to, but because it has nothing to do it with.
The target row is resolved by the API layer before the firewall runs, so an adapter
does not even need to read the database.

**An adapter is registered, never named by a request.** The registry maps an
identifier — the ``executor_id`` an :class:`~aicore_api.core.actions.ActionDefinition`
declares — to an object this build constructed at import time. There is no dynamic
import, no dotted path, no plugin discovery and no entry-point scan anywhere in this
package: a request names an *action*, and the action's definition was reviewed in
source.

**The one adapter this phase ships is read-only, and the tests assert it.** It
assesses facts the system already stores about one registered agent and returns a
deterministic verdict: the same facts always produce the same assessment, findings and
digest, and it reads no clock, no random source, no database and no network. A future
phase can add CRM, ERP, ticketing, mail, database and cloud adapters by registering
them here — each in the same shape, each reachable only through a decision this
build's firewall produced.
"""

from __future__ import annotations

import re
import uuid
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

from pydantic import BaseModel

from aicore_api.core.actions import (
    ACTION_ID_PATTERN,
    ActionDefinition,
    ActionTarget,
    AgentPostureArguments,
    canonical_json,
)
from aicore_api.core.agents import AgentCategory
from aicore_api.core.assets import AssetStatus, Environment, RiskClassification
from aicore_api.core.policy import ConditionField

__all__ = [
    "ActionExecutionError",
    "ActionExecutor",
    "ActionExecutorRegistry",
    "ActionInvocation",
    "ActionOutcome",
    "AgentRegistryExecutor",
    "ExecutorRegistryError",
    "PostureAssessment",
    "default_executors",
]

#: The same shape an action identifier has: an executor identifier is read and quoted
#: by people, and it is never a dotted path into a module.
_EXECUTOR_ID = re.compile(ACTION_ID_PATTERN)


class ExecutorRegistryError(ValueError):
    """A registry entry this build cannot serve — a duplicate or an invalid identifier.

    Raised while the registry is built, so a mistake is a startup failure rather than
    a request that runs the wrong adapter.
    """


class ActionExecutionError(RuntimeError):
    """An executor could not carry out an action it was allowed to run.

    The distinction that matters is that the decision was ``ALLOW`` and the *work*
    failed: the request was permitted, admitted to an adapter, and the adapter could
    not finish. Nothing is retried automatically — a failure leaves the idempotency key
    claimed, so a client that retries with the same key is refused rather than
    re-running an action whose outcome is unknown.
    """


@dataclass(frozen=True, slots=True)
class ActionInvocation:
    """One admitted action, resolved: exactly what an executor is given.

    Not the HTTP request, and not the :class:`~aicore_api.core.actions.ActionRequest`
    either: the identity of the *caller* is reduced to identifiers, the arguments are
    the validated model, and the target is the attested fact record. There is
    deliberately no session, engine, credential, filesystem path or URL in this shape —
    an adapter cannot do more than the invocation describes.
    """

    organization_id: uuid.UUID
    action_id: str
    target: ActionTarget
    environment: Environment
    arguments: BaseModel
    principal_id: uuid.UUID
    membership_id: uuid.UUID
    agent_id: uuid.UUID | None
    correlation_id: str
    invoked_at: datetime

    @property
    def argument_names(self) -> tuple[str, ...]:
        """The argument names the caller supplied, sorted. Values are not listed."""
        return tuple(sorted(self.arguments.model_fields_set))

    def argument_values(self) -> dict[str, Any]:
        """The validated arguments as plain data, for an adapter that needs them."""
        return self.arguments.model_dump(mode="json")

    def __repr__(self) -> str:
        """Name the invocation without rendering its arguments (which may be sensitive)."""
        return (
            f"<ActionInvocation {self.action_id!r} target={self.target.identifier!s} "
            f"arguments={self.argument_names}>"
        )


@dataclass(frozen=True, slots=True)
class ActionOutcome:
    """What an executor reports back: a summary, findings, and optional detail.

    Deliberately small and closed: a sentence, a tuple of stable finding codes, and a
    mapping of additional structured detail. An adapter's free-form prose would not be
    part of this build's contract, and an outcome that could carry arbitrary objects
    would be a second execution path.
    """

    summary: str
    findings: tuple[str, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.summary, str) or not self.summary.strip():
            raise ActionExecutionError("an outcome must state a summary")
        resolved_details = dict(self.details)
        for key, value in resolved_details.items():
            if not isinstance(key, str):
                raise ActionExecutionError("outcome detail keys must be strings")
            try:
                canonical_json({"value": value})
            except (TypeError, ValueError) as exc:
                raise ActionExecutionError(
                    f"outcome detail {key!r} is not representable as JSON"
                ) from exc
        object.__setattr__(self, "details", MappingProxyType(resolved_details))

    def payload(self) -> dict[str, Any]:
        """The outcome as a plain mapping: what the response reports and the ledger keeps."""
        return {
            "summary": self.summary,
            "findings": list(self.findings),
            "details": dict(self.details),
        }


class ActionExecutor(ABC):
    """The adapter interface. One method, one value in, one value out.

    Deliberately synchronous and exception-based: an adapter either returns an
    :class:`ActionOutcome` or raises :class:`ActionExecutionError`. It has no
    ``cancel``, no ``stream`` and no callback surface, because an execution path with
    more than one way to end is an execution path with more than one way to keep
    running after it was refused.
    """

    #: The identifier an action definition names. Declared by every subclass and
    #: checked when the class is defined, so an adapter without one cannot be built.
    executor_id: ClassVar[str]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        executor_id = getattr(cls, "executor_id", None)
        if not isinstance(executor_id, str) or not executor_id:
            raise ExecutorRegistryError(
                f"{cls.__name__} must declare an executor_id: the identifier an action "
                "definition names to reach it"
            )
        if _EXECUTOR_ID.match(executor_id) is None:
            raise ExecutorRegistryError(
                f"{cls.__name__}.executor_id = {executor_id!r} is not an executor identifier; the "
                f"shape is {ACTION_ID_PATTERN}"
            )

    @abstractmethod
    def execute(self, invocation: ActionInvocation) -> ActionOutcome:
        """Carry out ``invocation`` and report what happened."""

    def __repr__(self) -> str:
        return f"<{type(self).__name__} executor_id={self.executor_id!r}>"


class ActionExecutorRegistry:
    """Which adapter an ``executor_id`` reaches. Constructed once, from code."""

    def __init__(self, executors: Iterable[ActionExecutor] = ()) -> None:
        by_id: dict[str, ActionExecutor] = {}
        for executor in executors:
            if not isinstance(executor, ActionExecutor):
                raise ExecutorRegistryError(
                    f"the executor registry holds ActionExecutor instances, got "
                    f"{type(executor).__name__}"
                )
            if executor.executor_id in by_id:
                raise ExecutorRegistryError(
                    f"two executors are registered as {executor.executor_id!r}; the identifier is "
                    "how a definition names one, so it has to name exactly one"
                )
            by_id[executor.executor_id] = executor
        self._executors = MappingProxyType(by_id)

    def get(self, executor_id: object) -> ActionExecutor | None:
        """The adapter ``executor_id`` names, or ``None``."""
        if not isinstance(executor_id, str):
            return None
        return self._executors.get(executor_id)

    def resolve(self, definition: ActionDefinition) -> ActionExecutor:
        """The adapter a definition names, or :class:`ExecutorRegistryError`.

        Refused rather than defaulted: an action whose adapter is missing is an action
        that could be authorized, evaluated, decided and then quietly not run — which is
        exactly the kind of "no" that hides a broken deployment.
        """
        executor = self.get(definition.executor_id)
        if executor is None:
            registered = ", ".join(sorted(self._executors)) or "(none)"
            raise ExecutorRegistryError(
                f"action {definition.action_id!r} names executor {definition.executor_id!r}, which "
                f"is not registered; the adapters this build has are: {registered}"
            )
        return executor

    def executor_ids(self) -> tuple[str, ...]:
        """Every registered adapter identifier, sorted."""
        return tuple(sorted(self._executors))

    def __contains__(self, executor_id: object) -> bool:
        return self.get(executor_id) is not None

    def __len__(self) -> int:
        return len(self._executors)

    def __repr__(self) -> str:
        return f"<ActionExecutorRegistry {', '.join(self.executor_ids()) or 'empty'}>"


class PostureAssessment(StrEnum):
    """The closed verdict the reference adapter produces. Three values, no scores."""

    STANDARD = "standard"
    ELEVATED = "elevated"
    ATTENTION = "attention"


#: The finding codes the reference adapter can report, in the order it reports them.
#: Closed on purpose: a finding is a code a client can switch on, not prose.
FINDING_HIGH_RISK = "high_risk_classification"
FINDING_UNCLASSIFIED_RISK = "unclassified_risk"
FINDING_PRODUCTION_AUTONOMOUS = "production_autonomous_agent"
FINDING_SUSPENDED_ASSET = "suspended_asset"
FINDING_NEW_REGISTRATION = "recently_registered"

#: How recently a registration has to be, in days, to be worth reporting.
RECENT_REGISTRATION_DAYS = 7


class AgentRegistryExecutor(ActionExecutor):
    """The one adapter this phase ships: assess an agent from its recorded facts.

    Read-only by construction. The invocation already carries the attested facts — the
    environment, lifecycle state, risk classification, category and ages of the agent
    the request names — so this adapter opens no connection, reads no clock and calls
    nothing: it classifies what it was given and reports it. The same invocation always
    produces the same outcome, which is what makes an execution replayable and a test
    able to assert exact behaviour.
    """

    executor_id: ClassVar[str] = "agent_registry"

    def execute(self, invocation: ActionInvocation) -> ActionOutcome:
        """Classify the target's recorded posture and report the findings."""
        arguments = invocation.arguments
        if not isinstance(arguments, AgentPostureArguments):
            # Unreachable while the definition binds this adapter to this input schema,
            # and loud rather than defaulted: an adapter that guessed at arguments it does
            # not recognize would be an adapter whose behaviour nobody can review.
            raise ActionExecutionError(
                "the agent registry adapter was given arguments that are not this action's "
                "input model"
            )
        facts = invocation.target.facts
        environment = facts.get(ConditionField.ENVIRONMENT)
        risk = facts.get(ConditionField.RISK_CLASSIFICATION)
        status = facts.get(ConditionField.RESOURCE_STATUS)
        category = facts.get(ConditionField.AGENT_CATEGORY)
        age_days = facts.get(ConditionField.AGENT_AGE_DAYS)

        findings: list[str] = []
        if risk in {RiskClassification.HIGH.value, RiskClassification.CRITICAL.value}:
            findings.append(FINDING_HIGH_RISK)
        elif risk == RiskClassification.UNASSESSED.value:
            findings.append(FINDING_UNCLASSIFIED_RISK)
        if (
            environment == Environment.PRODUCTION.value
            and category == AgentCategory.AUTONOMOUS.value
        ):
            findings.append(FINDING_PRODUCTION_AUTONOMOUS)
        if status == AssetStatus.SUSPENDED.value:
            findings.append(FINDING_SUSPENDED_ASSET)
        if isinstance(age_days, int | float) and age_days <= RECENT_REGISTRATION_DAYS:
            findings.append(FINDING_NEW_REGISTRATION)

        assessment = self._assess(findings)
        detail: dict[str, Any] = {"assessment": assessment.value}
        if arguments.report_detail == "full":
            detail["facts"] = {
                condition.value: value
                for condition, value in sorted(facts.items(), key=lambda item: item[0].value)
            }
        return ActionOutcome(
            summary=(
                f"{invocation.action_id} assessed the recorded posture of the target as "
                f"{assessment.value}"
                + (f" ({len(findings)} finding(s))" if findings else " (no findings)")
            ),
            findings=tuple(findings),
            details=detail,
        )

    @staticmethod
    def _assess(findings: list[str]) -> PostureAssessment:
        """The verdict rule, in one place and in one order.

        ``attention`` for anything the organization has classified as high or critical
        risk or has suspended; ``elevated`` for an autonomous agent in production or a
        freshly registered one; ``standard`` otherwise. A closed table, not a score: an
        assessment whose arithmetic nobody can reproduce is not an assessment.
        """
        if FINDING_HIGH_RISK in findings or FINDING_SUSPENDED_ASSET in findings:
            return PostureAssessment.ATTENTION
        if FINDING_PRODUCTION_AUTONOMOUS in findings or FINDING_NEW_REGISTRATION in findings:
            return PostureAssessment.ELEVATED
        return PostureAssessment.STANDARD


#: The adapters this build has. A literal, reviewed like any other source here.
DEFAULT_EXECUTORS = ActionExecutorRegistry((AgentRegistryExecutor(),))


def default_executors() -> ActionExecutorRegistry:
    """The adapters an ``ALLOW`` may reach, as the process-wide registry."""
    return DEFAULT_EXECUTORS
