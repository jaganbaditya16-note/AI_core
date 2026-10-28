"""The action firewall: the one place a request to *do* something is decided.

Phases 5 and 6 answer questions. Phase 7 acts, and this module is the gate the acting
passes through. Its job is narrow and absolute: given a validated request, the
definition it names, the target row's attested facts, the Phase 5 authorization
answer and the Phase 6 policy answer, produce **one** typed decision — and make sure
that only ``ALLOW`` ever reaches an executor.

Four properties make it an enforcement point rather than a report.

**The decision is an object, not a convention.** :class:`FirewallDecision` carries an
:class:`FirewallOutcome` and a :class:`FirewallReason`; there is no string comparison
anywhere on the execution path, and no caller can "almost" allow something. The
execution service refuses to run unless the outcome is ``ALLOW`` — it re-checks that
rather than trusting the caller, so a future code path that skips a step fails closed
instead of executing.

**It cannot widen either upstream layer.** Phase 5's denial and Phase 6's denial both
map to ``DENY``; ``REQUIRE_APPROVAL`` maps to ``REQUIRE_APPROVAL`` and never executes
(Phase 11 owns approvals, and nothing here fakes one); ``ALLOW`` from the policy layer
means "no active policy objected", not "the caller may act", so it only continues
subject to the authorization decision. The combination is
:func:`aicore_api.auth.policy.combine` — Phase 6's own semantics, reused rather than
re-implemented, so an ALLOW can never come out of a DENY.

**Every failure is closed.** A missing authorization decision, an authorization
decision for a different organization or permission, a target outside the tenant, a
target that does not record the environment the request claims, a policy decision
about something else: all of them are refusals. The mismatches are programming
errors, so they raise :class:`FirewallConfigurationError` rather than being folded
into a decision — a build that assembles the pipeline wrongly must not answer
"allowed" or "denied", it must fail loudly.

**Nothing here reads a clock, a database or a network.** The decisions arrive as
values; the firewall is a pure function of them. That is what makes it testable case
by case, and what keeps the enforcement boundary from depending on anything that
could change between the decision and the execution.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum

from aicore_api.auth.authorization import AuthorizationDecision
from aicore_api.auth.policy import EffectiveDecision, EffectiveReason
from aicore_api.core.actions import ActionDefinition, ActionRequest, ActionTarget
from aicore_api.core.permissions import Permission

__all__ = [
    "FirewallConfigurationError",
    "FirewallDecision",
    "FirewallOutcome",
    "FirewallReason",
    "decide",
]


class FirewallConfigurationError(RuntimeError):
    """The pipeline handed the firewall a combination that cannot be decided.

    Deliberately not an :class:`~aicore_api.core.actions.ActionError`: this is not a
    request to refuse, it is a build that must not run. Refusals are values
    (:class:`FirewallDecision` with a ``DENY`` or ``REQUIRE_APPROVAL`` outcome); this
    is raised for the cases where "would you like to proceed?" has no answer — a
    decision about another organization, another permission, another action, or no
    authorization decision at all.
    """


class FirewallOutcome(StrEnum):
    """What the firewall decided. Three outcomes, and that is the whole vocabulary.

    No ``SANDBOXED``, no ``PARTIAL``, no ``DEFER``: an outcome that the executor
    cannot act on is an outcome that hides a decision. ``REQUIRE_APPROVAL`` is the one
    value that exists without a workflow behind it, because Phase 6 already produces
    it and dropping it here would silently turn "ask someone" into "no".
    """

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class FirewallReason(StrEnum):
    """Why the decision came out the way it did. Stable codes, never prose.

    The policy-derived reasons are Phase 6's own reason codes, so a client that
    already reads a dry-run evaluation sees the same vocabulary here — the firewall
    adds only the refusals that are about the request itself.
    """

    #: Both layers permitted the request.
    ALLOWED = "allowed"
    #: Phase 5 denied it: no permission, no active membership, another tenant's row.
    AUTHORIZATION_DENIED = "authorization_denied"
    #: Phase 6 denied it: an active policy said no.
    POLICY_DENIED = "policy_denied"
    #: Phase 6 asked for approval. A value, not a workflow.
    POLICY_REQUIRES_APPROVAL = "policy_requires_approval"
    #: The target row is not in this organization, or does not exist.
    TARGET_NOT_FOUND = "target_not_found"
    #: The request names an environment the target record does not confirm.
    ENVIRONMENT_MISMATCH = "environment_mismatch"


#: Policy reasons that mean "the policy layer did not permit this". Everything the
#: engine can produce is listed, so a new engine reason becomes a loud failure here
#: rather than a silent ALLOW.
_DENYING_POLICY_REASONS: frozenset[EffectiveReason] = frozenset(
    {EffectiveReason.POLICY_DENIED, EffectiveReason.AUTHORIZATION_DENIED}
)


@dataclass(frozen=True, slots=True)
class FirewallDecision:
    """The firewall's answer, as a value.

    Carries the action, the target, the organization and the correlation id so the
    execution service, the API response and a log line can all name *what* was
    decided without re-deriving it — and carries the :class:`EffectiveDecision` that
    produced it, so "why was this allowed?" is answerable from the decision alone.
    """

    outcome: FirewallOutcome
    reason: FirewallReason
    action_id: str
    target_id: uuid.UUID
    organization_id: uuid.UUID
    correlation_id: str
    effective: EffectiveDecision

    @property
    def allowed(self) -> bool:
        """Whether the request may proceed to an executor. Exactly one outcome may."""
        return self.outcome is FirewallOutcome.ALLOW

    @property
    def denied(self) -> bool:
        """Whether the request is refused outright."""
        return self.outcome is FirewallOutcome.DENY

    @property
    def requires_approval(self) -> bool:
        """Whether the request is refused *for now*, pending an approval Phase 7 lacks.

        Nothing in this build turns this into an execution: there is no approval
        workflow, no approver and no way to re-issue a decided request as approved.
        """
        return self.outcome is FirewallOutcome.REQUIRE_APPROVAL

    @property
    def permission_required(self) -> str:
        """The permission this request was decided against — always ``action.execute``."""
        return str(self.effective.permission_required)

    @property
    def policy_decision(self) -> str:
        """Phase 6's own outcome, for a response that reports the whole pipeline."""
        return str(self.effective.policy.decision.value)

    @property
    def effective_reason(self) -> str:
        """The reason the *combined* decision gives, in Phase 6's vocabulary."""
        return str(self.effective.reason.value)

    @property
    def principal_role(self) -> str | None:
        """The role the decision was made for. Reported, never used to widen anything."""
        return self.effective.authorization.role_code

    def __repr__(self) -> str:
        # Compact and stable: a decision ends up in log lines and test failures.
        return (
            f"<FirewallDecision {self.outcome.value.upper()} {self.action_id!r} "
            f"reason={self.reason.value}>"
        )


def _require(value: object, message: str) -> None:
    """Fail loudly when the pipeline is assembled wrongly."""
    if not value:
        raise FirewallConfigurationError(message)


def decide(
    *,
    request: ActionRequest,
    definition: ActionDefinition,
    target: ActionTarget | None,
    authorization: AuthorizationDecision,
    policy: EffectiveDecision,
) -> FirewallDecision:
    """Decide one request. Pure: values in, one typed decision out.

    The order of the checks is part of the contract.

    1. **The inputs must describe the same question.** The definition, the
       authorization decision, the policy decision and the request must all be about
       ``action.execute`` on the same action in the same organization. A mismatch is a
       programming error, not a refusal — a pipeline that asks about the wrong
       permission must not produce a decision at all.
    2. **Authorization first.** A Phase 5 denial is a ``DENY``, whatever the policy
       layer says, and it is decided before the target is considered: a caller who may
       not execute anything does not get to learn whether a row exists.
    3. **Then the request's referents.** A target that is not in this organization (or
       not there at all) is ``TARGET_NOT_FOUND``; a request whose declared environment
       the record does not confirm is ``ENVIRONMENT_MISMATCH``. Both are refusals, and
       both are about the request rather than about the organization's rules.
    4. **Then the policy answer**, already combined with the authorization decision by
       the Phase 6 combiner: deny → ``DENY``, require-approval → ``REQUIRE_APPROVAL``,
       anything else → ``ALLOW``.

    ``TARGET_NOT_FOUND`` before the policy answer is deliberate: "your policy says no"
    is not a true statement about a request that names a row this organization does
    not have.
    """
    _require(
        definition.action_id == request.action_id,
        f"the firewall was given the definition for {definition.action_id!r} and the request "
        f"for {request.action_id!r}; these must be the same action",
    )
    _require(
        authorization.organization_id == request.organization_id,
        "the authorization decision is about a different organization than the request",
    )
    _require(
        authorization.permission is not None
        and authorization.permission is Permission.ACTION_EXECUTE,
        "the authorization decision is not about the action.execute permission",
    )
    _require(
        policy.organization_id == request.organization_id
        and policy.resource == definition.policy_target[0]
        and policy.action == definition.policy_target[1],
        "the policy decision is not about this request's target; refusing to decide",
    )
    if target is not None:
        _require(
            target.resource is definition.target_resource,
            f"the target is a {target.resource.value} and the action addresses a "
            f"{definition.target_resource.value}",
        )
        _require(
            target.identifier == request.target_id,
            "the resolved target is not the target the request named",
        )

    def decision(outcome: FirewallOutcome, reason: FirewallReason) -> FirewallDecision:
        return FirewallDecision(
            outcome=outcome,
            reason=reason,
            action_id=request.action_id,
            target_id=request.target_id,
            organization_id=request.organization_id,
            correlation_id=request.correlation_id,
            effective=policy,
        )

    # 2. Phase 5's answer. A denial here is final: no policy can restore it.
    if authorization.denied:
        return decision(FirewallOutcome.DENY, FirewallReason.AUTHORIZATION_DENIED)

    # 3. The request's referents.
    if target is None:
        return decision(FirewallOutcome.DENY, FirewallReason.TARGET_NOT_FOUND)
    if target.environment is not request.environment:
        return decision(FirewallOutcome.DENY, FirewallReason.ENVIRONMENT_MISMATCH)

    # 4. Phase 6's answer, combined. ``combine`` already folded the authorization
    #    decision in, so this reads the effective outcome rather than re-deriving it.
    if policy.denied or policy.reason in _DENYING_POLICY_REASONS:
        return decision(FirewallOutcome.DENY, FirewallReason.POLICY_DENIED)
    if policy.requires_approval:
        return decision(FirewallOutcome.REQUIRE_APPROVAL, FirewallReason.POLICY_REQUIRES_APPROVAL)
    if not policy.allowed:
        # Unreachable while ``EffectiveDecision`` has three outcomes; kept so a fourth
        # one added later fails closed instead of being read as permission.
        raise FirewallConfigurationError(
            f"the combined decision {policy.decision.value!r} is neither allow, deny nor "
            "require_approval; refusing to interpret it"
        )
    return decision(FirewallOutcome.ALLOW, FirewallReason.ALLOWED)
