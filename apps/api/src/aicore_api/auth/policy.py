"""Where authorization and policy meet: two decisions, one effective answer.

Phase 5 answers *may this principal use this permission, in this organization, for
this row?* Phase 6 answers *given that, does the context satisfy the
organization's policy?* This module is the only place the two answers are
combined, and it is deliberately tiny, because the rule it encodes is the whole
relationship between the layers:

    a policy may further restrict an authorization decision, and may never
    widen one.

That is not a convention here, it is the arithmetic of :func:`combine`: the
authorization decision is the ceiling, the policy layer can only lower it, and
the combination is total (every pair of inputs produces one outcome):

===========================================  ==========================================
authorization                                effective
===========================================  ==========================================
DENY (whatever the policy layer says)        **DENY** — a policy cannot un-deny
ALLOW + policy DENY                          **DENY**
ALLOW + policy REQUIRE_APPROVAL              **REQUIRE_APPROVAL** — not permitted outright
ALLOW + policy ALLOW                         **ALLOW**
ALLOW + policy NOT_APPLICABLE                **ALLOW** — no policy addressed it
===========================================  ==========================================

``REQUIRE_APPROVAL`` is returned as a *value*. Nothing in this build collects,
routes or performs an approval: no queue, no approver, no notification, no
endpoint that could grant one. The phase that owns approvals consumes this value;
until then, "requires approval" means "not allowed outright", which is what the
table above says.

**Nothing here enforces anything.** Phase 6 evaluates; the phase that owns the
enforcement point is the one that turns an :class:`EffectiveDecision` into a
refused request. This module exists so that when that happens, there is one
function to call rather than a second place that re-derives authorization.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum

from aicore_api.auth.authorization import AuthorizationDecision
from aicore_api.core.permissions import Action, Resource
from aicore_api.core.policy_engine import PolicyDecision, PolicyDecisionKind

__all__ = ["EffectiveDecision", "EffectiveReason", "combine"]


class EffectiveReason(StrEnum):
    """Which layer produced the effective outcome, and why.

    Stable identifiers, like every other code in this system. They name the *layer*
    and the *kind* of outcome rather than repeating the details — the underlying
    :class:`~aicore_api.auth.authorization.AuthorizationDecision` and
    :class:`~aicore_api.core.policy_engine.PolicyDecision` carry those, and both
    travel with the effective decision.
    """

    #: Phase 5 refused. The policy layer was not consulted, or agreed.
    AUTHORIZATION_DENIED = "authorization_denied"
    #: Phase 5 allowed and a policy forbade it.
    POLICY_DENIED = "policy_denied"
    #: Phase 5 allowed and a policy requires approval. Not permitted outright.
    POLICY_REQUIRES_APPROVAL = "policy_requires_approval"
    #: Phase 5 allowed and a policy permitted it.
    POLICY_ALLOWED = "policy_allowed"
    #: Phase 5 allowed and no policy addressed the request. The authorization
    #: decision stands on its own — which is where every request stands today,
    #: because nothing consults this function in the request path yet.
    AUTHORIZATION_GRANT = "authorization_grant"


@dataclass(frozen=True, slots=True)
class EffectiveDecision:
    """The two layers' answers, and the one that follows from them.

    Both inputs are retained, not summarised: a caller that needs to explain the
    outcome — a log line, an audit record, an operator asking "why?" — has the
    permission that was required, the role that held it, the policy version that
    decided it and the conditions that matched, without re-reading the database.

    :attr:`decision` is always ``allow``, ``deny`` or ``require_approval``: only the
    policy layer can abstain, and when it does the authorization decision has
    already answered.
    """

    authorization: AuthorizationDecision
    policy: PolicyDecision

    @property
    def decision(self) -> PolicyDecisionKind:
        """The effective outcome.

        One vocabulary for outcomes, shared with the policy layer: ``allow``,
        ``deny`` and ``require_approval``. ``not_applicable`` cannot appear here —
        the authorization decision always says something.
        """
        if self.authorization.denied:
            return PolicyDecisionKind.DENY
        if self.policy.decision is PolicyDecisionKind.NOT_APPLICABLE:
            return PolicyDecisionKind.ALLOW
        return self.policy.decision

    @property
    def reason(self) -> EffectiveReason:
        """Why the effective outcome came out that way."""
        if self.authorization.denied:
            return EffectiveReason.AUTHORIZATION_DENIED
        if self.policy.decision is PolicyDecisionKind.DENY:
            return EffectiveReason.POLICY_DENIED
        if self.policy.decision is PolicyDecisionKind.REQUIRE_APPROVAL:
            return EffectiveReason.POLICY_REQUIRES_APPROVAL
        if self.policy.decision is PolicyDecisionKind.ALLOW:
            return EffectiveReason.POLICY_ALLOWED
        return EffectiveReason.AUTHORIZATION_GRANT

    @property
    def allowed(self) -> bool:
        """Whether the action is permitted outright.

        ``False`` for a request that needs approval — saying otherwise would be the
        one claim this build must never make.
        """
        return self.decision is PolicyDecisionKind.ALLOW

    @property
    def denied(self) -> bool:
        """Whether the action is refused."""
        return self.decision is PolicyDecisionKind.DENY

    @property
    def requires_approval(self) -> bool:
        """Whether a policy requires approval. Nothing here performs one."""
        return self.decision is PolicyDecisionKind.REQUIRE_APPROVAL

    @property
    def organization_id(self) -> uuid.UUID:
        return self.policy.organization_id

    @property
    def resource(self) -> Resource:
        return self.policy.resource

    @property
    def action(self) -> Action:
        return self.policy.action

    @property
    def permission_required(self) -> str | None:
        """The permission Phase 5 was asked about, when it was asked about one."""
        permission = self.authorization.permission
        return None if permission is None else permission.value

    def __repr__(self) -> str:
        return (
            f"<EffectiveDecision {self.decision.value} {self.resource.value}.{self.action.value} "
            f"reason={self.reason.value}>"
        )


def combine(authorization: AuthorizationDecision, policy: PolicyDecision) -> EffectiveDecision:
    """Combine the two layers' answers, refusing to combine two different questions.

    The consistency checks are not ceremony: an authorization decision about one
    organization (or one resource/action) and a policy decision about another are
    not two answers to one question, and quietly combining them would produce an
    outcome that is true of neither. That can only happen through a programming
    mistake, so it raises rather than being reconciled.

    ``resource``/``action`` are compared only when the authorization decision names
    them: a decision that answered "is this caller a member?" (a route that needs
    membership and nothing more) is about no particular permission, and it is
    compatible with any policy decision in the same organization — it still acts as
    a ceiling, because it is either an allow or a denial.
    """
    if (
        authorization.organization_id is not None
        and authorization.organization_id != policy.organization_id
    ):
        raise ValueError(
            "refusing to combine decisions about different organizations: "
            f"{authorization.organization_id} and {policy.organization_id}"
        )
    for asked, enforced in (
        (authorization.resource, policy.resource),
        (authorization.action, policy.action),
    ):
        if asked is not None and asked is not enforced:
            raise ValueError(
                "refusing to combine decisions about different questions: "
                f"{asked.value} and {enforced.value}"
            )
    return EffectiveDecision(authorization=authorization, policy=policy)
