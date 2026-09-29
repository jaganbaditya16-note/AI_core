"""Pure action enforcement boundary.

Authorization and policy remain authoritative. Phase 11 adds one narrow exception:
a *previously verified, unconsumed human approval* may satisfy a policy's
REQUIRE_APPROVAL result. The approval itself is verified by the persistence layer
before this function is called; this function never trusts an approval identifier.
"""
from __future__ import annotations
import uuid
from dataclasses import dataclass
from enum import StrEnum
from aicore_api.auth.authorization import AuthorizationDecision
from aicore_api.auth.policy import EffectiveDecision, EffectiveReason
from aicore_api.core.actions import ActionDefinition, ActionRequest, ActionTarget
from aicore_api.core.permissions import Permission

class FirewallConfigurationError(RuntimeError):
    """The enforcement pipeline was assembled inconsistently."""

class FirewallOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"

class FirewallReason(StrEnum):
    ALLOWED = "allowed"
    AUTHORIZATION_DENIED = "authorization_denied"
    POLICY_DENIED = "policy_denied"
    POLICY_REQUIRES_APPROVAL = "policy_requires_approval"
    TARGET_NOT_FOUND = "target_not_found"
    ENVIRONMENT_MISMATCH = "environment_mismatch"
    APPROVAL_ACCEPTED = "approval_accepted"

_DENYING_POLICY_REASONS: frozenset[EffectiveReason] = frozenset({EffectiveReason.POLICY_DENIED, EffectiveReason.AUTHORIZATION_DENIED})

@dataclass(frozen=True, slots=True)
class FirewallDecision:
    outcome: FirewallOutcome
    reason: FirewallReason
    action_id: str
    target_id: uuid.UUID
    organization_id: uuid.UUID
    correlation_id: str
    effective: EffectiveDecision
    @property
    def allowed(self) -> bool:
        return self.outcome is FirewallOutcome.ALLOW
    @property
    def denied(self) -> bool:
        return self.outcome is FirewallOutcome.DENY
    @property
    def requires_approval(self) -> bool:
        return self.outcome is FirewallOutcome.REQUIRE_APPROVAL
    @property
    def permission_required(self) -> str:
        return str(self.effective.permission_required)
    @property
    def policy_decision(self) -> str:
        return str(self.effective.policy.decision.value)
    @property
    def effective_reason(self) -> str:
        return str(self.effective.reason.value)
    @property
    def principal_role(self) -> str | None:
        return self.effective.authorization.role_code


def _require(value: object, message: str) -> None:
    if not value:
        raise FirewallConfigurationError(message)


def decide(*, request: ActionRequest, definition: ActionDefinition, target: ActionTarget | None,
           authorization: AuthorizationDecision, policy: EffectiveDecision, approved: bool = False) -> FirewallDecision:
    _require(definition.action_id == request.action_id, "definition and request name different actions")
    _require(authorization.organization_id == request.organization_id, "authorization is for another organization")
    _require(authorization.permission is Permission.ACTION_EXECUTE, "authorization is not action.execute")
    _require(policy.organization_id == request.organization_id and policy.resource == definition.policy_target[0] and policy.action == definition.policy_target[1], "policy decision is for another target")
    def result(outcome: FirewallOutcome, reason: FirewallReason) -> FirewallDecision:
        return FirewallDecision(outcome, reason, request.action_id, request.target_id, request.organization_id, request.correlation_id, policy)
    if authorization.denied:
        return result(FirewallOutcome.DENY, FirewallReason.AUTHORIZATION_DENIED)
    if target is None:
        return result(FirewallOutcome.DENY, FirewallReason.TARGET_NOT_FOUND)
    _require(target.resource is definition.target_resource, "target resource does not match action")
    _require(target.identifier == request.target_id, "resolved target does not match request")
    if target.environment is not request.environment:
        return result(FirewallOutcome.DENY, FirewallReason.ENVIRONMENT_MISMATCH)
    if policy.denied or policy.reason in _DENYING_POLICY_REASONS:
        return result(FirewallOutcome.DENY, FirewallReason.POLICY_DENIED)
    if policy.requires_approval:
        if approved:
            return result(FirewallOutcome.ALLOW, FirewallReason.APPROVAL_ACCEPTED)
        return result(FirewallOutcome.REQUIRE_APPROVAL, FirewallReason.POLICY_REQUIRES_APPROVAL)
    if not policy.allowed:
        raise FirewallConfigurationError("unknown effective policy outcome")
    # An approval cannot widen an ordinary ALLOW and cannot override a DENY.
    return result(FirewallOutcome.ALLOW, FirewallReason.ALLOWED)
