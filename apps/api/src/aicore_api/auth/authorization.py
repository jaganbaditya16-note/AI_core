"""Authorization: from "who is calling" to "may they do this, here?".

The flow is deliberately linear, and every step is a database fact rather than an
assumption:

    authenticate → identify user → resolve organization → verify membership
                 → resolve role → resolve permissions → authorize

Authorization is a **deterministic decision**, never a model call and never a
guess. Phase 5 makes that decision an explicit value:
:class:`AuthorizationDecision` — allowed or denied, about one permission, in one
organization, with a machine-readable :class:`DecisionReason` — computed by
:func:`authorize` from the caller's membership, the role recorded for it, the
permissions that role grants, and (when a concrete row is involved) that row's
tenant. Nothing in this path consults a policy engine, a network service or an
LLM; those are later phases, and they will consume this structure rather than
re-deriving it.

Failure modes are chosen so that nothing leaks and nothing is guessed:

- **The organization does not exist** and **the caller is not a member of it**
  produce the *same* denial (:attr:`DecisionReason.NO_MEMBERSHIP`) and, at the HTTP
  boundary, the same 404. A 403 for the second case would confirm that the tenant
  exists, which is exactly what a cross-tenant probe is looking for.
- **The membership exists but is suspended** is
  :attr:`DecisionReason.MEMBERSHIP_INACTIVE`: the caller is a member, so telling
  them their access is suspended reveals nothing they cannot already see in their
  own membership list.
- **A row in another organization** is
  :attr:`DecisionReason.RESOURCE_OUTSIDE_TENANT`, and the HTTP boundary answers it
  like a row that does not exist — the same indistinguishability, one level down.
- **A role the code does not know** is a fail-closed *denial* in the decision
  (:attr:`DecisionReason.UNKNOWN_ROLE`), so the decision layer is total and never
  silently permissive. The HTTP boundary still raises for it, because a
  deployment whose database holds a role this build cannot reason about is a
  defect that should be loud rather than a quiet 403.

Everything here is server-side. The same call path is used whether the client is
the web UI, a script or a future agent, so there is no "authorization that only
exists in the frontend".
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from sqlalchemy.orm import Session

from aicore_api.auth.principal import Principal
from aicore_api.core.domain_errors import NotFoundError, PermissionDeniedError
from aicore_api.core.permissions import (
    Action,
    Permission,
    Resource,
    permissions_for,
    sort_permissions,
)
from aicore_api.db.models.membership import Membership, MembershipStatus
from aicore_api.db.models.organization import Organization
from aicore_api.db.repositories.memberships import MembershipRepository
from aicore_api.db.repositories.organizations import OrganizationRepository

__all__ = [
    "AuthorizationDecision",
    "DecisionReason",
    "OrganizationContext",
    "ResourceScope",
    "authorize",
    "authorize_instance",
    "decide",
    "resolve_organization_context",
]


class DecisionReason(StrEnum):
    """Why an authorization decision came out the way it did.

    Stable identifiers, like every other code in this system: a later phase (audit,
    policy) can record them without parsing prose. The ``ALLOWED_*`` reasons mean
    the decision permitted the action; every other value means it did not.
    """

    #: The membership is active and its role grants the permission.
    ALLOWED = "role_permission_grant"
    #: The membership is active and no permission was asked for — used by routes
    #: that only require the caller to be a member (``GET /me``).
    ALLOWED_MEMBERSHIP = "active_membership"
    #: The caller holds no membership in that organization, so the organization is
    #: indistinguishable from one that does not exist.
    NO_MEMBERSHIP = "missing_membership"
    #: The membership exists but is not active.
    MEMBERSHIP_INACTIVE = "membership_not_active"
    #: The membership is active and the role is known, but the permission is not
    #: among the ones that role grants.
    MISSING_PERMISSION = "missing_permission"
    #: A concrete row was involved and it belongs to a different organization.
    RESOURCE_OUTSIDE_TENANT = "resource_outside_tenant"
    #: The role recorded for this membership is not in the code catalog.
    UNKNOWN_ROLE = "unknown_role"

    @property
    def allowed(self) -> bool:
        """Whether this reason describes a permitted decision."""
        return self in {DecisionReason.ALLOWED, DecisionReason.ALLOWED_MEMBERSHIP}


class TenantResource(Protocol):
    """The tenant facts a concrete row must be able to state.

    Structural on purpose: an :class:`~aicore_api.db.models.asset.Asset` and an
    :class:`~aicore_api.db.models.agent.Agent` both satisfy it without inheriting
    from anything, and the authorization layer stays free of ORM imports.
    """

    organization_id: uuid.UUID


@dataclass(frozen=True, slots=True)
class ResourceScope:
    """The tenant facts of one row a decision is about.

    Deliberately small. The composite foreign keys already guarantee that an owner
    membership belongs to the same organization as the row it owns, so ownership is
    information a decision *reports* (:attr:`AuthorizationDecision.principal_is_owner`)
    rather than a second thing to verify here. Ownership is not a permission in
    this build: it is a fact a later phase's policy can read, and reading it must
    never widen an ALLOW.
    """

    organization_id: uuid.UUID
    #: The membership that owns the row, when the row has an owner. ``None`` means
    #: "not owned", which is a valid state for an inventory record.
    owner_membership_id: uuid.UUID | None = None

    @classmethod
    def of(cls, instance: TenantResource) -> ResourceScope:
        """Read the scope off a row.

        Refuses an object that cannot state its organization instead of guessing:
        an unscoped row is exactly the case where a tenant check would be
        meaningless, and a silent default here would be an authorization hole.
        """
        organization_id = getattr(instance, "organization_id", None)
        if not isinstance(organization_id, uuid.UUID):
            raise TypeError(
                f"{type(instance).__name__} does not state an organization_id, so it cannot be "
                "authorized as a tenant-owned row"
            )
        owner_membership_id = getattr(instance, "owner_membership_id", None)
        if owner_membership_id is not None and not isinstance(owner_membership_id, uuid.UUID):
            raise TypeError(f"{type(instance).__name__}.owner_membership_id is not a UUID or None")
        return cls(organization_id=organization_id, owner_membership_id=owner_membership_id)


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """The result of one authorization question, as a value.

    Fields:

    - ``allowed`` — the answer;
    - ``reason`` — why, as a :class:`DecisionReason`;
    - ``permission`` — the permission that was asked about (``None`` when the
      question was only "is this caller a member?");
    - ``organization_id`` — the organization the question was asked in;
    - ``role_code`` — the role that decided it, when a membership was resolved;
    - ``membership_id`` / ``instance_organization_id`` — the identifiers the
      decision was made from, so a later phase can record *what* was decided
      without re-reading the database;
    - ``principal_is_owner`` — ``True``/``False`` when a concrete row with an owner
      was involved, ``None`` when nothing was known about ownership. Informational:
      it never changes ``allowed`` in this phase.
    """

    allowed: bool
    reason: DecisionReason
    permission: Permission | None = None
    organization_id: uuid.UUID | None = None
    role_code: str | None = None
    membership_id: uuid.UUID | None = None
    instance_organization_id: uuid.UUID | None = None
    principal_is_owner: bool | None = None

    @property
    def resource(self) -> Resource | None:
        """The resource the decision is about, when it is about a permission."""
        return None if self.permission is None else self.permission.resource

    @property
    def action(self) -> Action | None:
        """The action the decision is about, when it is about a permission."""
        return None if self.permission is None else self.permission.action

    @property
    def denied(self) -> bool:
        """The negation of :attr:`allowed`, for readability at call sites."""
        return not self.allowed

    def __repr__(self) -> str:
        # Compact and stable: a decision ends up in log lines and test failures.
        asked = "membership" if self.permission is None else str(self.permission)
        return (
            f"<AuthorizationDecision {'ALLOW' if self.allowed else 'DENY'} "
            f"{asked} reason={self.reason.value}>"
        )


@dataclass(frozen=True, slots=True)
class OrganizationContext:
    """An authorized caller, inside one organization.

    This is what a protected route receives instead of an organization id: the
    membership has been verified and the permissions resolved before the handler
    body runs, so a handler cannot forget either step. It carries the
    :class:`AuthorizationDecision` that produced it, which is what makes
    "why was this allowed?" answerable without repeating the resolution.
    """

    organization: Organization
    membership: Membership
    role_code: str
    permissions: frozenset[Permission]
    decision: AuthorizationDecision | None = None

    @property
    def organization_id(self) -> uuid.UUID:
        return self.organization.id

    @property
    def user_id(self) -> uuid.UUID:
        return self.membership.user_id

    @property
    def membership_id(self) -> uuid.UUID:
        return self.membership.id

    def holds(self, permission: Permission) -> bool:
        """Whether this membership grants ``permission``."""
        return permission in self.permissions

    def permission_codes(self) -> list[str]:
        """Granted permissions, in a stable order (for responses)."""
        return sort_permissions(self.permissions)


def _decision(
    *,
    allowed: bool,
    reason: DecisionReason,
    permission: Permission | None,
    organization_id: uuid.UUID,
    membership: Membership | None,
    scope: ResourceScope | None,
) -> AuthorizationDecision:
    """Assemble a decision, filling in the identifiers every caller wants."""
    return AuthorizationDecision(
        allowed=allowed,
        reason=reason,
        permission=permission,
        organization_id=organization_id,
        role_code=None if membership is None else membership.role.code,
        membership_id=None if membership is None else membership.id,
        instance_organization_id=None if scope is None else scope.organization_id,
        principal_is_owner=(
            None
            if membership is None or scope is None or scope.owner_membership_id is None
            else scope.owner_membership_id == membership.id
        ),
    )


def decide(
    membership: Membership | None,
    *,
    organization_id: uuid.UUID,
    permission: Permission | None = None,
    scope: ResourceScope | None = None,
) -> AuthorizationDecision:
    """Decide ``permission`` for ``membership``, without touching the database.

    A pure function of the facts, which is what makes the decision layer testable
    and deterministic: the same membership, permission and scope always produce the
    same decision, and there is nothing in here that could call out to a model.

    ``scope`` adds the instance dimension: a row in another organization is denied
    even for a caller holding the permission, because tenancy is part of the
    question, not an assumption about the query that loaded the row.
    """
    if membership is None:
        return _decision(
            allowed=False,
            reason=DecisionReason.NO_MEMBERSHIP,
            permission=permission,
            organization_id=organization_id,
            membership=None,
            scope=scope,
        )

    if membership.status != MembershipStatus.ACTIVE.value:
        return _decision(
            allowed=False,
            reason=DecisionReason.MEMBERSHIP_INACTIVE,
            permission=permission,
            organization_id=organization_id,
            membership=membership,
            scope=scope,
        )

    try:
        permissions = permissions_for(membership.role.code)
    except ValueError:
        # Fail closed: a role this build cannot reason about grants nothing, and
        # the reason makes the defect visible instead of looking like a normal 403.
        return _decision(
            allowed=False,
            reason=DecisionReason.UNKNOWN_ROLE,
            permission=permission,
            organization_id=organization_id,
            membership=membership,
            scope=scope,
        )

    if scope is not None and scope.organization_id != organization_id:
        return _decision(
            allowed=False,
            reason=DecisionReason.RESOURCE_OUTSIDE_TENANT,
            permission=permission,
            organization_id=organization_id,
            membership=membership,
            scope=scope,
        )

    if permission is not None and permission not in permissions:
        return _decision(
            allowed=False,
            reason=DecisionReason.MISSING_PERMISSION,
            permission=permission,
            organization_id=organization_id,
            membership=membership,
            scope=scope,
        )

    return _decision(
        allowed=True,
        reason=(
            DecisionReason.ALLOWED_MEMBERSHIP if permission is None else DecisionReason.ALLOWED
        ),
        permission=permission,
        organization_id=organization_id,
        membership=membership,
        scope=scope,
    )


def authorize(
    session: Session,
    principal: Principal,
    organization_id: uuid.UUID,
    permission: Permission | None = None,
    *,
    scope: ResourceScope | None = None,
) -> AuthorizationDecision:
    """Answer "may ``principal`` use ``permission`` in ``organization_id``?".

    Resolves the caller's membership in that organization and returns a decision;
    it never raises for a denial, so a caller that wants to *report* rather than
    refuse (a future policy layer, an audit record) can consume the answer
    directly. ``resolve_organization_context`` is the raising wrapper the HTTP
    routes use.
    """
    membership = MembershipRepository(session, organization_id).find_for_user(principal.user_id)
    return decide(
        membership,
        organization_id=organization_id,
        permission=permission,
        scope=scope,
    )


def authorize_instance(
    context: OrganizationContext,
    scope: ResourceScope,
    *,
    permission: Permission | None = None,
) -> AuthorizationDecision:
    """Decide an action on **one row**, from an already-authorized context.

    Pure and database-free: the context already proved the membership and its
    permissions, so this adds the instance dimension — the row's tenant, and the
    ownership fact — which is what turns "holds ``asset.update``" into "holds
    ``asset.update`` *for this row*". Routes use it after loading a row, so a
    repository that lost its tenant filter (a bug, not a policy) fails the request
    instead of serving another organization's data.
    """
    if scope.organization_id != context.organization_id:
        return AuthorizationDecision(
            allowed=False,
            reason=DecisionReason.RESOURCE_OUTSIDE_TENANT,
            permission=permission,
            organization_id=context.organization_id,
            role_code=context.role_code,
            membership_id=context.membership_id,
            instance_organization_id=scope.organization_id,
            principal_is_owner=None,
        )

    if permission is not None and not context.holds(permission):
        return AuthorizationDecision(
            allowed=False,
            reason=DecisionReason.MISSING_PERMISSION,
            permission=permission,
            organization_id=context.organization_id,
            role_code=context.role_code,
            membership_id=context.membership_id,
            instance_organization_id=scope.organization_id,
            principal_is_owner=None,
        )

    return AuthorizationDecision(
        allowed=True,
        reason=(
            DecisionReason.ALLOWED_MEMBERSHIP if permission is None else DecisionReason.ALLOWED
        ),
        permission=permission,
        organization_id=context.organization_id,
        role_code=context.role_code,
        membership_id=context.membership_id,
        instance_organization_id=scope.organization_id,
        principal_is_owner=(
            None
            if scope.owner_membership_id is None
            else scope.owner_membership_id == context.membership_id
        ),
    )


def _refusal(decision: AuthorizationDecision, required: Permission | None) -> Exception:
    """Translate a denial into the domain error the HTTP boundary publishes.

    The mapping is the phase's security contract, not a detail: "no membership"
    and "another tenant's row" both become :class:`NotFoundError` so that a
    resource's existence is not confirmed to someone who may not see it, while a
    member who simply lacks the permission gets
    :class:`PermissionDeniedError`.
    """
    if decision.reason in {
        DecisionReason.NO_MEMBERSHIP,
        DecisionReason.RESOURCE_OUTSIDE_TENANT,
    }:
        return NotFoundError(
            "organization not found"
            if decision.reason is DecisionReason.NO_MEMBERSHIP
            else "resource not found in this organization"
        )
    if decision.reason is DecisionReason.UNKNOWN_ROLE:
        # Loud on purpose: a role the code cannot reason about is a deployment
        # defect (the catalog and the seed disagree), not a caller's mistake.
        return ValueError(
            f"role {decision.role_code!r} is not in the code catalog; refusing to authorize"
        )
    if decision.reason is DecisionReason.MEMBERSHIP_INACTIVE:
        return PermissionDeniedError("your membership in this organization is not active")
    return PermissionDeniedError(f"this operation requires the {required} permission")


def resolve_organization_context(
    session: Session,
    principal: Principal,
    organization_id: uuid.UUID,
    *,
    required: Permission | None = None,
    scope: ResourceScope | None = None,
) -> OrganizationContext:
    """Authorize ``principal`` inside ``organization_id``.

    Returns the resolved context, or raises. ``required`` is the permission the
    route needs; when it is ``None`` the caller is only required to be an active
    member (used by routes that expose a caller's own membership). ``scope`` adds
    a concrete row to the question, for callers that already know which row they
    are about to act on.
    """
    membership = MembershipRepository(session, organization_id).find_for_user(principal.user_id)
    decision = decide(
        membership,
        organization_id=organization_id,
        permission=required,
        scope=scope,
    )
    if decision.denied:
        raise _refusal(decision, required)

    # A denial is already returned above, so the membership is active here and the
    # role is one this build knows how to resolve.
    assert membership is not None  # noqa: S101 - the branch above is exhaustive
    permissions = permissions_for(membership.role.code)

    organization = OrganizationRepository(session).find(organization_id)
    if organization is None:
        # Unreachable while the membership exists (memberships reference the
        # organization), and kept as a 404 rather than an assertion so that a
        # broken deployment fails closed.
        raise NotFoundError("organization not found")

    return OrganizationContext(
        organization=organization,
        membership=membership,
        role_code=membership.role.code,
        permissions=permissions,
        decision=decision,
    )
