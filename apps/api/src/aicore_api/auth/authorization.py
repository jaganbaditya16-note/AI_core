"""Authorization: from "who is calling" to "may they do this, here?".

The flow is deliberately linear, and every step is a database fact rather than an
assumption:

    authenticate → identify user → resolve organization → verify membership
                 → resolve role → resolve permissions → authorize

Failure modes are chosen so that nothing leaks and nothing is guessed:

- **The organization does not exist** and **the caller is not a member of it**
  produce the *same* :class:`~aicore_api.core.domain_errors.NotFoundError`. A 403
  for the second case would confirm that the tenant exists, which is exactly what
  a cross-tenant probe is looking for.
- **The membership exists but is suspended** produces
  :class:`~aicore_api.core.domain_errors.PermissionDeniedError`: the caller is a
  member, so telling them their access is suspended reveals nothing they cannot
  already see in their own membership list.
- **A role the code does not know** is a fail-closed error, never an empty (or
  full) permission set. :func:`aicore_api.core.permissions.permissions_for`
  raises, and the request ends in a 500 — a deployment defect should be loud, not
  silently permissive or silently useless.

Everything here is server-side. The same call path is used whether the client is
the web UI, a script or a future agent, so there is no "authorization that only
exists in the frontend".
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from aicore_api.auth.principal import Principal
from aicore_api.core.domain_errors import NotFoundError, PermissionDeniedError
from aicore_api.core.permissions import Permission, permissions_for, sort_permissions
from aicore_api.db.models.membership import Membership, MembershipStatus
from aicore_api.db.models.organization import Organization
from aicore_api.db.repositories.memberships import MembershipRepository
from aicore_api.db.repositories.organizations import OrganizationRepository

__all__ = ["OrganizationContext", "resolve_organization_context"]


@dataclass(frozen=True, slots=True)
class OrganizationContext:
    """An authorized caller, inside one organization.

    This is what a protected route receives instead of an organization id: the
    membership has been verified and the permissions resolved before the handler
    body runs, so a handler cannot forget either step.
    """

    organization: Organization
    membership: Membership
    role_code: str
    permissions: frozenset[Permission]

    @property
    def organization_id(self) -> uuid.UUID:
        return self.organization.id

    @property
    def user_id(self) -> uuid.UUID:
        return self.membership.user_id

    def holds(self, permission: Permission) -> bool:
        """Whether this membership grants ``permission``."""
        return permission in self.permissions

    def permission_codes(self) -> list[str]:
        """Granted permissions, in a stable order (for responses)."""
        return sort_permissions(self.permissions)


def resolve_organization_context(
    session: Session,
    principal: Principal,
    organization_id: uuid.UUID,
    *,
    required: Permission | None = None,
) -> OrganizationContext:
    """Authorize ``principal`` inside ``organization_id``.

    Returns the resolved context, or raises. ``required`` is the permission the
    route needs; when it is ``None`` the caller is only required to be an active
    member (used by routes that expose a caller's own membership).
    """
    organization = OrganizationRepository(session).find(organization_id)
    if organization is None:
        # Same error as "not a member": an outsider must not be able to tell
        # whether a tenant exists.
        raise NotFoundError("organization not found")

    membership = MembershipRepository(session, organization_id).find_for_user(principal.user_id)
    if membership is None:
        raise NotFoundError("organization not found")

    if membership.status != MembershipStatus.ACTIVE.value:
        raise PermissionDeniedError("your membership in this organization is not active")

    # Raises ValueError for a role code the code catalog does not know: refuse to
    # authorize against a policy this build cannot reason about.
    permissions = permissions_for(membership.role.code)

    if required is not None and required not in permissions:
        raise PermissionDeniedError(f"this operation requires the {required} permission")

    return OrganizationContext(
        organization=organization,
        membership=membership,
        role_code=membership.role.code,
        permissions=permissions,
    )
