"""Resolving an owner *within* an organization — the tenant-integrity rule, in one place.

Both the inventory and the agent registry accept an owner as a user id and store a
membership. That translation is a security rule, not a convenience:

- the membership must belong to **this** organization, so an id from another tenant
  resolves to nothing and is refused;
- the membership must be **active**, so a suspended member cannot be handed new
  responsibilities;
- the caller never supplies the membership id itself, so there is no way to assert
  ownership that was not resolved here.

The database would refuse a foreign or invented owner anyway — ``assets`` has a
composite foreign key to ``memberships(organization_id, id)`` — but a 422 that
names the problem is a better answer than an integrity error, and resolving here is
what makes "the owner is a member of this tenant" true at the API boundary as well
as in the schema.

Shared by both route modules rather than copied into each: two copies of a rule like
this are two places for it to drift, and the drift would be silent.
"""

from __future__ import annotations

import uuid

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from aicore_api.db.models.membership import MembershipStatus
from aicore_api.db.repositories.memberships import MembershipRepository

__all__ = ["resolve_owner_membership"]


def resolve_owner_membership(
    session: Session, organization_id: uuid.UUID, user_id: uuid.UUID | None
) -> uuid.UUID | None:
    """Resolve an owner user id to a membership of ``organization_id``, or refuse it.

    ``None`` means "no owner stated" and stays ``None``, so a caller can tell
    "remove the owner" (a clear flag, handled by the route) from "no opinion".
    """
    if user_id is None:
        return None
    membership = MembershipRepository(session, organization_id).find_for_user(user_id)
    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="owner must be a member of this organization",
        )
    if membership.status != MembershipStatus.ACTIVE.value:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="owner must be an active member of this organization",
        )
    return membership.id
