"""Identity and access contract.

The shapes here answer the five questions Phase 2 exists to answer: who the
caller is (``MeResponse.user``), which organizations they belong to
(``MeResponse.memberships[].organization``), what role they hold there
(``role``), what that role grants (``permissions``), and — implicitly, by
carrying the same fields on the organization-scoped responses — that everything
is answered *inside one tenant*.

Nothing here exposes a credential. A token is shown once, by the CLI that issues
it; no response model has a field for one.

Note what is absent: no organization-management, no invitations, no policy or
agent fields. Those are later phases, and a field published now would be a
promise this build does not keep.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict

__all__ = [
    "MeResponse",
    "MemberListResponse",
    "MemberRead",
    "MembershipRead",
    "OrganizationSummary",
    "PermissionListResponse",
    "PermissionRead",
    "RoleListResponse",
    "RoleRead",
    "RoleSummary",
    "UserRead",
    "membership_status",
    "user_status",
]

UserStatusLiteral = Literal["active", "suspended"]
MembershipStatusLiteral = Literal["active", "suspended"]
OrganizationStatusLiteral = Literal["active", "suspended", "archived"]


def _narrow_status(value: str, allowed: frozenset[str]) -> str:
    """Return ``value`` if it is one of ``allowed``, else fail loudly.

    Statuses are stored as text and constrained by a database CHECK, so this can
    only fire if the database and the published contract disagree — in which case
    refusing to serialise is the right outcome: publishing a status outside the
    Literal would break every client's exhaustive switch.
    """
    if value not in allowed:
        raise ValueError(f"unexpected status {value!r}; the database and the API contract disagree")
    return value


def user_status(value: str) -> UserStatusLiteral:
    """Narrow a stored user status to the published literal."""
    return cast("UserStatusLiteral", _narrow_status(value, frozenset({"active", "suspended"})))


def membership_status(value: str) -> MembershipStatusLiteral:
    """Narrow a stored membership status to the published literal."""
    return cast(
        "MembershipStatusLiteral", _narrow_status(value, frozenset({"active", "suspended"}))
    )


class UserRead(BaseModel):
    """A person, as the API describes them."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: str
    status: UserStatusLiteral


class OrganizationSummary(BaseModel):
    """The tenant a membership belongs to."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    status: OrganizationStatusLiteral


class RoleSummary(BaseModel):
    """A role, without its permission set (which is a catalog fact, not a grant)."""

    code: str
    name: str


class MembershipRead(BaseModel):
    """One of the caller's memberships, with the permissions it resolves to.

    ``permissions`` is empty for a membership that is not active: a suspended
    grant must never be readable as usable.
    """

    organization: OrganizationSummary
    role: RoleSummary
    status: MembershipStatusLiteral
    permissions: list[str]


class MeResponse(BaseModel):
    """``GET /me``: the caller's identity and every organization they belong to."""

    user: UserRead
    memberships: list[MembershipRead]


class MemberRead(BaseModel):
    """One member of an organization, as seen from inside that organization."""

    user: UserRead
    role: RoleSummary
    status: MembershipStatusLiteral
    created_at: datetime


class MemberListResponse(BaseModel):
    """``GET /organizations/{organization_id}/members``.

    ``organization_id`` is echoed so a response is self-describing: a client
    holding two of these can never mix up which tenant a directory came from.
    """

    organization_id: uuid.UUID
    members: list[MemberRead]


class RoleRead(BaseModel):
    """A role and the permissions it grants, as published to an organization."""

    code: str
    name: str
    description: str
    permissions: list[str]


class RoleListResponse(BaseModel):
    """``GET /organizations/{organization_id}/roles``."""

    organization_id: uuid.UUID
    roles: list[RoleRead]


class PermissionRead(BaseModel):
    """One capability the application knows how to check."""

    code: str
    description: str


class PermissionListResponse(BaseModel):
    """``GET /organizations/{organization_id}/permissions``."""

    organization_id: uuid.UUID
    permissions: list[PermissionRead]
