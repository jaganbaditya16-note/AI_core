"""Memberships: the tenant-owned grant that ties a user to an organization.

This table is where authorization actually lives. "What may this person do?" is
answered by following one row:

``membership (organization_id, user_id) → role → role_permissions → permissions``

It is **tenant-owned** (it inherits :class:`~aicore_api.db.base.TenantOwnedMixin`),
which means the isolation guard in :mod:`aicore_api.db.tenancy` refuses to read
it without a bound tenant and an ``organization_id`` filter. A user's own
membership rows are the one legitimate cross-tenant read (a person can belong to
several organizations, and must be able to discover which); that read is named
and confined in :func:`aicore_api.db.repositories.memberships.memberships_for_user`.

Deletion behaviour, chosen so that no grant can outlive its subject:

- deleting a **user** removes their memberships (CASCADE): a membership without
  an identity is not a grant, it is dangling authority;
- deleting a **role** is refused while memberships use it (RESTRICT): a role in
  use is part of the authorization state;
- deleting an **organization** is refused (RESTRICT, from the mixin) while
  memberships exist — the Phase 1 rule for every tenant-owned table.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aicore_api.db.base import (
    APP_SCHEMA,
    Base,
    TenantOwnedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from aicore_api.db.models.rbac import Role
from aicore_api.db.models.user import User

STATUS_MAX_LENGTH = 32


class MembershipStatus(StrEnum):
    """Lifecycle of a grant.

    Only ``active`` authorizes anything. A ``suspended`` membership still
    exists — it must, so the organization can see that the person is a member
    and that their access is suspended — and resolves to a refusal.
    """

    ACTIVE = "active"
    SUSPENDED = "suspended"


_STATUS_CHECK = "status IN ({})".format(
    ", ".join(f"'{status.value}'" for status in MembershipStatus)
)

TABLE_COMMENT = (
    "Membership of a user in an organization, carrying the role that grants their "
    "permissions. Tenant-owned: reads require a bound organization."
)


class Membership(UUIDPrimaryKeyMixin, TimestampMixin, TenantOwnedMixin, Base):
    """One user's role inside one organization."""

    __tablename__ = "memberships"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey(f"{APP_SCHEMA}.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey(f"{APP_SCHEMA}.roles.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(STATUS_MAX_LENGTH),
        nullable=False,
        server_default=MembershipStatus.ACTIVE.value,
    )

    # Eager, joined loading is not a performance tweak here: authorization always
    # needs the role and the person. It also keeps lookups to one statement, so
    # there is no second query that could reach a tenant-owned table without the
    # tenant filter the guard requires.
    role: Mapped[Role] = relationship(lazy="joined")
    user: Mapped[User] = relationship(lazy="joined")

    __table_args__ = (
        # One membership per person per organization: a second grant would make
        # "what is this user's role here?" ambiguous, and ambiguity in an
        # authorization decision is a defect, not a feature.
        UniqueConstraint("organization_id", "user_id"),
        CheckConstraint(_STATUS_CHECK, name="status_valid"),
        {"comment": TABLE_COMMENT},
    )

    def __repr__(self) -> str:
        """Identifiers only: a membership names a person, so no email here."""
        return (
            f"<Membership id={self.id} organization_id={self.organization_id} "
            f"user_id={self.user_id} status={self.status!r}>"
        )


__all__ = ["Membership", "MembershipStatus"]
