"""Roles and permissions: the catalog authorization resolves against.

Both tables are **reference data**, not tenant data:

- the *permission* catalog is the set of capabilities the application knows how
  to check;
- the *role* catalog is the named bundles of those capabilities that AICore
  ships (owner, admin, security_admin, ai_admin, analyst, viewer);
- ``role_permissions`` records which permissions each role grants.

Which role a member holds is tenant data, and that lives on
:class:`aicore_api.db.models.membership`. So "what can this person do in
organization X?" is answered by joining a tenant-owned row to this catalog —
never by reading the catalog alone.

The catalog is seeded by the migration that creates these tables and asserted
against :mod:`aicore_api.core.permissions` by the test suite, so the two cannot
disagree. Roles are extensible: adding one is a permission code (if needed), a
role row and its grants, in a reviewed migration.
"""

from __future__ import annotations

from sqlalchemy import CheckConstraint, Column, ForeignKey, String, Table, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aicore_api.db.base import APP_SCHEMA, Base, TimestampMixin, UUIDPrimaryKeyMixin

ROLE_CODE_MAX_LENGTH = 32
ROLE_NAME_MAX_LENGTH = 64
ROLE_DESCRIPTION_MAX_LENGTH = 500
PERMISSION_CODE_MAX_LENGTH = 64
PERMISSION_DESCRIPTION_MAX_LENGTH = 300

#: A role code or permission code: lowercase, dot- or underscore-separated.
#: Constrained because these strings are configuration contract, not prose.
CODE_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"

ROLES_TABLE_COMMENT = (
    "System role catalog (reference data). Which role a member holds is recorded "
    "on memberships, which are tenant-owned."
)
PERMISSIONS_TABLE_COMMENT = (
    "Permission catalog: the explicit capabilities authorization checks. Reference "
    "data, shared by every organization."
)
ROLE_PERMISSIONS_TABLE_COMMENT = (
    "Which permissions each role grants. Seeded by migration and asserted against "
    "the code catalog in aicore_api.core.permissions."
)


#: The grant table. A pure mapping, so it is a Core ``Table`` rather than a
#: mapped class — there is nothing to attach to a row beyond its two keys.
#:
#: Deletion behaviour is the interesting part: removing a role removes its grants
#: (CASCADE — a grant to a role that no longer exists means nothing), while
#: removing a permission that is still granted is refused (RESTRICT — it would
#: silently strip a capability from roles that advertise it).
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column(
        "role_id",
        ForeignKey(f"{APP_SCHEMA}.roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "permission_id",
        ForeignKey(f"{APP_SCHEMA}.permissions.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    comment=ROLE_PERMISSIONS_TABLE_COMMENT,
    schema=APP_SCHEMA,
)


class Role(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A named bundle of permissions (``owner``, ``analyst``, …)."""

    __tablename__ = "roles"

    code: Mapped[str] = mapped_column(String(ROLE_CODE_MAX_LENGTH), nullable=False)
    name: Mapped[str] = mapped_column(String(ROLE_NAME_MAX_LENGTH), nullable=False)
    description: Mapped[str] = mapped_column(String(ROLE_DESCRIPTION_MAX_LENGTH), nullable=False)

    grants: Mapped[list[Permission]] = relationship(
        secondary=lambda: role_permissions,
        lazy="selectin",
        order_by="Permission.code",
        viewonly=True,
    )

    __table_args__ = (
        UniqueConstraint("code"),
        CheckConstraint(f"code ~ '{CODE_PATTERN}'", name="code_format"),
        CheckConstraint(
            f"char_length(btrim(name)) BETWEEN 1 AND {ROLE_NAME_MAX_LENGTH}",
            name="name_length",
        ),
        {"comment": ROLES_TABLE_COMMENT},
    )

    def __repr__(self) -> str:
        # The code is a public label (`viewer`), not tenant data.
        return f"<Role code={self.code!r}>"


class Permission(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single capability, e.g. ``user.manage``."""

    __tablename__ = "permissions"

    code: Mapped[str] = mapped_column(String(PERMISSION_CODE_MAX_LENGTH), nullable=False)
    description: Mapped[str] = mapped_column(
        String(PERMISSION_DESCRIPTION_MAX_LENGTH), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("code"),
        CheckConstraint(f"code ~ '{CODE_PATTERN}'", name="code_format"),
        CheckConstraint(
            f"char_length(btrim(description)) BETWEEN 1 AND {PERMISSION_DESCRIPTION_MAX_LENGTH}",
            name="description_length",
        ),
        {"comment": PERMISSIONS_TABLE_COMMENT},
    )

    def __repr__(self) -> str:
        return f"<Permission code={self.code!r}>"


__all__ = [
    "CODE_PATTERN",
    "PERMISSION_CODE_MAX_LENGTH",
    "ROLE_CODE_MAX_LENGTH",
    "Permission",
    "Role",
    "role_permissions",
]
