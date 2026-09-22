"""Roles and permissions — the vocabulary authorization is written in.

Two rules shape this module:

1. **Permissions are explicit.** Authorization code asks "does this membership
   hold ``user.manage``?", never "is this user an ADMIN?". Role names are labels
   for humans; permissions are what the backend enforces. A role whose meaning
   changes is a data change in one place, not a hunt through route handlers.

2. **A role is a set of permissions, declared once.** :data:`ROLE_PERMISSIONS` is
   the single source of truth: the migration that seeds the database is asserted
   against it (``tests/test_authorization.py``), so the catalog in code and the
   catalog in PostgreSQL cannot drift apart.

Scope discipline: the permissions below are exactly those the application can
enforce today — the Phase 2 foundation (organization, membership, role and
read-only oversight) and the Phase 3 AI asset inventory. Permissions for the
policy engine, the action firewall, agent execution, approvals and incidents are
**not** declared yet: they belong to the phases that implement the resources
behind them. A permission with nothing to guard would be a claim, not a control,
and this table would become a document of intentions rather than a description of
the system.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import StrEnum
from types import MappingProxyType

__all__ = [
    "ROLE_INTENTS",
    "ROLE_PERMISSIONS",
    "Permission",
    "RoleCode",
    "all_permissions",
    "permissions_for",
    "role_holds",
    "sort_permissions",
]


class Permission(StrEnum):
    """A capability a membership can be granted.

    Values are stable identifiers: they appear in API responses, in the database
    seed, and eventually in audit records. Renaming one is a migration.
    """

    ORGANIZATION_READ = "organization.read"
    ORGANIZATION_UPDATE = "organization.update"
    USER_READ = "user.read"
    USER_MANAGE = "user.manage"
    ROLE_READ = "role.read"
    ROLE_MANAGE = "role.manage"
    AUDIT_READ = "audit.read"
    SECURITY_READ = "security.read"
    ASSET_READ = "asset.read"
    ASSET_CREATE = "asset.create"
    ASSET_UPDATE = "asset.update"
    ASSET_DELETE = "asset.delete"


class RoleCode(StrEnum):
    """The roles an organization member can hold.

    Extensible by adding a code here together with the seeded row and grants in
    the migration that introduces it. :func:`permissions_for` refuses anything it
    does not know, so an unknown role never resolves silently to "no
    permissions" — or, worse, to "all permissions".
    """

    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_ADMIN = "security_admin"
    AI_ADMIN = "ai_admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


#: The role model. Every role's permissions are listed literally — no role is
#: computed from another — so reading this table is reading the whole policy.
#:
#: - OWNER          — full organization administration.
#: - ADMIN          — general administration, stopping short of ``role.manage``
#:                    (deciding who may do what is an ownership decision) and of
#:                    the security/audit reads (oversight is not administration).
#: - SECURITY_ADMIN — security posture, the audit trail, and *recording* a
#:                    containment decision in the inventory (it may read and update
#:                    assets; it may not create or delete records). Enforcing
#:                    containment at runtime is a later phase with its own
#:                    permission — the inventory state is a record, not an action.
#: - AI_ADMIN       — AI asset/platform administration: creates and maintains
#:                    inventory records, but does not delete them (removing a
#:                    record is an administrative decision, not a stewardship one).
#: - ANALYST        — reads and analyses security information; no management
#:                    permission at all.
#: - VIEWER         — read-only access to what it is granted, and nothing else.
ROLE_PERMISSIONS: Mapping[RoleCode, frozenset[Permission]] = MappingProxyType(
    {
        # Every permission, by construction: OWNER is the role that can do
        # anything inside the organization it owns.
        RoleCode.OWNER: frozenset(Permission),
        RoleCode.ADMIN: frozenset(
            {
                Permission.ORGANIZATION_READ,
                Permission.ORGANIZATION_UPDATE,
                Permission.USER_READ,
                Permission.USER_MANAGE,
                Permission.ROLE_READ,
                Permission.ASSET_READ,
                Permission.ASSET_CREATE,
                Permission.ASSET_UPDATE,
                Permission.ASSET_DELETE,
            }
        ),
        RoleCode.SECURITY_ADMIN: frozenset(
            {
                Permission.ORGANIZATION_READ,
                Permission.USER_READ,
                Permission.AUDIT_READ,
                Permission.SECURITY_READ,
                Permission.ASSET_READ,
                Permission.ASSET_UPDATE,
            }
        ),
        RoleCode.AI_ADMIN: frozenset(
            {
                Permission.ORGANIZATION_READ,
                Permission.USER_READ,
                Permission.ASSET_READ,
                Permission.ASSET_CREATE,
                Permission.ASSET_UPDATE,
            }
        ),
        RoleCode.ANALYST: frozenset(
            {
                Permission.ORGANIZATION_READ,
                Permission.SECURITY_READ,
                Permission.ASSET_READ,
            }
        ),
        RoleCode.VIEWER: frozenset(
            {
                Permission.ORGANIZATION_READ,
                Permission.ASSET_READ,
            }
        ),
    }
)

#: One-line description of what each role is for, shown in the API and in docs.
ROLE_INTENTS: Mapping[RoleCode, str] = MappingProxyType(
    {
        RoleCode.OWNER: "Full organization administration, including roles.",
        RoleCode.ADMIN: "General organization administration.",
        RoleCode.SECURITY_ADMIN: "Security posture, audit trail and containment.",
        RoleCode.AI_ADMIN: "AI asset and AI platform administration.",
        RoleCode.ANALYST: "Read and analyse AI and security information.",
        RoleCode.VIEWER: "Read-only access to permitted resources.",
    }
)


def permissions_for(role: RoleCode | str) -> frozenset[Permission]:
    """The permissions ``role`` grants.

    An unknown role raises rather than resolving to an empty or full set: a
    lookup that silently succeeds on bad input is how a typo becomes a
    permission bug.
    """
    try:
        resolved = RoleCode(role)
    except ValueError as exc:
        raise ValueError(f"unknown role {role!r}") from exc
    return ROLE_PERMISSIONS[resolved]


def all_permissions() -> tuple[Permission, ...]:
    """Every permission, in a stable order (declaration order of the enum)."""
    return tuple(Permission)


def role_holds(role: RoleCode | str, permission: Permission) -> bool:
    """Whether ``role`` grants ``permission``. The whole authorization question."""
    return permission in permissions_for(role)


def sort_permissions(permissions: Iterable[Permission | str]) -> list[str]:
    """Permission codes in a deterministic order, for API responses and tests."""
    return sorted({str(permission) for permission in permissions})
