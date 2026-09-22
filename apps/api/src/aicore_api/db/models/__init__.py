"""SQLAlchemy models.

Importing this package imports every model, which is what registers the tables on
``Base.metadata``. Alembic's ``env.py`` imports it for exactly that reason: a
model that is not imported here would be invisible to migrations (and the
schema-drift test would catch the omission).

Phase 1 shipped the tenant root. Phase 2 added identity and authorization:
``users`` and ``api_tokens`` (who is calling), ``roles`` / ``permissions`` /
``role_permissions`` (what a role may do) and ``memberships`` (the tenant-owned
grant that ties the two together). Phase 3 adds the inventory: ``assets``, the
tenant-owned record of every AI-related thing an organization knows about. Phase 4
adds the agent registry: ``agents``, the stable identity of one of those assets.

Keep the per-type distinction in ``core/assets.py``, not here: assets of different
types share one table on purpose (see ``db/models/asset.py``).
"""

from __future__ import annotations

from aicore_api.db.models.agent import Agent
from aicore_api.db.models.api_token import ApiToken
from aicore_api.db.models.asset import Asset
from aicore_api.db.models.membership import Membership, MembershipStatus
from aicore_api.db.models.organization import (
    NAME_MAX_LENGTH,
    SLUG_MAX_LENGTH,
    Organization,
    OrganizationStatus,
)
from aicore_api.db.models.rbac import Permission, Role, role_permissions
from aicore_api.db.models.user import User, UserStatus, normalize_email

__all__ = [
    "NAME_MAX_LENGTH",
    "SLUG_MAX_LENGTH",
    "Agent",
    "ApiToken",
    "Asset",
    "Membership",
    "MembershipStatus",
    "Organization",
    "OrganizationStatus",
    "Permission",
    "Role",
    "User",
    "UserStatus",
    "normalize_email",
    "role_permissions",
]
