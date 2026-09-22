"""Data access.

Repositories are the only place that builds queries. Three rules apply to every
module added here:

1. Tenant-owned models are reached through
   :class:`aicore_api.db.repositories.organizations.OrganizationScopedRepository`
   (or a subclass of it), never with a bare ``select(model)``.
2. Reads that cross tenants — the tenant registry, and a user's own membership
   list — are confined to named functions in two files, so reviewing tenant
   visibility is reviewing two files.
3. Models that are global on purpose (``users``, ``api_tokens``, ``roles``,
   ``permissions``) are read here without a tenant scope because they carry no
   tenant data. They must never be used to decide what a caller may *see*: that
   answer comes from a membership, which is tenant-owned.
"""

from __future__ import annotations

from aicore_api.db.repositories.api_tokens import ApiTokenRepository
from aicore_api.db.repositories.memberships import MembershipRepository, memberships_for_user
from aicore_api.db.repositories.organizations import (
    OrganizationRepository,
    OrganizationScopedRepository,
)
from aicore_api.db.repositories.rbac import RoleCatalog
from aicore_api.db.repositories.users import UserRepository

__all__ = [
    "ApiTokenRepository",
    "MembershipRepository",
    "OrganizationRepository",
    "OrganizationScopedRepository",
    "RoleCatalog",
    "UserRepository",
    "memberships_for_user",
]
