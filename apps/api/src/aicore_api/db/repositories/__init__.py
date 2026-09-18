"""Data access.

Repositories are the only place that builds queries. Two rules apply to every
module added here:

1. Tenant-owned models are reached through
   :class:`aicore_api.db.repositories.organizations.OrganizationScopedRepository`
   (or a subclass of it), never with a bare ``select(model)``.
2. Reading across tenants is only possible through
   :class:`aicore_api.db.repositories.organizations.OrganizationRepository`, so
   review of tenant visibility is review of one file.
"""

from __future__ import annotations

from aicore_api.db.repositories.organizations import (
    OrganizationRepository,
    OrganizationScopedRepository,
)

__all__ = ["OrganizationRepository", "OrganizationScopedRepository"]
