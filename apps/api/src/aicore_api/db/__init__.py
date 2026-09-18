"""Database foundation.

Phase 1 adds the multi-tenancy foundation on top of the Phase 0 connection:

- :mod:`aicore_api.db.base` — declarative base plus the conventions every table
  follows (UUID keys, timestamps, deterministic constraint names) and the
  ``TenantOwnedMixin`` that declares the tenant boundary.
- :mod:`aicore_api.db.models` — the tables that exist today (``organizations``).
- :mod:`aicore_api.db.tenancy` — the isolation guard: statements touching
  tenant-owned tables are refused unless a tenant is explicitly bound.
- :mod:`aicore_api.db.repositories` — the only place queries are built.

Importing this package installs the guard, which is why the application imports it
during startup rather than relying on each module to remember.
"""

from __future__ import annotations

from aicore_api.db.tenancy import TenantScopeError, bind_tenant, current_tenant

__all__ = ["TenantScopeError", "bind_tenant", "current_tenant"]
