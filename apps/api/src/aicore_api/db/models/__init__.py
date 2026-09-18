"""SQLAlchemy models.

Importing this package imports every model, which is what registers the tables
on ``Base.metadata``. Alembic's ``env.py`` imports it for exactly that reason:
a model that is not imported here would be invisible to migrations (and the
schema-drift test would catch the omission).
"""

from __future__ import annotations

from aicore_api.db.models.organization import (
    NAME_MAX_LENGTH,
    SLUG_MAX_LENGTH,
    Organization,
    OrganizationStatus,
)

__all__ = [
    "NAME_MAX_LENGTH",
    "SLUG_MAX_LENGTH",
    "Organization",
    "OrganizationStatus",
]
