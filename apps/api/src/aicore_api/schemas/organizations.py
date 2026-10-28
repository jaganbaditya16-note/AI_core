"""Organization contract.

Deliberately minimum viable: enough to prove that the database foundation works
end to end (a tenant can be created and read back). A full organization
management API — rename, status transitions, suspension, deletion, membership —
belongs to the identity phase, together with the authorization that must guard it.

Note what is *absent*: no member, role, permission or policy fields. There is no
authentication in this build either, which is why this router is read/write only
in development and test environments (see ``api/routes/organizations.py``).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from aicore_api.db.models.organization import NAME_MAX_LENGTH, SLUG_MAX_LENGTH


class OrganizationCreate(BaseModel):
    """Request body for creating a tenant.

    ``status`` is not accepted: a tenant is created ``active``. Letting a caller
    choose its own lifecycle state is an authorization decision, and there is no
    authorization in this phase.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=NAME_MAX_LENGTH)
    slug: str = Field(
        min_length=1,
        max_length=SLUG_MAX_LENGTH,
        pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$",
        description="URL-safe unique identifier, e.g. acme-corp",
        examples=["acme-corp"],
    )


class OrganizationRead(BaseModel):
    """A tenant as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    status: Literal["active", "suspended", "archived"]
    created_at: datetime
    updated_at: datetime
