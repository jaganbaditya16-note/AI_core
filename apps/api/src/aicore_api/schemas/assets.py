"""Asset contract: what a client may send, and what it gets back.

Two rules shape these models.

**Closed where the value is a decision, open only where it is metadata.** Every
field with a controlled vocabulary (``asset_type``, ``status``, ``environment``,
``discovery_state``, ``risk_classification``) is typed as the enum, so an
invented state is a 422 from the boundary and never reaches the database's own
check constraint. Unknown fields are refused (``extra="forbid"``) rather than
ignored: a client that sends ``risk_score`` should be told it does not exist, not
have it silently dropped.

**Identity fields are not writable.** ``organization_id`` comes from the path
(and the caller's membership), ``asset_type`` is immutable because it selects the
metadata contract and participates in the deduplication key, and
``discovery_source``/``last_seen_at`` are set by the discovery boundary — a
client cannot claim a record was reported by an integration. ``id``, ``created_at``
and ``updated_at`` are server-generated, which is why they appear only in the read
model.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aicore_api.core.assets import (
    AssetStatus,
    AssetType,
    DiscoveryState,
    Environment,
    RiskClassification,
)
from aicore_api.db.models.asset import (
    DESCRIPTION_MAX_LENGTH,
    EXTERNAL_IDENTIFIER_MAX_LENGTH,
    NAME_MAX_LENGTH,
)

__all__ = [
    "AssetCreate",
    "AssetListResponse",
    "AssetOwnerListResponse",
    "AssetOwnerRead",
    "AssetRead",
    "AssetUpdateRequest",
]

#: Fields a PATCH may null out (``description``, ``external_identifier``,
#: ``metadata``, ``owner_user_id``): null removes the value, and
#: :meth:`AssetUpdateRequest.clears` is how the route reads that intent. For
#: everything else an explicit ``null`` is a mistake rather than a request —
#: "clear the name" is not an operation that should silently succeed.
#:
#: Fields that must carry a value when they appear in a PATCH at all.
_REQUIRED_WHEN_PRESENT = ("name", "status", "environment", "discovery_state", "risk_classification")


class AssetCreate(BaseModel):
    """Request body for ``POST /organizations/{organization_id}/assets``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        min_length=1,
        max_length=NAME_MAX_LENGTH,
        description="Human-readable name. Not an identifier: names are not unique.",
        examples=["Customer Support Copilot"],
    )
    asset_type: AssetType = Field(
        description="What the asset is. Immutable once created.",
        examples=[AssetType.APPLICATION.value],
    )
    description: str | None = Field(
        default=None, max_length=DESCRIPTION_MAX_LENGTH, examples=["Answers tier-1 tickets."]
    )
    status: AssetStatus = Field(
        default=AssetStatus.DRAFT,
        description="Inventory lifecycle state. Not a runtime control.",
    )
    environment: Environment = Field(default=Environment.UNKNOWN)
    discovery_state: DiscoveryState = Field(
        default=DiscoveryState.MANAGED,
        description=(
            "How the organization came to know about the asset. A record created "
            "here is managed by definition — it was registered on purpose."
        ),
    )
    risk_classification: RiskClassification = Field(
        default=RiskClassification.UNASSESSED,
        description="A stored label. No scoring is performed in this build.",
    )
    owner_user_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "The member who owns the asset, by user id. Resolved against this "
            "organization's memberships: a user who is not an active member here "
            "is refused, and a user from another tenant is not representable."
        ),
    )
    external_identifier: str | None = Field(
        default=None,
        max_length=EXTERNAL_IDENTIFIER_MAX_LENGTH,
        description=(
            "The identifier the producing system uses. Unique per organization and "
            "asset type; the deduplication key for discovered assets."
        ),
    )
    metadata: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Structured, type-specific attributes, validated against the asset "
            "type's contract (see docs/inventory.md). Unknown keys are refused."
        ),
    )


class AssetUpdateRequest(BaseModel):
    """Request body for ``PATCH /organizations/{organization_id}/assets/{asset_id}``.

    Partial by construction: a field that is absent is left alone, a field that is
    present is applied, and the four clearable fields may be set to ``null`` to
    remove the value. That distinction is the reason this is a PATCH with explicit
    nulls rather than a PUT that replaces the record — an inventory update should
    not require a client to resend fields it did not intend to touch.

    ``asset_type`` is absent on purpose. Changing it would change which metadata
    contract applies and which row the asset deduplicates against; an asset that
    is genuinely a different kind of thing is a different asset.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=NAME_MAX_LENGTH)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX_LENGTH)
    status: AssetStatus | None = None
    environment: Environment | None = None
    discovery_state: DiscoveryState | None = None
    risk_classification: RiskClassification | None = None
    owner_user_id: uuid.UUID | None = None
    external_identifier: str | None = Field(default=None, max_length=EXTERNAL_IDENTIFIER_MAX_LENGTH)
    metadata: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _check_shape(self) -> Self:
        """Refuse an empty patch, and refuse ``null`` where null means nothing."""
        provided = self.model_fields_set
        if not provided:
            raise ValueError("at least one field must be provided")
        for field_name in _REQUIRED_WHEN_PRESENT:
            if field_name in provided and getattr(self, field_name) is None:
                raise ValueError(f"{field_name} must not be null; omit it to leave it unchanged")
        return self

    def clears(self, field_name: str) -> bool:
        """Whether this request asked to remove ``field_name``'s value."""
        return field_name in self.model_fields_set and getattr(self, field_name) is None


class AssetOwnerRead(BaseModel):
    """Who owns an asset.

    The membership id is included because that is what the asset actually
    references; the user id and name are what a reader recognizes. Both are needed
    to browse without guessing, and neither is a credential.
    """

    membership_id: uuid.UUID
    user_id: uuid.UUID
    email: str
    full_name: str


class AssetRead(BaseModel):
    """An asset as returned by the API."""

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str | None
    asset_type: AssetType
    status: AssetStatus
    environment: Environment
    discovery_state: DiscoveryState
    risk_classification: RiskClassification
    external_identifier: str | None
    discovery_source: str = Field(
        description=(
            "``manual`` for a record registered through this API, "
            "``integration:<name>`` for one reported by a discovery integration. "
            "Server-set: a client cannot claim provenance."
        ),
        examples=["manual"],
    )
    last_seen_at: datetime | None = Field(
        description="When an integration last observed the asset; null for manual records."
    )
    metadata: dict[str, Any] | None
    owner: AssetOwnerRead | None
    created_at: datetime
    updated_at: datetime


class AssetListResponse(BaseModel):
    """``GET /organizations/{organization_id}/assets``.

    ``total`` is present only when the caller asked for it (``?total=true``): a
    count costs a second query over the same predicate, and a feed that pages by
    offset rarely needs it. ``count`` always describes the page itself, so a client
    can tell a full page from the last one without asking for a total.
    """

    organization_id: uuid.UUID
    items: list[AssetRead]
    limit: int
    offset: int
    count: int
    total: int | None = None


class AssetOwnerListResponse(BaseModel):
    """``GET /organizations/{organization_id}/assets/owners``.

    The candidate owners, so a client can offer a real choice instead of asking an
    operator to paste a UUID — and so the API never has to accept an identifier
    that was not resolved against this organization's memberships.
    """

    organization_id: uuid.UUID
    owners: list[AssetOwnerRead]
