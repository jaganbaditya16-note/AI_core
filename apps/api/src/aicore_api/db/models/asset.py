"""The asset inventory: one table for every kind of AI asset.

Seven asset types (agent, application, model, tool, MCP server, API, data source)
share one table, one set of lifecycle rules and one authorization path. That is a
deliberate refusal to build seven systems: they differ in their *metadata*, which
is validated per type (``core/assets.py``) and stored as ``JSONB``, not in their
identity, ownership or tenancy — and those are the parts that must be consistent,
because they are the parts a security decision is made from.

Three schema decisions are load-bearing:

1. **``organization_id`` comes from the tenant mixin.** Every rule the isolation
   guard enforces applies here without an exception, and the column is ``NOT
   NULL``: an asset that belongs to nobody cannot exist.

2. **Ownership is a membership, not a user id.** ``owner_membership_id`` points at
   ``memberships``, and the foreign key is *composite*
   (``organization_id, owner_membership_id``) against
   ``memberships (organization_id, id)``. That single constraint makes "the owner
   is a member of the same organization as the asset" a property of the database
   rather than a rule an application must remember — the cross-tenant owner is not
   merely rejected, it is unrepresentable. The owner is nullable on purpose: an
   ``UNKNOWN`` or ``SHADOW`` asset frequently has nobody recorded against it yet.

3. **Detection is not identity.** ``external_identifier`` is the identifier the
   *producing system* uses, and the uniqueness rule
   ``(organization_id, asset_type, external_identifier)`` is what prevents the
   same discovered asset from being recorded twice. It is a partial unique index
   (only where the identifier is present, since a hand-registered asset has none),
   and names are deliberately excluded from it: two assets may share a name, and
   nothing is ever looked up by name.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aicore_api.core.assets import (
    AssetStatus,
    AssetType,
    DiscoveryState,
    Environment,
    RiskClassification,
)
from aicore_api.db.base import (
    APP_SCHEMA,
    Base,
    TenantOwnedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from aicore_api.db.models.membership import Membership

NAME_MAX_LENGTH = 200
DESCRIPTION_MAX_LENGTH = 2000
EXTERNAL_IDENTIFIER_MAX_LENGTH = 512
DISCOVERY_SOURCE_MAX_LENGTH = 100

TABLE_COMMENT = (
    "AI asset inventory: every AI-related thing an organization knows about, "
    "whatever its type. Tenant-owned; the owner is a membership of the same "
    "organization, enforced by a composite foreign key."
)


def _allowed_values(enum_type: type[StrEnum]) -> str:
    """Render a StrEnum as the value list a CHECK constraint expects."""
    return ", ".join(f"'{member.value}'" for member in enum_type)


#: Enum-ish columns are ``VARCHAR`` + ``CHECK`` rather than PostgreSQL ``ENUM``,
#: exactly as in the Phase 1 and Phase 2 tables: adding a state stays an ordinary
#: transactional migration, while the database still refuses anything outside the
#: documented set.
_TYPE_CHECK = f"asset_type IN ({_allowed_values(AssetType)})"
_STATUS_CHECK = f"status IN ({_allowed_values(AssetStatus)})"
_DISCOVERY_CHECK = f"discovery_state IN ({_allowed_values(DiscoveryState)})"
_ENVIRONMENT_CHECK = f"environment IN ({_allowed_values(Environment)})"
_RISK_CHECK = f"risk_classification IN ({_allowed_values(RiskClassification)})"


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, TenantOwnedMixin, Base):
    """One AI-related asset an organization has recorded."""

    __tablename__ = "assets"

    name: Mapped[str] = mapped_column(String(NAME_MAX_LENGTH), nullable=False)
    description: Mapped[str | None] = mapped_column(String(DESCRIPTION_MAX_LENGTH), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default=AssetStatus.DRAFT.value,
    )
    environment: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default=Environment.UNKNOWN.value,
    )
    discovery_state: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default=DiscoveryState.MANAGED.value,
    )
    risk_classification: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default=RiskClassification.UNASSESSED.value,
    )

    #: The identifier the producing system uses — an ARN, a registry id, a vendor's
    #: model slug. Nullable because a hand-registered asset may have none.
    external_identifier: Mapped[str | None] = mapped_column(
        String(EXTERNAL_IDENTIFIER_MAX_LENGTH), nullable=True
    )

    #: Where the record came from: ``manual`` for the API, ``integration:<name>``
    #: for the discovery boundary. Server-set, never client-set, so a caller cannot
    #: claim provenance it does not have — and nobody can mistake a hand-typed row
    #: for something a collector observed.
    discovery_source: Mapped[str] = mapped_column(
        String(DISCOVERY_SOURCE_MAX_LENGTH),
        nullable=False,
        server_default=text("'manual'"),
    )

    #: When an integration last observed the asset. ``None`` for manual records:
    #: nobody observed anything, and inventing a timestamp would be a lie the
    #: inventory tells about its own confidence.
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: Type-specific, validated against the contract for :attr:`asset_type`.
    #: ``JSONB`` rather than a column per field: the fields differ per type, and
    #: sparse columns shared across seven types would be mostly NULL and entirely
    #: untyped. The database enforces that it is an *object*; the shape is enforced
    #: by ``core/assets.py`` before the row is written.
    #: ``none_as_null=True`` is load-bearing: without it SQLAlchemy writes Python
    #: ``None`` as the JSON value ``null``, and the check constraint below — which
    #: insists metadata is an object — refuses the row. "No metadata" is SQL NULL
    #: here: an absent value, not a JSON document that happens to be null.
    asset_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata", JSONB(none_as_null=True), nullable=True
    )

    owner_membership_id: Mapped[uuid.UUID | None] = mapped_column(
        nullable=True,
    )

    #: Loaded with the row: a listing that showed ownership would otherwise issue a
    #: query per asset, and the membership's user is eager-loaded in turn, so one
    #: query answers "who owns this and what is their name".
    owner_membership: Mapped[Membership | None] = relationship(lazy="joined")

    __table_args__ = (
        # The owner is a member of this organization. ON DELETE RESTRICT: removing
        # a member who still owns inventory is refused rather than silently
        # leaving assets unowned.
        ForeignKeyConstraint(
            ["organization_id", "owner_membership_id"],
            [
                f"{APP_SCHEMA}.memberships.organization_id",
                f"{APP_SCHEMA}.memberships.id",
            ],
            ondelete="RESTRICT",
        ),
        # Redundant with the primary key, and load-bearing anyway: an agent
        # registry record addresses its asset as ``(organization_id, asset_id)``
        # through a composite foreign key, and PostgreSQL can only reference a
        # unique set of columns. This is that set — so "the agent's asset belongs
        # to the agent's organization" is enforced by the database rather than
        # remembered by the application.
        UniqueConstraint("organization_id", "id"),
        # Deduplication: one row per (organization, type, external identifier).
        # Partial, because an asset registered by hand has no external identifier
        # and two such assets are not duplicates of each other.
        Index(
            "uq_assets_organization_id_asset_type_external_identifier",
            "organization_id",
            "asset_type",
            "external_identifier",
            unique=True,
            postgresql_where=text("external_identifier IS NOT NULL"),
        ),
        # Filtering is per tenant, so every index leads with organization_id. These
        # are the two filters an inventory is actually interrogated with; status,
        # environment and risk classification are low-cardinality within a tenant
        # and are served by the tenant index rather than by an index each.
        Index("ix_assets_organization_id_asset_type", "organization_id", "asset_type"),
        Index("ix_assets_organization_id_discovery_state", "organization_id", "discovery_state"),
        # "Everything this person owns" — for the owner filter and for the RESTRICT
        # above, which must be checkable without scanning the table.
        Index("ix_assets_owner_membership_id", "owner_membership_id"),
        CheckConstraint(
            f"char_length(btrim(name)) BETWEEN 1 AND {NAME_MAX_LENGTH}", name="name_length"
        ),
        CheckConstraint(
            "description IS NULL OR char_length(btrim(description)) BETWEEN 1 "
            f"AND {DESCRIPTION_MAX_LENGTH}",
            name="description_length",
        ),
        CheckConstraint(
            f"external_identifier IS NULL OR char_length(btrim(external_identifier)) "
            f"BETWEEN 1 AND {EXTERNAL_IDENTIFIER_MAX_LENGTH}",
            name="external_identifier_length",
        ),
        CheckConstraint(
            f"char_length(btrim(discovery_source)) BETWEEN 1 AND {DISCOVERY_SOURCE_MAX_LENGTH}",
            name="discovery_source_length",
        ),
        CheckConstraint(_TYPE_CHECK, name="asset_type_valid"),
        CheckConstraint(_STATUS_CHECK, name="status_valid"),
        CheckConstraint(_DISCOVERY_CHECK, name="discovery_state_valid"),
        CheckConstraint(_ENVIRONMENT_CHECK, name="environment_valid"),
        CheckConstraint(_RISK_CHECK, name="risk_classification_valid"),
        # Metadata is an object or nothing: an array or a bare scalar in a JSONB
        # column is not "flexible", it is a shape no reader can rely on.
        CheckConstraint(
            "metadata IS NULL OR jsonb_typeof(metadata) = 'object'", name="metadata_is_object"
        ),
        {"comment": TABLE_COMMENT},
    )

    def __repr__(self) -> str:
        """Identifiers and the controlled vocabulary only — a name is tenant data."""
        return (
            f"<Asset id={self.id} type={self.asset_type!r} "
            f"status={self.status!r} discovery={self.discovery_state!r}>"
        )
