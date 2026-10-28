"""The ingestion path: a reported asset, normalized, validated, recorded.

The pipeline this module implements is the one the phase asks for — *discovery
source → normalization → validation → organization ownership → inventory record*
— and each stage is a step in :func:`register_discovered_asset` that either
produces a well-formed row or refuses the report:

1. **Discovery source.** The caller names itself (``integration:aws-organizations``,
   ``integration:mcp-registry``, …). The name is required and is stored on the row,
   so provenance is a fact about the record rather than a claim a client made
   through the API.
2. **Normalization.** The name is trimmed and its internal whitespace collapsed;
   the external identifier is trimmed but **not** case-folded (it is opaque, and
   lowercasing an ARN or a vendor id could merge two different assets).
   :class:`DiscoveredAsset` refuses a report with no external identifier at all,
   because without one there is nothing to deduplicate against — that is a manual
   registration, and it has a different endpoint.
3. **Validation.** The asset type must be one the vocabulary knows, the metadata
   must match that type's contract, and the environment must be a real environment.
   An unknown value is an error, not a new kind of asset.
4. **Organization ownership.** The caller passes the organization explicitly, and
   the write goes through ``AssetRepository``, which cannot be constructed without
   a tenant and cannot write outside it. An integration that reports into the wrong
   organization is a configuration error the type system makes visible; a report
   can never *choose* an owner, either — ownership is a membership of the
   organization, and an integration may propose one only if it resolves to a real
   member (it usually does not: a collector knows what exists, not who is
   accountable for it).
5. **Inventory record.** The row is upserted on
   ``(organization_id, asset_type, external_identifier)``, so re-reporting the same
   asset refreshes it instead of duplicating it. A repeat report updates what the
   integration is authoritative about (name, metadata, ``last_seen_at``) and leaves
   the organization's judgement alone (lifecycle ``status``, owner, risk
   classification). The returned :class:`DiscoveryResult` says which of the two
   happened, and a first sighting emits ``asset.discovered``.

What this module is not: a collector, a scheduler, or a runtime control. It
records what it is told, in the tenant it is told about, and nothing about an
asset's behaviour is decided here. Callers today are tests and the CLI; a future
integration calls exactly this function.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from aicore_api.core.assets import (
    MANUAL_DISCOVERY_SOURCE,
    AssetStatus,
    AssetType,
    DiscoveryState,
    Environment,
    RiskClassification,
    normalize_name,
    validate_metadata,
)
from aicore_api.core.audit import AuditSource
from aicore_api.core.events import ASSET_DISCOVERED, DomainEvent, emit_event
from aicore_api.db.models.asset import EXTERNAL_IDENTIFIER_MAX_LENGTH, Asset
from aicore_api.db.models.membership import MembershipStatus
from aicore_api.db.repositories.assets import AssetRepository
from aicore_api.db.repositories.memberships import MembershipRepository

__all__ = ["DiscoveredAsset", "DiscoveryResult", "register_discovered_asset"]

#: Every integration reports under this prefix, so "who recorded this?" is
#: answerable by looking at the row: ``manual`` or ``integration:<name>``.
_INTEGRATION_PREFIX = "integration:"


@dataclass(frozen=True, slots=True)
class DiscoveredAsset:
    """One asset an integration observed, as the integration describes it.

    This is deliberately *not* the API's create model. An integration knows what
    exists and where, and very little else: it does not decide an asset's
    lifecycle, its owner, or its risk classification. Those are the organization's
    judgement, and a report that could set them would be a collector deciding what
    the business thinks.

    ``discovery_state`` is the one exception, and only because a source can
    genuinely know one thing a person cannot see: a collector that walks an
    environment and finds something the inventory does not contain has *observed*
    it outside governance. Left unset — the usual case — the record is stored as
    ``UNKNOWN``: "we found this and nobody has accounted for it yet" is the honest
    starting point, and promoting it to ``MANAGED`` is a person's decision.

    Constructing one validates it: the type must be known, the identifier must be
    usable, the environment must be real, and the metadata must match the type's
    contract. A malformed report fails here rather than three layers down.
    """

    source: str
    external_identifier: str
    name: str
    asset_type: AssetType
    environment: Environment = Environment.UNKNOWN
    description: str | None = None
    #: ``None`` means "the integration did not say". It is filled in with
    #: ``DiscoveryState.UNKNOWN`` at registration time.
    discovery_state: DiscoveryState | None = None
    asset_metadata: dict[str, Any] = field(default_factory=dict)
    owner_user_id: uuid.UUID | None = None
    observed_at: datetime | None = None

    def __post_init__(self) -> None:
        source = self.source.strip()
        if not source or source == MANUAL_DISCOVERY_SOURCE:
            raise ValueError(
                "a discovered asset must name its discovery source; 'manual' is what the "
                "API records for hand-registered assets"
            )
        if not source.startswith(_INTEGRATION_PREFIX):
            source = f"{_INTEGRATION_PREFIX}{source}"
        object.__setattr__(self, "source", source)

        identifier = self.external_identifier.strip()
        if not identifier or len(identifier) > EXTERNAL_IDENTIFIER_MAX_LENGTH:
            raise ValueError(
                "a discovered asset needs an external identifier of at most "
                f"{EXTERNAL_IDENTIFIER_MAX_LENGTH} characters; without one there is "
                "nothing to deduplicate against, and it should be registered through "
                "the API instead"
            )
        object.__setattr__(self, "external_identifier", identifier)

        name = normalize_name(self.name)
        if not name:
            raise ValueError("a discovered asset must have a name")
        object.__setattr__(self, "name", name)

        # Raises ValueError for an unknown type or metadata that does not match it:
        # a collector reporting a shape the application cannot reason about is a
        # defect to fix, not a row to store.
        validated = validate_metadata(self.asset_type, self.asset_metadata)
        object.__setattr__(self, "asset_metadata", validated or {})


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """What happened when a report was recorded."""

    asset: Asset
    created: bool

    @property
    def asset_id(self) -> uuid.UUID:
        return self.asset.id

    @property
    def discovery_state(self) -> str:
        return self.asset.discovery_state

    @property
    def last_seen_at(self) -> datetime | None:
        return self.asset.last_seen_at


def register_discovered_asset(
    session: Session, organization_id: uuid.UUID, report: DiscoveredAsset
) -> DiscoveryResult:
    """Record ``report`` in ``organization_id``'s inventory, idempotently.

    Returns the asset and whether this call created it. A first sighting emits
    ``asset.discovered``; a refresh does not, because "we saw it again" is not a
    change the organization needs to be told about, and a trail full of them would
    bury the one that matters. The event is recorded as a *system* event with an
    ingestion source: an integration observed something, and no person did.

    The caller supplies the organization, never the report: an integration is
    configured for a tenant, and that configuration is what this argument is.
    """
    repository = AssetRepository(session, organization_id)

    owner_membership_id = None
    if report.owner_user_id is not None:
        # A reported owner must be a real member of this organization. Resolving
        # here means an integration cannot introduce a person the tenant does not
        # have — the composite foreign key would refuse the row anyway, but a
        # clear refusal is better than an integrity error.
        membership = MembershipRepository(session, organization_id).find_for_user(
            report.owner_user_id
        )
        if membership is None or membership.status != MembershipStatus.ACTIVE.value:
            raise ValueError("a reported owner must be an active member of the organization")
        owner_membership_id = membership.id

    asset, created = repository.register_discovered(
        name=report.name,
        asset_type=report.asset_type.value,
        external_identifier=report.external_identifier,
        discovery_source=report.source,
        description=report.description,
        status=AssetStatus.ACTIVE.value,
        environment=report.environment.value,
        discovery_state=(report.discovery_state or DiscoveryState.UNKNOWN).value,
        risk_classification=RiskClassification.UNASSESSED.value,
        owner_membership_id=owner_membership_id,
        # ``None`` rather than ``{}`` when the source reported nothing: an empty
        # object and "no metadata" are different facts, and the API's own create
        # path stores the latter.
        asset_metadata=report.asset_metadata or None,
        observed_at=report.observed_at or datetime.now(UTC),
    )
    if created:
        # No actor, and none is invented: an integration reported something, and no person
        # performed it. Phase 8 records that as a *system* event — the honest attribution —
        # with ``source=ingestion`` rather than a request id, because there was no request.
        emit_event(
            DomainEvent(
                name=ASSET_DISCOVERED,
                organization_id=organization_id,
                resource_type="asset",
                resource_id=asset.id,
                actor_membership_id=None,
                actor_id=None,
                data={
                    "asset_type": asset.asset_type,
                    "discovery_source": asset.discovery_source,
                    "discovery_state": asset.discovery_state,
                },
            ),
            session=session,
            source=AuditSource.INGESTION,
        )
    return DiscoveryResult(asset=asset, created=created)
