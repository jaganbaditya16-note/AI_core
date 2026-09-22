"""The inventory at the database level: what is stored, and what is refused.

These tests run against real PostgreSQL (``scripts/test-db.sh`` sets
``AICORE_TEST_DATABASE_URL``) because everything asserted here is a database
property: the composite foreign key that makes a cross-tenant owner
unrepresentable, the check constraints that keep the controlled vocabularies
closed, the partial unique index that deduplicates discovered assets, and the
tenant guard that refuses an unscoped statement.

That is not incidental coverage. If these constraints lived only in the
application, the first integration or data fix to write a row directly would put
a foreign owner or an unknown asset type into the inventory, and no test going
through the API would notice.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aicore_api.core.assets import (
    METADATA_MODELS,
    AssetStatus,
    AssetType,
    DiscoveryState,
    Environment,
    RiskClassification,
    metadata_model_for,
    normalize_external_identifier,
    validate_metadata,
)
from aicore_api.core.domain_errors import InvalidReferenceError
from aicore_api.db.models.asset import Asset
from aicore_api.db.repositories.assets import AssetRepository, AssetUpdate
from aicore_api.db.tenancy import TenantScopeError, bind_tenant
from aicore_api.discovery import DiscoveredAsset, register_discovered_asset
from assets_fixture import ASSET_TYPES, count_assets, insert_asset_row, sample_metadata
from identity_fixture import Identity, IdentityFactory


def _repository(session: Session, identity: Identity) -> AssetRepository:
    return AssetRepository(session, identity.organization_id)


# ── Storage: every type, every field ─────────────────────────────────────────


def test_every_asset_type_is_stored_with_its_own_metadata(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """All seven types share one table, and each keeps its own metadata contract."""
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    created: dict[str, uuid.UUID] = {}

    for asset_type in ASSET_TYPES:
        asset = repository.add(
            name=f"{asset_type} asset",
            asset_type=asset_type,
            asset_metadata=sample_metadata(asset_type),
        )
        created[asset_type] = asset.id

    assert set(created) == set(ASSET_TYPES)
    for asset_type, asset_id in created.items():
        stored = repository.find(asset_id)
        assert stored is not None
        assert stored.asset_type == asset_type
        assert stored.asset_metadata == sample_metadata(asset_type)
        # Defaults come from the database, not from the caller.
        assert stored.status == "draft"
        assert stored.environment == "unknown"
        assert stored.discovery_state == "managed"
        assert stored.risk_classification == "unassessed"
        # …and a hand-registered record says so about itself.
        assert stored.discovery_source == "manual"
        assert stored.last_seen_at is None


def test_ids_and_timestamps_are_assigned_by_the_database(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """A row is identifiable and auditable without the application supplying ids."""
    identity = identity_factory()
    asset = _repository(integration_session, identity).add(name="Timestamped", asset_type="api")

    assert isinstance(asset.id, uuid.UUID)
    assert asset.created_at is not None and asset.created_at.tzinfo is not None
    assert asset.updated_at is not None


def test_an_asset_may_have_no_owner(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """A discovered asset frequently has nobody accountable for it yet."""
    identity = identity_factory()
    asset = _repository(integration_session, identity).add(name="Unowned", asset_type="mcp_server")
    assert asset.owner_membership_id is None


def test_risk_classification_is_stored_and_defaults_to_unassessed(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """A stored label, and nothing more: no scoring happens in this build."""
    identity = identity_factory()
    repository = _repository(integration_session, identity)
    default = repository.add(name="Unassessed", asset_type="model")
    labelled = repository.add(
        name="Critical", asset_type="model", risk_classification=RiskClassification.CRITICAL.value
    )

    assert default.risk_classification == "unassessed"
    assert labelled.risk_classification == "critical"


# ── Tenancy ──────────────────────────────────────────────────────────────────


def test_assets_of_one_organization_are_invisible_to_another(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """The tenant filter is applied by the repository, not remembered by the caller."""
    first = identity_factory(role_code="owner")
    second = identity_factory(role_code="owner")
    asset = _repository(integration_session, first).add(name="First Only", asset_type="model")

    other = _repository(integration_session, second)
    assert other.find(asset.id) is None
    assert other.page(limit=50, offset=0) == []
    assert other.count() == 0


def test_a_repository_cannot_be_built_without_an_organization(integration_session: Session) -> None:
    """Tenant-owned data is never reached through an unbound repository."""
    with pytest.raises(TenantScopeError):
        AssetRepository(integration_session)


def test_an_unscoped_statement_against_the_inventory_is_refused(
    integration_engine: Engine, identity_factory: IdentityFactory
) -> None:
    """The engine-level guard, asserted for this table specifically.

    ``find()`` returning ``None`` for a foreign asset proves the repository
    filters. This proves what happens when somebody does not use the repository.
    """
    identity = identity_factory()
    insert_asset_row(integration_engine, organization_id=identity.organization_id, name="Guarded")

    with pytest.raises(TenantScopeError), integration_engine.connect() as connection:
        connection.execute(select(Asset)).all()

    # The same read inside a bound tenant works, so the guard is not simply
    # refusing everything.
    with bind_tenant(identity.organization_id), integration_engine.connect() as connection:
        rows = connection.execute(
            select(Asset).where(Asset.organization_id == identity.organization_id)
        ).all()
    assert len(rows) == 1


# ── Ownership ────────────────────────────────────────────────────────────────


def test_an_owner_from_another_organization_is_refused_by_the_database(
    integration_engine: Engine, integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """The composite foreign key makes a cross-tenant owner unrepresentable.

    The API resolves owners against the organization's own memberships, so this
    request never reaches the database through the application. It is asserted
    anyway: this constraint is what protects the inventory from a fixture, a data
    fix, or a future integration.
    """
    first = identity_factory(role_code="owner")
    second = identity_factory(role_code="owner")

    with pytest.raises(IntegrityError):
        insert_asset_row(
            integration_engine,
            organization_id=first.organization_id,
            name="Owned By An Outsider",
            owner_membership_id=second.membership_id,
        )

    # The repository translates the same violation into a domain error, so a
    # driver message never reaches a client.
    with pytest.raises(InvalidReferenceError):
        _repository(integration_session, first).add(
            name="Owned By An Outsider",
            asset_type="model",
            owner_membership_id=second.membership_id,
        )


def test_an_owner_who_still_owns_assets_cannot_be_removed_from_the_organization(
    integration_engine: Engine, integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """Ownership is a real reference: removing the member is refused, not ignored."""
    identity = identity_factory(role_code="owner")
    _repository(integration_session, identity).add(
        name="Owned Asset", asset_type="application", owner_membership_id=identity.membership_id
    )
    integration_session.commit()

    with (
        pytest.raises(IntegrityError),
        bind_tenant(identity.organization_id),
        integration_engine.begin() as connection,
    ):
        connection.execute(
            text(
                "DELETE FROM aicore.memberships "
                "WHERE id = :id AND organization_id = :organization_id"
            ),
            {"id": str(identity.membership_id), "organization_id": str(identity.organization_id)},
        )


# ── The controlled vocabularies ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("asset_type", "llm"),
        ("status", "deprecated"),
        ("discovery_state", "guessed"),
        ("environment", "qa"),
        ("risk_classification", "extreme"),
    ],
)
def test_the_database_refuses_a_value_outside_a_documented_vocabulary(
    integration_engine: Engine, identity_factory: IdentityFactory, column: str, value: str
) -> None:
    """Each vocabulary is closed in the database, not only in the API model."""
    identity = identity_factory()
    with pytest.raises(IntegrityError):
        insert_asset_row(
            integration_engine,
            organization_id=identity.organization_id,
            name="Invented Value",
            **{column: value},
        )


def test_metadata_that_is_not_an_object_is_refused(
    integration_engine: Engine, identity_factory: IdentityFactory
) -> None:
    """``JSONB`` holds an object or nothing — not an array, not a scalar."""
    identity = identity_factory()
    with (
        pytest.raises(IntegrityError),
        bind_tenant(identity.organization_id),
        integration_engine.begin() as connection,
    ):
        connection.execute(
            text(
                "INSERT INTO aicore.assets (organization_id, name, asset_type, metadata) "
                "VALUES (:organization_id, 'Array Metadata', 'model', "
                'CAST(\'["not", "an object"]\' AS jsonb))'
            ),
            {"organization_id": str(identity.organization_id)},
        )


def test_every_type_has_a_metadata_contract_and_there_is_no_permissive_fallback() -> None:
    """One metadata model per asset type; an unknown type is an error, not a free pass."""
    assert set(METADATA_MODELS) == set(AssetType)
    for asset_type in AssetType:
        assert validate_metadata(asset_type, sample_metadata(asset_type.value)) == sample_metadata(
            asset_type.value
        )

    with pytest.raises(ValueError):
        metadata_model_for("llm")
    with pytest.raises(ValueError):
        validate_metadata("llm", {"provider": "x"})


@pytest.mark.parametrize(
    "payload",
    [
        {"unknown_field": "value"},
        {"provider": ""},
        {"model_identifier": 42},
        {"provider": ["not", "a", "string"]},
    ],
)
def test_metadata_that_violates_the_contract_is_refused(payload: dict[str, object]) -> None:
    """Unknown keys, blank strings and wrong types are errors, not stored data."""
    with pytest.raises(ValueError):
        validate_metadata(AssetType.MODEL, payload)


def test_metadata_is_an_object_or_nothing() -> None:
    """No metadata and empty metadata are the same absent value."""
    assert validate_metadata(AssetType.TOOL, None) is None
    assert validate_metadata(AssetType.TOOL, {}) is None


def test_external_identifiers_are_trimmed_but_not_case_folded() -> None:
    """Identifiers are opaque: trimming is normalization, lowercasing is invention."""
    assert normalize_external_identifier("  arn:aws:bedrock:MODEL-1  ") == "arn:aws:bedrock:MODEL-1"
    assert normalize_external_identifier(None) is None
    with pytest.raises(ValueError):
        normalize_external_identifier("   ")
    with pytest.raises(ValueError):
        normalize_external_identifier("x" * 600)


# ── Deduplication ────────────────────────────────────────────────────────────


def test_an_external_identifier_is_unique_per_organization_and_type(
    integration_engine: Engine, identity_factory: IdentityFactory
) -> None:
    """The documented dedup rule, exactly: (organization, type, identifier)."""
    first = identity_factory(role_code="owner")
    second = identity_factory(role_code="owner")
    identifier = "registry://models/shared-1"

    insert_asset_row(
        integration_engine,
        organization_id=first.organization_id,
        name="First",
        external_identifier=identifier,
    )

    # Same tenant and type: refused.
    with pytest.raises(IntegrityError):
        insert_asset_row(
            integration_engine,
            organization_id=first.organization_id,
            name="Duplicate",
            external_identifier=identifier,
        )

    # Same tenant, different type: a different asset.
    insert_asset_row(
        integration_engine,
        organization_id=first.organization_id,
        name="Same Identifier, Other Type",
        asset_type="tool",
        external_identifier=identifier,
    )

    # Different tenant: nothing to do with the first organization's inventory.
    insert_asset_row(
        integration_engine,
        organization_id=second.organization_id,
        name="Same Identifier, Other Tenant",
        external_identifier=identifier,
    )

    assert count_assets(integration_engine, first.organization_id) == 2
    assert count_assets(integration_engine, second.organization_id) == 1


def test_names_are_not_identifiers(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """Two assets may share a name; nothing is ever looked up by one."""
    identity = identity_factory()
    repository = _repository(integration_session, identity)
    first = repository.add(name="Support Copilot", asset_type="application")
    second = repository.add(name="Support Copilot", asset_type="model")

    assert first.id != second.id
    assert len(repository.page(limit=50, offset=0)) == 2


def test_many_assets_may_have_no_external_identifier_at_all(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """The uniqueness index is partial: hand-registered assets do not collide."""
    identity = identity_factory()
    repository = _repository(integration_session, identity)
    for index in range(3):
        repository.add(name=f"Manual {index}", asset_type="model")

    assert repository.count() == 3


# ── Filtering and pagination ─────────────────────────────────────────────────


@pytest.fixture
def inventory(integration_session: Session, identity_factory: IdentityFactory) -> Identity:
    """A tenant with five assets that differ along every filterable dimension."""
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    repository.add(
        name="Prod Model",
        asset_type="model",
        status="active",
        environment="production",
        discovery_state="managed",
        risk_classification="high",
        owner_membership_id=identity.membership_id,
    )
    repository.add(
        name="Staging Tool",
        asset_type="tool",
        status="active",
        environment="staging",
        discovery_state="managed",
    )
    repository.add(
        name="Shadow Agent",
        asset_type="agent",
        status="active",
        environment="production",
        discovery_state="shadow",
        risk_classification="critical",
    )
    repository.add(name="Draft API", asset_type="api", status="draft", environment="development")
    repository.add(
        name="Retired Data Source",
        asset_type="data_source",
        status="retired",
        environment="unknown",
        discovery_state="unknown",
    )
    return identity


def test_each_filter_narrows_the_inventory(
    integration_session: Session, inventory: Identity
) -> None:
    """Filters work per dimension, and repeated values are ORed within one."""
    repository = _repository(integration_session, inventory)

    assert repository.count(asset_types=["model"]) == 1
    assert repository.count(asset_types=["model", "tool"]) == 2
    assert repository.count(statuses=["active"]) == 3
    assert repository.count(environments=["production"]) == 2
    assert repository.count(discovery_states=["shadow"]) == 1
    assert repository.count(risk_classifications=["unassessed"]) == 3
    assert repository.count(owner_membership_id=inventory.membership_id) == 1

    # Across dimensions the filters are ANDed, which is what a query string says.
    assert repository.count(asset_types=["model"], environments=["production"]) == 1
    assert repository.count(asset_types=["model"], environments=["staging"]) == 0

    page = repository.page(limit=50, offset=0, discovery_states=["shadow"])
    assert [asset.name for asset in page] == ["Shadow Agent"]


def test_pages_do_not_overlap_and_are_newest_first(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """Ordering by (created_at, id) means paging cannot skip or repeat a row."""
    identity = identity_factory()
    repository = _repository(integration_session, identity)
    created = [repository.add(name=f"Asset {index}", asset_type="model").id for index in range(5)]

    page_one = [asset.id for asset in repository.page(limit=2, offset=0)]
    page_two = [asset.id for asset in repository.page(limit=2, offset=2)]
    page_three = [asset.id for asset in repository.page(limit=2, offset=4)]
    everything = page_one + page_two + page_three

    assert len(set(everything)) == 5
    assert set(everything) == set(created)
    assert page_one == list(reversed(created))[:2]
    assert page_three == list(reversed(created))[4:]


def test_a_page_is_bounded_by_the_limit_it_is_given(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """``limit`` is required: this layer cannot be asked for "all assets"."""
    identity = identity_factory()
    repository = _repository(integration_session, identity)
    for index in range(4):
        repository.add(name=f"Bounded {index}", asset_type="model")

    assert len(repository.page(limit=1, offset=0)) == 1
    assert len(repository.page(limit=3, offset=0)) == 3
    assert repository.page(limit=10, offset=10) == []
    assert repository.count() == 4


# ── Discovery ingestion ──────────────────────────────────────────────────────


def test_a_discovered_asset_is_recorded_once_and_refreshed_afterwards(
    integration_engine: Engine, integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """Re-reporting the same asset converges on one row.

    This is what an integration does every few minutes, so the second report must
    not create a second asset — and must not overwrite what the organization has
    decided about the first one.
    """
    identity = identity_factory(role_code="owner")
    report = DiscoveredAsset(
        source="test-collector",
        external_identifier="cluster://agents/planner",
        name="Planner Agent",
        asset_type=AssetType.AGENT,
        environment=Environment.PRODUCTION,
        asset_metadata={"framework": "langgraph"},
    )

    first = register_discovered_asset(integration_session, identity.organization_id, report)
    assert first.created is True
    assert first.discovery_state == DiscoveryState.UNKNOWN.value
    assert first.last_seen_at is not None
    assert first.asset.discovery_source == "integration:test-collector"
    assert first.asset.asset_metadata == {"framework": "langgraph"}

    # The organization adopts the record…
    repository = _repository(integration_session, identity)
    asset = repository.find(first.asset_id)
    assert asset is not None
    repository.update(
        asset,
        AssetUpdate(
            status="active",
            discovery_state="managed",
            owner_membership_id=identity.membership_id,
        ),
    )

    # …and the collector reports it again, later, slightly differently.
    later = datetime.now(UTC) + timedelta(minutes=5)
    second = register_discovered_asset(
        integration_session,
        identity.organization_id,
        DiscoveredAsset(
            source="test-collector",
            external_identifier="cluster://agents/planner",
            name="Planner Agent (renamed)",
            asset_type=AssetType.AGENT,
            environment=Environment.PRODUCTION,
            asset_metadata={"framework": "langgraph", "version": "1.2"},
            observed_at=later,
        ),
    )

    assert second.created is False
    assert second.asset_id == first.asset_id
    assert count_assets(integration_engine, identity.organization_id) == 1
    # What the integration is authoritative about was refreshed…
    assert second.asset.name == "Planner Agent (renamed)"
    assert second.asset.asset_metadata == {"framework": "langgraph", "version": "1.2"}
    assert second.asset.last_seen_at == later
    # …and the organization's own decisions survived.
    assert second.asset.discovery_state == "managed"
    assert second.asset.owner_membership_id == identity.membership_id
    assert second.asset.status == "active"


def test_a_report_without_a_source_identifier_or_known_type_is_refused() -> None:
    """The discovery boundary validates what it is told, before any row exists."""
    with pytest.raises(ValueError):
        DiscoveredAsset(
            source="manual",
            external_identifier="x",
            name="Not Discovered",
            asset_type=AssetType.MODEL,
        )
    with pytest.raises(ValueError):
        DiscoveredAsset(
            source="test-collector",
            external_identifier="   ",
            name="No Identifier",
            asset_type=AssetType.MODEL,
        )
    with pytest.raises(ValueError):
        DiscoveredAsset(
            source="test-collector",
            external_identifier="x",
            name="Unknown Type",
            asset_type="llm",  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError):
        DiscoveredAsset(
            source="test-collector",
            external_identifier="x",
            name="Bad Metadata",
            asset_type=AssetType.MODEL,
            asset_metadata={"not_a_model_field": "value"},
        )


def test_a_report_cannot_invent_an_owner(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """A reported owner must be an active member of the organization reported to."""
    first = identity_factory(role_code="owner")
    second = identity_factory(role_code="owner")

    with pytest.raises(ValueError):
        register_discovered_asset(
            integration_session,
            first.organization_id,
            DiscoveredAsset(
                source="test-collector",
                external_identifier="cluster://agents/outsider",
                name="Outsider Owner",
                asset_type=AssetType.AGENT,
                owner_user_id=second.user_id,
            ),
        )


@pytest.mark.parametrize("status", [state.value for state in AssetStatus])
@pytest.mark.parametrize("environment", [value.value for value in Environment])
def test_every_documented_lifecycle_and_environment_value_round_trips(
    integration_session: Session,
    identity_factory: IdentityFactory,
    status: str,
    environment: str,
) -> None:
    """The vocabularies are closed *and* complete: nothing documented is unstorable.

    A vocabulary that refuses unknown values but cannot hold one of its own would
    fail only in production, on the day someone first suspends an asset.
    """
    identity = identity_factory()
    repository = _repository(integration_session, identity)
    asset = repository.add(
        name=f"{environment} {status} asset",
        asset_type=AssetType.AGENT.value,
        status=status,
        environment=environment,
    )

    stored = repository.find(asset.id)
    assert stored is not None
    assert (stored.status, stored.environment) == (status, environment)


@pytest.mark.parametrize("discovery_state", [value.value for value in DiscoveryState])
def test_every_discovery_state_is_available_to_a_reporting_integration(
    integration_session: Session, identity_factory: IdentityFactory, discovery_state: str
) -> None:
    """An integration can say what it knows: managed, not yet accounted for, or shadow.

    Which of the three is the right label is the integration's judgement; storing
    all three is this phase's job, and the vocabulary has to have a slot for each.
    """
    identity = identity_factory()
    result = register_discovered_asset(
        integration_session,
        identity.organization_id,
        DiscoveredAsset(
            source="estate-scan",
            external_identifier=f"estate://{discovery_state}/1",
            name=f"Observed {discovery_state}",
            asset_type=AssetType.API,
            discovery_state=DiscoveryState(discovery_state),
            asset_metadata={"endpoint": "https://api.test/v1"},
        ),
    )

    assert result.asset.discovery_state == discovery_state


def test_a_source_may_label_what_it_observed(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """A scan that finds something outside the inventory can say so; the default is not."""
    identity = identity_factory()
    shadow = register_discovered_asset(
        integration_session,
        identity.organization_id,
        DiscoveredAsset(
            source="integration:estate-scan",
            external_identifier="estate://shadow/1",
            name="Shadow MCP Server",
            asset_type=AssetType.MCP_SERVER,
            discovery_state=DiscoveryState.SHADOW,
            asset_metadata={"server_identifier": "files", "endpoint": "https://mcp.test/files"},
        ),
    )

    assert shadow.asset.discovery_source == "integration:estate-scan"
    assert shadow.asset.discovery_state == "shadow"
    assert shadow.asset.asset_metadata == {
        "server_identifier": "files",
        "endpoint": "https://mcp.test/files",
    }


def test_a_discovered_asset_starts_active_but_unknown_and_unassessed(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """The integration reports that the asset exists, not what it means.

    ``unknown`` is the honest starting point: nothing has been accounted for yet,
    and promoting the record to ``managed`` is a person's decision, made through
    ``PATCH``.
    """
    identity = identity_factory()
    result = register_discovered_asset(
        integration_session,
        identity.organization_id,
        DiscoveredAsset(
            source="test-collector",
            external_identifier="estate://api/1",
            name="Observed API",
            asset_type=AssetType.API,
        ),
    )

    assert result.asset.discovery_state == "unknown"
    assert result.asset.status == "active"
    assert result.asset.risk_classification == "unassessed"
    assert result.asset.owner_membership_id is None
    assert result.asset.last_seen_at is not None


# ── Deletion ─────────────────────────────────────────────────────────────────


def test_deleting_an_asset_removes_the_row_and_only_that_row(
    integration_engine: Engine, integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """Deletion is a real, tenant-scoped delete."""
    identity = identity_factory()
    repository = _repository(integration_session, identity)
    keep = repository.add(name="Kept", asset_type="tool")
    doomed = repository.add(name="Doomed", asset_type="tool")

    repository.delete(doomed)

    assert repository.find(doomed.id) is None
    assert repository.find(keep.id) is not None
    assert count_assets(integration_engine, identity.organization_id) == 1


def test_deleting_an_asset_in_another_organization_changes_nothing(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """A delete built from a foreign row's id removes nothing anywhere."""
    first = identity_factory(role_code="owner")
    second = identity_factory(role_code="owner")
    asset = _repository(integration_session, first).add(name="Foreign Target", asset_type="model")

    # Handed the first organization's row, the second organization's repository
    # still deletes nothing: the statement carries its own tenant filter, so a
    # stray object cannot be used to delete across the boundary.
    with bind_tenant(second.organization_id):
        _repository(integration_session, second).delete(asset)

    assert _repository(integration_session, first).find(asset.id) is not None
