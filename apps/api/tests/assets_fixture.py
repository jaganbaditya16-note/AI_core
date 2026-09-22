"""Real inventory records for tests: assets written through the API, then checked.

Phase 3's tests ask questions the API answers — is this asset listed, can that role
create one, does the filter narrow the page — so the assets they ask about are
created the way an operator creates them: over HTTP, authenticated with a real
token. Nothing here writes an asset behind the API's back, because a fixture that
bypassed validation and authorization would let a broken endpoint pass its own
test.

There is one deliberate exception, and it is narrow: :func:`insert_asset_row`
writes a row directly, for the database-level tests that assert what the schema
refuses (a cross-tenant owner, an unknown asset type, metadata that is not an
object). Those cases are meant to be unreachable through the API, so they cannot
be set up through it either.

Like ``identity_fixture``, this module commits: the application under test runs in
its own session and can only see committed rows. ``AssetFactory.purge`` puts the
table back, by organization, before the identity fixtures remove the organizations
themselves.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from aicore_api.core.assets import AssetType, DiscoveryState, Environment, RiskClassification
from aicore_api.db.tenancy import bind_tenant

__all__ = [
    "ASSET_TYPES",
    "AssetFactory",
    "AssetRecord",
    "count_assets",
    "insert_asset_row",
    "sample_metadata",
]

#: Every asset type the inventory is required to support, in the vocabulary's order.
ASSET_TYPES: tuple[str, ...] = tuple(asset_type.value for asset_type in AssetType)


@dataclass(frozen=True, slots=True)
class AssetRecord:
    """An asset as the API returned it, plus what a test needs to clean up."""

    id: uuid.UUID
    organization_id: uuid.UUID
    asset_type: str
    name: str
    status: str
    environment: str
    discovery_state: str
    risk_classification: str
    #: The full response body, for assertions about fields this dataclass omits.
    body: Mapping[str, Any]


def assets_path(organization_id: uuid.UUID) -> str:
    """The collection URL for one organization's inventory."""
    return f"/organizations/{organization_id}/assets"


def asset_path(organization_id: uuid.UUID, asset_id: uuid.UUID) -> str:
    """The item URL for one asset."""
    return f"{assets_path(organization_id)}/{asset_id}"


@dataclass
class AssetFactory:
    """Creates assets through the API for one test, and removes them afterwards."""

    client: TestClient
    organization_id: uuid.UUID
    engine: Engine
    _created: list[uuid.UUID] = field(default_factory=list)

    def create(
        self,
        *,
        name: str = "Inventory Asset",
        asset_type: str = AssetType.MODEL.value,
        expected_status: int = 201,
        **fields: Any,
    ) -> AssetRecord | None:
        """``POST`` one asset and return it, or ``None`` when the call is expected to fail.

        ``expected_status`` exists because half the interesting assertions are about
        *refusals* — an invalid lifecycle state, an owner from another tenant — and
        the test should not have to hand-build the request to see the error.
        """
        payload: dict[str, Any] = {"name": name, "asset_type": asset_type, **fields}
        response = self.client.post(assets_path(self.organization_id), json=payload)
        assert response.status_code == expected_status, response.text
        if expected_status != 201:
            return None
        body = response.json()
        asset_id = uuid.UUID(body["id"])
        self._created.append(asset_id)
        return _record(body, self.organization_id)

    def create_each_type(self) -> list[AssetRecord]:
        """One asset of every supported type — the inventory's own coverage check."""
        records = [
            self.create(name=f"{asset_type.replace('_', ' ').title()} Asset", asset_type=asset_type)
            for asset_type in ASSET_TYPES
        ]
        return [record for record in records if record is not None]

    def purge(self) -> None:
        """Delete the assets this factory created.

        By organization rather than by id: the tenant guard refuses an unscoped
        delete on a tenant-owned table, which is the same rule that keeps the
        application's own queries inside their tenant. Called before the identity
        fixtures remove the organizations, because an owner's membership cannot be
        deleted while assets still reference it.
        """
        with bind_tenant(self.organization_id), self.engine.begin() as connection:
            connection.execute(
                text("DELETE FROM aicore.assets WHERE organization_id = :organization_id"),
                {"organization_id": str(self.organization_id)},
            )
        self._created.clear()


def _record(body: Mapping[str, Any], organization_id: uuid.UUID) -> AssetRecord:
    return AssetRecord(
        id=uuid.UUID(body["id"]),
        organization_id=organization_id,
        asset_type=body["asset_type"],
        name=body["name"],
        status=body["status"],
        environment=body["environment"],
        discovery_state=body["discovery_state"],
        risk_classification=body["risk_classification"],
        body=body,
    )


def sample_metadata(asset_type: str) -> dict[str, str]:
    """A valid, type-appropriate metadata object for ``asset_type``.

    Shared by the database tests, the API tests and the documentation example, so
    "one example per type" is stated in one place.
    """
    examples: dict[str, dict[str, str]] = {
        AssetType.AGENT.value: {"framework": "langgraph", "version": "0.2.1"},
        AssetType.APPLICATION.value: {
            "application_identifier": "support-copilot",
            "repository_url": "https://example.test/acme/support-copilot",
        },
        AssetType.MODEL.value: {
            "provider": "example-provider",
            "model_identifier": "example-large-1",
            "version": "2026-05",
        },
        AssetType.TOOL.value: {
            "tool_identifier": "ticket.lookup",
            "endpoint": "https://tools.example.test/tickets/lookup",
        },
        AssetType.MCP_SERVER.value: {
            "server_identifier": "files-server",
            "endpoint": "https://mcp.example.test/files",
        },
        AssetType.API.value: {
            "endpoint": "https://api.example.test/v1/complete",
            "provider": "example-provider",
        },
        AssetType.DATA_SOURCE.value: {"classification": "internal"},
    }
    return examples[asset_type]


def insert_asset_row(
    engine: Engine,
    *,
    organization_id: uuid.UUID,
    name: str,
    asset_type: str = AssetType.MODEL.value,
    owner_membership_id: uuid.UUID | None = None,
    external_identifier: str | None = None,
    discovery_state: str = DiscoveryState.MANAGED.value,
    status: str = "draft",
    environment: str = Environment.UNKNOWN.value,
    risk_classification: str = RiskClassification.UNASSESSED.value,
    metadata: dict[str, Any] | None = None,
) -> uuid.UUID:
    """Write a row straight into the table, bypassing the API.

    Raises whatever PostgreSQL raises, which is the point: the tests that use this
    assert that the *database* refuses a cross-tenant owner, an unknown asset type
    or metadata that is not an object. Constraints are only worth having if
    something exercises them, and the API is designed never to let these requests
    through. The tenant is bound because this helper writes tenant-owned data and
    the guard applies to raw SQL like everything else.
    """
    with bind_tenant(organization_id), engine.begin() as connection:
        return connection.execute(
            text(
                "INSERT INTO aicore.assets "
                "(organization_id, owner_membership_id, name, asset_type, status, environment, "
                " discovery_state, risk_classification, external_identifier, metadata) "
                "VALUES (:organization_id, :owner_membership_id, :name, :asset_type, :status, "
                " :environment, :discovery_state, :risk_classification, :external_identifier, "
                " CAST(:metadata AS jsonb)) "
                "RETURNING id"
            ),
            {
                "organization_id": str(organization_id),
                "owner_membership_id": (
                    str(owner_membership_id) if owner_membership_id is not None else None
                ),
                "name": name,
                "asset_type": asset_type,
                "status": status,
                "environment": environment,
                "discovery_state": discovery_state,
                "risk_classification": risk_classification,
                "external_identifier": external_identifier,
                "metadata": None if metadata is None else json.dumps(metadata),
            },
        ).scalar_one()


def count_assets(engine: Engine, organization_id: uuid.UUID) -> int:
    """How many asset rows exist for an organization, read from the raw table.

    Read directly rather than through the repository so that "the row is gone" is
    asserted about the database, not about a repository's behaviour. The tenant is
    bound because the guard applies to raw SQL too — which is the point: this
    helper cannot quietly read across tenants either.
    """
    with bind_tenant(organization_id), engine.connect() as connection:
        return int(
            connection.execute(
                text("SELECT count(*) FROM aicore.assets WHERE organization_id = :organization_id"),
                {"organization_id": str(organization_id)},
            ).scalar_one()
        )
