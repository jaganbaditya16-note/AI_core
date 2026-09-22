"""Real registered agents for tests: registered through the API, then checked.

Phase 4's tests ask questions the API answers — does this registration produce a
stable identity, can that role move an agent through its lifecycle, is a foreign
identity indistinguishable from an unknown one — so the agents they ask about are
created the way an operator creates them: over HTTP, authenticated with a real
token. Nothing here registers an agent behind the API's back, because a fixture
that bypassed validation and authorization would let a broken endpoint pass its own
test.

Two deliberate exceptions, both narrow:

- :meth:`AgentFactory.register_row` writes a registry row directly, for the tests
  that assert what the schema *refuses* — a cross-tenant asset, an unknown category,
  a duplicate identity, a blank version. Those cases are meant to be unreachable
  through the API, so they cannot be set up through it either.
- :func:`insert_agent_asset` writes an inventory row directly, to set up the
  pre-registry situation an adoption test needs (an ``agent`` asset that exists
  before anything registered it).

Like the other fixtures, this module commits: the application under test runs in its
own session and can only see committed rows. ``AgentFactory.purge`` puts the tables
back, by organization, before the identity fixtures remove the organizations
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

from aicore_api.core.agents import AgentCategory
from aicore_api.core.assets import AssetType
from aicore_api.db.tenancy import bind_tenant

__all__ = [
    "AGENT_CATEGORIES",
    "AgentFactory",
    "AgentRecord",
    "agent_path",
    "agents_path",
    "count_agent_rows",
    "identity_path",
    "insert_agent_asset",
]

#: Every agent category the registry is required to support, in the vocabulary's
#: order — the completeness check for the closed vocabulary.
AGENT_CATEGORIES: tuple[str, ...] = tuple(category.value for category in AgentCategory)


@dataclass(frozen=True, slots=True)
class AgentRecord:
    """A registered agent as the API returned it, plus what a test needs to clean up."""

    id: uuid.UUID
    organization_id: uuid.UUID
    identity_id: uuid.UUID
    asset_id: uuid.UUID
    display_name: str
    category: str
    version: str
    status: str
    #: The full response body, for assertions about fields this dataclass omits.
    body: Mapping[str, Any]


def agents_path(organization_id: uuid.UUID) -> str:
    """The collection URL for one organization's agent registry."""
    return f"/organizations/{organization_id}/agents"


def agent_path(organization_id: uuid.UUID, agent_id: uuid.UUID) -> str:
    """The item URL for one registered agent."""
    return f"{agents_path(organization_id)}/{agent_id}"


def identity_path(organization_id: uuid.UUID, identity_id: uuid.UUID | str) -> str:
    """The identity-lookup URL for one agent."""
    return f"{agents_path(organization_id)}/identity/{identity_id}"


@dataclass
class AgentFactory:
    """Registers agents through the API for one test, and removes them afterwards."""

    client: TestClient
    organization_id: uuid.UUID
    engine: Engine
    _created: list[uuid.UUID] = field(default_factory=list)

    def register(
        self,
        *,
        display_name: str = "Support Triage",
        category: str = AgentCategory.ASSISTANT.value,
        version: str = "1.0.0",
        expected_status: int = 201,
        **fields: Any,
    ) -> AgentRecord | None:
        """``POST`` one registration and return it, or ``None`` when it is expected to fail.

        ``expected_status`` exists because half the interesting assertions are about
        *refusals* — an invented category, an owner from another tenant, a request
        that contradicts an existing record — and the test should not have to
        hand-build the request to see the error.
        """
        payload: dict[str, Any] = {
            "display_name": display_name,
            "category": category,
            "version": version,
            **fields,
        }
        response = self.client.post(agents_path(self.organization_id), json=payload)
        assert response.status_code == expected_status, response.text
        if expected_status != 201:
            return None
        body = response.json()
        agent_id = uuid.UUID(body["id"])
        self._created.append(agent_id)
        return _record(body, self.organization_id)

    def register_each_category(self) -> list[AgentRecord]:
        """One agent per category — the registry's own coverage check."""
        records = [
            self.register(
                display_name=f"{category.replace('_', ' ').title()} Agent", category=category
            )
            for category in AGENT_CATEGORIES
        ]
        return [record for record in records if record is not None]

    def register_row(
        self,
        *,
        asset_id: uuid.UUID,
        category: str = AgentCategory.ASSISTANT.value,
        version: str = "1.0.0",
        identity_id: uuid.UUID | None = None,
        organization_id: uuid.UUID | None = None,
        identity_metadata: dict[str, Any] | None = None,
    ) -> uuid.UUID:
        """Write a registry row straight into the table, bypassing the API.

        Raises whatever PostgreSQL raises, which is the point: the tests that use it
        assert that the *database* refuses a cross-tenant asset, an unknown category,
        a duplicate identity or a blank version. Constraints are only worth having if
        something exercises them, and the API is designed never to let these requests
        through. ``organization_id`` defaults to the factory's tenant and can be
        overridden precisely so the cross-tenant case can be attempted.
        """
        tenant = organization_id or self.organization_id
        with bind_tenant(tenant), self.engine.begin() as connection:
            return connection.execute(
                text(
                    "INSERT INTO aicore.agents "
                    "(organization_id, asset_id, identity_id, category, version, "
                    " identity_metadata) "
                    "VALUES (:organization_id, :asset_id, "
                    " COALESCE(:identity_id, gen_random_uuid()), :category, :version, "
                    " CAST(:identity_metadata AS jsonb)) "
                    "RETURNING id"
                ),
                {
                    "organization_id": str(tenant),
                    "asset_id": str(asset_id),
                    "identity_id": str(identity_id) if identity_id is not None else None,
                    "category": category,
                    "version": version,
                    "identity_metadata": (
                        None if identity_metadata is None else json.dumps(identity_metadata)
                    ),
                },
            ).scalar_one()

    def purge(self) -> None:
        """Delete the registry rows and inventory records this factory created.

        By organization rather than by id: the tenant guard refuses an unscoped
        delete on a tenant-owned table, which is the same rule that keeps the
        application's own queries inside their tenant. Called before the identity
        fixtures remove the organizations, because an agent's asset may be owned by a
        membership that cannot be deleted while it is referenced.
        """
        with bind_tenant(self.organization_id), self.engine.begin() as connection:
            connection.execute(
                text("DELETE FROM aicore.agents WHERE organization_id = :organization_id"),
                {"organization_id": str(self.organization_id)},
            )
            connection.execute(
                text("DELETE FROM aicore.assets WHERE organization_id = :organization_id"),
                {"organization_id": str(self.organization_id)},
            )
        self._created.clear()


def _record(body: Mapping[str, Any], organization_id: uuid.UUID) -> AgentRecord:
    return AgentRecord(
        id=uuid.UUID(body["id"]),
        organization_id=organization_id,
        identity_id=uuid.UUID(body["identity_id"]),
        asset_id=uuid.UUID(body["asset_id"]),
        display_name=body["display_name"],
        category=body["category"],
        version=body["version"],
        status=body["status"],
        body=body,
    )


def insert_agent_asset(
    engine: Engine,
    *,
    organization_id: uuid.UUID,
    name: str,
    owner_membership_id: uuid.UUID | None = None,
    external_identifier: str | None = None,
    status: str = "draft",
    environment: str = "unknown",
) -> uuid.UUID:
    """Write an ``agent`` inventory row directly, without registering it.

    The pre-registry situation an adoption test needs: an organization that already
    knows about an agent asset (an integration recorded it, or it predates the
    registry) and now registers it. Writing it through the API would be a *manual*
    registration, which is exactly what the test is not describing.
    """
    with bind_tenant(organization_id), engine.begin() as connection:
        return connection.execute(
            text(
                "INSERT INTO aicore.assets "
                "(organization_id, owner_membership_id, name, asset_type, status, environment, "
                " discovery_source, external_identifier) "
                "VALUES (:organization_id, :owner_membership_id, :name, :asset_type, :status, "
                " :environment, :discovery_source, :external_identifier) "
                "RETURNING id"
            ),
            {
                "organization_id": str(organization_id),
                "owner_membership_id": (
                    str(owner_membership_id) if owner_membership_id is not None else None
                ),
                "name": name,
                "asset_type": AssetType.AGENT.value,
                "status": status,
                "environment": environment,
                "discovery_source": "integration:test",
                "external_identifier": external_identifier,
            },
        ).scalar_one()


def count_agent_rows(engine: Engine, organization_id: uuid.UUID) -> int:
    """How many registry rows exist for an organization, read from the raw table.

    Read directly rather than through the repository so that "the identity is gone"
    is asserted about the database, not about a repository's behaviour. The tenant is
    bound because the guard applies to raw SQL too — which is the point: this helper
    cannot quietly read across tenants either.
    """
    with bind_tenant(organization_id), engine.connect() as connection:
        return int(
            connection.execute(
                text("SELECT count(*) FROM aicore.agents WHERE organization_id = :organization_id"),
                {"organization_id": str(organization_id)},
            ).scalar_one()
        )
