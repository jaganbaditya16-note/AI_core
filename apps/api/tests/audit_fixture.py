"""Reading the audit trail in tests: real requests, and what the table records.

Phase 8's subject is a durable record, so its tests read the record — from the raw table,
with the tenant bound, the same way ``actions_fixture`` reads the idempotency ledger. The
endpoint has its own tests (``test_audit_api.py``); this module exists so a test can ask
"what is actually stored?" without going through the API that is being tested.

Two rules, both borrowed from the Phase 7 fixture because they are the reason its tests
mean anything:

- **Nothing here decides anything.** No helper produces an event; the helpers send
  requests and read rows. A fixture that could write a trail row could satisfy an
  assertion about one.
- **Reads are direct and tenant-bound.** ``count``, ``rows`` and ``find`` never go through
  the repository, so "the trail holds exactly these rows" is a statement about PostgreSQL
  rather than about a repository's behaviour.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from actions_fixture import ActionFactory
from agents_fixture import AgentFactory
from aicore_api.db.tenancy import bind_tenant
from assets_fixture import AssetFactory
from identity_fixture import Identity
from policies_fixture import PolicyFactory

__all__ = [
    "AuditFactory",
    "AuditScene",
    "audit_path",
    "count_events",
    "delete_events",
    "find_events",
    "list_events",
]

#: The columns a trail row has, as the tests read them. Listed rather than derived so a
#: column added to the table shows up as a failing expectation rather than a silent pass.
ROW_COLUMNS = (
    "id",
    "organization_id",
    "event_type",
    "schema_version",
    "occurred_at",
    "actor_type",
    "actor_id",
    "actor_membership_id",
    "agent_id",
    "resource_type",
    "resource_id",
    "action",
    "decision",
    "outcome",
    "correlation_id",
    "request_id",
    "source",
    "metadata",
)

_SELECT = "SELECT " + ", ".join(ROW_COLUMNS) + " FROM aicore.audit_events"


def audit_path(organization_id: uuid.UUID) -> str:
    """The read-only audit route for one organization."""
    return f"/organizations/{organization_id}/audit-events"


def list_events(
    engine: Engine, organization_id: uuid.UUID, *, event_type: str | None = None
) -> list[Mapping[str, Any]]:
    """Every stored event for one organization, oldest first.

    Ordered by ``occurred_at`` then by id so a test can assert a *sequence* — which is what
    makes "the request was recorded before the execution" checkable.
    """
    statement = f"{_SELECT} WHERE organization_id = :organization_id"
    parameters: dict[str, Any] = {"organization_id": str(organization_id)}
    if event_type is not None:
        statement += " AND event_type = :event_type"
        parameters["event_type"] = event_type
    statement += " ORDER BY occurred_at, id"
    with bind_tenant(organization_id), engine.connect() as connection:
        rows = connection.execute(text(statement), parameters).mappings().all()
    return [_decode(row) for row in rows]


def find_events(
    engine: Engine, organization_id: uuid.UUID, event_type: str
) -> list[Mapping[str, Any]]:
    """Every stored event of one type, oldest first."""
    return list_events(engine, organization_id, event_type=event_type)


def count_events(engine: Engine, organization_id: uuid.UUID) -> int:
    """How many rows the trail holds for one organization."""
    with bind_tenant(organization_id), engine.connect() as connection:
        return int(
            connection.execute(
                text(
                    "SELECT count(*) FROM aicore.audit_events "
                    "WHERE organization_id = :organization_id"
                ),
                {"organization_id": str(organization_id)},
            ).scalar_one()
        )


def delete_events(engine: Engine, organization_id: uuid.UUID, reason: str) -> int:
    """Remove this organization's trail, stating out loud that this is teardown.

    The only way to delete an audit row, and it goes through the same named override the
    application would have to use: a test that could delete a row without it would not be
    testing the guard the schema installs.
    """
    with bind_tenant(organization_id), engine.begin() as connection:
        connection.execute(
            text("SELECT set_config('aicore.audit_retention', :reason, true)"),
            {"reason": reason},
        )
        result = connection.execute(
            text("DELETE FROM aicore.audit_events WHERE organization_id = :organization_id"),
            {"organization_id": str(organization_id)},
        )
        return int(result.rowcount)


def _decode(row: Mapping[str, Any]) -> Mapping[str, Any]:
    """A stored row as a plain mapping, with the JSONB decoded.

    ``metadata`` comes back as text or as a dict depending on the driver, and a test that
    asserted against a string would be asserting about psycopg rather than about the trail.
    """
    record = dict(row)
    metadata = record.get("metadata")
    record["metadata"] = json.loads(metadata) if isinstance(metadata, str) else metadata
    return record


@dataclass
class AuditFactory:
    """Reads the trail of one organization, and reads it through the API as its owner.

    Both halves matter: the HTTP calls prove what an operator sees, the direct reads prove
    what is stored. A test about secret hygiene needs the second — a redaction that only
    happens in the serializer would pass an HTTP assertion and fail the security requirement.
    """

    client: TestClient
    organization_id: uuid.UUID
    engine: Engine
    token: str
    created: list[uuid.UUID] = field(default_factory=list)

    @property
    def path(self) -> str:
        """The read route for this factory's organization."""
        return audit_path(self.organization_id)

    def as_owner(self) -> TestClient:
        """Put the owner's credential back on the client and hand it over.

        Public because the trail is only half of what a test needs: a test that wants an
        event to look at also has to perform the operation that produces it, and it does
        that as the same owner, on the same client.
        """
        self.client.headers["Authorization"] = f"Bearer {self.token}"
        return self.client

    # ── Through the API ──────────────────────────────────────────────────────

    def get(self, *, path: str | None = None, **params: Any) -> Any:
        """``GET`` the trail as the owner, without asserting — refusals matter too."""
        resolved = path or self.path
        wanted = {key: value for key, value in params.items() if value is not None}
        return self.as_owner().get(resolved, params=wanted or None)

    def page(self, **params: Any) -> list[Mapping[str, Any]]:
        """``GET`` the trail as the owner, assert 200, and return the items."""
        response = self.get(**params)
        assert response.status_code == 200, response.text
        return response.json()["items"]

    def types(self, **params: Any) -> list[str]:
        """The event types on one page, in the order the API returned them."""
        return [item["event_type"] for item in self.page(**params)]

    # ── What is actually stored ──────────────────────────────────────────────

    def stored(self, *, event_type: str | None = None) -> list[Mapping[str, Any]]:
        """Every stored row for this organization, oldest first."""
        return list_events(self.engine, self.organization_id, event_type=event_type)

    def stored_types(self) -> list[str]:
        """The stored event types, in the order PostgreSQL returns them."""
        return [row["event_type"] for row in self.stored()]

    def count(self) -> int:
        """How many rows this organization's trail holds."""
        return count_events(self.engine, self.organization_id)

    def purge(self) -> None:
        """Delete this organization's trail, before the identity fixtures remove it.

        The tenant foreign key is ``RESTRICT`` and the table is append-only, so this is not
        tidiness: without it, removing the organization fails.
        """
        delete_events(self.engine, self.organization_id, "phase 8 test teardown")
        self.created.clear()


@dataclass
class AuditScene:
    """One tenant, its owner, and every factory that acts inside it.

    The trail is only interesting next to the operations that wrote it, so this fixture
    hands them over together: a test can register an agent, execute an action against it
    and then read the record the two produced — all as the same person, in the same
    organization, through the same client. The alternative (an audit fixture in one tenant
    and an inventory fixture in another) would make every integration assertion vacuous.

    Nothing here writes a trail row. Each factory writes its own subject — an asset, an
    agent, a policy, an execution — and the trail is a consequence of doing so.
    """

    identity: Identity
    trail: AuditFactory
    assets: AssetFactory
    agents: AgentFactory
    policies: PolicyFactory
    actions: ActionFactory

    @property
    def organization_id(self) -> uuid.UUID:
        """The tenant every factory above acts in."""
        return self.identity.organization_id

    def purge(self) -> None:
        """Put the tenant back, in the order the foreign keys require.

        The registry's purge also removes the inventory records agent registration
        created, so it goes first; policies and the ledger follow; the trail goes last,
        under the one override that permits a delete.
        """
        self.actions.purge()
        self.agents.purge()
        self.assets.purge()
        self.policies.purge()
        self.trail.purge()
