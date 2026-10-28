"""Real policies for tests: definitions written through the API, then checked.

Phase 6's tests ask questions the API answers — is this policy listed, can that role
activate one, does this condition apply — so the policies they ask about are created
the way an operator creates them: over HTTP, authenticated with a real token, through
the endpoints that validate and authorize. Nothing here writes a policy behind the
API's back, because a fixture that bypassed validation and authorization would let a
broken endpoint pass its own test.

Like ``identity_fixture`` and the inventory's factory, this module commits: the
application under test runs in its own session and can only see committed rows.
:meth:`PolicyFactory.purge` puts the tables back, by organization, before the
identity fixtures remove the organizations themselves.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from aicore_api.db.tenancy import bind_tenant

__all__ = [
    "DEFAULT_CONDITION",
    "PolicyFactory",
    "PolicyRecord",
    "count_policies",
    "count_versions",
    "policy_payload",
]

#: The condition most tests use: it constrains the policy to production, which is the
#: one context fact a test can always supply and the one a policy most plausibly cares
#: about. Kept here so a test that means "the usual policy" does not restate it.
DEFAULT_CONDITION: dict[str, Any] = {
    "field": "environment",
    "operator": "equals",
    "value": "production",
}


def policy_payload(name: str, **overrides: Any) -> dict[str, Any]:
    """A valid create request for a policy called ``name``.

    Every field has a value an operator would plausibly send, so a test that means to
    exercise one thing can override exactly that one thing and leave the rest alone —
    which is also what makes a *refusal* test honest: it differs from a valid request
    in the field under test and in nothing else.
    """
    payload: dict[str, Any] = {
        "name": name,
        "description": "Written by the test suite; deny production agent changes.",
        "resource": "agent",
        "action": "update",
        "effect": "deny",
        "priority": 100,
        "conditions": [dict(DEFAULT_CONDITION)],
    }
    payload.update(overrides)
    return payload


@dataclass(frozen=True, slots=True)
class PolicyRecord:
    """A policy as the API returned it, plus what a test needs to reach it."""

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    version: int
    status: str
    effect: str
    resource: str
    action: str
    priority: int
    conditions: tuple[Mapping[str, Any], ...]
    body: Mapping[str, Any]

    @property
    def item_path(self) -> str:
        """The route that addresses this policy, relative to the API root."""
        return f"/organizations/{self.organization_id}/policies/{self.id}"


def _record(body: Mapping[str, Any], organization_id: uuid.UUID) -> PolicyRecord:
    return PolicyRecord(
        id=uuid.UUID(str(body["policy_id"])),
        organization_id=organization_id,
        name=str(body["name"]),
        version=int(body["version"]),
        status=str(body["status"]),
        effect=str(body["effect"]),
        resource=str(body["resource"]),
        action=str(body["action"]),
        priority=int(body["priority"]),
        conditions=tuple(body["conditions"]),
        body=body,
    )


class PolicyFactory:
    """Creates policies over HTTP for one organization, and cleans them up."""

    def __init__(
        self,
        *,
        client: TestClient,
        organization_id: uuid.UUID,
        engine: Engine,
        token: str,
    ) -> None:
        self.client = client
        self.organization_id = organization_id
        self.engine = engine
        self.created: list[uuid.UUID] = []
        #: The owner's credential, re-attached before every call this factory makes.
        #: The test client carries one ``Authorization`` header, and cross-tenant
        #: tests change it mid-test; re-attaching makes a factory call mean "the
        #: owner acts", whichever identity the test used last.
        self._token = token

    def _as_owner(self) -> TestClient:
        """Put the owner's credential back on the client and hand it over."""
        self.client.headers["Authorization"] = f"Bearer {self._token}"
        return self.client

    # ── Writing ──────────────────────────────────────────────────────────────

    @property
    def path(self) -> str:
        """The collection route for this factory's organization."""
        return f"/organizations/{self.organization_id}/policies"

    def create(self, name: str | None = None, **overrides: Any) -> PolicyRecord:
        """Create a policy through the API.

        The create is asserted rather than returned: a fixture whose setup can fail
        silently turns every later assertion into a statement about a policy that was
        never written. The name defaults to something unique per test, because names
        are unique per organization and a fixed name would make a second call a 409.
        """
        resolved = name or f"Policy {uuid.uuid4().hex[:8]}"
        response = self._as_owner().post(self.path, json=policy_payload(resolved, **overrides))
        assert response.status_code == 201, response.text
        record = _record(response.json(), self.organization_id)
        self.created.append(record.id)
        return record

    def create_in(
        self, organization_id: uuid.UUID, client: TestClient, name: str, **overrides: Any
    ) -> PolicyRecord:
        """Create a policy in another organization, as a different member.

        One method rather than a second factory: everything else about the policy is
        the same, and cross-tenant tests read better when the only difference between
        the two calls is the tenant.
        """
        response = client.post(
            f"/organizations/{organization_id}/policies",
            json=policy_payload(name, **overrides),
        )
        assert response.status_code == 201, response.text
        record = _record(response.json(), organization_id)
        self.created.append(record.id)
        return record

    def activate(self, policy: PolicyRecord, client: TestClient | None = None) -> PolicyRecord:
        """Put a policy in force, through the lifecycle route."""
        return self.set_status(policy, "active", client=client)

    def set_status(
        self, policy: PolicyRecord, status: str, *, client: TestClient | None = None
    ) -> PolicyRecord:
        """Move a policy through its lifecycle, asserting the move was accepted."""
        response = (client or self._as_owner()).patch(policy.item_path, json={"status": status})
        assert response.status_code == 200, response.text
        return _record(response.json(), policy.organization_id)

    def patch(self, policy: PolicyRecord, payload: Mapping[str, Any]) -> Any:
        """Send a PATCH and hand back the raw response, for the tests about refusals."""
        return self._as_owner().patch(policy.item_path, json=dict(payload))

    # ── Reading, and the raw calls behind the refusal tests ──────────────────

    def post(self, payload: Mapping[str, Any]) -> Any:
        """``POST`` a body as the owner, without asserting — for the refusals."""
        return self._as_owner().post(self.path, json=dict(payload))

    def get(self, path: str | None = None, **params: Any) -> Any:
        """``GET`` a route of this organization as the owner."""
        return self._as_owner().get(path or self.path, params=params or None)

    def read(self, policy: PolicyRecord) -> Any:
        """``GET`` one policy as the owner."""
        return self.get(policy.item_path)

    def versions(self, policy: PolicyRecord, **params: Any) -> Any:
        """``GET`` a policy's version history as the owner."""
        return self.get(f"{policy.item_path}/versions", **params)

    def delete(self, path: str) -> Any:
        """``DELETE`` a route of this organization as the owner, without asserting."""
        return self._as_owner().delete(path)

    # ── Cleanup ──────────────────────────────────────────────────────────────

    def purge(self) -> None:
        """Delete the policies this factory created.

        By organization rather than by id, and by raw statement rather than through
        the repository: the guard refuses an unscoped delete on a tenant-owned table,
        which is the same rule that keeps the application's own queries inside their
        tenant. The version history follows by cascade. Called before the identity
        fixtures remove the organizations, because a policy references its
        organization with RESTRICT.
        """
        with bind_tenant(self.organization_id), self.engine.begin() as connection:
            connection.execute(
                text("DELETE FROM aicore.policies WHERE organization_id = :organization_id"),
                {"organization_id": str(self.organization_id)},
            )
        self.created.clear()


def count_policies(engine: Engine, organization_id: uuid.UUID) -> int:
    """How many policy rows exist for an organization, read from the raw table.

    Read directly rather than through the repository so that "the row is gone" is
    asserted about the database rather than about a repository's behaviour. The
    tenant is bound because the guard applies to raw SQL too.
    """
    return _count(engine, organization_id, "aicore.policies")


def count_versions(engine: Engine, organization_id: uuid.UUID) -> int:
    """How many version rows exist for an organization, read from the raw table."""
    return _count(engine, organization_id, "aicore.policy_versions")


def _count(engine: Engine, organization_id: uuid.UUID, table: str) -> int:
    # The table name is a module-level literal, never user input, and it is
    # interpolated rather than parameterized because it is an identifier.
    with bind_tenant(organization_id), engine.connect() as connection:
        return int(
            connection.execute(
                text(f"SELECT count(*) FROM {table} WHERE organization_id = :organization_id"),
                {"organization_id": str(organization_id)},
            ).scalar_one()
        )
