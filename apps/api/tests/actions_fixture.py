"""Executing actions for tests: real requests, and what they leave behind.

Phase 7 is the first phase whose subject is *doing* something, so its tests need two
things the earlier fixtures did not have: a way to send an execution request as a
particular identity, and a way to read what an execution left in the idempotency
ledger. Both are here, and both are deliberately literal — the request is assembled
from the documented fields, and the ledger is read from the raw table with the tenant
bound, the same way ``policies_fixture`` reads policy rows.

Nothing here decides anything. A fixture that could produce an ``ALLOW`` would let a
broken firewall pass its own test, so the helpers only *send* requests and *read* rows;
every assertion about what happened belongs to the test that made it happen.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from aicore_api.db.tenancy import bind_tenant

__all__ = [
    "ACTION_ID",
    "ActionFactory",
    "count_executions",
    "execution_path",
    "execution_payload",
    "find_execution",
]

#: The one action this build registers. A literal rather than an import of
#: ``core.actions.AGENT_POSTURE_CHECK``: a test that asked the code what it registers
#: would agree with any catalogue, including an empty one.
ACTION_ID = "agent.posture_check"


def execution_path(organization_id: uuid.UUID) -> str:
    """The execution route for one organization."""
    return f"/organizations/{organization_id}/actions/execute"


def execution_payload(target_id: uuid.UUID | str, **overrides: Any) -> dict[str, Any]:
    """A valid execution request for ``target_id``.

    Every field has a value an operator would plausibly send. ``environment`` is
    ``production`` because that is what the fixtures register their agents in, and the
    firewall refuses a request whose declared environment the target's record does not
    confirm — so a test that means something else overrides it, visibly.
    """
    payload: dict[str, Any] = {
        "action": ACTION_ID,
        "target_id": str(target_id),
        "environment": "production",
        "arguments": {},
        "idempotency_key": f"test-{uuid.uuid4().hex}",
    }
    payload.update(overrides)
    return payload


@dataclass
class ActionFactory:
    """Sends execution requests for one organization as its owner.

    The owner's credential is re-attached before every call, because the test client
    carries a single ``Authorization`` header and the cross-tenant tests change it
    mid-test: a factory call then means "the owner acts", whichever identity the test
    used last.
    """

    client: TestClient
    organization_id: uuid.UUID
    engine: Engine
    token: str
    created: list[str] = field(default_factory=list)

    @property
    def path(self) -> str:
        """The execution route for this factory's organization."""
        return execution_path(self.organization_id)

    def _as_owner(self) -> TestClient:
        self.client.headers["Authorization"] = f"Bearer {self.token}"
        return self.client

    def execute(self, target_id: uuid.UUID | str, **overrides: Any) -> Any:
        """``POST`` one execution request as the owner, without asserting.

        Raw on purpose: half of Phase 7 is about refusals, and a test asserting a 403
        should not have to hand-build the request to see it.
        """
        payload = execution_payload(target_id, **overrides)
        response = self._as_owner().post(self.path, json=payload)
        self.created.append(str(payload["idempotency_key"]))
        return response

    def post(self, payload: Mapping[str, Any]) -> Any:
        """``POST`` a body verbatim, for the tests that build their own request."""
        return self._as_owner().post(self.path, json=dict(payload))

    def executed(self, target_id: uuid.UUID | str, **overrides: Any) -> Mapping[str, Any]:
        """Execute, assert that it ran, and return the response body."""
        response = self.execute(target_id, **overrides)
        assert response.status_code == 200, response.text
        return response.json()

    # ── What the execution left behind ───────────────────────────────────────

    def count_executions(self) -> int:
        """How many ledger rows exist for this organization."""
        return count_executions(self.engine, self.organization_id)

    def find_execution(self, idempotency_key: str) -> Mapping[str, Any] | None:
        """The ledger row for one key, or ``None``."""
        return find_execution(self.engine, self.organization_id, idempotency_key)

    def purge(self) -> None:
        """Delete this organization's ledger rows.

        Called before the identity fixtures remove the organization, because a ledger
        row references it with RESTRICT.
        """
        purge_executions(self.engine, self.organization_id)
        self.created.clear()


def purge_executions(engine: Engine, organization_id: uuid.UUID) -> None:
    """Delete every ledger row for one organization.

    By organization rather than by key: the guard refuses an unscoped delete on a
    tenant-owned table, which is the same rule the application is held to. A test that
    writes through the repository (which commits) calls this from a fixture, so the
    rows it created cannot outlive it.
    """
    with bind_tenant(organization_id), engine.begin() as connection:
        connection.execute(
            text("DELETE FROM aicore.action_executions WHERE organization_id = :organization_id"),
            {"organization_id": str(organization_id)},
        )


def count_executions(engine: Engine, organization_id: uuid.UUID) -> int:
    """How many ledger rows exist for an organization, read from the raw table.

    Read directly rather than through the repository so that "nothing was recorded" is
    asserted about the database rather than about a repository's behaviour.
    """
    with bind_tenant(organization_id), engine.connect() as connection:
        return int(
            connection.execute(
                text(
                    "SELECT count(*) FROM aicore.action_executions "
                    "WHERE organization_id = :organization_id"
                ),
                {"organization_id": str(organization_id)},
            ).scalar_one()
        )


def find_execution(
    engine: Engine, organization_id: uuid.UUID, idempotency_key: str
) -> Mapping[str, Any] | None:
    """One ledger row as a plain mapping, or ``None``.

    ``outcome`` is handed back as decoded JSON rather than as a string, so a test can
    assert what the row records — and, in the tests about secrets, what it does not.
    """
    with bind_tenant(organization_id), engine.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT idempotency_key, action_id, target_id, request_fingerprint, "
                    " status, outcome, error_code, created_at, completed_at "
                    "FROM aicore.action_executions "
                    "WHERE organization_id = :organization_id "
                    "AND idempotency_key = :idempotency_key"
                ),
                {"organization_id": str(organization_id), "idempotency_key": idempotency_key},
            )
            .mappings()
            .one_or_none()
        )
    if row is None:
        return None
    record = dict(row)
    outcome = record.get("outcome")
    record["outcome"] = json.loads(outcome) if isinstance(outcome, str) else outcome
    return record
