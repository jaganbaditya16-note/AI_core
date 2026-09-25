"""Reading monitoring in tests, over a real trail.

Two rules, and the second one is the interesting one.

**Nothing here asserts quietly.** Every accessor returns the parsed response, and the ones
that mean "this worked" assert 200 with the body in the failure message; a test that wants
to see a refusal calls :meth:`MonitoringScene.get` and asserts the status itself.

**History can be seeded, and only where it must be.** The audit trail's clock is the
server's: an event happens when it happens, and no API call can place one in last Tuesday.
That is the right rule for the platform and an impossible one for a test of *windows* —
"the last hour contains this, the hour before does not" cannot be expressed by making
requests in the present. So :meth:`MonitoringScene.seed` writes rows directly, and it is
the only place in this suite that fabricates history. Three things keep it honest:

- it writes rows the platform itself writes — the same event types, the same
  decision/outcome pairs Phase 7 records, a ``system`` actor with no request id, exactly
  the shape the ingestion path produces;
- it writes to the table, never through the application, so a test cannot use it to fake
  what the *API* does — the assertions about real requests are still made against real
  requests;
- it is used for placement (which window, which bucket) and for scale (a hundred events
  without a hundred HTTP calls), never to make a measurement say something the trail would
  not say.

Everything else here goes through the endpoints the phase ships, as the tenant's owner.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from actions_fixture import ACTION_ID
from aicore_api.core.audit import AuditEventType
from aicore_api.db.tenancy import bind_tenant
from audit_fixture import AuditScene, list_events

__all__ = [
    "MonitoringScene",
    "SeededEvent",
    "action_event",
    "fixed_agent_id",
    "monitoring_path",
    "seed_events",
]

#: The five views Phase 9 publishes, as the path segment each one hangs off. Listed rather
#: than derived so a view renamed in the routes shows up as a failing test here.
VIEWS = ("summary", "agents", "actions", "policies", "trends")

#: What each event type records when Phase 7 writes it. Seeded history uses these, so a
#: fixture row is shaped exactly like a real one — and if the pipeline's own pairing ever
#: changes, the ``CHECK`` constraints refuse these rows and the failure is loud.
_EVENT_SHAPES: Mapping[str, tuple[str | None, str]] = {
    AuditEventType.ACTION_REQUESTED.value: (None, "pending"),
    AuditEventType.ACTION_DENIED.value: ("deny", "blocked"),
    AuditEventType.ACTION_REQUIRE_APPROVAL.value: ("require_approval", "not_executed"),
    AuditEventType.ACTION_EXECUTED.value: ("allow", "success"),
    AuditEventType.ACTION_FAILED.value: ("allow", "failed"),
    AuditEventType.ACTION_REPLAYED.value: ("allow", "replayed"),
    AuditEventType.ASSET_CREATED.value: (None, "success"),
    AuditEventType.ASSET_UPDATED.value: (None, "success"),
    AuditEventType.ASSET_DELETED.value: (None, "success"),
    AuditEventType.ASSET_DISCOVERED.value: (None, "success"),
    AuditEventType.AGENT_REGISTERED.value: (None, "success"),
    AuditEventType.AGENT_UPDATED.value: (None, "success"),
    AuditEventType.AGENT_DELETED.value: (None, "success"),
    AuditEventType.POLICY_CREATED.value: (None, "success"),
    AuditEventType.POLICY_UPDATED.value: (None, "success"),
    AuditEventType.POLICY_VERSION_PUBLISHED.value: (None, "success"),
    AuditEventType.POLICY_STATUS_CHANGED.value: (None, "success"),
    AuditEventType.POLICY_DELETED.value: (None, "success"),
}

#: The event types that carry an action identifier and a decision: the action pipeline.
_ACTION_EVENTS = frozenset(
    {
        AuditEventType.ACTION_REQUESTED.value,
        AuditEventType.ACTION_DENIED.value,
        AuditEventType.ACTION_REQUIRE_APPROVAL.value,
        AuditEventType.ACTION_EXECUTED.value,
        AuditEventType.ACTION_FAILED.value,
        AuditEventType.ACTION_REPLAYED.value,
    }
)


def monitoring_path(organization_id: uuid.UUID, view: str) -> str:
    """The monitoring route for one organization and one view."""
    assert view in VIEWS, view
    return f"/organizations/{organization_id}/monitoring/{view}"


def fixed_agent_id(index: int) -> uuid.UUID:
    """A stable identifier for seeded history: same input, same agent, every run.

    Derived from a name rather than generated, because a test that asserts which agent a
    row is about must not depend on anything random — the ordering assertions here compare
    identifiers, and a fresh uuid per run would make them unstable.
    """
    return uuid.uuid5(uuid.NAMESPACE_URL, f"aicore-test-agent-{index}")


@dataclass(frozen=True, slots=True)
class SeededEvent:
    """One row of fabricated history: what happened, and how long ago.

    ``minutes_ago`` is a float so a test can place two events either side of a bucket
    boundary (``60.0`` and ``59.9``) and assert they land in different buckets.
    """

    event_type: str
    minutes_ago: float
    agent_id: uuid.UUID | None = None
    action: str | None = None
    resource_id: uuid.UUID | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.event_type not in _EVENT_SHAPES:
            raise ValueError(f"{self.event_type!r} is not a declared audit event type")
        if self.event_type in _ACTION_EVENTS and self.action is None:
            raise ValueError(f"{self.event_type!r} is an action event and needs an action")


def seed_events(
    engine: Engine, organization_id: uuid.UUID, events: Sequence[SeededEvent], *, now: datetime
) -> int:
    """Write fabricated history straight into the trail, and say how many rows it wrote.

    The one place in this suite that inserts audit rows. It bypasses the writer on purpose —
    the point is to place events at instants the server's clock will not produce — and it
    writes the shape the platform writes for a *system* origin, so the ``CHECK`` constraints
    accept exactly what a real ingestion run would have written. A malformed row is a
    database error here, not a silent pass.
    """
    rows = list(events)
    if not rows:
        return 0
    prefix = f"seed-{uuid.uuid4().hex[:8]}"
    with bind_tenant(organization_id), engine.begin() as connection:
        for index, event in enumerate(rows):
            decision, outcome = _EVENT_SHAPES[event.event_type]
            action = event.action
            if action is None and event.event_type in _ACTION_EVENTS:
                action = ACTION_ID
            resource_type = "asset" if event.event_type.startswith("asset.") else "agent"
            if event.event_type.startswith("policy."):
                resource_type = "policy"
            metadata: dict[str, Any] = {}
            if event.reason is not None:
                metadata["reason"] = event.reason
            connection.execute(
                text(
                    "INSERT INTO aicore.audit_events (organization_id, event_type,"
                    " schema_version, occurred_at, actor_type, agent_id, resource_type,"
                    " resource_id, action, decision, outcome, correlation_id, source, metadata)"
                    " VALUES (:organization_id, :event_type, 1, :occurred_at, 'system',"
                    " :agent_id, :resource_type, :resource_id, :action, :decision, :outcome,"
                    " :correlation_id, 'ingestion', CAST(:metadata AS jsonb))"
                ),
                {
                    "organization_id": str(organization_id),
                    "event_type": event.event_type,
                    "occurred_at": now - timedelta(minutes=event.minutes_ago),
                    "agent_id": None if event.agent_id is None else str(event.agent_id),
                    "resource_type": resource_type,
                    "resource_id": None if event.resource_id is None else str(event.resource_id),
                    "action": action,
                    "decision": decision,
                    "outcome": outcome,
                    # Unique per row and inside the correlation-id alphabet, so paging and
                    # per-row assertions cannot collide on a duplicate identifier.
                    "correlation_id": f"{prefix}-{index}",
                    "metadata": json.dumps(metadata),
                },
            )
    return len(rows)


def action_event(event_type: str, minutes_ago: float, **kwargs: Any) -> SeededEvent:
    """A seeded action-pipeline event, with the fixture's action identifier by default."""
    return SeededEvent(event_type=event_type, minutes_ago=minutes_ago, action=ACTION_ID, **kwargs)


@dataclass
class MonitoringScene:
    """One tenant's audit scene, read through the monitoring endpoints.

    The scene is the audit one, extended rather than replaced: monitoring is a view over the
    trail, so the tests that matter here need to produce activity *and* measure it in the
    same tenant, under the same credential, on the same client.
    """

    audit: AuditScene
    seeded: int = 0

    # ── The tenant, and the raw material ─────────────────────────────────────

    @property
    def organization_id(self) -> uuid.UUID:
        return self.audit.organization_id

    @property
    def client(self) -> TestClient:
        """The owner's authenticated client."""
        return self.audit.trail.as_owner()

    @property
    def actions(self) -> Any:
        return self.audit.actions

    @property
    def agents(self) -> Any:
        return self.audit.agents

    @property
    def assets(self) -> Any:
        return self.audit.assets

    @property
    def policies(self) -> Any:
        return self.audit.policies

    @property
    def trail(self) -> Any:
        return self.audit.trail

    def seed(self, *events: SeededEvent, now: datetime | None = None) -> int:
        """Place fabricated history in the trail; see :func:`seed_events`."""
        moment = now or datetime.now(UTC)
        written = seed_events(
            self.audit.trail.engine, self.organization_id, list(events), now=moment
        )
        self.seeded += written
        return written

    # ── The endpoints ────────────────────────────────────────────────────────

    def get(self, view: str, **params: Any) -> Any:
        """``GET`` one monitoring view as the owner, without asserting."""
        wanted = {key: value for key, value in params.items() if value is not None}
        return self.client.get(monitoring_path(self.organization_id, view), params=wanted or None)

    def read(self, view: str, **params: Any) -> Mapping[str, Any]:
        """``GET`` one view, assert 200, and return the parsed body."""
        response = self.get(view, **params)
        assert response.status_code == 200, response.text
        return response.json()

    # Named after what each view returns rather than after its path segment: ``agents``
    # and ``actions`` above are the factories that *produce* activity, and one attribute
    # cannot be both the thing that acts and the reading of what it did.
    def summary(self, **params: Any) -> Mapping[str, Any]:
        return self.read("summary", **params)

    def agent_activity(self, **params: Any) -> Mapping[str, Any]:
        return self.read("agents", **params)

    def action_activity(self, **params: Any) -> Mapping[str, Any]:
        return self.read("actions", **params)

    def policy_activity(self, **params: Any) -> Mapping[str, Any]:
        return self.read("policies", **params)

    def trends(self, **params: Any) -> Mapping[str, Any]:
        return self.read("trends", **params)

    # ── The trail itself ─────────────────────────────────────────────────────

    def stored(self) -> list[Mapping[str, Any]]:
        """Every stored row for this tenant, oldest first."""
        return list_events(self.audit.trail.engine, self.organization_id)

    def trail_count(self) -> int:
        return self.audit.trail.count()

    def trail_signature(self) -> str:
        """A digest of the tenant's whole trail: what "monitoring changed nothing" means.

        Rows, their identifiers, their timestamps and their metadata, hashed in order. A
        read that rewrote a row, dropped one, or added one — including an audit event
        recording the read — changes this, which a row count alone would not notice.
        """
        rendered = json.dumps(
            [{key: str(value) for key, value in row.items()} for row in self.stored()],
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(rendered.encode("utf-8")).hexdigest()

    def purge(self) -> None:
        """Remove the tenant's activity — seeded history included."""
        self.audit.purge()
        self.seeded = 0
