"""Phase 10 test support: history placed at exact instants, and the risk endpoints read.

The anomaly engine compares an observation window against a baseline of 7 to 30 days, so
its tests need history the server's clock cannot produce. Like Phase 9's
:func:`monitoring_fixture.seed_events`, :func:`seed_risk_events` writes trail rows directly
— the same event types and decision/outcome pairs the pipeline writes, a ``system`` actor,
no request id — but placed at absolute instants relative to an explicit ``as_of``, and in
one ``executemany`` so a month of history costs one round trip.

Every analysis in these tests passes ``as_of`` explicitly. The default ("the start of the
current hour") would make a test that straddles an hour boundary analyse a different window
than the one it seeded.

Metadata is seeded with a canary secret on purpose (:data:`CANARY_SECRET`): the engine must
never read metadata, so the canary must never appear in any analysis, detection or evidence.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import sessionmaker

from actions_fixture import ACTION_ID
from aicore_api.core.audit import AuditEventType
from aicore_api.core.risk import (
    AnalysisWindows,
    BaselineWindow,
    ObservationWindow,
    floor_to_hour,
    resolve_analysis_windows,
)
from aicore_api.db.tenancy import bind_tenant
from aicore_api.risk.cli import main as risk_cli
from monitoring_fixture import MonitoringScene

__all__ = [
    "CANARY_SECRET",
    "RiskEvent",
    "RiskScene",
    "analysis_as_of",
    "count_detections",
    "delete_detections",
    "list_detections",
    "observed",
    "pipeline",
    "risk_path",
    "seed_risk_events",
    "steady_history",
    "windows_for",
]

REQUESTED = AuditEventType.ACTION_REQUESTED.value
DENIED = AuditEventType.ACTION_DENIED.value
EXECUTED = AuditEventType.ACTION_EXECUTED.value
FAILED = AuditEventType.ACTION_FAILED.value

#: Written into every seeded row's metadata. Never allowed to surface anywhere.
CANARY_SECRET = "sk_live_CANARY_7f3a9c_do_not_leak"

_SHAPES: Mapping[str, tuple[str | None, str]] = {
    REQUESTED: (None, "pending"),
    DENIED: ("deny", "blocked"),
    EXECUTED: ("allow", "success"),
    FAILED: ("allow", "failed"),
    AuditEventType.ACTION_REQUIRE_APPROVAL.value: ("require_approval", "not_executed"),
    AuditEventType.ACTION_REPLAYED.value: ("allow", "replayed"),
}


def risk_path(organization_id: uuid.UUID, view: str) -> str:
    return f"/organizations/{organization_id}/risk/{view}"


def analysis_as_of() -> datetime:
    """A whole UTC hour safely in the past: the start of the previous hour."""
    return floor_to_hour(datetime.now(UTC)) - timedelta(hours=1)


def windows_for(
    as_of: datetime,
    baseline: BaselineWindow | str = BaselineWindow.FOURTEEN_DAYS,
    observation: ObservationWindow | str = ObservationWindow.TWENTY_FOUR_HOURS,
) -> AnalysisWindows:
    """The windows an analysis with this ``as_of`` compares."""
    return resolve_analysis_windows(
        baseline=baseline, observation=observation, as_of=as_of, now=datetime.now(UTC)
    )


@dataclass(frozen=True, slots=True)
class RiskEvent:
    """One seeded trail row at an absolute instant."""

    event_type: str
    at: datetime
    agent_id: uuid.UUID | None
    action: str = ACTION_ID
    resource_id: uuid.UUID | None = None


def pipeline(
    agent_id: uuid.UUID,
    at: datetime,
    outcome: str | None = EXECUTED,
    *,
    action: str = ACTION_ID,
    resource_id: uuid.UUID | None = None,
) -> list[RiskEvent]:
    """A request and (optionally) what came of it, one second later — as Phase 7 writes it."""
    events = [RiskEvent(REQUESTED, at, agent_id, action, resource_id)]
    if outcome is not None:
        events.append(RiskEvent(outcome, at + timedelta(seconds=1), agent_id, action, resource_id))
    return events


def steady_history(
    agent_id: uuid.UUID,
    windows: AnalysisWindows,
    *,
    per_slot: int,
    first_slot: int = 0,
    outcome: str | None = EXECUTED,
    action: str = ACTION_ID,
    resource_id: uuid.UUID | None = None,
    offset: timedelta = timedelta(minutes=10),
    spacing: timedelta = timedelta(minutes=6),
) -> list[RiskEvent]:
    """``per_slot`` requests in every baseline slot from ``first_slot`` on.

    Each slot's requests start ``offset`` after the slot begins and are ``spacing`` apart,
    so (by default) each sits in its own five-minute bucket and all of them fall in the
    same UTC hour of day as the observation window's first hour.
    """
    events: list[RiskEvent] = []
    for slot in range(first_slot, windows.slots):
        start = windows.baseline_start + slot * windows.slot
        for index in range(per_slot):
            events.extend(
                pipeline(
                    agent_id,
                    start + offset + index * spacing,
                    outcome,
                    action=action,
                    resource_id=resource_id,
                )
            )
    return events


def observed(
    agent_id: uuid.UUID,
    windows: AnalysisWindows,
    *,
    count: int,
    outcome: str | None = EXECUTED,
    action: str = ACTION_ID,
    resource_id: uuid.UUID | None = None,
    offset: timedelta = timedelta(minutes=10),
    spacing: timedelta = timedelta(minutes=6),
) -> list[RiskEvent]:
    """``count`` requests in the observation window, laid out like :func:`steady_history`."""
    return [
        event
        for index in range(count)
        for event in pipeline(
            agent_id,
            windows.observation_start + offset + index * spacing,
            outcome,
            action=action,
            resource_id=resource_id,
        )
    ]


def seed_risk_events(
    engine: Engine, organization_id: uuid.UUID, events: Iterable[RiskEvent]
) -> int:
    """Write trail rows directly, in one statement; return how many."""
    prefix = f"risk-{uuid.uuid4().hex[:8]}"
    rows: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        decision, outcome = _SHAPES[event.event_type]
        rows.append(
            {
                "organization_id": str(organization_id),
                "event_type": event.event_type,
                "occurred_at": event.at,
                "agent_id": None if event.agent_id is None else str(event.agent_id),
                "resource_id": None if event.resource_id is None else str(event.resource_id),
                "action": event.action,
                "decision": decision,
                "outcome": outcome,
                "correlation_id": f"{prefix}-{index}",
                "metadata": json.dumps({"reason": "seeded", "note": CANARY_SECRET}),
            }
        )
    if not rows:
        return 0
    with bind_tenant(organization_id), engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO aicore.audit_events (organization_id, event_type, schema_version,"
                " occurred_at, actor_type, agent_id, resource_type, resource_id, action,"
                " decision, outcome, correlation_id, source, metadata)"
                " VALUES (:organization_id, :event_type, 1, :occurred_at, 'system', :agent_id,"
                " 'agent', :resource_id, :action, :decision, :outcome, :correlation_id,"
                " 'ingestion', CAST(:metadata AS jsonb))"
            ),
            rows,
        )
    return len(rows)


def delete_detections(engine: Engine, organization_id: uuid.UUID) -> int:
    """Remove this organization's recorded detections (the table permits DELETE)."""
    with bind_tenant(organization_id), engine.begin() as connection:
        result = connection.execute(
            text("DELETE FROM aicore.anomaly_detections WHERE organization_id = :organization_id"),
            {"organization_id": str(organization_id)},
        )
        return int(result.rowcount)


def list_detections(engine: Engine, organization_id: uuid.UUID) -> list[dict[str, Any]]:
    """Every stored detection of this organization, oldest first, as plain mappings."""
    with bind_tenant(organization_id), engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT * FROM aicore.anomaly_detections WHERE organization_id = :organization_id"
                " ORDER BY detected_at, id"
            ),
            {"organization_id": str(organization_id)},
        )
        return [dict(row) for row in rows.mappings().all()]


def count_detections(engine: Engine, organization_id: uuid.UUID) -> int:
    with bind_tenant(organization_id), engine.connect() as connection:
        return int(
            connection.execute(
                text(
                    "SELECT count(*) FROM aicore.anomaly_detections"
                    " WHERE organization_id = :organization_id"
                ),
                {"organization_id": str(organization_id)},
            ).scalar_one()
        )


@dataclass
class RiskScene:
    """One tenant's trail, analysed through the risk endpoints and the recorder."""

    monitoring: MonitoringScene
    engine: Engine
    as_of: datetime = field(default_factory=analysis_as_of)

    @property
    def organization_id(self) -> uuid.UUID:
        return self.monitoring.organization_id

    @property
    def client(self) -> TestClient:
        """The owner's authenticated client (re-attached on every access)."""
        return self.monitoring.client

    def windows(
        self,
        baseline: BaselineWindow | str = BaselineWindow.FOURTEEN_DAYS,
        observation: ObservationWindow | str = ObservationWindow.TWENTY_FOUR_HOURS,
    ) -> AnalysisWindows:
        return windows_for(self.as_of, baseline, observation)

    def seed(self, events: Sequence[RiskEvent]) -> int:
        return seed_risk_events(self.engine, self.organization_id, events)

    # ── Endpoints ────────────────────────────────────────────────────────────

    def get(self, view: str, **params: Any) -> Any:
        wanted = {key: value for key, value in params.items() if value is not None}
        return self.client.get(risk_path(self.organization_id, view), params=wanted or None)

    def analysis(self, **params: Any) -> Mapping[str, Any]:
        params.setdefault("as_of", self.as_of.isoformat())
        response = self.get("analysis", **params)
        assert response.status_code == 200, response.text
        body: Mapping[str, Any] = response.json()
        return body

    def agent(self, agent_id: uuid.UUID, **params: Any) -> Mapping[str, Any]:
        """The analysis of exactly one agent."""
        body = self.analysis(agent_id=str(agent_id), **params)
        assert body["count"] == 1, body
        item: Mapping[str, Any] = body["items"][0]
        return item

    def detections(self, **params: Any) -> Mapping[str, Any]:
        response = self.get("detections", **params)
        assert response.status_code == 200, response.text
        body: Mapping[str, Any] = response.json()
        return body

    # ── Recording ────────────────────────────────────────────────────────────

    def record(
        self,
        *,
        baseline: str = "14d",
        observation: str = "24h",
        as_of: datetime | None = None,
        organization: str | None = None,
    ) -> int:
        """Run the operator command against the test database; return its exit code."""
        return risk_cli(
            [
                "record",
                "--organization",
                organization or str(self.organization_id),
                "--baseline",
                baseline,
                "--observation",
                observation,
                "--as-of",
                (as_of or self.as_of).isoformat(),
            ],
            session_factory=sessionmaker(bind=self.engine, expire_on_commit=False),
        )

    def stored(self) -> list[dict[str, Any]]:
        return list_detections(self.engine, self.organization_id)

    def purge(self) -> None:
        """Detections first (tenant FK is RESTRICT), then the trail via Phase 9's scene."""
        delete_detections(self.engine, self.organization_id)
        self.monitoring.purge()
