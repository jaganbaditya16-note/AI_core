"""Assessing agents in tests, over a real trail and a real registry.

Phase 10's subject is a *comparison*, so its tests need two things at once: activity that a
registry knows about, and history — enough of it, in the right places, for a baseline to
have a distribution. Both are available next door: :mod:`monitoring_fixture` already seeds
trail rows at chosen instants through the one function that fabricates history in this
suite, and the registry fixtures register real agents through the real API.

Three rules, borrowed from those fixtures because they are what make the assertions mean
something.

**History is seeded, and only where it must be.** An event happens when it happens, and no
API call can place one last Tuesday. So the helpers below build
:class:`~monitoring_fixture.SeededEvent` lists — the same shape the platform writes — and
place them at instants derived from one pinned window. Nothing here writes a detection: the
engine's own writes go through the endpoint under test.

**The windows are pinned to whole hours.** The scene's clock is floored to the hour, and the
observation window is the hour that ended there — in the past, by up to an hour. That is a
deliberate trade: it buys arithmetic a test can state exactly (a week of hours is 168 sample
buckets, every one of them whole, and an hour-long window makes a rate a count). A window
that ended "now" would be hour-and-a-fraction long, its edge buckets would be partial, and
every baseline sample count would depend on the minute the test ran.

**Reads are direct and tenant-bound.** ``stored()`` and ``count()`` read the detection table
with the tenant bound, so "exactly one record exists" is a statement about PostgreSQL rather
than about a repository's account of it.

Teardown order matters and is deliberate: detection rows are removed under the table's own
named retention override (the one way past its append-only guard), and the audit scene's
purge then runs as it always does.
"""

from __future__ import annotations

import ast
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from actions_fixture import ACTION_ID
from agents_fixture import agents_path
from aicore_api.core.audit import AuditEventType
from aicore_api.core.risk import DetectionType, RiskLevel
from aicore_api.db.tenancy import bind_tenant
from monitoring_fixture import MonitoringScene, SeededEvent, fixed_agent_id, seed_events

__all__ = [
    "BASELINE_HOURS",
    "BASELINE_WINDOW",
    "ForeignRiskTenant",
    "RiskScene",
    "declared_names",
    "delete_detections",
    "detection_rows",
    "fixed_agent_id",
    "level_of",
    "risk_path",
    "types_of",
]

#: The baseline every test pins unless it is testing the parameter itself. Seven days: the
#: API's default, the shortest named span that gives a rate comparison a full week of hourly
#: buckets, and short enough that seeding it stays cheap.
BASELINE_WINDOW = "7d"

#: A week of hourly buckets — the whole of the default baseline.
BASELINE_HOURS = 168

#: How long the pinned observation window is.
OBSERVATION_HOURS = 1


def risk_path(organization_id: uuid.UUID, *parts: str) -> str:
    """The risk route for one organization: a view, or a view and an identifier."""
    return "/".join([f"/organizations/{organization_id}/risk", *parts])


def detection_rows(engine: Engine, organization_id: uuid.UUID) -> list[Mapping[str, Any]]:
    """Every stored detection for one tenant, oldest first, with JSONB decoded.

    Read straight from the table with the tenant bound: a test asserting about records must
    look at records, not at a repository's account of them.
    """
    with bind_tenant(organization_id), engine.connect() as connection:
        rows = (
            connection.execute(
                text(
                    "SELECT id, organization_id, detected_at, entity_type, entity_id, status,"
                    " anomaly, risk_level, detection_type, observation_start, observation_end,"
                    " baseline_start, baseline_end, baseline_window, schema_version, evidence,"
                    " factors FROM aicore.anomaly_detections WHERE organization_id ="
                    " :organization_id ORDER BY detected_at, id"
                ),
                {"organization_id": str(organization_id)},
            )
            .mappings()
            .all()
        )
    decoded: list[Mapping[str, Any]] = []
    for row in rows:
        record = dict(row)
        for column in ("evidence", "factors"):
            value = record[column]
            record[column] = json.loads(value) if isinstance(value, str) else value
        decoded.append(record)
    return decoded


def delete_detections(engine: Engine, organization_id: uuid.UUID, reason: str) -> int:
    """Remove this tenant's detection records, stating that this is teardown.

    The same shape as the trail's delete helper: the database's append-only guard refuses a
    plain ``DELETE``, and the only way past it is the named, transaction-local setting — so a
    fixture that removed a row without it would not be testing the guard.
    """
    with bind_tenant(organization_id), engine.begin() as connection:
        connection.execute(
            text("SELECT set_config('aicore.risk_retention', :reason, true)"),
            {"reason": reason},
        )
        result = connection.execute(
            text("DELETE FROM aicore.anomaly_detections WHERE organization_id = :organization_id"),
            {"organization_id": str(organization_id)},
        )
        return int(result.rowcount)


def _at(moment: datetime, *, scene_clock: datetime) -> float:
    """How long before the scene's clock ``moment`` is, in minutes — the fixture's one input.

    The trail is written at instants, and the only way to state an instant here is as an
    offset from the scene's pinned hour. Everything below converts once, at the edge.
    """
    return (scene_clock - moment).total_seconds() / 60


def _request(
    moment: datetime, *, scene_clock: datetime, agent_id: uuid.UUID, action: str
) -> SeededEvent:
    """One admitted request at ``moment``, as the pipeline would have written it.

    The resource is the agent it acted on, which is what the pipeline records: an action
    event names what it addressed, and the resource dimensions of this phase measure exactly
    that. Seeding it any other way would leave a resource dimension with nothing to compare.
    """
    return SeededEvent(
        event_type=AuditEventType.ACTION_REQUESTED.value,
        minutes_ago=_at(moment, scene_clock=scene_clock),
        agent_id=agent_id,
        action=action,
        resource_id=agent_id,
    )


def _outcome(
    event_type: AuditEventType,
    moment: datetime,
    *,
    scene_clock: datetime,
    agent_id: uuid.UUID,
    action: str,
) -> SeededEvent:
    """One terminal outcome at ``moment``, with the reason a refusal would carry."""
    return SeededEvent(
        event_type=event_type.value,
        minutes_ago=_at(moment, scene_clock=scene_clock),
        agent_id=agent_id,
        action=action,
        resource_id=agent_id,
        reason="policy_denied" if event_type is AuditEventType.ACTION_DENIED else None,
    )


def level_of(assessment: Mapping[str, Any]) -> RiskLevel:
    """The level of an assessment body, as the vocabulary's own value."""
    return RiskLevel(assessment["risk_level"])


def types_of(assessment: Mapping[str, Any]) -> list[DetectionType]:
    """The detection types an assessment body's factors carry, in order."""
    return [DetectionType(factor["type"]) for factor in assessment["factors"]]


@dataclass
class RiskScene:
    """One tenant: a registry, an action pipeline, a trail, and the risk endpoints.

    Wraps the monitoring scene rather than rebuilding it — the risk engine reads the same
    trail monitoring measures, and its seeding helper already exists there. What this adds is
    the risk surface (five routes), a pinned pair of windows, and direct reads of the
    detection table.
    """

    monitoring: MonitoringScene
    now: datetime = field(
        default_factory=lambda: datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    )
    seeded: int = 0

    # ── The tenant, and the raw material ─────────────────────────────────────

    @property
    def organization_id(self) -> uuid.UUID:
        return self.monitoring.organization_id

    @property
    def client(self) -> TestClient:
        """The owner's authenticated client."""
        return self.monitoring.client

    @property
    def agents(self) -> Any:
        self.as_owner()
        return self.monitoring.agents

    @property
    def actions(self) -> Any:
        self.as_owner()
        return self.monitoring.actions

    @property
    def assets(self) -> Any:
        self.as_owner()
        return self.monitoring.assets

    @property
    def trail(self) -> Any:
        return self.monitoring.trail

    @property
    def engine(self) -> Engine:
        return self.monitoring.audit.trail.engine

    # ── The pinned windows ───────────────────────────────────────────────────

    def observation_window(self) -> tuple[datetime, datetime]:
        """The observation window every test pins: the whole hour that ended at the clock.

        Ended, not ending: the scene's clock is floored to the hour, so this window is
        between a few seconds and an hour in the past. Both of its bounds are hour-aligned,
        so it holds exactly one bucket and its rate is its request count.
        """
        return self.now - timedelta(hours=OBSERVATION_HOURS), self.now

    def baseline_buckets(self, hours: int = BASELINE_HOURS) -> list[datetime]:
        """The last ``hours`` whole hourly buckets of the baseline, oldest first.

        Worked backwards from where the baseline ends — which is where the observation
        begins — so every bucket is inside the baseline and every one of them is whole. A
        test that seeds these knows its sample count exactly.
        """
        end = self.observation_window()[0]
        return [end - timedelta(hours=index + 1) for index in reversed(range(hours))]

    def minutes_ago(self, moment: datetime) -> float:
        """How long before this scene's clock ``moment`` is, in minutes."""
        return (self.now - moment).total_seconds() / 60

    # ── Placing history ──────────────────────────────────────────────────────

    def seed(self, *events: SeededEvent) -> int:
        """Write fabricated history at instants relative to this scene's clock."""
        written = seed_events(self.engine, self.organization_id, list(events), now=self.now)
        self.seeded += written
        return written

    def seed_baseline(
        self,
        agent_id: uuid.UUID,
        *,
        hours: int = BASELINE_HOURS,
        per_hour: int = 1,
        executions_per_hour: int = 0,
        failures_per_hour: int = 0,
        denials_per_hour: int = 0,
        approvals_per_hour: int = 0,
        action: str = ACTION_ID,
    ) -> int:
        """Fill whole hours of the baseline with an identical pattern.

        One hour, one sample: the helper writes the *same* counts into each of the last
        ``hours`` full hourly buckets of the baseline, which is what makes a test able to
        state the baseline's mean in one line — and why the sample count it will get back
        is ``hours`` exactly, not "about that many".

        Requests are placed a quarter of the way into their bucket and outcomes three
        quarters of the way in, so nothing sits on a bucket edge where a rounding rule could
        decide what happened. Identical buckets mean the population spread is zero and both
        bounds are the mean: a test that wants a spike can then say so with one number.
        """
        events: list[SeededEvent] = []
        for bucket in self.baseline_buckets(hours):
            for index in range(per_hour):
                events.append(
                    _request(
                        bucket + timedelta(minutes=15, seconds=index),
                        scene_clock=self.now,
                        agent_id=agent_id,
                        action=action,
                    )
                )
            for index in range(executions_per_hour):
                events.append(
                    _outcome(
                        AuditEventType.ACTION_EXECUTED,
                        bucket + timedelta(minutes=45, seconds=index),
                        scene_clock=self.now,
                        agent_id=agent_id,
                        action=action,
                    )
                )
            for index in range(failures_per_hour):
                events.append(
                    _outcome(
                        AuditEventType.ACTION_FAILED,
                        bucket + timedelta(minutes=40, seconds=index),
                        scene_clock=self.now,
                        agent_id=agent_id,
                        action=action,
                    )
                )
            for index in range(denials_per_hour):
                events.append(
                    _outcome(
                        AuditEventType.ACTION_DENIED,
                        bucket + timedelta(minutes=35, seconds=index),
                        scene_clock=self.now,
                        agent_id=agent_id,
                        action=action,
                    )
                )
            for index in range(approvals_per_hour):
                events.append(
                    _outcome(
                        AuditEventType.ACTION_REQUIRE_APPROVAL,
                        bucket + timedelta(minutes=30, seconds=index),
                        scene_clock=self.now,
                        agent_id=agent_id,
                        action=action,
                    )
                )
        return self.seed(*events)

    def seed_observation(
        self,
        agent_id: uuid.UUID | None,
        *,
        requests: int = 0,
        executions: int = 0,
        failures: int = 0,
        denials: int = 0,
        approvals: int = 0,
        action: str = ACTION_ID,
    ) -> int:
        """Place activity inside the observation window, near its start.

        The window is one whole hour, so ``requests`` is also the rate in requests per hour —
        which is what makes a deviation's expected number easy to state in a test.
        """
        start, _ = self.observation_window()
        events: list[SeededEvent] = []
        for index in range(requests):
            events.append(
                _request(
                    start + timedelta(seconds=10 + index),
                    scene_clock=self.now,
                    agent_id=agent_id,
                    action=action,
                )
            )
        for index in range(executions):
            events.append(
                _outcome(
                    AuditEventType.ACTION_EXECUTED,
                    start + timedelta(seconds=40 + index),
                    scene_clock=self.now,
                    agent_id=agent_id,
                    action=action,
                )
            )
        for index in range(failures):
            events.append(
                _outcome(
                    AuditEventType.ACTION_FAILED,
                    start + timedelta(seconds=45 + index),
                    scene_clock=self.now,
                    agent_id=agent_id,
                    action=action,
                )
            )
        for index in range(denials):
            events.append(
                _outcome(
                    AuditEventType.ACTION_DENIED,
                    start + timedelta(seconds=50 + index),
                    scene_clock=self.now,
                    agent_id=agent_id,
                    action=action,
                )
            )
        for index in range(approvals):
            events.append(
                _outcome(
                    AuditEventType.ACTION_REQUIRE_APPROVAL,
                    start + timedelta(seconds=55 + index),
                    scene_clock=self.now,
                    agent_id=agent_id,
                    action=action,
                )
            )
        return self.seed(*events)

    # ── The endpoints ────────────────────────────────────────────────────────

    def query(
        self,
        *,
        window: str = "custom",
        baseline: str = BASELINE_WINDOW,
        **extra: Any,
    ) -> dict[str, Any]:
        """Query parameters for the pinned windows, plus whatever a test wants to add.

        The pinned window is explicit — ``window=custom`` with both bounds — so the same
        request twice is the same request, which is what makes recording idempotent. A test
        that wants a named window or a malformed bound passes it here and it is used instead,
        with ``None`` values dropped so an omitted bound is omitted rather than sent empty.
        """
        if window == "custom":
            start, end = self.observation_window()
            params: dict[str, Any] = {
                "window": "custom",
                "start_time": start.isoformat(),
                "end_time": end.isoformat(),
                "baseline": baseline,
            }
        else:
            params = {"window": window, "baseline": baseline}
        params.update({key: value for key, value in extra.items() if value is not None})
        return params

    def as_identity(self, identity: Any) -> TestClient:
        """Point the *shared* client at ``identity`` and hand it back.

        Captured here and returned rather than looked up again, because the audit fixture's
        client is one object with one authorization header and every access re-attaches the
        owner: a test that speaks as somebody else has to hold the client it was given. The
        alternative — touching ``risk.client.headers`` and then calling ``risk.client.get``
        — silently makes the request as the owner, which is exactly the kind of test that
        passes for the wrong reason.
        """
        client = self.client
        client.headers["Authorization"] = f"Bearer {identity.token}"
        return client

    def as_owner(self) -> TestClient:
        """Put this scene's owner back on the shared client."""
        return self.client

    def get(self, view: str, *parts: str, **params: Any) -> Any:
        """``GET`` one risk route as the owner, without asserting.

        ``view`` is the collection — ``agents``, ``detections`` — and ``parts`` optionally
        names one record inside it, so a test reads ``risk.get("detections", str(record_id))``
        the way the route is shaped.
        """
        return self.client.get(
            risk_path(self.organization_id, view, *parts), params=self.query(**params)
        )

    def read(self, view: str, *parts: str, **params: Any) -> Mapping[str, Any]:
        """``GET`` one risk route, assert 200, and return the parsed body."""
        response = self.get(view, *parts, **params)
        assert response.status_code == 200, response.text
        return response.json()

    def assessments(self, **params: Any) -> Mapping[str, Any]:
        """``GET /risk/agents``: a page of assessments."""
        return self.read("agents", **params)

    def assessment(self, agent_id: uuid.UUID, **params: Any) -> Mapping[str, Any]:
        """``GET /risk/agents/{agent_id}``: one assessment."""
        response = self.client.get(
            risk_path(self.organization_id, "agents", str(agent_id)), params=self.query(**params)
        )
        assert response.status_code == 200, response.text
        return response.json()

    def detected(self, **params: Any) -> Mapping[str, Any]:
        """``GET /risk/detections``: a page of records."""
        return self.read("detections", **params)

    def detection(self, detection_id: uuid.UUID) -> Mapping[str, Any]:
        """``GET /risk/detections/{detection_id}``: one record."""
        return self.read("detections", str(detection_id))

    def analyze(self, agent_id: uuid.UUID, **params: Any) -> Any:
        """``POST /risk/analysis``: assess and record one agent, without asserting."""
        return self.client.post(
            risk_path(self.organization_id, "analysis"),
            json={"agent_id": str(agent_id)},
            params=self.query(**params),
        )

    def record(self, agent_id: uuid.UUID, **params: Any) -> Mapping[str, Any]:
        """``POST /risk/analysis``, asserting success and returning the body."""
        response = self.analyze(agent_id, **params)
        assert response.status_code in (200, 201), response.text
        return response.json()

    # ── What is stored ───────────────────────────────────────────────────────

    def stored(self) -> list[Mapping[str, Any]]:
        """Every detection row for this tenant, oldest first."""
        return detection_rows(self.engine, self.organization_id)

    def stored_count(self) -> int:
        """How many detection rows this tenant has."""
        return len(self.stored())

    def purge(self) -> None:
        """Remove this tenant's records, then put the rest of the scene back."""
        delete_detections(self.engine, self.organization_id, "phase 10 test teardown")
        self.monitoring.purge()
        self.seeded = 0


@dataclass(frozen=True, slots=True)
class ForeignRiskTenant:
    """A second organization, with a real registry and a real trail of its own.

    The other side of an isolation assertion: an agent that exists, history that exists, and
    a record that exists — all in a tenant the first caller cannot see. ``as_owner()`` hands
    over the suite's shared client after re-pointing it at *this* tenant's credential, which
    is what makes "not visible here" a statement about the boundary rather than about
    whichever identity happened to speak last.
    """

    organization_id: uuid.UUID
    identity: Any
    authenticate: Any
    engine: Engine
    now: datetime

    def as_owner(self) -> TestClient:
        """Speak as this tenant's owner for the next call."""
        return self.authenticate(self.identity)

    def register_agent(self, display_name: str = "Foreign Agent") -> uuid.UUID:
        """Register one agent in the foreign registry, through the real API."""
        response = self.as_owner().post(
            agents_path(self.organization_id),
            json={"display_name": display_name, "category": "assistant", "version": "1.0.0"},
        )
        assert response.status_code == 201, response.text
        return uuid.UUID(response.json()["id"])

    def observation_window(self) -> tuple[datetime, datetime]:
        """The same pinned hour :class:`RiskScene` reads, so the two tenants' windows align."""
        return self.now - timedelta(hours=OBSERVATION_HOURS), self.now

    def query(self, **extra: Any) -> dict[str, Any]:
        """The same pinned request :class:`RiskScene` sends, addressed to this tenant."""
        start, end = self.observation_window()
        params: dict[str, Any] = {
            "window": "custom",
            "start_time": start.isoformat(),
            "end_time": end.isoformat(),
            "baseline": BASELINE_WINDOW,
        }
        params.update({key: value for key, value in extra.items() if value is not None})
        return params

    def seed(self, *events: SeededEvent) -> int:
        """Write fabricated history into the foreign trail."""
        return seed_events(self.engine, self.organization_id, list(events), now=self.now)

    def seed_observation(self, agent_id: uuid.UUID, *, requests: int = 0) -> int:
        """Place admitted requests in the foreign observation window, as the scene does."""
        start, _ = self.observation_window()
        return self.seed(
            *[
                _request(
                    start + timedelta(seconds=10 + index),
                    scene_clock=self.now,
                    agent_id=agent_id,
                    action=ACTION_ID,
                )
                for index in range(requests)
            ]
        )

    def analyze(self, agent_id: uuid.UUID, **extra: Any) -> Any:
        """Ask the foreign tenant's own API to record a finding about its own agent."""
        return self.as_owner().post(
            risk_path(self.organization_id, "analysis"),
            json={"agent_id": str(agent_id)},
            params=self.query(**extra),
        )

    def detections(self, **extra: Any) -> Mapping[str, Any]:
        """The foreign tenant's own page of records, asserted successful."""
        response = self.as_owner().get(
            risk_path(self.organization_id, "detections"), params=self.query(**extra)
        )
        assert response.status_code == 200, response.text
        return response.json()

    def detection_ids(self) -> list[uuid.UUID]:
        """The identifiers of the records this tenant holds."""
        return [uuid.UUID(item["id"]) for item in self.detections()["items"]]

    def minutes_ago(self, moment: datetime) -> float:
        """How long before this tenant's clock ``moment`` is, in minutes."""
        return (self.now - moment).total_seconds() / 60


def declared_names(module: Path) -> set[str]:
    """Every identifier and non-docstring literal a module declares.

    Used by the scans that check the phase's *vocabulary* rather than its behaviour: the
    names a client renders, a log carries and a later phase extends. Docstrings are
    deliberately excluded — the prose of this phase is where the boundaries are stated
    ("a detection is not an incident", "nothing here is a claim about intent"), so the
    words belong there and nowhere else.
    """
    tree = ast.parse(module.read_text(), filename=str(module))
    prose = _docstrings(tree)
    declared: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            declared.add(node.name)
        elif isinstance(node, (ast.Name,)):
            declared.add(node.id)
        elif isinstance(node, ast.Attribute):
            declared.add(node.attr)
        elif isinstance(node, ast.arg) or (isinstance(node, ast.keyword) and node.arg is not None):
            declared.add(node.arg)
        elif (
            isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in prose
        ):
            declared.add(node.value)
    return declared


def _docstrings(tree: ast.Module) -> set[int]:
    """The node ids of every docstring in a module — prose, which is exempt by design."""
    prose: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                prose.add(id(body[0].value))
    return prose
