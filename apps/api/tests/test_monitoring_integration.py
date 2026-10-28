"""Monitoring counted against known activity, and against the SQL it actually runs.

Everything here is arithmetic over history the test states in advance. The numbers are not
invented and they are not sampled: a stated set of rows is written into the trail — one
request, one execution, one refusal at a time — and the API must report exactly those
counts, in exactly the window that contains them, attributed to exactly the right agent and
action.

Two things make that possible without pretending to be the platform. History is *placed*
(with the fixture's one seeding helper, at instants the server's clock cannot produce), so
windows and bucket boundaries are testable at all; and the amounts are small enough to add
up by hand, so the expectations in this file are counts a reader can check rather than
numbers copied from a previous run.

The last group reads the statements the database was asked to run. It is the evidence for
two claims that would otherwise be hopes: every aggregate is bounded by tenant *and* by
window, and reading a measurement never writes anything. Role-based access to these five
endpoints is asserted in the authorization suite, which sweeps every route the phase
declares; this file stays on the numbers.

Nothing here is random. A random fixture would make "the count is 7" unwritable, and it is
the whole point of the phase that a measurement can be checked.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, event, text
from sqlalchemy.orm import Session

from actions_fixture import ACTION_ID
from aicore_api.core.audit import AuditEventType
from aicore_api.core.monitoring import TimeInterval
from aicore_api.db.repositories.monitoring import MonitoringRepository
from aicore_api.db.session import get_engine
from identity_fixture import IdentityFactory
from monitoring_fixture import (
    MonitoringScene,
    SeededEvent,
    action_event,
    fixed_agent_id,
    monitoring_path,
    seed_events,
)

#: Two agents, so per-agent attribution is a distinction rather than a count of one.
AGENT_A = fixed_agent_id(1)
AGENT_B = fixed_agent_id(2)

#: One asset, so the four lifecycle events describe the same subject.
ASSET = fixed_agent_id(9)

#: How wide the window under test is. Half an hour is long enough for the stated activity
#: and short enough that nothing outside it can accidentally be inside it.
WINDOW = timedelta(minutes=30)

#: What the seeded activity is, as (minutes ago, event). Written out rather than generated:
#: the expectations below are the sum of these lines, and a reader should be able to add
#: them up without running anything.
KNOWN_ACTIVITY: tuple[tuple[float, SeededEvent], ...] = (
    # Ten requests, six from A and four from B.
    *(
        (minutes, action_event(AuditEventType.ACTION_REQUESTED.value, minutes, agent_id=agent))
        for minutes, agent in (
            (2, AGENT_A),
            (4, AGENT_A),
            (6, AGENT_A),
            (8, AGENT_A),
            (10, AGENT_A),
            (12, AGENT_A),
            (14, AGENT_B),
            (16, AGENT_B),
            (18, AGENT_B),
            (20, AGENT_B),
        )
    ),
    # Seven of them end well: four for A, three for B.
    *(
        (minutes, action_event(AuditEventType.ACTION_EXECUTED.value, minutes, agent_id=agent))
        for minutes, agent in (
            (3, AGENT_A),
            (5, AGENT_A),
            (7, AGENT_A),
            (9, AGENT_A),
            (15, AGENT_B),
            (17, AGENT_B),
            (19, AGENT_B),
        )
    ),
    # Two are refused, one per agent, by two different layers.
    (
        11,
        action_event(
            AuditEventType.ACTION_DENIED.value, 11, agent_id=AGENT_A, reason="policy_denied"
        ),
    ),
    (
        21,
        action_event(
            AuditEventType.ACTION_DENIED.value,
            21,
            agent_id=AGENT_B,
            reason="authorization_denied",
        ),
    ),
    # One is held for an approval this build does not have, one fails, one is replayed.
    (
        13,
        action_event(AuditEventType.ACTION_REQUIRE_APPROVAL.value, 13, agent_id=AGENT_A),
    ),
    (22, action_event(AuditEventType.ACTION_FAILED.value, 22, agent_id=AGENT_B)),
    (23, action_event(AuditEventType.ACTION_REPLAYED.value, 23, agent_id=AGENT_A)),
    # Lifecycle activity on one asset and one agent.
    (24, SeededEvent(AuditEventType.ASSET_CREATED.value, 24, resource_id=ASSET)),
    (25, SeededEvent(AuditEventType.ASSET_CREATED.value, 25, resource_id=ASSET)),
    (26, SeededEvent(AuditEventType.ASSET_UPDATED.value, 26, resource_id=ASSET)),
    (27, SeededEvent(AuditEventType.ASSET_DELETED.value, 27, resource_id=ASSET)),
    (28, SeededEvent(AuditEventType.AGENT_REGISTERED.value, 28, agent_id=AGENT_A)),
)

#: The summary the activity above must produce, field by field. Every number here is the
#: count of the lines in ``KNOWN_ACTIVITY`` that produce it.
KNOWN_SUMMARY = {
    "total_events": 27,
    "action_requests": 10,
    "action_executions": 7,
    "action_failures": 1,
    "action_denials": 2,
    "action_replays": 1,
    "approval_required": 1,
    "asset_creations": 2,
    "asset_updates": 1,
    "asset_deletions": 1,
    "asset_discoveries": 0,
    "agent_registrations": 1,
    "agent_updates": 0,
    "agent_deletions": 0,
    "policy_creations": 0,
    "policy_updates": 0,
    "policy_version_publications": 0,
    "policy_status_changes": 0,
    "policy_deletions": 0,
    "policy_changes": 0,
    "active_agents": 2,
    "active_assets": 1,
}

#: What each agent did, as the same counts from that agent's side.
KNOWN_AGENTS = {
    AGENT_A: {
        "events": 14,
        "action_requests": 6,
        "executions": 4,
        "failures": 0,
        "denials": 1,
        "approval_required": 1,
        "replays": 1,
    },
    AGENT_B: {
        "events": 9,
        "action_requests": 4,
        "executions": 3,
        "failures": 1,
        "denials": 1,
        "approval_required": 0,
        "replays": 0,
    },
}

#: How long ago each agent's newest attributed event was, in minutes.
KNOWN_LAST_ACTIVITY = {AGENT_A: 2.0, AGENT_B: 14.0}

#: The one registered action's activity: two axes, which do not have to agree.
KNOWN_ACTION = {
    "requested": 10,
    "allowed": 9,  # every ending that was permitted: 7 executed + 1 failed + 1 replayed
    "denied": 2,
    "approval_required": 1,
    "executed": 7,
    "failed": 1,
    "replayed": 1,
}

#: The statements each view is allowed to send to the trail. Published in
#: ``docs/monitoring.md`` as well, so the document and the code cannot disagree quietly.
STATEMENTS_PER_VIEW = {
    "summary": 3,  # counters, distinct identifiers, refusals by reason
    "agents": 1,
    "actions": 1,
    "policies": 2,  # lifecycle counters, decision counts
    "trends": 1,
}


def _minutes_before(moment: datetime, now: datetime) -> float:
    """How long before ``now`` an instant is, in minutes — the fixture's unit."""
    return (now - moment).total_seconds() / 60


def _seed_known_activity(scene: MonitoringScene, now: datetime) -> None:
    written = seed_events(
        scene.trail.engine,
        scene.organization_id,
        [event for _, event in KNOWN_ACTIVITY],
        now=now,
    )
    assert written == len(KNOWN_ACTIVITY) == 27


def _window(scene: MonitoringScene, now: datetime) -> dict[str, str]:
    """The custom window that contains exactly the seeded activity."""
    return {
        "window": "custom",
        "start_time": (now - WINDOW).isoformat(),
        "end_time": now.isoformat(),
    }


@pytest.fixture
def known(monitoring: MonitoringScene) -> tuple[MonitoringScene, datetime]:
    """A tenant whose trail holds the stated activity, and the instant it was seeded at."""
    now = datetime.now(UTC)
    _seed_known_activity(monitoring, now)
    return monitoring, now


# ── the numbers ──────────────────────────────────────────────────────────────


def test_the_summary_reports_exactly_the_stated_activity(
    known: tuple[MonitoringScene, datetime],
) -> None:
    """Twenty-seven rows in, the same counts out — every field, by hand.

    The window is the caller's, so the assertions do not depend on what time the test ran;
    the activity is inside it and nothing else is.
    """
    scene, now = known
    body = scene.summary(**_window(scene, now))

    for field, expected in KNOWN_SUMMARY.items():
        assert body[field] == expected, field

    assert body["execution_health"] == {
        "completed": 8,
        "succeeded": 7,
        "failed": 1,
        "success_rate": 0.875,
        "failure_rate": 0.125,
    }
    assert body["denials"] == {
        "total": 2,
        "by_reason": {"policy_denied": 1, "authorization_denied": 1},
    }
    # Ten requests, eighteen lifecycle rows and the rest: nothing was left uncounted.
    assert body["total_events"] == scene.trail_count() == 27


def test_the_agents_view_reports_exactly_what_each_agent_did(
    known: tuple[MonitoringScene, datetime],
) -> None:
    scene, now = known
    page = scene.agent_activity(**_window(scene, now))
    assert page["count"] == 2

    by_agent = {uuid.UUID(item["agent_id"]): item for item in page["items"]}
    assert set(by_agent) == {AGENT_A, AGENT_B}
    for agent_id, expected in KNOWN_AGENTS.items():
        for field, count in expected.items():
            assert by_agent[agent_id][field] == count, (agent_id, field)

    for agent_id, minutes in KNOWN_LAST_ACTIVITY.items():
        expected = now - timedelta(minutes=minutes)
        assert (
            datetime.fromisoformat(by_agent[agent_id]["last_activity_at"].replace("Z", "+00:00"))
            == expected
        )

    # Most active first: 14 attributed events, then 9.
    assert [item["agent_id"] for item in page["items"]] == [str(AGENT_A), str(AGENT_B)]


def test_an_agent_with_nothing_in_the_window_is_not_a_row_of_zeros(
    known: tuple[MonitoringScene, datetime],
) -> None:
    """The view reports activity, so silence is an empty page rather than six zeroes."""
    scene, now = known
    assert scene.agent_activity(agent_id=str(fixed_agent_id(3)))["items"] == []

    # And a window that contains nothing reports nothing, for an agent that *is* active.
    empty = {
        "window": "custom",
        "start_time": (now - timedelta(days=10)).isoformat(),
        "end_time": (now - timedelta(days=9)).isoformat(),
    }
    page = scene.agent_activity(**empty)
    assert page["items"] == []
    assert page["count"] == 0


def test_the_action_view_reports_both_axes_of_the_stated_activity(
    known: tuple[MonitoringScene, datetime],
) -> None:
    scene, now = known
    body = scene.action_activity(**_window(scene, now))
    assert body["count"] == 1
    item = body["items"][0]
    assert item["action"] == ACTION_ID
    for field, expected in KNOWN_ACTION.items():
        assert item[field] == expected, field

    # The two axes are not the same number: nine requests were permitted, seven of them
    # ran to completion. Collapsing them would lose the fact that one was permitted and
    # then failed.
    assert item["allowed"] == item["executed"] + item["failed"] + item["replayed"] == 9


def test_the_policy_view_separates_decisions_from_lifecycle(
    known: tuple[MonitoringScene, datetime],
) -> None:
    scene, now = known
    body = scene.policy_activity(**_window(scene, now))
    assert body["decisions"] == {"allow": 9, "deny": 2, "require_approval": 1}
    assert body["lifecycle"] == {
        "created": 0,
        "updated": 0,
        "version_published": 0,
        "status_changed": 0,
        "deleted": 0,
        "changes": 0,
    }


def test_the_decision_counts_are_the_pipeline_vocabulary(
    known: tuple[MonitoringScene, datetime],
) -> None:
    """Every row the pipeline wrote carries one of the three decisions, and is counted once."""
    scene, now = known
    decisions = scene.policy_activity(**_window(scene, now))["decisions"]
    summary = scene.summary(**_window(scene, now))

    assert sum(decisions.values()) == 12
    assert decisions["allow"] == (
        summary["action_executions"] + summary["action_failures"] + summary["action_replays"]
    )
    assert decisions["deny"] == summary["action_denials"]
    assert decisions["require_approval"] == summary["approval_required"]


def test_an_empty_window_is_zeros_and_not_nulls(
    known: tuple[MonitoringScene, datetime],
) -> None:
    """A quiet period says zero; only the two rates say null, and only because they must."""
    scene, now = known
    body = scene.summary(
        window="custom",
        start_time=(now - timedelta(days=400)).isoformat(),
        end_time=(now - timedelta(days=399)).isoformat(),
    )

    for field in KNOWN_SUMMARY:
        assert body[field] == 0, field
    assert body["execution_health"] == {
        "completed": 0,
        "succeeded": 0,
        "failed": 0,
        "success_rate": None,
        "failure_rate": None,
    }
    assert body["denials"] == {"total": 0, "by_reason": {}}


# ── windows and buckets ──────────────────────────────────────────────────────


def test_an_event_on_the_window_edge_is_inside_it(monitoring: MonitoringScene) -> None:
    """Both bounds are inclusive: two adjacent windows overlap rather than lose an event."""
    end = datetime(2026, 3, 1, 2, 30, tzinfo=UTC)
    start = end - timedelta(hours=2)
    edges = {
        "just before the window": start - timedelta(seconds=1),
        "the first instant": start,
        "the last instant": end - timedelta(seconds=1),
        "the closing instant": end,
        "just after the window": end + timedelta(seconds=1),
    }
    seed_events(
        monitoring.trail.engine,
        monitoring.organization_id,
        [
            action_event(
                AuditEventType.ACTION_REQUESTED.value,
                _minutes_before(moment, end),
                agent_id=AGENT_A,
            )
            for moment in edges.values()
        ],
        now=end,
    )

    body = monitoring.summary(
        window="custom", start_time=start.isoformat(), end_time=end.isoformat()
    )
    assert body["total_events"] == 3
    assert body["action_requests"] == 3


def test_the_series_counts_each_event_in_the_bucket_it_belongs_to(
    monitoring: MonitoringScene,
) -> None:
    """Hand-placed instants, either side of two hour boundaries and one window edge."""
    end = datetime(2026, 3, 1, 2, 30, tzinfo=UTC)
    start = end - timedelta(hours=2)
    moments = (
        start - timedelta(seconds=1),  # outside: the second before the window opens
        start,  # exactly the window start → the 00:00 bucket
        start + timedelta(minutes=29, seconds=59),  # 00:59:59 → the 00:00 bucket
        start + timedelta(minutes=30),  # 01:00:00 → the 01:00 bucket
        end - timedelta(seconds=1),  # 02:29:59 → the 02:00 bucket
        end,  # exactly the window end, inclusive → the 02:00 bucket
        end + timedelta(seconds=1),  # outside: the second after the window closes
    )
    seed_events(
        monitoring.trail.engine,
        monitoring.organization_id,
        [
            action_event(
                AuditEventType.ACTION_REQUESTED.value,
                _minutes_before(moment, end),
                agent_id=AGENT_A,
            )
            for moment in moments
        ],
        now=end,
    )

    body = monitoring.trends(
        window="custom",
        start_time=start.isoformat(),
        end_time=end.isoformat(),
        interval="hour",
    )
    assert body["count"] == 3
    assert [bucket["events"] for bucket in body["buckets"]] == [2, 1, 2]
    assert [bucket["action_requests"] for bucket in body["buckets"]] == [2, 1, 2]
    assert body["buckets"][0]["start"] == "2026-03-01T00:00:00Z"
    assert body["buckets"][-1]["start"] == "2026-03-01T02:00:00Z"


def test_the_series_sums_to_the_summary_over_the_same_window(
    known: tuple[MonitoringScene, datetime],
) -> None:
    """Two views of one window, one total: a bucket cannot lose or double an event."""
    scene, now = known
    window = _window(scene, now)
    summary = scene.summary(**window)
    series = scene.trends(**window, interval="hour")

    assert sum(bucket["events"] for bucket in series["buckets"]) == summary["total_events"]
    for counter in (
        "action_requests",
        "action_executions",
        "action_failures",
        "action_denials",
        "approval_required",
    ):
        assert sum(bucket[counter] for bucket in series["buckets"]) == summary[counter], counter


def test_a_day_bucket_starts_at_midnight_utc_and_the_empty_day_is_present(
    monitoring: MonitoringScene,
) -> None:
    """Three events on three days, four days requested: the quiet one is a zero, not a gap."""
    end = datetime(2026, 2, 13, 12, 0, tzinfo=UTC)
    start = datetime(2026, 2, 10, 12, 0, tzinfo=UTC)
    seed_events(
        monitoring.trail.engine,
        monitoring.organization_id,
        [
            action_event(
                AuditEventType.ACTION_REQUESTED.value,
                _minutes_before(moment, end),
                agent_id=AGENT_A,
            )
            for moment in (
                datetime(2026, 2, 10, 23, 59, 59, tzinfo=UTC),
                datetime(2026, 2, 11, 0, 0, 0, tzinfo=UTC),
                datetime(2026, 2, 13, 0, 0, 0, tzinfo=UTC),
            )
        ],
        now=end,
    )

    body = monitoring.trends(
        window="custom",
        start_time=start.isoformat(),
        end_time=end.isoformat(),
        interval="day",
    )
    assert [bucket["start"] for bucket in body["buckets"]] == [
        "2026-02-10T00:00:00Z",
        "2026-02-11T00:00:00Z",
        "2026-02-12T00:00:00Z",
        "2026-02-13T00:00:00Z",
    ]
    assert [bucket["events"] for bucket in body["buckets"]] == [1, 1, 0, 1]


def test_a_changing_database_timezone_does_not_move_a_bucket(
    known: tuple[MonitoringScene, datetime],
) -> None:
    """Buckets are floored in UTC: the session's zone is not a measurement input.

    Read twice for the same window — once through the API, once through a session whose
    ``TimeZone`` is +05:30 — and the two series have to be the same instants with the same
    counts. ``date_trunc`` in a non-UTC session would shift every bucket by five and a half
    hours, which is the kind of bug that only shows up in a report nobody re-runs.
    """
    scene, now = known
    window = _window(scene, now)
    published = scene.trends(**window, interval="hour")

    engine = get_engine()
    with engine.connect() as connection:
        connection.execute(text("SET TIME ZONE 'Asia/Kolkata'"))
        with Session(bind=connection) as session:
            rows = MonitoringRepository(session, scene.organization_id).trend(
                start=datetime.fromisoformat(window["start_time"]),
                end=datetime.fromisoformat(window["end_time"]),
                interval=TimeInterval.HOUR,
            )

    counted = {row["bucket"].astimezone(UTC): row["events"] for row in rows}
    series = {
        datetime.fromisoformat(bucket["start"].replace("Z", "+00:00")): bucket["events"]
        for bucket in published["buckets"]
    }

    # The database returns the buckets that hold events; the response adds the zeros. The
    # two must agree wherever both speak, which is what proves the SQL flooring did not
    # move under a session whose timezone is five and a half hours from UTC.
    assert counted
    assert set(counted) <= set(series)
    for bucket, events in counted.items():
        assert series[bucket] == events, bucket
    assert sum(series.values()) == sum(counted.values())


# ── the statements behind the numbers ────────────────────────────────────────


class _TrailStatements:
    """Every statement one tenant's views sent to the trail, in order."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self.statements: list[str] = []

    def __enter__(self) -> _TrailStatements:
        event.listen(self._engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *_: object) -> None:
        event.remove(self._engine, "before_cursor_execute", self._record)

    def _record(self, connection: Any, cursor: Any, statement: str, *rest: Any) -> None:
        if "audit_events" in statement:
            self.statements.append(" ".join(statement.split()))

    def reset(self) -> None:
        self.statements.clear()


def _trail_statements(scene: MonitoringScene) -> _TrailStatements:
    """Capture the statements the *application's* engine sends, for the rest of the test.

    The fixture's engine is the test suite's own connection, and the requests under test
    travel through the application's — so this listens where the queries actually happen.
    A listener on the wrong engine captures nothing, and a test that asserts about an
    empty list is a test that proves nothing.
    """
    del scene  # the engine is the application's; the scene is passed for readability
    return _TrailStatements(get_engine())


def test_each_view_sends_the_declared_number_of_statements(
    known: tuple[MonitoringScene, datetime],
) -> None:
    """The count is published in the documentation, so it is asserted against the code."""
    scene, now = known
    window = _window(scene, now)

    with _trail_statements(scene) as captured:
        for view, expected in STATEMENTS_PER_VIEW.items():
            captured.reset()
            assert scene.get(view, **window).status_code == 200
            assert len(captured.statements) == expected, view

        captured.reset()
        assert scene.get("agents", **window, total="true").status_code == 200
        assert len(captured.statements) == 2  # the page, and the count it was asked for


def test_every_statement_is_scoped_to_the_tenant_and_to_the_window(
    known: tuple[MonitoringScene, datetime],
) -> None:
    """No view can ask an unbounded question, because no view can write one.

    Each statement must name the organization, name the trail, and bound ``occurred_at`` —
    which is what "bounded by tenant and window" means once it is checked rather than
    intended.
    """
    scene, now = known
    window = _window(scene, now)

    with _trail_statements(scene) as captured:
        for view in STATEMENTS_PER_VIEW:
            captured.reset()
            assert scene.get(view, **window).status_code == 200
            assert captured.statements, view
            for statement in captured.statements:
                lowered = statement.lower()
                assert lowered.startswith("select"), (view, statement)
                assert "aicore.audit_events" in lowered, (view, statement)
                assert "organization_id" in lowered, (view, statement)
                assert "occurred_at" in lowered, (view, statement)
                for verb in ("insert into", "update ", "delete from", "truncate", "for update"):
                    assert verb not in lowered, (view, statement)


def test_the_summary_counts_the_whole_vocabulary_in_one_pass(
    known: tuple[MonitoringScene, datetime],
) -> None:
    """Eighteen counters, one statement: a metric per query would be a metric per 100 ms."""
    scene, now = known
    window = _window(scene, now)

    with _trail_statements(scene) as captured:
        assert scene.get("summary", **window).status_code == 200
        counts = captured.statements[0].lower()

    assert counts.count("count(*)") >= 18
    assert "group by" not in counts  # the per-identifier counts are a second statement


def test_reading_measures_the_committed_trail_and_nothing_else(
    known: tuple[MonitoringScene, datetime],
) -> None:
    """The consistency model, stated as an assertion: what is committed is what is counted.

    A row appended after a read is visible to the next read — no cache, no invalidation,
    nothing to go stale — and a row the *window* excludes is never counted, however
    recently it was written.
    """
    scene, now = known
    window = _window(scene, now)
    assert scene.summary(**window)["total_events"] == 27

    seed_events(
        scene.trail.engine,
        scene.organization_id,
        [action_event(AuditEventType.ACTION_REQUESTED.value, 1.0, agent_id=AGENT_A)],
        now=now,
    )
    assert scene.summary(**window)["total_events"] == 28

    seed_events(
        scene.trail.engine,
        scene.organization_id,
        [action_event(AuditEventType.ACTION_REQUESTED.value, 45.0, agent_id=AGENT_A)],
        now=now,
    )
    assert scene.summary(**window)["total_events"] == 28
    assert scene.trail_count() == 29  # written, and deliberately outside the window


def test_a_second_tenant_measures_its_own_trail(
    known: tuple[MonitoringScene, datetime],
    identity_factory: IdentityFactory,
    authenticate: Any,
) -> None:
    """Isolation, with activity on one side and none on the other."""
    scene, now = known
    window = _window(scene, now)

    stranger = identity_factory(role_code="owner")
    client = authenticate(stranger)

    theirs = client.get(monitoring_path(stranger.organization_id, "summary"), params=window)
    assert theirs.status_code == 200
    assert theirs.json()["total_events"] == 0
    assert theirs.json()["active_agents"] == 0

    their_agents = client.get(
        monitoring_path(stranger.organization_id, "agents"), params=window
    ).json()
    assert their_agents["items"] == []

    # The first tenant's numbers are unchanged by another tenant asking about a window
    # that contains its activity: the filters are tenant-scoped before they are filters.
    assert scene.summary(**window)["total_events"] == 27
    assert scene.agent_activity(**window, agent_id=str(AGENT_A))["count"] == 1
    assert scene.action_activity(**window, action=ACTION_ID)["count"] == 1


def test_a_second_tenant_cannot_reach_this_trail(
    known: tuple[MonitoringScene, datetime],
    identity_factory: IdentityFactory,
    authenticate: Any,
) -> None:
    """A foreign identifier reads as absent, in every one of the five views."""
    scene, _ = known
    stranger = identity_factory(role_code="owner")
    client = authenticate(stranger)

    for view in STATEMENTS_PER_VIEW:
        response = client.get(monitoring_path(scene.organization_id, view))
        assert response.status_code == 404, view
        assert response.json()["error"]["code"] == "not_found", view
