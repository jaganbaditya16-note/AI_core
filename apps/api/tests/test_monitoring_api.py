"""The five monitoring endpoints, over HTTP, against a live database.

This file is about the *contract* rather than the arithmetic: the published shape of each
view, the window every response repeats, the pagination that makes the per-agent view
bounded, the refusals (a malformed window is a 422 and not a quiet zero), and the two
things a monitoring endpoint is most likely to get wrong in production — tenant isolation
and the size of the answer.

The numbers themselves are asserted in ``test_monitoring_integration.py``, from known
activity; here the fixtures are only as large as they must be to make a page, a filter and
an attribution observable.

Two boundaries are re-asserted from the outside, because a client can see them. Monitoring
is a *read*: every path answers only ``GET``. And the aggregate publishes no event
identifier, no correlation id, no request id and no metadata — a measurement is counts and
times, and a response that leaked a row would be a second, less careful audit listing.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aicore_api.core.audit import AuditEventType
from audit_fixture import delete_events
from identity_fixture import IdentityFactory
from monitoring_fixture import MonitoringScene, action_event, fixed_agent_id, seed_events

#: The five views, and the keys each response must publish. Declared as sets so a new field
#: has to be added here — an undeclared metric is as much a contract change as a missing one.
VIEW_KEYS = {
    "summary": {
        "organization_id",
        "window",
        "total_events",
        "action_requests",
        "action_executions",
        "action_failures",
        "action_denials",
        "action_replays",
        "approval_required",
        "asset_creations",
        "asset_updates",
        "asset_deletions",
        "asset_discoveries",
        "agent_registrations",
        "agent_updates",
        "agent_deletions",
        "policy_creations",
        "policy_updates",
        "policy_version_publications",
        "policy_status_changes",
        "policy_deletions",
        "policy_changes",
        "active_agents",
        "active_assets",
        "execution_health",
        "denials",
    },
    "agents": {"organization_id", "window", "items", "limit", "offset", "count", "total"},
    "actions": {"organization_id", "window", "items", "count"},
    "policies": {"organization_id", "window", "decisions", "lifecycle"},
    "trends": {"organization_id", "window", "interval", "buckets", "count"},
}

#: Every named window the API declares, and how long it is. A named window always ends at
#: the server's clock, so only its length is knowable from the outside.
NAMED_WINDOWS = {
    "5m": timedelta(minutes=5),
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}

#: Requests the phase must refuse, and why. Each is a query a caller could plausibly send;
#: each is answered with a 422 naming the problem rather than with zeros.
BAD_WINDOWS = {
    "a window this build does not declare": {"window": "30d"},
    "a custom window without its bounds": {"window": "custom"},
    "a custom window with one bound": {
        "window": "custom",
        "start_time": "2026-01-01T00:00:00Z",
    },
    "a bound on a named window": {"window": "1h", "start_time": "2026-01-01T00:00:00Z"},
    "a naive lower bound": {
        "window": "custom",
        "start_time": "2026-01-01T00:00:00",
        "end_time": "2026-01-02T00:00:00Z",
    },
    "a naive upper bound": {
        "window": "custom",
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-01-02T00:00:00",
    },
    "an inverted range": {
        "window": "custom",
        "start_time": "2026-01-02T00:00:00Z",
        "end_time": "2026-01-01T00:00:00Z",
    },
    "a range longer than a month": {
        "window": "custom",
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-03-01T00:00:00Z",
    },
    "an interval too fine for the span": {
        "window": "custom",
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-02-01T00:00:00Z",
        "interval": "hour",
    },
}


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _register(scene: MonitoringScene, name: str) -> str:
    """Register one agent and return its identifier, as a string."""
    agent = scene.agents.register(display_name=name, environment="production")
    assert agent is not None
    return str(agent.id)


def _execute(
    scene: MonitoringScene, target_id: str, *, agent_id: str | None = None, **overrides: Any
) -> Any:
    """Run the registered action against ``target_id``, attributed to ``agent_id``."""
    payload: dict[str, Any] = {} if agent_id is None else {"agent_id": agent_id}
    response = scene.actions.execute(target_id, **payload, **overrides)
    assert response.status_code == 200, response.text
    return response.json()


def _three_agents(scene: MonitoringScene) -> list[str]:
    """Three agents with attributed activity: three events, then two, then one."""
    agents = [_register(scene, f"Measured Agent {index}") for index in range(3)]
    for index, agent_id in enumerate(agents):
        for _ in range(3 - index):
            _execute(scene, agent_id, agent_id=agent_id)
    return agents


@dataclass(frozen=True, slots=True)
class ForeignTenant:
    """A second organization, and a way to speak as its owner when a test needs to.

    The authenticated client is shared across the suite, and the monitoring scene keeps
    re-attaching *its* owner's credential — so a foreign call has to say which identity it
    means immediately before making it, or it is a request from the wrong tenant (which is
    exactly the 404 this fixture exists to compare against).
    """

    organization_id: uuid.UUID
    identity: Any
    authenticate: Any

    def as_owner(self) -> TestClient:
        return self.authenticate(self.identity)


@pytest.fixture
def foreign_tenant(
    identity_factory: IdentityFactory, authenticate: Any, integration_engine: Any
) -> Any:
    """A committed second tenant, cleaned up after the test that used it.

    A cross-tenant assertion needs a tenant that really exists — an identifier nobody has
    is a weaker test than one that is in use somewhere else. The trail's rows go first
    (the foreign key is ``RESTRICT``), and this fixture's teardown runs before the identity
    factory's, because it depends on it.
    """
    identity = identity_factory(role_code="owner")
    try:
        yield ForeignTenant(
            organization_id=identity.organization_id,
            identity=identity,
            authenticate=authenticate,
        )
    finally:
        delete_events(integration_engine, identity.organization_id, "phase 9 monitoring teardown")


# ── the surface ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("view", sorted(VIEW_KEYS))
def test_each_view_answers_the_declared_keys(monitoring: MonitoringScene, view: str) -> None:
    assert set(monitoring.read(view)) == VIEW_KEYS[view]


@pytest.mark.parametrize("view", sorted(VIEW_KEYS))
def test_every_view_states_the_window_it_measured(monitoring: MonitoringScene, view: str) -> None:
    """A number without its interval is a number nobody can read twice."""
    window = monitoring.read(view)["window"]
    assert set(window) == {"name", "start", "end"}
    assert window["name"] == "24h"

    start, end = _instant(window["start"]), _instant(window["end"])
    assert end - start == timedelta(hours=24)
    assert start.utcoffset() == timedelta(0)


def test_a_default_request_measures_the_last_day(monitoring: MonitoringScene) -> None:
    assert monitoring.summary()["window"]["name"] == "24h"


@pytest.mark.parametrize("window", sorted(NAMED_WINDOWS))
def test_a_named_window_is_that_span_ending_at_the_server_clock(
    monitoring: MonitoringScene, window: str
) -> None:
    before = datetime.now(UTC)
    resolved = monitoring.summary(window=window)["window"]
    after = datetime.now(UTC)

    assert resolved["name"] == window
    start, end = _instant(resolved["start"]), _instant(resolved["end"])
    assert end - start == NAMED_WINDOWS[window]
    assert before - timedelta(seconds=5) <= end <= after + timedelta(seconds=5)


def test_a_custom_window_is_measured_exactly_as_asked(monitoring: MonitoringScene) -> None:
    """The caller chooses which interval; the server still decides what a number means."""
    end = datetime(2026, 2, 1, 6, 30, tzinfo=UTC)
    start = end - timedelta(hours=6)
    resolved = monitoring.summary(
        window="custom", start_time=start.isoformat(), end_time=end.isoformat()
    )["window"]

    assert resolved["name"] == "custom"
    assert _instant(resolved["start"]) == start
    assert _instant(resolved["end"]) == end


def test_a_custom_window_states_the_same_instants_whatever_zone_they_arrive_in(
    monitoring: MonitoringScene,
) -> None:
    """Timestamps are instants: the offset a caller writes them in changes nothing."""
    kolkata = timezone(timedelta(hours=5, minutes=30))
    end = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
    start = end - timedelta(hours=2)
    resolved = monitoring.summary(
        window="custom",
        start_time=start.astimezone(kolkata).isoformat(),
        end_time=end.astimezone(kolkata).isoformat(),
    )["window"]

    assert _instant(resolved["start"]) == start
    assert _instant(resolved["end"]) == end


@pytest.mark.parametrize("reason", sorted(BAD_WINDOWS))
def test_a_window_this_build_will_not_measure_is_a_422(
    monitoring: MonitoringScene, reason: str
) -> None:
    """A mistake is an error, not an empty answer: zeros would look like a quiet period."""
    response = monitoring.get("summary", **BAD_WINDOWS[reason])
    assert response.status_code == 422, reason
    assert response.json()["error"]["code"] == "validation_error", reason


def test_the_refusal_names_the_problem(monitoring: MonitoringScene) -> None:
    too_long = monitoring.get(
        "summary",
        window="custom",
        start_time="2026-01-01T00:00:00Z",
        end_time="2026-03-01T00:00:00Z",
    )
    assert "at most 30 days" in too_long.text

    naive = monitoring.get(
        "summary",
        window="custom",
        start_time="2026-01-01T00:00:00",
        end_time="2026-01-02T00:00:00Z",
    )
    assert "timezone" in naive.text

    fine = monitoring.get(
        "trends",
        window="custom",
        start_time="2026-01-01T00:00:00Z",
        end_time="2026-01-17T00:00:00Z",
        interval="hour",
    )
    assert "interval=day" in fine.text


# ── the four views that are not the summary ──────────────────────────────────


def test_the_trend_series_is_complete_and_labelled(monitoring: MonitoringScene) -> None:
    body = monitoring.trends(window="1h", interval="hour")
    assert body["interval"] == "hour"
    assert body["count"] == len(body["buckets"]) == 2

    window_start = _instant(body["window"]["start"])
    previous: datetime | None = None
    for index, bucket in enumerate(body["buckets"]):
        assert set(bucket) == {
            "start",
            "end",
            "events",
            "action_requests",
            "action_executions",
            "action_failures",
            "action_denials",
            "approval_required",
        }
        begin, finish = _instant(bucket["start"]), _instant(bucket["end"])
        assert finish - begin == timedelta(hours=1)
        assert begin.minute == 0 and begin.second == 0
        if previous is not None:
            assert begin == previous
        previous = finish
        if index == 0:
            assert begin <= window_start  # the first bucket contains the window's start

    assert _instant(body["buckets"][-1]["end"]) > _instant(body["window"]["end"])


def test_a_daily_series_over_a_month_is_the_longest_fine_grained_answer(
    monitoring: MonitoringScene,
) -> None:
    body = monitoring.trends(
        window="custom",
        start_time="2026-01-01T00:00:00Z",
        end_time="2026-01-31T00:00:00Z",
        interval="day",
    )
    assert body["count"] == 31
    assert all(bucket["events"] == 0 for bucket in body["buckets"])


def test_an_interval_outside_the_vocabulary_is_refused(monitoring: MonitoringScene) -> None:
    response = monitoring.get("trends", window="24h", interval="minute")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_the_policy_view_keeps_decisions_and_lifecycle_apart(
    monitoring: MonitoringScene,
) -> None:
    body = monitoring.policy_activity()
    assert set(body["decisions"]) == {"allow", "deny", "require_approval"}
    assert set(body["lifecycle"]) == {
        "created",
        "updated",
        "version_published",
        "status_changed",
        "deleted",
        "changes",
    }
    assert body["lifecycle"]["changes"] == sum(
        value for key, value in body["lifecycle"].items() if key != "changes"
    )


def test_the_denial_breakdown_adds_up_to_its_total(monitoring: MonitoringScene) -> None:
    body = monitoring.summary()
    assert set(body["denials"]) == {"total", "by_reason"}
    assert body["denials"]["total"] == sum(body["denials"]["by_reason"].values())
    assert body["denials"]["total"] == body["action_denials"]


def test_the_execution_health_is_counts_and_two_rates(monitoring: MonitoringScene) -> None:
    health = monitoring.summary()["execution_health"]
    assert set(health) == {"completed", "succeeded", "failed", "success_rate", "failure_rate"}
    assert health["completed"] == health["succeeded"] + health["failed"]

    if health["completed"] == 0:
        # Nothing ran: null, never 0.0, which would read as "everything failed".
        assert health["success_rate"] is None
        assert health["failure_rate"] is None
    else:
        assert health["success_rate"] == pytest.approx(health["succeeded"] / health["completed"])
        assert health["failure_rate"] == pytest.approx(health["failed"] / health["completed"])
        assert health["success_rate"] + health["failure_rate"] == pytest.approx(1.0)


# ── the per-agent page ───────────────────────────────────────────────────────


def test_the_agent_page_publishes_exactly_its_declared_fields(
    monitoring: MonitoringScene,
) -> None:
    agents = _three_agents(monitoring)
    body = monitoring.agent_activity(agent_id=agents[0])

    assert body["count"] == len(body["items"]) == 1
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert body["total"] is None  # not asked for, so no second pass
    assert set(body["items"][0]) == {
        "agent_id",
        "events",
        "action_requests",
        "executions",
        "failures",
        "denials",
        "approval_required",
        "replays",
        "last_activity_at",
    }
    assert body["items"][0]["agent_id"] == agents[0]


def test_the_agent_page_counts_only_the_named_agent(monitoring: MonitoringScene) -> None:
    agents = _three_agents(monitoring)
    for index, agent_id in enumerate(agents):
        body = monitoring.agent_activity(agent_id=agent_id)
        assert body["count"] == 1
        # One execution records two attributed events: the request and its ending.
        assert body["items"][0]["events"] == 2 * (3 - index)
        assert body["items"][0]["action_requests"] == 3 - index
        assert body["items"][0]["executions"] == 3 - index


def test_the_agent_page_is_ordered_by_activity_and_then_by_identifier(
    monitoring: MonitoringScene,
) -> None:
    agents = _three_agents(monitoring)
    body = monitoring.agent_activity()
    assert [item["agent_id"] for item in body["items"]] == agents
    assert body["count"] == len(agents)


def test_the_total_is_reported_only_when_it_is_asked_for(monitoring: MonitoringScene) -> None:
    _three_agents(monitoring)
    without = monitoring.agent_activity()
    with_total = monitoring.agent_activity(total="true")

    assert without["total"] is None
    assert with_total["total"] == 3
    assert with_total["items"] == without["items"]


def test_paging_returns_every_agent_once(monitoring: MonitoringScene) -> None:
    """A total order is what makes a page boundary safe: no repeats, no omissions."""
    agents = _three_agents(monitoring)
    seen = [
        monitoring.agent_activity(limit=1, offset=offset)["items"][0]["agent_id"]
        for offset in range(3)
    ]
    assert seen == agents
    assert len(set(seen)) == 3


def test_paging_is_stable_between_identical_requests(monitoring: MonitoringScene) -> None:
    """The same question over the same pinned window gets the same answer, twice."""
    _three_agents(monitoring)
    pinned = {
        "window": "custom",
        "start_time": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
        "end_time": datetime.now(UTC).isoformat(),
        "limit": 2,
        "offset": 1,
    }
    first = monitoring.agent_activity(**pinned)
    second = monitoring.agent_activity(**pinned)
    assert first == second


def test_an_unknown_agent_selects_nothing_and_reveals_nothing(
    monitoring: MonitoringScene,
) -> None:
    _three_agents(monitoring)
    body = monitoring.agent_activity(agent_id=str(uuid.uuid4()))
    assert body["items"] == []
    assert body["count"] == 0


def test_a_foreign_agent_selects_nothing_in_this_tenant(
    monitoring: MonitoringScene, foreign_tenant: ForeignTenant
) -> None:
    """The tenant scope is applied before the filter, so a foreign id is simply not here."""
    _three_agents(monitoring)
    seed_events(
        monitoring.trail.engine,
        foreign_tenant.organization_id,
        [
            action_event(
                AuditEventType.ACTION_EXECUTED.value,
                10.0,
                agent_id=fixed_agent_id(7),
            )
        ],
        now=datetime.now(UTC),
    )
    foreign_id = str(fixed_agent_id(7))

    # The other tenant's own view counts it, so the identifier is real and in use.
    theirs = (
        foreign_tenant.as_owner()
        .get(f"/organizations/{foreign_tenant.organization_id}/monitoring/agents")
        .json()
    )
    assert theirs["count"] == 1
    assert theirs["items"][0]["agent_id"] == foreign_id

    # And this tenant's view does not see it: empty, not "exists but not yours".
    body = monitoring.agent_activity(agent_id=foreign_id)
    assert body["items"] == []
    assert body["count"] == 0


# ── the per-action page ──────────────────────────────────────────────────────


def test_the_action_page_publishes_both_axes(monitoring: MonitoringScene) -> None:
    agents = _three_agents(monitoring)
    _execute(monitoring, agents[0], agent_id=agents[0])
    body = monitoring.action_activity()

    assert body["count"] == len(body["items"]) == 1
    item = body["items"][0]
    assert set(item) == {
        "action",
        "requested",
        "allowed",
        "denied",
        "approval_required",
        "executed",
        "failed",
        "replayed",
    }
    assert item["action"] == "agent.posture_check"
    assert item["requested"] == item["allowed"] == item["executed"] == 7
    assert item["denied"] == item["failed"] == item["replayed"] == 0


def test_the_action_filter_narrows_the_page(monitoring: MonitoringScene) -> None:
    _three_agents(monitoring)
    known = monitoring.action_activity(action="agent.posture_check")
    assert known["count"] == 1
    assert known["items"][0]["requested"] == 6


@pytest.mark.parametrize(
    "action",
    [
        "Agent.Posture_Check",
        "agent..posture",
        ".agent",
        "agent.",
        "agent posture",
        "agent;posture",
        "agent.posture' OR 1=1--",
        "agent.posture_check\n",
        "x" * 5000,
    ],
)
def test_a_filter_outside_the_action_vocabulary_is_refused(
    monitoring: MonitoringScene, action: str
) -> None:
    """A filter is a value from a closed vocabulary, never a fragment of a query."""
    response = monitoring.get("actions", action=action)
    assert response.status_code == 422, action


def test_a_valid_shape_that_matches_no_action_selects_nothing(
    monitoring: MonitoringScene,
) -> None:
    body = monitoring.action_activity(action="vendor.never_registered")
    assert body["items"] == []
    assert body["count"] == 0


def test_lifecycle_events_are_not_listed_as_actions(monitoring: MonitoringScene) -> None:
    """``asset.create`` is a permission code on a lifecycle event, not a registered action."""
    monitoring.assets.create(name="Measured Asset", asset_type="model")
    assert monitoring.stored()[0]["action"] == "asset.create"
    body = monitoring.action_activity()
    assert body["items"] == []
    assert body["count"] == 0


# ── refusals, isolation and the size of an answer ────────────────────────────


def test_a_malformed_organization_identifier_is_refused(monitoring: MonitoringScene) -> None:
    response = monitoring.client.get("/organizations/not-a-uuid/monitoring/summary")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_an_unknown_query_parameter_does_not_change_the_answer(
    monitoring: MonitoringScene,
) -> None:
    """There is no parameter by which a client can add, write or widen anything."""
    pinned = {
        "window": "custom",
        "start_time": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
        "end_time": datetime.now(UTC).isoformat(),
    }
    baseline = monitoring.summary(**pinned)
    noisy = monitoring.summary(
        **pinned,
        unexpected="value",
        organization_id=str(uuid.uuid4()),
        limit=99999,
        tenant=str(uuid.uuid4()),
    )
    assert noisy == baseline


@pytest.mark.parametrize(
    "params", [{"limit": 201}, {"limit": 0}, {"offset": -1}, {"offset": 100_001}]
)
def test_an_oversized_page_is_refused(monitoring: MonitoringScene, params: Any) -> None:
    assert monitoring.get("agents", **params).status_code == 422


def test_the_biggest_page_the_api_serves_is_served(monitoring: MonitoringScene) -> None:
    body = monitoring.agent_activity(limit=200, offset=0, total="false")
    assert body["limit"] == 200
    assert body["total"] is None


def test_a_foreign_organization_is_not_found(monitoring: MonitoringScene) -> None:
    """Not 403: a tenant the caller may not read answers exactly like one that is absent."""
    response = monitoring.client.get(f"/organizations/{uuid.uuid4()}/monitoring/summary")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_a_member_of_another_organization_cannot_measure_this_one(
    monitoring: MonitoringScene, foreign_tenant: ForeignTenant
) -> None:
    """A valid caller, a real tenant, no membership: refused before a row is read."""
    response = foreign_tenant.as_owner().get(
        f"/organizations/{monitoring.organization_id}/monitoring/summary"
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_an_anonymous_caller_measures_nothing(monitoring: MonitoringScene) -> None:
    client = monitoring.trail.client  # the raw client: no credential is re-attached
    client.headers.pop("Authorization", None)
    try:
        response = client.get(f"/organizations/{monitoring.organization_id}/monitoring/summary")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "unauthorized"
    finally:
        monitoring.trail.as_owner()


def test_the_aggregate_publishes_no_row_identifiers(monitoring: MonitoringScene) -> None:
    """A measurement names counts, never the events behind them."""
    _three_agents(monitoring)
    for view in VIEW_KEYS:
        rendered = str(monitoring.read(view))
        for row in monitoring.stored():
            assert str(row["id"]) not in rendered, view
            assert row["correlation_id"] not in rendered, view
            assert row["event_type"] not in rendered, view
            if row["request_id"] is not None:
                assert row["request_id"] not in rendered, view
            document = row["metadata"] or {}
            assert json.dumps(document) not in rendered, view
            for value in document.values():
                if isinstance(value, str) and len(value) >= 8:
                    assert value not in rendered, (view, value)
