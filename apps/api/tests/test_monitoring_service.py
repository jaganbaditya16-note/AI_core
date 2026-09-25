"""The service, assembled: a stub repository in, a complete measurement out.

Between the SQL and the HTTP there is exactly one layer that decides what a caller
receives — which counters travel together, which zeros are stated, which total is derived
rather than counted, and which moment a bucket represents. That layer is testable without a
database, and this file does exactly that: the stub below returns rows a test wrote by
hand, so every assertion is about the *assembly* rather than about PostgreSQL.

The stub is also how two properties of this phase are checked without any data at all: the
service never looks at a clock (a window is an argument, never a moment), and the service
has no way to write (there is no method here, and no session to reach for).
"""

from __future__ import annotations

import inspect
import uuid
from datetime import UTC, datetime, timedelta, timezone
from itertools import pairwise
from typing import Any

import pytest

from aicore_api.core.audit import AuditDecision
from aicore_api.core.monitoring import (
    SUMMARY_COUNTERS,
    ExecutionHealth,
    MonitoringWindow,
    ResolvedWindow,
    TimeInterval,
)
from aicore_api.monitoring import service as monitoring_service
from aicore_api.monitoring.service import MonitoringService

NOW = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
IST = timezone(timedelta(hours=5, minutes=30))
WINDOW = ResolvedWindow(name=MonitoringWindow.CUSTOM, start=NOW - timedelta(hours=1), end=NOW)


class StubRepository:
    """A stand-in for the aggregation layer that returns whatever a test hands it.

    It records the window and the arguments it was called with, so the assertions can cover
    the hand-off as well as the result: that the window arrives unchanged, that a page size
    is passed through rather than decided here, and that the total is not queried when the
    caller did not ask for it.
    """

    def __init__(
        self,
        *,
        counters: dict[str, int] | None = None,
        denial_reasons: dict[str, int] | None = None,
        decisions: dict[str, int] | None = None,
        active: tuple[int, int] = (0, 0),
        agents: list[dict[str, Any]] | None = None,
        agent_total: int | None = None,
        actions: list[dict[str, Any]] | None = None,
        trend: list[dict[str, Any]] | None = None,
    ) -> None:
        self.counters = {"events": 0, **dict.fromkeys(SUMMARY_COUNTERS, 0)}
        self.counters.update(counters or {})
        # Named differently from the methods below on purpose: the repository's *API* is
        # what this stub imitates, so the methods keep its names and the data does not.
        self.reason_counts = denial_reasons or {}
        self.decision_totals = decisions or {}
        self.active = active
        self.agent_rows = agents or []
        self.agent_total = agent_total
        self.action_rows = actions or []
        self.trend_rows = trend or []
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _called(self, name: str, **arguments: Any) -> None:
        self.calls.append((name, arguments))

    def called(self, name: str) -> list[dict[str, Any]]:
        return [arguments for call, arguments in self.calls if call == name]

    def summary(self, *, start: datetime, end: datetime) -> dict[str, int]:
        self._called("summary", start=start, end=end)
        return dict(self.counters)

    def active_identifiers(self, *, start: datetime, end: datetime) -> tuple[int, int]:
        self._called("active_identifiers", start=start, end=end)
        return self.active

    def denial_reasons(self, *, start: datetime, end: datetime) -> dict[str, int]:
        self._called("denial_reasons", start=start, end=end)
        return dict(self.reason_counts)

    def decision_counts(self, *, start: datetime, end: datetime) -> dict[str, int]:
        self._called("decision_counts", start=start, end=end)
        return dict(self.decision_totals)

    def agent_activity(
        self,
        *,
        start: datetime,
        end: datetime,
        limit: int,
        offset: int,
        agent_id: uuid.UUID | None = None,
    ) -> list[dict[str, Any]]:
        self._called(
            "agent_activity", start=start, end=end, limit=limit, offset=offset, agent_id=agent_id
        )
        return list(self.agent_rows)

    def count_agents(
        self, *, start: datetime, end: datetime, agent_id: uuid.UUID | None = None
    ) -> int:
        self._called("count_agents", start=start, end=end, agent_id=agent_id)
        assert self.agent_total is not None
        return self.agent_total

    def action_activity(
        self, *, start: datetime, end: datetime, action: str | None = None
    ) -> list[dict[str, Any]]:
        self._called("action_activity", start=start, end=end, action=action)
        return list(self.action_rows)

    def trend(
        self, *, start: datetime, end: datetime, interval: TimeInterval
    ) -> list[dict[str, Any]]:
        self._called("trend", start=start, end=end, interval=interval)
        return list(self.trend_rows)


def _service(repository: StubRepository) -> MonitoringService:
    return MonitoringService(repository)  # type: ignore[arg-type]


def _agent_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "agent_id": uuid.uuid4(),
        "events": 4,
        "action_requests": 1,
        "executions": 1,
        "failures": 0,
        "denials": 1,
        "approval_required": 0,
        "replays": 0,
        "last_activity_at": NOW - timedelta(minutes=5),
    }
    row.update(overrides)
    return row


def _action_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "action": "agent.posture_check",
        "requested": 2,
        "allowed": 1,
        "denied": 1,
        "approval_required": 0,
        "executed": 1,
        "failed": 0,
        "replayed": 0,
    }
    row.update(overrides)
    return row


# ── Summary ───────────────────────────────────────────────────────────────────


def test_the_summary_reports_every_counter_the_table_defines() -> None:
    repository = StubRepository(counters={"events": 11, "action_denials": 3})
    summary = _service(repository).summary(WINDOW)
    assert summary.total_events == 11
    assert set(summary.counters) == set(SUMMARY_COUNTERS)
    assert summary.counters["action_denials"] == 3
    # ``events`` is the total, published as ``total_events`` rather than as a nineteenth
    # counter — one number, one name.
    assert "events" not in summary.counters


def test_the_summary_passes_the_window_through_unchanged() -> None:
    repository = StubRepository()
    _service(repository).summary(WINDOW)
    for call in repository.calls:
        assert call[1]["start"] == WINDOW.start
        assert call[1]["end"] == WINDOW.end


def test_the_summary_counters_cannot_be_edited_by_a_caller() -> None:
    summary = _service(StubRepository()).summary(WINDOW)
    with pytest.raises(TypeError):
        summary.counters["action_denials"] = 99  # type: ignore[index]


def test_policy_changes_is_derived_from_the_five_counters_beside_it() -> None:
    counters = {
        "policy_creations": 2,
        "policy_updates": 1,
        "policy_version_publications": 3,
        "policy_status_changes": 4,
        "policy_deletions": 5,
    }
    summary = _service(StubRepository(counters=counters)).summary(WINDOW)
    assert summary.policy_changes == 15
    assert summary.policy_changes == sum(summary.counters[name] for name in counters)


def test_policy_changes_counts_only_policy_events() -> None:
    """A busy window with no policy activity reports zero changes, not "no data"."""
    summary = _service(
        StubRepository(counters={"events": 40, "action_requests": 20, "agent_registrations": 3})
    ).summary(WINDOW)
    assert summary.policy_changes == 0


def test_the_health_ratios_are_computed_from_the_counters_that_are_published() -> None:
    """A rate derived from different rows than the counts beside it would contradict them."""
    summary = _service(
        StubRepository(counters={"action_executions": 5, "action_failures": 1})
    ).summary(WINDOW)
    assert summary.execution_health.succeeded == summary.counters["action_executions"]
    assert summary.execution_health.failed == summary.counters["action_failures"]
    assert summary.execution_health.completed == 6
    assert summary.execution_health.success_rate == round(5 / 6, 6)


def test_a_refused_request_is_neither_an_execution_nor_a_failure() -> None:
    """Refusals never ran, so they cannot be part of an execution's health."""
    summary = _service(
        StubRepository(
            counters={
                "action_requests": 10,
                "action_denials": 7,
                "action_executions": 2,
                "action_failures": 1,
                "approval_required": 1,
            }
        )
    ).summary(WINDOW)
    assert summary.counters["action_denials"] == 7
    assert summary.execution_health.completed == 3
    assert summary.execution_health.success_rate == round(2 / 3, 6)


def test_a_window_where_nothing_ran_reports_no_rate_rather_than_zero() -> None:
    summary = _service(StubRepository(counters={"action_denials": 4})).summary(WINDOW)
    assert summary.execution_health.completed == 0
    assert summary.execution_health.success_rate is None
    assert summary.execution_health.failure_rate is None


def test_denial_reasons_are_ordered_and_copied_out_of_the_repository() -> None:
    """A breakdown is not the repository's dictionary, and its order is not the query's."""
    repository = StubRepository(denial_reasons={"policy_denied": 2, "authorization_denied": 1})
    summary = _service(repository).summary(WINDOW)
    assert list(summary.denial_reasons) == ["authorization_denied", "policy_denied"]
    repository.reason_counts["policy_denied"] = 99
    assert summary.denial_reasons["policy_denied"] == 2
    with pytest.raises(TypeError):
        summary.denial_reasons["policy_denied"] = 5  # type: ignore[index]


def test_an_empty_window_is_zero_everywhere_and_not_an_error() -> None:
    summary = _service(StubRepository()).summary(WINDOW)
    assert summary.total_events == 0
    assert all(value == 0 for value in summary.counters.values())
    assert summary.active_agents == 0 and summary.active_assets == 0
    assert summary.denial_reasons == {}
    assert summary.execution_health.completed == 0


# ── Agents ────────────────────────────────────────────────────────────────────


def test_the_agents_page_returns_the_rows_the_repository_returned() -> None:
    agent_id = uuid.uuid4()
    repository = StubRepository(agents=[_agent_row(agent_id=agent_id, events=9)])
    page = _service(repository).agents(WINDOW, limit=50, offset=0)
    assert [item.agent_id for item in page.items] == [agent_id]
    assert page.items[0].events == 9
    assert page.items[0].executions == 1


def test_the_total_is_absent_unless_it_was_asked_for_and_never_queried_when_it_was_not() -> None:
    repository = StubRepository(agents=[_agent_row()], agent_total=7)
    page = _service(repository).agents(WINDOW, limit=50, offset=0)
    assert page.total is None
    assert repository.called("count_agents") == []
    again = _service(repository).agents(WINDOW, limit=50, offset=0, total=True)
    assert again.total == 7
    assert repository.called("count_agents")[0]["agent_id"] is None


def test_the_page_size_and_filter_are_passed_through_rather_than_decided_here() -> None:
    repository = StubRepository()
    agent_id = uuid.uuid4()
    _service(repository).agents(WINDOW, limit=5, offset=10, agent_id=agent_id)
    call = repository.called("agent_activity")[0]
    assert call["limit"] == 5 and call["offset"] == 10 and call["agent_id"] == agent_id


def test_last_activity_is_stated_in_utc_whatever_zone_the_driver_used() -> None:
    moment = (NOW - timedelta(minutes=5)).astimezone(IST)
    repository = StubRepository(agents=[_agent_row(last_activity_at=moment)])
    item = _service(repository).agents(WINDOW, limit=1, offset=0).items[0]
    assert item.last_activity_at.tzinfo is UTC
    assert item.last_activity_at == NOW - timedelta(minutes=5)


def test_an_agent_with_no_activity_is_absent_rather_than_reported_as_zeros() -> None:
    page = _service(StubRepository(agents=[])).agents(WINDOW, limit=50, offset=0)
    assert page.items == []


# ── Actions ───────────────────────────────────────────────────────────────────


def test_the_action_rows_are_converted_field_for_field() -> None:
    row = _action_row(
        requested=5, allowed=3, denied=1, approval_required=1, executed=2, failed=1, replayed=0
    )
    items = _service(StubRepository(actions=[row])).actions(WINDOW)
    (item,) = items
    assert item.action == "agent.posture_check"
    assert (
        item.requested,
        item.allowed,
        item.denied,
        item.approval_required,
        item.executed,
        item.failed,
        item.replayed,
    ) == (5, 3, 1, 1, 2, 1, 0)


def test_an_action_filter_is_passed_to_the_repository() -> None:
    repository = StubRepository()
    _service(repository).actions(WINDOW, action="agent.posture_check")
    assert repository.called("action_activity")[0]["action"] == "agent.posture_check"


def test_the_action_list_keeps_the_order_the_repository_chose() -> None:
    """Alphabetical is the repository's decision, and the service does not re-sort it."""
    rows = [_action_row(action="zeta.check"), _action_row(action="alpha.check")]
    items = _service(StubRepository(actions=rows)).actions(WINDOW)
    assert [item.action for item in items] == ["zeta.check", "alpha.check"]


# ── Policies ──────────────────────────────────────────────────────────────────


def test_the_policy_view_states_every_decision_including_the_zeros() -> None:
    """A missing key and a zero would look the same to a caller comparing two windows."""
    activity = _service(StubRepository(decisions={AuditDecision.ALLOW.value: 2})).policies(WINDOW)
    assert set(activity.decisions) == {decision.value for decision in AuditDecision}
    assert activity.decisions["allow"] == 2
    assert activity.decisions["deny"] == 0
    assert activity.decisions["require_approval"] == 0


def test_policy_activity_separates_lifecycle_counts_from_decisions() -> None:
    activity = _service(
        StubRepository(
            counters={
                "policy_creations": 1,
                "policy_updates": 2,
                "policy_version_publications": 3,
                "policy_status_changes": 1,
                "policy_deletions": 1,
            },
            decisions={AuditDecision.DENY.value: 4},
        )
    ).policies(WINDOW)
    assert activity.creations == 1
    assert activity.version_publications == 3
    assert activity.changes == 8
    assert activity.decisions["deny"] == 4
    assert activity.decisions["allow"] == 0


# ── Trends ────────────────────────────────────────────────────────────────────


def test_the_series_has_one_bucket_per_interval_in_the_window() -> None:
    buckets = _service(StubRepository()).trends(WINDOW, interval=TimeInterval.HOUR)
    assert len(buckets) == 2
    assert buckets[0].start == NOW.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    assert buckets[-1].start == NOW.replace(minute=0, second=0, microsecond=0)


def test_every_bucket_in_the_series_is_one_interval_wide_and_contiguous() -> None:
    buckets = _service(StubRepository()).trends(WINDOW, interval=TimeInterval.DAY)
    for earlier, later in pairwise(buckets):
        assert earlier.end - earlier.start == timedelta(days=1)
        assert earlier.end == later.start


def test_a_bucket_with_no_events_is_present_and_zero() -> None:
    """A gap would be indistinguishable from missing data, so the zeros are stated."""
    quiet = NOW.replace(minute=0, second=0, microsecond=0)
    repository = StubRepository(
        trend=[
            {
                "bucket": quiet,
                "events": 3,
                "action_requests": 1,
                "action_executions": 1,
                "action_failures": 0,
                "action_denials": 0,
                "approval_required": 0,
            }
        ]
    )
    buckets = _service(repository).trends(WINDOW, interval=TimeInterval.HOUR)
    assert [bucket.events for bucket in buckets] == [0, 3]
    assert buckets[0].start + timedelta(hours=1) == buckets[1].start
    assert buckets[0].action_requests == 0 and buckets[0].approval_required == 0


def test_trend_rows_are_merged_by_instant_not_by_position() -> None:
    """A driver in another timezone renders the same bucket differently; it is the same one."""
    quiet = NOW.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    earlier = quiet.astimezone(IST)
    assert earlier == quiet  # the same instant, stated in a zone that is not UTC
    repository = StubRepository(
        trend=[
            # Out of order, and rendered in IST: a positional merge would misplace both.
            {
                "bucket": earlier + timedelta(hours=1),
                "events": 5,
                "action_requests": 1,
                "action_executions": 1,
                "action_failures": 0,
                "action_denials": 0,
                "approval_required": 0,
            },
            {
                "bucket": earlier,
                "events": 2,
                "action_requests": 0,
                "action_executions": 0,
                "action_failures": 0,
                "action_denials": 1,
                "approval_required": 0,
            },
        ]
    )
    buckets = _service(repository).trends(WINDOW, interval=TimeInterval.HOUR)
    assert [bucket.events for bucket in buckets] == [2, 5]
    assert [bucket.action_denials for bucket in buckets] == [1, 0]
    assert all(bucket.start.tzinfo is UTC for bucket in buckets)


def test_a_trend_row_outside_the_window_has_no_bucket_to_land_in() -> None:
    """The series covers the window and nothing else, so a stray row is not published."""
    repository = StubRepository(
        trend=[
            {
                "bucket": NOW + timedelta(days=1),
                "events": 9,
                "action_requests": 0,
                "action_executions": 0,
                "action_failures": 0,
                "action_denials": 0,
                "approval_required": 0,
            }
        ]
    )
    buckets = _service(repository).trends(WINDOW, interval=TimeInterval.HOUR)
    assert sum(bucket.events for bucket in buckets) == 0


def test_the_interval_is_passed_to_the_repository() -> None:
    repository = StubRepository()
    _service(repository).trends(WINDOW, interval=TimeInterval.DAY)
    assert repository.called("trend")[0]["interval"] is TimeInterval.DAY


# ── What this layer cannot do ─────────────────────────────────────────────────


def test_the_service_never_reads_a_clock() -> None:
    """A window is an argument. A layer that read a clock would answer differently twice."""
    source = inspect.getsource(monitoring_service)
    for forbidden in ("datetime.now", "utcnow", "time.time", "today("):
        assert forbidden not in source, forbidden


def test_the_service_has_no_write_surface_and_no_session() -> None:
    declared = {
        name
        for name in dir(MonitoringService)
        if not name.startswith("_") and callable(getattr(MonitoringService, name))
    }
    assert declared == {"actions", "agents", "policies", "summary", "trends"}
    source = inspect.getsource(monitoring_service)
    for forbidden in ("session.add", ".commit(", ".flush(", "delete(", "update(", "insert("):
        assert forbidden not in source, forbidden


def test_the_service_computes_no_ratio_of_its_own() -> None:
    """Ratios are defined once, in the core vocabulary; this layer only carries them.

    A second division somewhere in the service is how two screens end up disagreeing about
    the same window — so the arithmetic lives with the counters, and the assertion here is
    that nothing in this module divides or rounds.
    """
    source = inspect.getsource(monitoring_service)
    assert " / " not in source
    assert "round(" not in source
    assert ExecutionHealth(succeeded=1, failed=1).success_rate == 0.5
