"""The monitoring service: window arithmetic, assembly, and the shape of a measurement.

Phase 9 has two halves, and this is the one between them: :mod:`aicore_api.core.monitoring`
defines what a metric *is*, :mod:`aicore_api.db.repositories.monitoring` computes it in
PostgreSQL, and this module decides what a caller receives — the counters of a window, one
row per agent, one row per action, the policy record's activity, and a zero-filled time
series. It holds the arithmetic the database cannot do (merging sparse buckets into a
complete series, deriving a total from its parts, computing a rate) and nothing else: no
SQL, no session, no FastAPI.

Why a service rather than a fatter route handler: every number here is checkable without
an HTTP client or a database, and the endpoints become a thin translation from query
parameters to a window and from these dataclasses to response models. That keeps the
interesting part — *what does this number mean* — in one place with one test file.

The classes below are frozen dataclasses rather than the response models: the API's
schemas live with the other schemas and are free to describe the same measurement in
whatever shape the contract wants. What must not vary is the meaning, and that is fixed
here.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType

from aicore_api.core.audit import AuditDecision
from aicore_api.core.monitoring import (
    INTERVAL_SPANS,
    POLICY_CHANGE_TYPES,
    SUMMARY_COUNTERS,
    ExecutionHealth,
    ResolvedWindow,
    TimeInterval,
    bucket_starts,
)
from aicore_api.db.repositories.monitoring import MonitoringRepository

__all__ = [
    "ActionActivity",
    "AgentActivity",
    "AgentActivityPage",
    "MonitoringService",
    "PolicyActivity",
    "Summary",
    "TrendBucket",
]


def _as_utc(moment: datetime) -> datetime:
    """Render an instant in UTC, whatever timezone the driver returned it in.

    PostgreSQL hands a ``timestamptz`` back in the session's ``TimeZone``, and the check
    constraints are about instants, not renderings — so a series bucketed at 04:00 UTC
    arrives as 09:30+05:30 on a server set to Kolkata. Those are the same moment, and
    publishing whichever one the driver happened to choose would make two identical
    measurements look different. Responses state their times in UTC, always.
    """
    return moment.astimezone(UTC)


#: The counters :attr:`Summary.policy_changes` adds up, derived from the two declarations
#: rather than listed again: "a policy changed" is exactly "one of the policy lifecycle
#: event types was recorded", and a metric added to one list cannot fall out of the other.
_POLICY_CHANGE_COUNTERS: tuple[str, ...] = tuple(
    name
    for name, event_types in SUMMARY_COUNTERS.items()
    if set(event_types) <= set(POLICY_CHANGE_TYPES)
)


@dataclass(frozen=True, slots=True)
class Summary:
    """What happened in one organization, in one window, as counts.

    ``counters`` holds every metric :data:`~aicore_api.core.monitoring.SUMMARY_COUNTERS`
    declares, keyed by its published name. ``policy_changes`` is derived from five of them
    rather than counted separately, so "how many policy changes were there?" and "what kind
    were they?" cannot come out inconsistent.
    """

    total_events: int
    counters: Mapping[str, int]
    active_agents: int
    active_assets: int
    execution_health: ExecutionHealth
    denial_reasons: Mapping[str, int]

    @property
    def policy_changes(self) -> int:
        """Policy lifecycle events of every kind: the sum of the five counters."""
        return sum(self.counters[name] for name in _POLICY_CHANGE_COUNTERS)


@dataclass(frozen=True, slots=True)
class AgentActivity:
    """One agent's activity in the window.

    Attribution, not identity: these are the events that *named* the agent, which in this
    build means an execution request that carried ``agent_id``. Counting them is not a
    claim about the agent's behaviour — this build has no runtime for an agent to behave
    in — and nothing here ranks, scores or flags one.
    """

    agent_id: uuid.UUID
    events: int
    action_requests: int
    executions: int
    failures: int
    denials: int
    approval_required: int
    replays: int
    last_activity_at: datetime


@dataclass(frozen=True, slots=True)
class AgentActivityPage:
    """One page of the per-agent view, and the total behind it.

    ``total`` is ``None`` when the caller did not ask for it, because the count is a
    second pass over the same predicate — the same contract the audit listing uses.
    """

    items: list[AgentActivity]
    total: int | None


@dataclass(frozen=True, slots=True)
class ActionActivity:
    """One registered action's activity in the window.

    ``allowed`` counts the rows whose *decision* was ``allow`` — the requests that got
    past the firewall — while the other fields count by event type. The two axes are kept
    apart on purpose: a request that was allowed and then failed is one ``allowed`` and one
    ``failed``, and collapsing them would lose the fact that it was permitted.
    """

    action: str
    requested: int
    allowed: int
    denied: int
    approval_required: int
    executed: int
    failed: int
    replayed: int


@dataclass(frozen=True, slots=True)
class PolicyActivity:
    """The policy record's activity, and how the pipeline answered, in one window.

    Two sections, because "the policy changed" and "a policy decided something" are
    different facts: the first is a lifecycle event on the policy record, the second is a
    decision the action pipeline recorded on a request. Both come from the trail; neither
    is inferred.

    ``decisions`` counts the decision axis over the actions that carried one — ``allow``,
    ``deny``, ``require_approval`` — which is Phase 6's and Phase 7's own vocabulary, not a
    new classification of it.
    """

    decisions: Mapping[str, int]
    creations: int
    updates: int
    version_publications: int
    status_changes: int
    deletions: int

    @property
    def changes(self) -> int:
        """Every lifecycle event on the policy record: the sum of the five above."""
        return (
            self.creations
            + self.updates
            + self.version_publications
            + self.status_changes
            + self.deletions
        )


@dataclass(frozen=True, slots=True)
class TrendBucket:
    """One bucket of a time series, with every counter — including the zeros.

    A bucket with no events is present and says zero. Omitting it would leave a caller
    unable to tell a quiet hour from a query that returned early, and interpolating would
    be worse: this build never draws a line through data it does not have.
    """

    start: datetime
    end: datetime
    events: int
    action_requests: int
    action_executions: int
    action_failures: int
    action_denials: int
    approval_required: int


class MonitoringService:
    """Measurements over one organization's audit trail, in bounded windows.

    Every method takes a :class:`~aicore_api.core.monitoring.ResolvedWindow`: the caller
    (a route) resolves *which* window, and this layer never looks at a clock. That is what
    makes "the last hour" reproducible in a test — the window is an argument, not a moment.

    Read-only by construction: it holds a repository that has no write method, and it adds
    none. Nothing here can change an event, a policy, an agent or a permission, and nothing
    here can execute an action — the only object it touches is the trail.
    """

    def __init__(self, repository: MonitoringRepository) -> None:
        self.repository = repository

    # ── The window's headline numbers ────────────────────────────────────────

    def summary(self, window: ResolvedWindow) -> Summary:
        """Every summary counter for the window, plus the derived measurements."""
        counters = self.repository.summary(start=window.start, end=window.end)
        total_events = counters.pop("events")
        active_agents, active_assets = self.repository.active_identifiers(
            start=window.start, end=window.end
        )
        return Summary(
            total_events=total_events,
            counters=MappingProxyType(counters),
            active_agents=active_agents,
            active_assets=active_assets,
            execution_health=ExecutionHealth(
                # The two counters the health ratios are computed from are the same two the
                # summary publishes: a rate derived from different rows than the counts
                # beside it would be a contradiction waiting to be noticed.
                succeeded=counters["action_executions"],
                failed=counters["action_failures"],
            ),
            denial_reasons=MappingProxyType(
                dict(
                    sorted(
                        self.repository.denial_reasons(start=window.start, end=window.end).items()
                    )
                )
            ),
        )

    # ── Per agent ────────────────────────────────────────────────────────────

    def agents(
        self,
        window: ResolvedWindow,
        *,
        limit: int,
        offset: int,
        agent_id: uuid.UUID | None = None,
        total: bool = False,
    ) -> AgentActivityPage:
        """One page of agents with activity in the window, most active first."""
        rows = self.repository.agent_activity(
            start=window.start, end=window.end, limit=limit, offset=offset, agent_id=agent_id
        )
        items = [
            AgentActivity(
                agent_id=row["agent_id"],
                events=int(row["events"]),
                action_requests=int(row["action_requests"]),
                executions=int(row["executions"]),
                failures=int(row["failures"]),
                denials=int(row["denials"]),
                approval_required=int(row["approval_required"]),
                replays=int(row["replays"]),
                last_activity_at=_as_utc(row["last_activity_at"]),
            )
            for row in rows
        ]
        count = (
            self.repository.count_agents(start=window.start, end=window.end, agent_id=agent_id)
            if total
            else None
        )
        return AgentActivityPage(items=items, total=count)

    # ── Per action ───────────────────────────────────────────────────────────

    def actions(self, window: ResolvedWindow, *, action: str | None = None) -> list[ActionActivity]:
        """One row per registered action with activity in the window."""
        rows = self.repository.action_activity(start=window.start, end=window.end, action=action)
        return [
            ActionActivity(
                action=str(row["action"]),
                requested=int(row["requested"]),
                allowed=int(row["allowed"]),
                denied=int(row["denied"]),
                approval_required=int(row["approval_required"]),
                executed=int(row["executed"]),
                failed=int(row["failed"]),
                replayed=int(row["replayed"]),
            )
            for row in rows
        ]

    # ── The policy record ────────────────────────────────────────────────────

    def policies(self, window: ResolvedWindow) -> PolicyActivity:
        """Policy lifecycle activity and the pipeline's decisions for the window."""
        counters = self.repository.summary(start=window.start, end=window.end)
        decisions = self.repository.decision_counts(start=window.start, end=window.end)
        # Every declared decision appears, even at zero: a caller comparing two windows
        # should not have to guess whether a missing key means "none" or "not measured".
        stated = {
            decision.value: int(decisions.get(decision.value, 0)) for decision in AuditDecision
        }
        return PolicyActivity(
            decisions=MappingProxyType(stated),
            creations=counters["policy_creations"],
            updates=counters["policy_updates"],
            version_publications=counters["policy_version_publications"],
            status_changes=counters["policy_status_changes"],
            deletions=counters["policy_deletions"],
        )

    # ── Over time ────────────────────────────────────────────────────────────

    def trends(self, window: ResolvedWindow, *, interval: TimeInterval) -> list[TrendBucket]:
        """Activity per bucket over the whole window, zeros included.

        The bucket list comes first, and it is what bounds the result: it is capped at
        :data:`~aicore_api.core.monitoring.MAX_BUCKETS`, so a request for an hour-by-hour
        series over a month is refused before a query runs rather than answered with a
        payload nobody asked for. The rows are then merged into that list by instant, which
        is why the merge is a lookup rather than a scan — and why a database session in a
        different timezone cannot shift a bucket into its neighbour.

        Every bucket is one interval wide, including the first and last: the series is
        floored to bucket boundaries, so the bucket containing ``window.start`` begins at
        or before it and the one containing ``window.end`` ends at or after it. That is the
        same half-open convention :func:`bucket_starts` floors by, stated in the response
        so a chart can lay the buckets side by side without gaps.
        """
        starts = bucket_starts(window, interval)
        span = INTERVAL_SPANS[interval]
        rows = self.repository.trend(start=window.start, end=window.end, interval=interval)
        by_instant = {_as_utc(row["bucket"]): row for row in rows}

        buckets: list[TrendBucket] = []
        for start in starts:
            row = by_instant.get(start)
            buckets.append(
                TrendBucket(
                    start=start,
                    end=start + span,
                    events=0 if row is None else int(row["events"]),
                    action_requests=0 if row is None else int(row["action_requests"]),
                    action_executions=0 if row is None else int(row["action_executions"]),
                    action_failures=0 if row is None else int(row["action_failures"]),
                    action_denials=0 if row is None else int(row["action_denials"]),
                    approval_required=0 if row is None else int(row["approval_required"]),
                )
            )
        return buckets
