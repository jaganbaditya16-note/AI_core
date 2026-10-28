"""Monitoring: what Phase 9 measures, over which window, and with what arithmetic.

Phase 8 remembers. This module is the first half of Phase 9's answer to the next
question — *what is happening?* — and it is deliberately the half that touches nothing:
the window vocabulary, the counter definitions, the time-bucket arithmetic and the
execution-health ratios. Everything here is pure, so the parts of monitoring that can be
wrong in a subtle way (a boundary hour counted in two buckets, a ratio divided by zero,
a window that silently means something else than it says) are testable without a
database, a clock or a request.

Four decisions are encoded here rather than left to each call site.

**A window is named or it is explicit, never neither.** :class:`MonitoringWindow` holds
the bounded spans this build serves (five minutes to seven days) and ``custom`` for a
caller-supplied range, which is itself bounded by :data:`MAX_CUSTOM_WINDOW`. There is no
open-ended window: "since the beginning" is a query whose cost is decided by how long
the organization has existed, which is exactly the property a monitoring endpoint must
not have.

**Time is the server's.** :func:`resolve_window` takes ``now`` as an argument and never
reads a clock; the routes pass the server's clock. A caller may say *which* interval to
look at, never what time it is — a measurement whose "now" a client can choose is not a
measurement. Timestamps are timezone-aware throughout, and bucketing happens in UTC so a
bucket means the same thing regardless of the database session's ``TimeZone``.

**Zero is a value.** :func:`bucket_starts` returns every bucket in the window, and the
service fills the ones with no events with zeros rather than omitting them. A chart that
cannot tell "no events" from "a gap in the data" is worse than no chart: an absence
would look like missing information instead of a quiet period.

**A rate over nothing is ``None``, never zero.** :class:`ExecutionHealth` returns
``None`` for a success rate when nothing completed, because ``0.0`` would read as "every
execution failed" — the opposite of the truth. See :meth:`ExecutionHealth.success_rate`.

What this module is not: it is not a detector, a scorer or a classifier. It has no
baseline, no threshold and no notion of *normal*; it counts what the audit trail
recorded, in a window, exactly. Nothing here can call an agent suspicious, rank a risk
or open an incident, and no future phase gets that ability by extending this one — an
anomaly engine is a different subject with a different vocabulary, and it will have to
state its own.

The counters below are the *definition* of every metric the API publishes. The
repository builds its SQL from these mappings rather than restating them, so a metric
cannot quietly mean something different from what it is named: adding a counter here is
what makes it appear, and the tests assert the two stay in step.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType

from aicore_api.core.audit import AuditDecision, AuditEventType

__all__ = [
    "ACTION_ACTIVITY_COUNTERS",
    "ACTION_DECISION_COUNTERS",
    "AGENT_ACTIVITY_COUNTERS",
    "DEFAULT_WINDOW",
    "MAX_BUCKETS",
    "MAX_CUSTOM_WINDOW",
    "POLICY_CHANGE_TYPES",
    "SUMMARY_COUNTERS",
    "TREND_COUNTERS",
    "UNSPECIFIED_REASON",
    "ExecutionHealth",
    "MonitoringError",
    "MonitoringWindow",
    "MonitoringWindowError",
    "ResolvedWindow",
    "TimeInterval",
    "bucket_start",
    "bucket_starts",
    "resolve_window",
]


class MonitoringError(ValueError):
    """A monitoring request this build will not answer.

    Raised for a request that is well-formed but meaningless — an inverted range, a
    window longer than this build measures, an interval too fine for the span. The routes
    translate it into a 422 naming the problem, because the alternative (answering with an
    empty or silently-truncated result) would make a mistake look like a quiet period.
    """


class MonitoringWindowError(MonitoringError):
    """A time window that cannot be resolved."""


class MonitoringWindow(StrEnum):
    """The bounded spans this build will measure over, plus an explicit range.

    Five named spans and one escape hatch. The named ones are the spans an operator
    actually asks for while something is happening (``5m``, ``15m``, ``1h``, ``24h``) and
    the one they ask for the morning after (``7d``); ``custom`` exists because an
    investigation has its own edges and forcing it onto a named span would mean reporting
    a *different* window than the one that was asked about.

    There is deliberately no ``all``, no ``forever`` and no ``since=``: every window this
    build serves has a bounded length, and the database is allowed to rely on that.
    """

    FIVE_MINUTES = "5m"
    FIFTEEN_MINUTES = "15m"
    ONE_HOUR = "1h"
    TWENTY_FOUR_HOURS = "24h"
    SEVEN_DAYS = "7d"
    CUSTOM = "custom"


#: How long each named window is. ``custom`` is absent on purpose: its length comes from
#: the caller's timestamps and is checked against :data:`MAX_CUSTOM_WINDOW` instead.
WINDOW_SPANS: Mapping[MonitoringWindow, timedelta] = MappingProxyType(
    {
        MonitoringWindow.FIVE_MINUTES: timedelta(minutes=5),
        MonitoringWindow.FIFTEEN_MINUTES: timedelta(minutes=15),
        MonitoringWindow.ONE_HOUR: timedelta(hours=1),
        MonitoringWindow.TWENTY_FOUR_HOURS: timedelta(hours=24),
        MonitoringWindow.SEVEN_DAYS: timedelta(days=7),
    }
)

#: The window a request gets when it does not name one. A day is the span that answers
#: "what has been happening?" without an operator having to think about it first.
DEFAULT_WINDOW = MonitoringWindow.TWENTY_FOUR_HOURS

#: The longest range an explicit ``start_time``/``end_time`` pair may cover. Thirty days
#: is long enough for a monthly review and short enough that the aggregate stays a
#: single bounded scan of one organization's slice of the trail. A longer history is a
#: reporting job with its own storage, not an interactive query — and saying so here is
#: what keeps "the endpoint got slow" from being discovered in production.
MAX_CUSTOM_WINDOW = timedelta(days=30)

#: What a refusal whose reason cannot be read is counted as, in the denial breakdown.
#: A row written by a data fix, or by a future event type that carries no reason, is still
#: a refusal; dropping it would make the breakdown disagree with the denial count beside it.
UNSPECIFIED_REASON = "unspecified"

#: The most buckets one time-series response may contain. An hour-by-hour series over the
#: longest window this build serves (30 days) would be 720 points, which is a chart nobody
#: reads and a payload nobody needs; the caller is told to ask for days instead. Bounded
#: here rather than in the route so the repository cannot be asked either.
MAX_BUCKETS = 366


class TimeInterval(StrEnum):
    """How finely a time series is bucketed.

    Two values, because two are what a monitoring view is read at: ``hour`` for the day
    an operator is working in, ``day`` for anything longer. A ``minute`` series would
    mostly measure the query, not the activity.
    """

    HOUR = "hour"
    DAY = "day"


#: How long one bucket of each interval lasts.
INTERVAL_SPANS: Mapping[TimeInterval, timedelta] = MappingProxyType(
    {
        TimeInterval.HOUR: timedelta(hours=1),
        TimeInterval.DAY: timedelta(days=1),
    }
)


@dataclass(frozen=True, slots=True)
class ResolvedWindow:
    """A window that has been decided: what it is called, and where it starts and ends.

    Both bounds are inclusive and timezone-aware, and ``end`` is the server's clock at
    the moment the request was handled — which is what makes every number in a response
    attributable to a stated interval instead of to "whenever the query ran".
    """

    name: MonitoringWindow
    start: datetime
    end: datetime

    @property
    def span(self) -> timedelta:
        """How long the window covers. Never negative; the resolver refuses that."""
        return self.end - self.start

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise MonitoringWindowError(
                "a monitoring window is timezone-aware: a naive bound would be interpreted "
                "against whatever the server's locale happens to be"
            )
        if self.end < self.start:
            raise MonitoringWindowError("a monitoring window ends at or after it starts")


def _describe_span(span: timedelta) -> str:
    """A span as a person would read it: whole days, and the leftover hours if any.

    ``timedelta.days`` alone would report a 30-day-and-12-hour range as "30 days", which
    is the one thing a refusal must not do — the caller has to be able to see *why* a range
    was refused, and "covers 30 days" against a limit of 30 days is not an answer.
    """
    hours = span.seconds // 3600
    return f"{span.days} days" if hours == 0 else f"{span.days} days and {hours} hours"


def resolve_window(
    *,
    window: MonitoringWindow | str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    now: datetime | None = None,
) -> ResolvedWindow:
    """Decide which interval a monitoring request is asking about.

    The rules, in one place, so every endpoint answers the same way:

    - no arguments at all → the default named window, ending at ``now``;
    - a named window → that span, ending at ``now``;
    - ``custom`` → ``start_time`` and ``end_time`` are both required, and the span is
      checked against :data:`MAX_CUSTOM_WINDOW`;
    - a bound given *without* ``custom`` is refused rather than merged, because guessing
      what ``window=1h&start_time=…`` means is how a caller ends up looking at a
      different interval than the one they asked about.

    A named window always ends at the clock this function was handed: a caller can choose
    *which* interval to measure — that is what ``custom`` is for — but not what time it
    is, because a measurement whose "now" the client picks is not a measurement of the
    same thing every time it is asked.

    ``now`` is injected rather than read, so this function is a pure function of its
    arguments and a test can place a window exactly where it wants one.
    """
    if window is None:
        window = DEFAULT_WINDOW
    try:
        resolved_name = MonitoringWindow(window)
    except ValueError as exc:
        declared = ", ".join(member.value for member in MonitoringWindow)
        raise MonitoringWindowError(
            f"{window!r} is not a declared window; declared: {declared}"
        ) from exc

    for label, value in (("start_time", start_time), ("end_time", end_time)):
        if value is not None and value.tzinfo is None:
            raise MonitoringWindowError(
                f"{label} must include a timezone (did you mean {value.isoformat()}Z?)"
            )

    if resolved_name is MonitoringWindow.CUSTOM:
        if start_time is None or end_time is None:
            raise MonitoringWindowError(
                "window=custom requires both start_time and end_time: an explicit window "
                "with one open end is an unbounded query"
            )
        if end_time < start_time:
            raise MonitoringWindowError("start_time must not be later than end_time")
        if end_time - start_time > MAX_CUSTOM_WINDOW:
            raise MonitoringWindowError(
                f"a custom window may cover at most {MAX_CUSTOM_WINDOW.days} days; this one "
                f"covers {_describe_span(end_time - start_time)}"
            )
        return ResolvedWindow(name=resolved_name, start=start_time, end=end_time)

    if start_time is not None or end_time is not None:
        raise MonitoringWindowError(
            f"window={resolved_name.value} is a named window and already has bounds; pass "
            "window=custom with start_time and end_time to choose your own"
        )

    if now is None:
        raise MonitoringWindowError(
            "a named window needs the server's clock: pass now, or an explicit window=custom"
        )
    if now.tzinfo is None:
        raise MonitoringWindowError("the server clock must be timezone-aware")
    return ResolvedWindow(
        name=resolved_name,
        start=now - WINDOW_SPANS[resolved_name],
        end=now,
    )


def bucket_start(moment: datetime, interval: TimeInterval) -> datetime:
    """The start of the bucket ``moment`` falls in, aligned to UTC.

    Buckets are half-open intervals ``[start, start + interval)``, floored in UTC rather
    than in the session's timezone: an hour bucket means 10:00-11:00 UTC whatever the
    database or the caller's locale is set to. ``date_trunc`` in SQL does the same
    flooring for the stored rows; this function is the Python half, and a test asserts the
    two agree — including under a session timezone that is not UTC.
    """
    if moment.tzinfo is None:
        raise MonitoringWindowError("bucket_start needs a timezone-aware instant")
    utc = moment.astimezone(UTC)
    if interval is TimeInterval.HOUR:
        return utc.replace(minute=0, second=0, microsecond=0)
    return utc.replace(hour=0, minute=0, second=0, microsecond=0)


def bucket_starts(window: ResolvedWindow, interval: TimeInterval) -> list[datetime]:
    """Every bucket in ``window``, in order, including the ones with no events.

    The first bucket is the one containing ``window.start`` and the last is the one
    containing ``window.end``, so the series covers the whole window and nothing outside
    it. The count is bounded by :data:`MAX_BUCKETS`, and a request that would exceed it is
    refused with the interval it should have asked for instead.
    """
    span = INTERVAL_SPANS[interval]
    first = bucket_start(window.start, interval)
    last = bucket_start(window.end, interval)
    count = int((last - first) / span) + 1
    if count > MAX_BUCKETS:
        alternative = TimeInterval.DAY if interval is TimeInterval.HOUR else None
        hint = (
            f"ask for interval={alternative.value} instead"
            if alternative is not None
            else "shorten the window"
        )
        raise MonitoringWindowError(
            f"{interval.value} buckets over this window would be {count} points, and at "
            f"most {MAX_BUCKETS} are served; {hint}"
        )
    return [first + span * index for index in range(count)]


@dataclass(frozen=True, slots=True)
class ExecutionHealth:
    """How the actions that ran in a window ended: a count of both, and two ratios.

    Only *completed* executions are in the denominator. A request that was refused never
    ran, and counting it as a failure would report the firewall's refusals as an
    execution problem; a request that was replayed was answered from the ledger and did
    not execute either. The two counters here are exactly ``action.executed`` and
    ``action.failed``.
    """

    succeeded: int
    failed: int

    @property
    def completed(self) -> int:
        """How many executions reached an end — the denominator of both rates."""
        return self.succeeded + self.failed

    @property
    def success_rate(self) -> float | None:
        """The share of completed executions that succeeded, or ``None`` if none completed.

        ``None`` rather than ``0.0``: with nothing to divide by, a zero would read as
        "every execution failed", which is the opposite of what happened. A caller
        renders null as "no executions", and that is a different statement from "all of
        them failed" — which is why the two are not allowed to look alike.
        """
        if self.completed == 0:
            return None
        return round(self.succeeded / self.completed, 6)

    @property
    def failure_rate(self) -> float | None:
        """The share of completed executions that failed. Always ``1 - success_rate``."""
        if self.completed == 0:
            return None
        return round(self.failed / self.completed, 6)


# ── What each metric counts ───────────────────────────────────────────────────
#
# Every counter is an event type (or a set of them) from Phase 8's closed vocabulary —
# never a new fact, never a reinterpretation of an existing one. ``action.denied`` means
# what Phase 8 made it mean: the request was refused and nothing ran. Monitoring adds
# arithmetic, not semantics.

ACTION_REQUESTED = AuditEventType.ACTION_REQUESTED
ACTION_DENIED = AuditEventType.ACTION_DENIED
ACTION_REQUIRE_APPROVAL = AuditEventType.ACTION_REQUIRE_APPROVAL
ACTION_EXECUTED = AuditEventType.ACTION_EXECUTED
ACTION_FAILED = AuditEventType.ACTION_FAILED
ACTION_REPLAYED = AuditEventType.ACTION_REPLAYED

#: The summary's counters, in the order the API publishes them. Each maps to the event
#: types it counts, so "action_denials" cannot come to mean something else by accident —
#: changing what a metric counts means editing this table.
SUMMARY_COUNTERS: Mapping[str, tuple[AuditEventType, ...]] = MappingProxyType(
    {
        "action_requests": (ACTION_REQUESTED,),
        "action_executions": (ACTION_EXECUTED,),
        "action_failures": (ACTION_FAILED,),
        "action_denials": (ACTION_DENIED,),
        "action_replays": (ACTION_REPLAYED,),
        "approval_required": (ACTION_REQUIRE_APPROVAL,),
        "asset_creations": (AuditEventType.ASSET_CREATED,),
        "asset_updates": (AuditEventType.ASSET_UPDATED,),
        "asset_deletions": (AuditEventType.ASSET_DELETED,),
        "asset_discoveries": (AuditEventType.ASSET_DISCOVERED,),
        "agent_registrations": (AuditEventType.AGENT_REGISTERED,),
        "agent_updates": (AuditEventType.AGENT_UPDATED,),
        "agent_deletions": (AuditEventType.AGENT_DELETED,),
        "policy_creations": (AuditEventType.POLICY_CREATED,),
        "policy_updates": (AuditEventType.POLICY_UPDATED,),
        "policy_version_publications": (AuditEventType.POLICY_VERSION_PUBLISHED,),
        "policy_status_changes": (AuditEventType.POLICY_STATUS_CHANGED,),
        "policy_deletions": (AuditEventType.POLICY_DELETED,),
    }
)

#: What "a policy changed" means, as one number: the five lifecycle events above. A
#: derived counter rather than an event type, so it cannot drift from its parts.
POLICY_CHANGE_TYPES: tuple[AuditEventType, ...] = (
    AuditEventType.POLICY_CREATED,
    AuditEventType.POLICY_UPDATED,
    AuditEventType.POLICY_VERSION_PUBLISHED,
    AuditEventType.POLICY_STATUS_CHANGED,
    AuditEventType.POLICY_DELETED,
)

#: Per-action counters. ``allowed`` is not among them because it is not an event type:
#: it counts rows whose ``decision`` is ``allow``, which is how Phase 7 records a request
#: that got past the firewall — see :data:`ACTION_DECISION_COUNTERS`.
ACTION_ACTIVITY_COUNTERS: Mapping[str, tuple[AuditEventType, ...]] = MappingProxyType(
    {
        "requested": (ACTION_REQUESTED,),
        "denied": (ACTION_DENIED,),
        "approval_required": (ACTION_REQUIRE_APPROVAL,),
        "executed": (ACTION_EXECUTED,),
        "failed": (ACTION_FAILED,),
        "replayed": (ACTION_REPLAYED,),
    }
)

#: The decision axis of the action pipeline, per action: every row Phase 7 wrote after a
#: decision carries one. ``allowed`` therefore equals ``executed + failed + replayed``
#: under the current vocabulary, and a test asserts exactly that — if a future outcome
#: stops carrying ``allow``, the equality breaks loudly instead of the number silently
#: changing meaning.
ACTION_DECISION_COUNTERS: Mapping[str, AuditDecision] = MappingProxyType(
    {"allowed": AuditDecision.ALLOW}
)

#: Per-agent counters. ``events`` is every event attributed to the agent, whichever
#: event type it is, and the rest are the same action-pipeline states the per-action view
#: counts — seen from the agent's side, which is the question "what did *this* agent do?".
AGENT_ACTIVITY_COUNTERS: Mapping[str, tuple[AuditEventType, ...]] = MappingProxyType(
    {
        #: Every event type: an agent attributed to any of them has activity in this
        #: window. Spelled as the whole vocabulary rather than "no filter" so that adding
        #: an event type cannot leave this counter behind.
        "events": tuple(AuditEventType),
        "action_requests": (ACTION_REQUESTED,),
        "executions": (ACTION_EXECUTED,),
        "failures": (ACTION_FAILED,),
        "denials": (ACTION_DENIED,),
        "approval_required": (ACTION_REQUIRE_APPROVAL,),
        "replays": (ACTION_REPLAYED,),
    }
)

#: The series a time-series response carries, per bucket. A subset of the summary's
#: action counters: the ones that describe a decision over time, which is what a trend
#: line is read for. Lifecycle counters are deliberately absent — "assets created per
#: hour" is inventory reporting, and the summary already answers it for the window.
TREND_COUNTERS: Mapping[str, tuple[AuditEventType, ...]] = MappingProxyType(
    {
        "action_requests": (ACTION_REQUESTED,),
        "action_executions": (ACTION_EXECUTED,),
        "action_failures": (ACTION_FAILED,),
        "action_denials": (ACTION_DENIED,),
        "approval_required": (ACTION_REQUIRE_APPROVAL,),
    }
)
