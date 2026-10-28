"""The arithmetic of monitoring, without a database: windows, buckets and rates.

Phase 9's numbers come from PostgreSQL, but its *decisions* do not: which interval a
request is asking about, which bucket an instant belongs to, and what a success rate means
when nothing ran. Those are the parts that can be wrong in a way no integration test would
catch — an off-by-one bucket boundary, a window silently one span wide, a ratio that reads
as "everything failed" because the denominator was empty — so they are tested here, as
pure functions, with no engine, no session and no clock.

Time is an argument everywhere in this suite. ``NOW`` is fixed, ``end`` is derived from it
and the assertions compare instants rather than moments, which is what makes a test about
"the last hour" mean the same thing tomorrow.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta, timezone

import pytest

from aicore_api.core.monitoring import (
    DEFAULT_WINDOW,
    MAX_BUCKETS,
    MAX_CUSTOM_WINDOW,
    WINDOW_SPANS,
    ExecutionHealth,
    MonitoringWindow,
    MonitoringWindowError,
    ResolvedWindow,
    TimeInterval,
    bucket_start,
    bucket_starts,
    resolve_window,
)

#: The instant every test in this file measures from. A Thursday afternoon in UTC, chosen
#: so that a window spanning days crosses a month boundary and a local-time bug would be
#: visible rather than accidentally correct.
NOW = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)

#: A zone half an hour off UTC, on the other side of the date line from a UTC day start:
#: 04:30 on the 25th here is 23:00 on the 24th in UTC, which is the case that catches
#: bucketing done in local time.
IST = timezone(timedelta(hours=5, minutes=30))


def _window(start: datetime, end: datetime) -> ResolvedWindow:
    """A window built by hand, for the bucket tests."""
    return ResolvedWindow(name=MonitoringWindow.CUSTOM, start=start, end=end)


# ── Windows ───────────────────────────────────────────────────────────────────


def test_every_named_window_declares_a_bounded_span() -> None:
    """Five named spans, all positive, and ``custom`` deliberately without one."""
    named = {member for member in MonitoringWindow if member is not MonitoringWindow.CUSTOM}
    assert set(WINDOW_SPANS) == named
    assert all(span > timedelta(0) for span in WINDOW_SPANS.values())
    assert MonitoringWindow.CUSTOM not in WINDOW_SPANS


def test_the_declared_windows_are_the_ones_the_api_documents() -> None:
    assert [member.value for member in MonitoringWindow] == [
        "5m",
        "15m",
        "1h",
        "24h",
        "7d",
        "custom",
    ]
    assert WINDOW_SPANS[MonitoringWindow.FIVE_MINUTES] == timedelta(minutes=5)
    assert WINDOW_SPANS[MonitoringWindow.SEVEN_DAYS] == timedelta(days=7)


def test_the_default_window_is_the_bounded_day() -> None:
    assert DEFAULT_WINDOW is MonitoringWindow.TWENTY_FOUR_HOURS
    assert resolve_window(now=NOW) == resolve_window(window=DEFAULT_WINDOW, now=NOW)


@pytest.mark.parametrize("name", ["5m", "15m", "1h", "24h", "7d"])
def test_a_named_window_ends_at_the_server_clock_and_starts_one_span_earlier(name: str) -> None:
    window = resolve_window(window=name, now=NOW)
    span = WINDOW_SPANS[MonitoringWindow(name)]
    assert window.name == MonitoringWindow(name)
    assert window.end == NOW
    assert window.start == NOW - span
    assert window.span == span


def test_a_window_may_be_named_by_its_value_or_by_its_member() -> None:
    """FastAPI hands over the enum; a test or a caller writes the string."""
    assert resolve_window(window=MonitoringWindow.FIVE_MINUTES, now=NOW) == resolve_window(
        window="5m", now=NOW
    )


def test_an_undeclared_window_is_refused_and_lists_the_declared_ones() -> None:
    with pytest.raises(MonitoringWindowError) as raised:
        resolve_window(window="30d", now=NOW)
    message = str(raised.value)
    assert "30d" in message
    assert "5m" in message and "7d" in message and "custom" in message


def test_a_named_window_needs_a_clock_to_end_at() -> None:
    """Without ``now`` there is no way to say when the window ended, so it is refused."""
    with pytest.raises(MonitoringWindowError, match="server's clock"):
        resolve_window(window="1h")


def test_a_naive_clock_is_refused() -> None:
    with pytest.raises(MonitoringWindowError, match="timezone-aware"):
        resolve_window(window="1h", now=NOW.replace(tzinfo=None))


@pytest.mark.parametrize("field", ["start_time", "end_time"])
def test_a_naive_bound_is_refused_whoever_asks(field: str) -> None:
    """A client timestamp without a zone would be read against the server's locale."""
    bounds: dict[str, datetime] = {
        "start_time": NOW - timedelta(hours=1),
        "end_time": NOW,
    }
    bounds[field] = bounds[field].replace(tzinfo=None)
    with pytest.raises(MonitoringWindowError, match="include a timezone"):
        resolve_window(window="custom", **bounds)
    # …and the same bound on a *named* window is refused, for the same reason, before the
    # named-window rule below even applies.
    with pytest.raises(MonitoringWindowError, match="include a timezone"):
        resolve_window(window="1h", **bounds, now=NOW)


@pytest.mark.parametrize("missing", ["start_time", "end_time"])
def test_custom_requires_both_bounds(missing: str) -> None:
    """One open end is an unbounded query wearing a window's clothes."""
    bounds: dict[str, datetime | None] = {"start_time": NOW - timedelta(hours=1), "end_time": NOW}
    bounds[missing] = None
    with pytest.raises(MonitoringWindowError, match="requires both"):
        resolve_window(window="custom", **bounds)


def test_an_inverted_custom_range_is_refused() -> None:
    with pytest.raises(MonitoringWindowError, match="not be later"):
        resolve_window(window="custom", start_time=NOW, end_time=NOW - timedelta(microseconds=1))


def test_a_custom_window_of_zero_length_is_allowed() -> None:
    """A degenerate range is a legitimate question ("this instant"); it is not inverted."""
    window = resolve_window(window="custom", start_time=NOW, end_time=NOW)
    assert window.span == timedelta(0)


def test_a_custom_window_is_bounded_at_thirty_days() -> None:
    at_the_limit = resolve_window(window="custom", start_time=NOW - MAX_CUSTOM_WINDOW, end_time=NOW)
    assert at_the_limit.span == MAX_CUSTOM_WINDOW
    with pytest.raises(MonitoringWindowError, match="at most 30 days"):
        resolve_window(
            window="custom",
            start_time=NOW - MAX_CUSTOM_WINDOW - timedelta(seconds=1),
            end_time=NOW,
        )


def test_a_named_window_refuses_bounds_rather_than_guessing_what_they_mean() -> None:
    """``window=1h&start_time=…`` has two answers and this build refuses to pick one."""
    both = {"start_time": NOW - timedelta(minutes=5), "end_time": NOW}
    with pytest.raises(MonitoringWindowError, match="already has bounds"):
        resolve_window(window="1h", **both, now=NOW)
    with pytest.raises(MonitoringWindowError, match="already has bounds"):
        resolve_window(window="1h", start_time=NOW - timedelta(minutes=5), now=NOW)
    with pytest.raises(MonitoringWindowError, match="already has bounds"):
        resolve_window(window="1h", end_time=NOW - timedelta(minutes=5), now=NOW)


def test_a_resolved_window_refuses_naive_bounds() -> None:
    with pytest.raises(MonitoringWindowError, match="timezone-aware"):
        ResolvedWindow(name=MonitoringWindow.ONE_HOUR, start=NOW.replace(tzinfo=None), end=NOW)


def test_a_resolved_window_refuses_an_inverted_range() -> None:
    with pytest.raises(MonitoringWindowError, match="ends at or after"):
        ResolvedWindow(name=MonitoringWindow.ONE_HOUR, start=NOW, end=NOW - timedelta(seconds=1))


def test_a_resolved_window_states_the_same_instant_whatever_zone_it_is_read_in() -> None:
    """Bounds are compared as instants, not as renderings: the same moment is one moment."""
    local_start = (NOW - timedelta(hours=1)).astimezone(IST)
    window = _window(local_start, NOW.astimezone(IST))
    assert window.start == NOW - timedelta(hours=1)
    assert window.end == NOW
    assert window.span == timedelta(hours=1)


# ── Buckets ───────────────────────────────────────────────────────────────────


def test_bucket_start_floors_in_utc_not_in_the_local_calendar() -> None:
    """04:30 in Kolkata is 23:00 the previous day in UTC — and that is its bucket."""
    local = datetime(2026, 9, 25, 4, 30, tzinfo=IST)
    assert local.astimezone(UTC) == datetime(2026, 9, 24, 23, 0, tzinfo=UTC)
    assert bucket_start(local, TimeInterval.HOUR) == datetime(2026, 9, 24, 23, 0, tzinfo=UTC)
    assert bucket_start(local, TimeInterval.DAY) == datetime(2026, 9, 24, 0, 0, tzinfo=UTC)


def test_a_bucket_start_is_returned_in_utc() -> None:
    assert bucket_start(datetime(2026, 9, 25, 10, 0, tzinfo=IST), TimeInterval.HOUR).tzinfo == UTC


def test_the_last_instant_of_a_bucket_belongs_to_it() -> None:
    """Buckets are half-open: 10:59:59.999999 is still the ten o'clock hour."""
    hour = datetime(2026, 9, 25, 10, 0, tzinfo=UTC)
    assert bucket_start(hour, TimeInterval.HOUR) == hour
    last_instant = hour + timedelta(hours=1) - timedelta(microseconds=1)
    assert bucket_start(last_instant, TimeInterval.HOUR) == hour
    assert bucket_start(hour + timedelta(hours=1), TimeInterval.HOUR) == hour + timedelta(hours=1)


def test_a_day_bucket_start_is_midnight_utc() -> None:
    moment = datetime(2026, 9, 25, 23, 59, 59, 999999, tzinfo=UTC)
    assert bucket_start(moment, TimeInterval.DAY) == datetime(2026, 9, 25, tzinfo=UTC)


def test_bucket_start_refuses_a_naive_instant() -> None:
    with pytest.raises(MonitoringWindowError, match="timezone-aware"):
        bucket_start(datetime(2026, 9, 25, 10, 0), TimeInterval.HOUR)


def test_bucket_starts_covers_the_window_from_the_bucket_containing_its_start() -> None:
    window = _window(
        datetime(2026, 9, 25, 10, 5, tzinfo=UTC), datetime(2026, 9, 25, 13, 20, tzinfo=UTC)
    )
    starts = bucket_starts(window, TimeInterval.HOUR)
    assert starts == [datetime(2026, 9, 25, hour, 0, tzinfo=UTC) for hour in (10, 11, 12, 13)]
    assert starts[0] <= window.start
    assert window.end < starts[-1] + timedelta(hours=1)


def test_the_buckets_are_contiguous_to_the_microsecond() -> None:
    """No instant inside the window can fall between two buckets, or be counted twice."""
    window = _window(NOW - timedelta(hours=5), NOW)
    starts = bucket_starts(window, TimeInterval.HOUR)
    assert all(
        later - earlier == timedelta(hours=1) for earlier, later in itertools.pairwise(starts)
    )


def test_a_series_over_a_day_boundary_keeps_every_bucket() -> None:
    """A 24h window is 25 hourly buckets, and the day boundary is not a special case."""
    window = _window(NOW - timedelta(hours=24), NOW)
    starts = bucket_starts(window, TimeInterval.HOUR)
    assert len(starts) == 25
    assert starts[0] == bucket_start(NOW - timedelta(hours=24), TimeInterval.HOUR)
    assert starts[-1] == bucket_start(NOW, TimeInterval.HOUR)


def test_a_zero_length_window_measures_exactly_one_bucket() -> None:
    """The one bucket containing the instant, whatever the interval — never zero buckets."""
    window = _window(NOW, NOW)
    for interval in TimeInterval:
        assert bucket_starts(window, interval) == [bucket_start(NOW, interval)]


def test_an_hourly_series_too_fine_for_its_window_is_refused_with_what_to_ask_for() -> None:
    window = _window(NOW - timedelta(days=30), NOW)
    with pytest.raises(MonitoringWindowError, match="interval=day"):
        bucket_starts(window, TimeInterval.HOUR)
    assert len(bucket_starts(window, TimeInterval.DAY)) == 31


def test_the_bucket_ceiling_is_exact() -> None:
    """The limit is a stated number of points, inclusive at the boundary."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    at_the_limit = _window(start, start + timedelta(days=365))
    assert len(bucket_starts(at_the_limit, TimeInterval.DAY)) == MAX_BUCKETS == 366
    over_the_limit = _window(start, start + timedelta(days=366))
    with pytest.raises(MonitoringWindowError, match="shorten the window"):
        bucket_starts(over_the_limit, TimeInterval.DAY)


def test_the_longest_window_the_build_serves_fits_a_daily_series() -> None:
    """Every window ``resolve_window`` can return is representable as a time series."""
    window = resolve_window(window="custom", start_time=NOW - MAX_CUSTOM_WINDOW, end_time=NOW)
    assert len(bucket_starts(window, TimeInterval.DAY)) <= MAX_BUCKETS


# ── Execution health ──────────────────────────────────────────────────────────


def test_health_rates_are_over_completed_executions() -> None:
    health = ExecutionHealth(succeeded=7, failed=1)
    assert health.completed == 8
    assert health.success_rate == 0.875
    assert health.failure_rate == 0.125


def test_health_rates_are_none_when_nothing_completed_and_never_zero() -> None:
    """``0.0`` would read as "every execution failed" — the opposite of "none ran"."""
    health = ExecutionHealth(succeeded=0, failed=0)
    assert health.completed == 0
    assert health.success_rate is None
    assert health.failure_rate is None


def test_a_window_with_only_failures_reports_a_zero_success_rate() -> None:
    """Which is a different statement from the one above, and is allowed to look different."""
    health = ExecutionHealth(succeeded=0, failed=3)
    assert health.success_rate == 0.0
    assert health.failure_rate == 1.0


def test_the_two_rates_are_complementary_for_every_combination() -> None:
    for succeeded in range(0, 26):
        for failed in range(0, 26):
            health = ExecutionHealth(succeeded=succeeded, failed=failed)
            if health.completed == 0:
                assert health.success_rate is None and health.failure_rate is None
                continue
            assert health.success_rate == round(succeeded / health.completed, 6)
            assert health.failure_rate == round(failed / health.completed, 6)
            # Both are rounded to six places, so the sum is 1 up to the rounding of each.
            assert abs(health.success_rate + health.failure_rate - 1.0) <= 1e-6


def test_health_counts_serialize_as_they_are_named() -> None:
    """The dataclass is what the schema copies, so the two cannot disagree on a field name."""
    assert set(ExecutionHealth.__dataclass_fields__) == {"succeeded", "failed"}
