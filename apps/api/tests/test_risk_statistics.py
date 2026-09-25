"""Phase 10 statistics and cold start: exact, explainable, and never fabricated.

Pure tests of :func:`aicore_api.core.risk.baseline_statistics` and of the cold-start rules
in :func:`aicore_api.core.risk.analyze_agent`. No database.
"""

from __future__ import annotations

import math
import statistics as reference
import uuid
from datetime import UTC, datetime

import pytest

from aicore_api.core.risk import (
    MIN_ACTIVE_SLOTS,
    MIN_BASELINE_EVENTS,
    MIN_HISTORY_SLOTS,
    AgentProfile,
    AnalysisStatus,
    AnomalyState,
    CheckReason,
    CheckStatus,
    DetectionType,
    InsufficientReason,
    RiskError,
    RiskLevel,
    analyze_agent,
    baseline_statistics,
    resolve_analysis_windows,
)

AGENT = uuid.UUID("00000000-0000-4000-8000-000000000001")
NOW = datetime(2026, 9, 25, 10, tzinfo=UTC)
DAILY = resolve_analysis_windows(baseline="14d", observation="24h", now=NOW)  # 14 slots
HOURLY = resolve_analysis_windows(baseline="7d", observation="1h", now=NOW)  # 168 slots


def _sums(counts: list[int]) -> tuple[int, int]:
    return sum(counts), sum(count * count for count in counts)


# ── baseline_statistics ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "counts",
    [[3] * 14, [1, 2, 3, 4, 5], [0, 0, 10, 0, 0, 0, 0], [7, 9, 8, 12, 3, 4, 5, 6, 10, 11], [1]],
)
def test_mean_and_population_stddev_match_the_reference(counts: list[int]) -> None:
    events, squares = _sums(counts)
    result = baseline_statistics(events=events, sum_squares=squares, history_slots=len(counts))

    assert result.mean == pytest.approx(reference.fmean(counts), abs=1e-6)
    assert result.stddev == pytest.approx(reference.pstdev(counts), abs=1e-6)
    assert result.events == events
    assert result.history_slots == len(counts)


def test_zero_variance_is_an_exact_equality_not_a_tiny_float() -> None:
    events, squares = _sums([5] * 30)
    result = baseline_statistics(events=events, sum_squares=squares, history_slots=30)
    assert result.stddev == 0.0
    assert result.zero_variance is True


def test_large_equal_counts_still_have_exactly_zero_variance() -> None:
    # Floating-point E[x^2] - E[x]^2 would wobble here; integer arithmetic does not.
    count = 1_000_003
    events, squares = _sums([count] * 720)
    result = baseline_statistics(events=events, sum_squares=squares, history_slots=720)
    assert result.stddev == 0.0
    assert result.mean == float(count)


def test_empty_slots_are_zeros_and_lower_the_mean() -> None:
    """Slots with no requests are part of the history: missing data is not ignored."""
    busy = baseline_statistics(events=28, sum_squares=28 * 4, history_slots=7)  # 4 per slot
    sparse = baseline_statistics(events=28, sum_squares=28 * 4, history_slots=14)  # 4 or 0
    assert busy.mean == 4.0 and busy.zero_variance
    assert sparse.mean == 2.0 and sparse.stddev == 2.0


def test_results_are_rounded_and_deterministic() -> None:
    first = baseline_statistics(events=10, sum_squares=38, history_slots=3)
    second = baseline_statistics(events=10, sum_squares=38, history_slots=3)
    assert first == second
    assert first.mean == round(10 / 3, 6)
    assert all(math.isfinite(value) for value in (first.mean, first.stddev))


@pytest.mark.parametrize(
    ("events", "squares", "slots"),
    [(0, 0, 0), (5, 25, -1), (-1, 1, 3), (3, -1, 3), (10, 10, 2)],
)
def test_impossible_inputs_are_refused(events: int, squares: int, slots: int) -> None:
    with pytest.raises(RiskError):
        baseline_statistics(events=events, sum_squares=squares, history_slots=slots)


# ── cold start ────────────────────────────────────────────────────────────────


def _profile(**fields: object) -> AgentProfile:
    return AgentProfile(agent_id=AGENT, **fields)  # type: ignore[arg-type]


def _steady(per_slot: int, *, slots: int = 14, first: int = 0, **fields: object) -> AgentProfile:
    active = slots - first
    return _profile(
        baseline_requests=per_slot * active,
        baseline_sum_squares=per_slot * per_slot * active,
        first_active_slot=first,
        active_slots=active,
        **fields,
    )


def _assert_undetermined(result: object, *reasons: InsufficientReason) -> None:
    analysis = result
    assert analysis.status is AnalysisStatus.INSUFFICIENT_HISTORY  # type: ignore[attr-defined]
    assert analysis.anomaly_state is AnomalyState.UNDETERMINED  # type: ignore[attr-defined]
    assert analysis.risk_level is RiskLevel.NONE  # type: ignore[attr-defined]
    assert analysis.risk_factors == ()  # type: ignore[attr-defined]
    assert analysis.detections == ()  # type: ignore[attr-defined]
    assert analysis.statistics is None  # type: ignore[attr-defined]
    assert set(analysis.insufficient_reasons) == set(reasons)  # type: ignore[attr-defined]
    for check in analysis.checks:  # type: ignore[attr-defined]
        assert check.status is CheckStatus.NOT_EVALUATED
        assert check.reason is CheckReason.ENTITY_HISTORY_INSUFFICIENT
    assert {check.detection_type for check in analysis.checks} == set(DetectionType)  # type: ignore[attr-defined]


def test_a_brand_new_agent_is_undetermined_even_when_its_observation_is_extreme() -> None:
    """Never anomalous for lack of history: a new agent doing a lot is not a spike."""
    profile = _profile(
        observed_requests=5_000,
        observed_denials=4_000,
        observed_peak=900,
        novel_action_count=3,
        novel_actions=("a.b", "c.d", "e.f"),
        observed_distinct_actions=3,
        observed_hours=(100,) * 24,
    )
    _assert_undetermined(analyze_agent(profile, DAILY), InsufficientReason.NO_BASELINE_ACTIVITY)


def test_too_few_baseline_events_is_insufficient() -> None:
    profile = _profile(
        baseline_requests=MIN_BASELINE_EVENTS - 1,
        baseline_sum_squares=MIN_BASELINE_EVENTS - 1,
        first_active_slot=0,
        active_slots=MIN_BASELINE_EVENTS - 1,
    )
    result = analyze_agent(profile, HOURLY)
    _assert_undetermined(result, InsufficientReason.BASELINE_EVENTS_BELOW_MINIMUM)


def test_history_that_started_too_recently_is_insufficient() -> None:
    # Busy, but only in the last 3 daily slots: fewer than MIN_HISTORY_SLOTS.
    profile = _steady(20, first=14 - 3)
    _assert_undetermined(
        analyze_agent(profile, DAILY), InsufficientReason.HISTORY_SPAN_BELOW_MINIMUM
    )


def test_seven_hourly_slots_are_still_less_than_a_day_of_history() -> None:
    """The span rule is in time as well as slots: 7 hours is not a baseline."""
    profile = _steady(5, slots=168, first=168 - MIN_HISTORY_SLOTS)
    _assert_undetermined(
        analyze_agent(profile, HOURLY), InsufficientReason.HISTORY_SPAN_BELOW_MINIMUM
    )


def test_activity_in_too_few_slots_is_insufficient() -> None:
    profile = _profile(
        baseline_requests=100,
        baseline_sum_squares=50 * 50 * 2,
        first_active_slot=0,
        active_slots=MIN_ACTIVE_SLOTS - 1,
    )
    _assert_undetermined(
        analyze_agent(profile, DAILY), InsufficientReason.ACTIVE_SLOTS_BELOW_MINIMUM
    )


def test_every_unmet_rule_is_reported_not_just_the_first() -> None:
    profile = _profile(
        baseline_requests=4, baseline_sum_squares=8, first_active_slot=12, active_slots=2
    )
    _assert_undetermined(
        analyze_agent(profile, DAILY),
        InsufficientReason.BASELINE_EVENTS_BELOW_MINIMUM,
        InsufficientReason.HISTORY_SPAN_BELOW_MINIMUM,
        InsufficientReason.ACTIVE_SLOTS_BELOW_MINIMUM,
    )


def test_exactly_the_minimum_history_is_analyzed() -> None:
    # 21 events over the last 7 daily slots, 3 in each: every rule exactly met or just over.
    profile = _steady(3, first=14 - MIN_HISTORY_SLOTS, observed_requests=3)
    assert profile.baseline_requests == MIN_BASELINE_EVENTS + 1
    result = analyze_agent(profile, DAILY)
    assert result.status is AnalysisStatus.ANALYZED
    assert result.statistics is not None
    assert result.statistics.history_slots == MIN_HISTORY_SLOTS


def test_history_is_counted_from_first_activity_not_from_the_window_start() -> None:
    """A baseline is never padded with slots before the entity existed."""
    profile = _steady(4, first=4, observed_requests=4)
    result = analyze_agent(profile, DAILY)
    assert result.statistics is not None
    assert result.statistics.history_slots == 10
    assert result.statistics.mean == 4.0
    assert result.statistics.zero_variance


def test_a_sufficient_quiet_agent_is_not_anomalous_and_has_no_level() -> None:
    result = analyze_agent(_steady(3, observed_requests=3), DAILY)
    assert result.status is AnalysisStatus.ANALYZED
    assert result.anomaly_state is AnomalyState.NOT_ANOMALOUS
    assert result.risk_level is RiskLevel.NONE
    assert result.risk_factors == ()
    assert result.insufficient_reasons == ()


def test_profiles_refuse_malformed_hour_profiles_and_oversized_samples() -> None:
    with pytest.raises(ValueError, match="24 entries"):
        _profile(baseline_hours=(0,) * 23)
    with pytest.raises(ValueError, match="at most"):
        _profile(novel_action_count=20, novel_actions=tuple(f"a.a{i}" for i in range(17)))
    with pytest.raises(ValueError, match="larger than"):
        _profile(novel_action_count=1, novel_actions=("a.b", "c.d"))
