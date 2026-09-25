"""The arithmetic underneath an assessment, checked against hand-computed answers.

Every test here states its inputs and its expected number explicitly. No fixture, no
database, no clock: this is the part of the engine whose correctness can be settled with
paper, and if it is wrong then every conclusion built on it is wrong in a way no API test
would notice.

The cases that matter most are the degenerate ones, because they are where a detector
usually lies. An empty baseline has a mean of zero and a spread of zero, and a naive
implementation divides by that spread and reports an infinite deviation — so this suite
asserts that an empty distribution is refused rather than extrapolated, that a single
sample has no spread rather than an invented one, and that a zero-width baseline cannot be
left either by a fraction of an event.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest

from aicore_api.core.monitoring import MonitoringWindow
from aicore_api.core.risk import (
    DEFAULT_PARAMETERS,
    MAX_BASELINE_WINDOW,
    MIN_BASELINE_BUCKETS,
    ActivityFrame,
    AssessmentStatus,
    Baseline,
    BaselineWindow,
    BucketCounts,
    DetectionParameters,
    DetectionType,
    DimensionStatus,
    InsufficiencyReason,
    RiskLevel,
    RiskMetric,
    RiskThresholdError,
    RiskWindowError,
    WindowTotals,
    assess_risk_level,
    deviation_is_extreme,
    hour_bucket,
    is_full_bucket,
    mean,
    population_stddev,
    resolve_baseline,
    resolve_observation,
)

#: A fixed instant for every baseline assertion, so "seven days before" is arithmetic
#: rather than whatever the wall clock said when the test ran.
NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)


# ── Descriptive statistics ───────────────────────────────────────────────────


def test_mean_of_nothing_is_zero_not_undefined() -> None:
    """An empty sample has no mean, and the engine states that as zero.

    Zero is the only value that cannot be mistaken for a measurement later: every
    dimension that could be misled by it checks the sample count first, so ``mean([])``
    being 0.0 is a defined placeholder rather than a silent claim about the data.
    """
    assert mean([]) == 0.0
    assert mean([4.0]) == 4.0
    assert mean([1.0, 2.0, 3.0, 4.0]) == 2.5


def test_population_stddev_of_a_single_sample_is_zero() -> None:
    """One sample has no spread. ``statistics.stdev`` would raise; the engine says zero."""
    assert population_stddev([7.0]) == 0.0
    assert population_stddev([]) == 0.0


def test_population_stddev_is_the_population_definition() -> None:
    """The spread is over the samples themselves, not an estimate of a wider population.

    ``[2, 4, 4, 4, 5, 5, 7, 9]`` has a mean of 5 and a *population* standard deviation of
    exactly 2. The sample standard deviation would be about 2.138 — a different number, and
    a different bound, which is why the definition is asserted rather than assumed.
    """
    assert population_stddev([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]) == 2.0


def test_identical_samples_have_no_spread() -> None:
    """A perfectly steady baseline has a zero-width interval — handled, not divided by."""
    assert population_stddev([6.0] * 50) == 0.0


# ── The level table ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("strong", "weak", "extreme", "expected"),
    [
        # The strongest row first: three mutually corroborating strong factors with an
        # extreme one among them.
        (3, 0, True, RiskLevel.CRITICAL),
        (4, 1, True, RiskLevel.CRITICAL),
        # Without the extreme member, the same three factors stop at HIGH.
        (3, 0, False, RiskLevel.HIGH),
        (2, 0, False, RiskLevel.HIGH),
        (2, 3, False, RiskLevel.HIGH),
        # One strong factor is corroboration for another, or for a first-use factor.
        (1, 1, True, RiskLevel.HIGH),
        (1, 1, False, RiskLevel.MEDIUM),
        (1, 0, True, RiskLevel.MEDIUM),
        (1, 0, False, RiskLevel.LOW),
        # Two weak factors are two first uses, which is more than one but not a rate.
        (0, 2, False, RiskLevel.MEDIUM),
        (0, 2, True, RiskLevel.MEDIUM),
        (0, 1, False, RiskLevel.LOW),
        (0, 0, False, RiskLevel.NONE),
    ],
)
def test_level_table_is_total_and_publishes_its_rows(
    strong: int, weak: int, extreme: bool, expected: RiskLevel
) -> None:
    """Every combination of factor counts maps to exactly one level.

    The table is the whole of the risk-level method: there is no score, no weighting and no
    arithmetic between counts and labels. Each row here is a row of ``LEVEL_RULES``, so the
    test fails if a rule is reordered as well as if one is changed.
    """
    assert assess_risk_level(strong=strong, weak=weak, extreme=extreme) is expected


def test_no_factors_is_no_level() -> None:
    """Nothing found is ``none`` — not ``low``. An absence of evidence is not a finding."""
    assert assess_risk_level(strong=0, weak=0, extreme=False) is RiskLevel.NONE


def test_extremity_needs_a_bound_and_a_mean_to_compare() -> None:
    """A spike is extreme when it is at least a multiple past the bound; a drop when below.

    Both comparisons are refused when there is nothing to divide or compare: a mean of zero
    has no "half of it", and a zero bound means the baseline had no spread to cross.
    """
    parameters = DEFAULT_PARAMETERS
    assert deviation_is_extreme(
        detection_type=DetectionType.ACTION_RATE_SPIKE,
        observed=40.0,
        baseline_mean=10.0,
        upper_bound=13.0,
        parameters=parameters,
    )
    assert not deviation_is_extreme(
        detection_type=DetectionType.ACTION_RATE_SPIKE,
        observed=30.0,  # above the bound (13) but not 3x past it (39)
        baseline_mean=10.0,
        upper_bound=13.0,
        parameters=parameters,
    )
    assert deviation_is_extreme(
        detection_type=DetectionType.ACTION_RATE_DROP,
        observed=2.0,
        baseline_mean=10.0,
        upper_bound=13.0,
        parameters=parameters,
    )
    assert not deviation_is_extreme(
        detection_type=DetectionType.ACTION_RATE_DROP,
        observed=4.0,
        baseline_mean=10.0,
        upper_bound=13.0,
        parameters=parameters,
    )
    # No mean to divide for a drop; no bound to multiply for a spike.
    assert not deviation_is_extreme(
        detection_type=DetectionType.ACTION_RATE_DROP,
        observed=0.0,
        baseline_mean=0.0,
        upper_bound=0.0,
        parameters=parameters,
    )
    assert not deviation_is_extreme(
        detection_type=DetectionType.ACTION_RATE_SPIKE,
        observed=1.0,
        baseline_mean=0.0,
        upper_bound=0.0,
        parameters=parameters,
    )


def test_first_use_factors_are_never_extreme() -> None:
    """Novelty has no intensity: a first use is a first use, however many times it repeats."""
    for detection_type in (
        DetectionType.NOVEL_ACTION,
        DetectionType.NOVEL_RESOURCE,
        DetectionType.UNUSUAL_TIME,
    ):
        assert not deviation_is_extreme(
            detection_type=detection_type,
            observed=99.0,
            baseline_mean=0.0,
            upper_bound=0.0,
            parameters=DEFAULT_PARAMETERS,
        )


# ── Parameters ───────────────────────────────────────────────────────────────


def test_parameters_refuse_values_the_arithmetic_cannot_support() -> None:
    """Each threshold is refused where it stops meaning anything.

    A negative bound multiple, a zero sample minimum, a ratio of one (a deviation no larger
    than the baseline it deviates from), an extreme multiple below one, and a value that is
    not a count of hours: all are rejected where they are set, rather than quietly
    collapsing or widening every bound.
    """
    for field, value in (
        ("deviation_multiple", -1.0),
        ("extreme_multiple", 0.5),
        ("rate_change_ratio", 1.0),
        ("min_baseline_buckets", 0),
        ("min_baseline_events", 0),
        ("min_ratio_samples", 0),
        ("min_observed_samples", 0),
        ("min_novel_occurrences", 0),
        ("min_distinct_hours", -1),
        ("min_distinct_hours", 25),
    ):
        with pytest.raises(RiskThresholdError):
            DetectionParameters(**{field: value})


def test_a_zero_deviation_multiple_is_allowed_and_documented() -> None:
    """Zero is a legal multiple: the bound *is* the mean, so any change from it deviates.

    It is the most sensitive setting the engine offers, and it still cannot fire on an
    unchanged rate — which is the difference between "sensitive" and "broken".
    """
    parameters = DetectionParameters(deviation_multiple=0.0)
    samples = [4.0, 4.0, 4.0]
    assert mean(samples) + parameters.deviation_multiple * population_stddev(samples) == 4.0


def test_default_parameters_are_internally_consistent() -> None:
    """The shipped defaults: a bound two spreads out, and extremity at three bounds."""
    parameters = DetectionParameters()
    assert parameters.deviation_multiple == 2.0
    assert parameters.extreme_multiple == 3.0
    assert parameters.min_baseline_buckets == MIN_BASELINE_BUCKETS
    assert parameters.extreme_multiple > parameters.deviation_multiple


# ── Windows ──────────────────────────────────────────────────────────────────


def test_named_observation_windows_end_at_now() -> None:
    """A named window is relative to the instant the request resolved it against."""
    resolved = resolve_observation(
        window=MonitoringWindow.ONE_HOUR, start_time=None, end_time=None, now=NOW
    )
    assert resolved.end == NOW
    assert resolved.start == NOW - timedelta(hours=1)


def test_explicit_observation_window_is_taken_verbatim() -> None:
    """A ``custom`` window uses the caller's bounds, in UTC, unchanged."""
    start = NOW - timedelta(minutes=30)
    resolved = resolve_observation(
        window=MonitoringWindow.CUSTOM, start_time=start, end_time=NOW, now=NOW
    )
    assert (resolved.start, resolved.end) == (start, NOW)


def test_an_observation_window_may_not_have_zero_duration() -> None:
    """A rate whose divisor is zero is refused, not approximated.

    The refusal is explicit rather than a division guarded by an epsilon: "no time passed"
    is a question the engine declines to answer instead of answering with a huge number.
    """
    with pytest.raises(RiskWindowError):
        resolve_observation(window=MonitoringWindow.CUSTOM, start_time=NOW, end_time=NOW, now=NOW)


def test_an_observation_window_may_not_be_naive() -> None:
    """A timestamp without a timezone is refused: "12:00" is not an instant."""
    with pytest.raises(RiskWindowError):
        resolve_observation(
            window=MonitoringWindow.CUSTOM,
            start_time=datetime(2026, 9, 25, 11, 0),
            end_time=NOW,
            now=NOW,
        )


def test_baseline_ends_where_the_observation_begins() -> None:
    """The two windows abut and never overlap — the property the whole comparison rests on."""
    observation_start = NOW - timedelta(hours=1)
    baseline = resolve_baseline(name=BaselineWindow.SEVEN_DAYS, observation_start=observation_start)
    assert baseline.end == observation_start
    assert baseline.start == observation_start - timedelta(days=7)
    assert baseline.name is BaselineWindow.SEVEN_DAYS
    assert baseline.buckets == 168


def test_named_baselines_are_bounded_and_documented() -> None:
    """Four spans — a day, a week, a fortnight, a month — and a hard ceiling of thirty days."""
    assert set(BaselineWindow) == {
        BaselineWindow.ONE_DAY,
        BaselineWindow.SEVEN_DAYS,
        BaselineWindow.FOURTEEN_DAYS,
        BaselineWindow.THIRTY_DAYS,
    }
    for window, span, buckets in (
        (BaselineWindow.ONE_DAY, timedelta(days=1), 24),
        (BaselineWindow.SEVEN_DAYS, timedelta(days=7), 168),
        (BaselineWindow.FOURTEEN_DAYS, timedelta(days=14), 336),
        (BaselineWindow.THIRTY_DAYS, timedelta(days=30), 720),
    ):
        resolved = resolve_baseline(name=window, observation_start=NOW)
        assert resolved.end - resolved.start == span <= MAX_BASELINE_WINDOW
        assert resolved.buckets == buckets


def test_baseline_refuses_mislabelled_bounds() -> None:
    """A baseline whose span disagrees with its own name is a bug, not a comparison."""
    with pytest.raises(RiskWindowError):
        Baseline(
            name=BaselineWindow.SEVEN_DAYS,
            start=NOW - timedelta(days=3),
            end=NOW,
        )


def test_baseline_refuses_naive_or_inverted_bounds() -> None:
    """Naive bounds, and a baseline that ends before it starts, are both refused."""
    with pytest.raises(RiskWindowError):
        Baseline(
            name=BaselineWindow.SEVEN_DAYS,
            start=datetime(2026, 9, 18, 12, 0),
            end=NOW,
        )
    with pytest.raises(RiskWindowError):
        Baseline(
            name=BaselineWindow.SEVEN_DAYS,
            start=NOW,
            end=NOW - timedelta(days=7),
        )


# ── Buckets and frames ───────────────────────────────────────────────────────


def test_only_whole_hours_inside_the_window_are_samples() -> None:
    """A bucket counts when the whole hour is inside the window.

    The baseline's first and last buckets are usually partial — the window starts mid-hour
    unless the clock cooperates — and a partial hour is not an hour's worth of behaviour:
    counting one would put the window's own edge into the distribution.
    """
    start = datetime(2026, 9, 18, 12, 30, tzinfo=UTC)
    end = start + timedelta(days=1)
    floor = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    # The bucket the window opens inside is partial: half of it is before the window.
    assert not is_full_bucket(floor, start=start, end=end)
    assert is_full_bucket(floor + timedelta(hours=1), start=start, end=end)
    # And the bucket the window closes inside is partial too: half of it is after.
    assert is_full_bucket(end - timedelta(hours=1), start=start, end=end)
    assert not is_full_bucket(end, start=start, end=end)


def test_hour_bucket_floors_to_the_utc_hour() -> None:
    """Buckets are UTC clock hours, so a bucket is comparable across deployments."""
    assert hour_bucket(datetime(2026, 9, 25, 12, 59, 59, tzinfo=UTC)) == datetime(
        2026, 9, 25, 12, 0, tzinfo=UTC
    )


def test_a_frame_reports_its_totals_and_active_hours() -> None:
    """Totals sum the buckets; active hours are the clock hours that saw anything."""
    start = datetime(2026, 9, 25, 10, 0, tzinfo=UTC)
    frame = ActivityFrame(
        start=start,
        end=start + timedelta(hours=3),
        buckets=(
            BucketCounts(
                bucket=start,
                events=4,
                requests=4,
                executions=2,
                failures=1,
                denials=1,
                approval_required=0,
                replays=0,
            ),
            BucketCounts(
                bucket=start + timedelta(hours=1),
                events=0,
                requests=0,
                executions=0,
                failures=0,
                denials=0,
                approval_required=0,
                replays=0,
            ),
            BucketCounts(
                bucket=start + timedelta(hours=2),
                events=2,
                requests=2,
                executions=1,
                failures=0,
                denials=0,
                approval_required=1,
                replays=1,
            ),
        ),
        actions={"agent.posture_check": 6},
        resources={},
    )
    totals: WindowTotals = frame.totals
    assert (totals.events, totals.requests, totals.executions) == (6, 6, 3)
    assert (totals.failures, totals.denials, totals.approval_required, totals.replays) == (
        1,
        1,
        1,
        1,
    )
    assert totals.completed == 4  # three successes plus one failure
    assert frame.active_hours == frozenset({10, 12})
    assert frame.span_hours == 3.0
    assert len(frame.full_buckets()) == 3
    assert frame.events_by_active_hour() == {10: 4, 12: 2}


def test_a_frame_refuses_an_empty_or_backwards_span() -> None:
    """A frame with no duration cannot produce a rate, so it cannot be constructed."""
    with pytest.raises(RiskWindowError):
        ActivityFrame(start=NOW, end=NOW, buckets=(), actions={}, resources={})


def test_an_assessment_status_is_total() -> None:
    """Three outcomes, and each means something different to a reader."""
    assert set(AssessmentStatus) == {
        AssessmentStatus.INSUFFICIENT_DATA,
        AssessmentStatus.WITHIN_BASELINE,
        AssessmentStatus.DEVIATING,
    }
    assert set(DimensionStatus) == {
        DimensionStatus.INSUFFICIENT_DATA,
        DimensionStatus.MEASURED,
        DimensionStatus.DEVIATION,
    }
    assert len(set(InsufficiencyReason)) == 7


def test_metrics_and_detection_types_line_up() -> None:
    """Every detection type names exactly one metric, and every metric has a dimension."""
    from aicore_api.core.risk import DETECTION_METRICS, STRONG_DETECTION_TYPES

    assert set(DETECTION_METRICS) == set(DetectionType)
    assert set(DETECTION_METRICS.values()) == set(RiskMetric)
    assert len(STRONG_DETECTION_TYPES) == 4
    assert set(STRONG_DETECTION_TYPES) < set(DetectionType)


def test_population_stddev_is_not_the_sample_definition() -> None:
    """Guards the choice against a well-meaning refactor to ``statistics.stdev``."""
    values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
    assert math.isclose(population_stddev(values), 2.0)
    assert not math.isclose(population_stddev(values), 2.138089935299395)
