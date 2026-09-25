"""The engine's behaviour on datasets whose expected answers can be computed by hand.

Each test builds two frames — a baseline and an observation — from explicit hourly counts,
states the arithmetic in a comment, and asserts the resulting status, factors, level and
evidence. There is no database here and no clock: if an assertion fails, the failure is in
the comparison, not in the query behind it.

The datasets are deliberately small and boring. A detector that only fires on dramatic
numbers has not been tested; the interesting cases are the boundaries — a rate exactly at
its bound, a deviation that crosses the bound but not the change ratio, a ratio whose
baseline denominator is zero, and a baseline so steady that its spread is zero.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import pytest

from aicore_api.core.risk import (
    DEFAULT_PARAMETERS,
    ActivityFrame,
    AssessmentStatus,
    BucketCounts,
    DetectionParameters,
    DetectionType,
    DimensionStatus,
    EntityType,
    InsufficiencyReason,
    ResourceKey,
    RiskLevel,
    RiskMetric,
    WindowTotals,
)
from aicore_api.risk.engine import (
    DIMENSION_ORDER,
    FACTOR_ORDER,
    Assessment,
    assess_agent,
)

#: The agent every test assesses. A fixed uuid so a failure is reproducible.
AGENT = uuid.uuid5(uuid.NAMESPACE_URL, "aicore-test-risk-agent")

#: The instant the observation window ends, so baselines are placed by arithmetic.
END = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)

#: The action every seeded request carries. One identifier, so the novel-action dimension
#: stays silent unless a test introduces a second one on purpose.
ACTION = "agent.posture_check"

#: A week of hours, the default baseline. Standalone here so a test can state its own.
WEEK_HOURS = 168


def frame(
    *,
    hours: int,
    end: datetime = END,
    requests: Mapping[int, int] | None = None,
    executions: Mapping[int, int] | None = None,
    failures: Mapping[int, int] | None = None,
    denials: Mapping[int, int] | None = None,
    approvals: Mapping[int, int] | None = None,
    replays: Mapping[int, int] | None = None,
    actions: Mapping[str, int] | None = None,
    resources: Mapping[tuple[str, str], int] | None = None,
) -> ActivityFrame:
    """Build a frame of ``hours`` hourly buckets ending at ``end``.

    Each mapping holds *how many of that kind of event happened in the i-th hour-slot*,
    counting from the start of the frame — so a test states its dataset as counts per hour
    and the helper does the bookkeeping. The frame's totals are computed from its buckets,
    exactly as the repository's do, which is what lets a test assert on either.
    """
    start = end - timedelta(hours=hours)
    buckets: list[BucketCounts] = []
    for index in range(hours):
        request_count = (requests or {}).get(index, 0)
        execution_count = (executions or {}).get(index, 0)
        failure_count = (failures or {}).get(index, 0)
        denial_count = (denials or {}).get(index, 0)
        approval_count = (approvals or {}).get(index, 0)
        replay_count = (replays or {}).get(index, 0)
        buckets.append(
            BucketCounts(
                bucket=start + timedelta(hours=index),
                events=(
                    request_count
                    + execution_count
                    + failure_count
                    + denial_count
                    + approval_count
                    + replay_count
                ),
                requests=request_count,
                executions=execution_count,
                failures=failure_count,
                denials=denial_count,
                approval_required=approval_count,
                replays=replay_count,
            )
        )
    return ActivityFrame(
        start=start,
        end=end,
        buckets=tuple(buckets),
        actions=dict(actions or {}),
        resources=dict(resources or {}),
    )


def steady_baseline(
    *,
    hours: int = WEEK_HOURS,
    requests_per_hour: int = 10,
    executions_per_hour: int = 9,
    failures_per_hour: int = 0,
    denials_per_hour: int = 0,
    actions: Mapping[str, int] | None = None,
) -> ActivityFrame:
    """A week of identical hours: the baseline every comparison below is measured against.

    Identical hours mean a mean of ``requests_per_hour`` and a standard deviation of
    exactly zero, so the bound is the mean itself and the arithmetic in each test is short
    enough to check by eye. Some tests use a varying baseline instead, on purpose.
    """
    return frame(
        hours=hours,
        requests=dict.fromkeys(range(hours), requests_per_hour),
        executions=dict.fromkeys(range(hours), executions_per_hour) if executions_per_hour else {},
        failures=dict.fromkeys(range(hours), failures_per_hour) if failures_per_hour else {},
        denials=dict.fromkeys(range(hours), denials_per_hour) if denials_per_hour else {},
        actions=actions or {ACTION: requests_per_hour * hours},
    )


def with_resources(frame_: ActivityFrame, resources: Mapping[ResourceKey, int]) -> ActivityFrame:
    """The same frame, with the resources it saw. Kept separate so the helper above stays
    about counts and this one stays about the one field a resource test needs."""
    return ActivityFrame(
        start=frame_.start,
        end=frame_.end,
        buckets=frame_.buckets,
        actions=frame_.actions,
        resources=dict(resources),
    )


def assess(observation: ActivityFrame, baseline: ActivityFrame, **kwargs: object) -> Assessment:
    """Assess the test agent, with the parameters a test names."""
    return assess_agent(
        agent_id=AGENT,
        observation=observation,
        baseline=baseline,
        parameters=kwargs.get("parameters", DEFAULT_PARAMETERS),  # type: ignore[arg-type]
    )


def dimension(assessment: Assessment, metric: RiskMetric) -> object:
    """One dimension of an assessment, by metric."""
    for candidate in assessment.dimensions:
        if candidate.metric is metric:
            return candidate
    raise AssertionError(f"{metric} is missing from the assessment")


# ── The window the engine reports ────────────────────────────────────────────


def test_every_dimension_is_reported_in_a_fixed_order() -> None:
    """All six, always, in the order the level was computed in.

    A response that only listed what fired would hide what was looked for, and a reader
    cannot tell "nothing here" from "nothing was checked".
    """
    assessment = assess(
        frame(hours=1, requests={0: 10}, actions={ACTION: 10}),
        steady_baseline(),
    )
    assert tuple(candidate.metric for candidate in assessment.dimensions) == DIMENSION_ORDER
    assert assessment.entity_type is EntityType.AGENT
    assert assessment.entity_id == AGENT


def test_an_unchanged_agent_is_within_its_baseline() -> None:
    """The same hour as every hour in the baseline is not a finding."""
    assessment = assess(
        frame(hours=1, requests={0: 10}, executions={0: 9}, actions={ACTION: 10}),
        steady_baseline(),
    )
    assert assessment.status is AssessmentStatus.WITHIN_BASELINE
    assert assessment.anomaly is False
    assert assessment.factors == ()
    assert assessment.risk_level is RiskLevel.NONE
    assert assessment.detection_type is None


def test_cold_start_is_insufficient_data_never_an_anomaly() -> None:
    """A baseline with no events at all is refused, and refusal is not a deviation.

    This is the rule the whole phase turns on: an agent the platform has never watched must
    not be reported as anomalous for being new. Both shapes of "no history" are checked —
    buckets that are all zero, and no buckets at all.
    """
    observation = frame(hours=1, requests={0: 5}, actions={ACTION: 5})

    empty_buckets = frame(hours=WEEK_HOURS)  # a week of empty hours, no actions
    cold = assess(observation, empty_buckets)
    assert cold.status is AssessmentStatus.INSUFFICIENT_DATA
    assert cold.anomaly is False
    assert cold.risk_level is RiskLevel.NONE
    assert cold.factors == ()
    rate = dimension(cold, RiskMetric.ACTION_RATE)
    assert rate.status is DimensionStatus.INSUFFICIENT_DATA
    assert rate.reason is InsufficiencyReason.BASELINE_EMPTY

    no_buckets = ActivityFrame(
        start=END - timedelta(hours=1), end=END, buckets=(), actions={}, resources={}
    )
    assert assess(observation, no_buckets).status is AssessmentStatus.INSUFFICIENT_DATA


def test_a_baseline_that_is_too_short_to_have_a_spread_is_insufficient() -> None:
    """Fewer full buckets than the minimum is a baseline without a distribution."""
    short = steady_baseline(hours=6)
    assessment = assess(frame(hours=1, requests={0: 40}, actions={ACTION: 40}), short)
    rate = dimension(assessment, RiskMetric.ACTION_RATE)
    assert rate.status is DimensionStatus.INSUFFICIENT_DATA
    assert rate.reason is InsufficiencyReason.BASELINE_TOO_SHORT
    assert rate.baseline_samples == 0


def test_a_baseline_with_no_rate_at_all_is_refused_rather_than_divided_by() -> None:
    """Zero events every hour: there is no mean to be above, so there is no ratio.

    This is the division-by-zero case stated as behaviour. The bound would be zero, the
    observation would be "infinitely" above it, and a naive engine would report a maximum
    deviation from a tenant it has never seen act.
    """
    quiet = frame(hours=WEEK_HOURS, actions={ACTION: 0})
    assessment = assess(frame(hours=1, requests={0: 1}, actions={ACTION: 1}), quiet)
    rate = dimension(assessment, RiskMetric.ACTION_RATE)
    assert rate.status is DimensionStatus.INSUFFICIENT_DATA
    assert rate.reason is InsufficiencyReason.BASELINE_EMPTY
    assert assessment.anomaly is False


# ── Rates ────────────────────────────────────────────────────────────────────


def test_a_rate_spike_fires_with_the_bound_it_crossed() -> None:
    """Ten requests an hour for a week, then forty in one hour.

    Baseline: mean 10, population standard deviation 0, so the upper bound is 10 and the
    lower bound is 10. The observation is 40 requests per hour, which is above the bound
    *and* at least twice the mean (the change-ratio rule), and at least three times the
    bound — so the deviation is extreme. One strong factor, extreme: MEDIUM.
    """
    assessment = assess(
        frame(hours=1, requests={0: 40}, actions={ACTION: 40}),
        steady_baseline(),
    )
    assert assessment.status is AssessmentStatus.DEVIATING
    assert assessment.anomaly is True
    assert [factor.type for factor in assessment.factors] == [DetectionType.ACTION_RATE_SPIKE]
    assert assessment.detection_type is DetectionType.ACTION_RATE_SPIKE
    assert assessment.risk_level is RiskLevel.MEDIUM

    factor = assessment.factors[0]
    assert (factor.observed, factor.baseline_mean) == (40.0, 10.0)
    assert factor.baseline_stddev == 0.0
    assert factor.upper_bound == 10.0
    assert factor.lower_bound == 10.0
    assert factor.baseline_samples == WEEK_HOURS
    assert factor.observation_samples == 40


def test_a_rate_drop_fires_and_its_extremity_is_measured_against_the_mean() -> None:
    """A week of ten requests an hour, then an hour of none.

    The lower bound is 10, the observation is 0, and 0 is at most a third of the mean — so
    the deviation is extreme. A drop is a finding in its own right: an agent that stops is
    as interesting as one that starts.
    """
    assessment = assess(
        frame(hours=1, requests={0: 0}),
        steady_baseline(),
    )
    assert assessment.status is AssessmentStatus.DEVIATING
    assert [factor.type for factor in assessment.factors] == [DetectionType.ACTION_RATE_DROP]
    assert assessment.risk_level is RiskLevel.MEDIUM
    factor = assessment.factors[0]
    assert (factor.observed, factor.lower_bound, factor.upper_bound) == (0.0, 10.0, 10.0)


def test_crossing_the_bound_is_not_enough_without_the_change_ratio() -> None:
    """A baseline that varies: mean 10, population standard deviation 2, so the bound is 14.

    An observed rate of 15 crosses the bound, and is *not* reported, because a rate that is
    half again the usual one is not a change in behaviour — it is the same behaviour with a
    busy hour in it. The dimension is still measured and reported, so a reader can see the
    comparison rather than having to infer that it happened.
    """
    baseline = frame(
        hours=WEEK_HOURS,
        requests={index: (8 if index % 2 else 12) for index in range(WEEK_HOURS)},
        executions=dict.fromkeys(range(WEEK_HOURS), 9),
        actions={ACTION: 10 * WEEK_HOURS},
    )
    assessment = assess(frame(hours=1, requests={0: 15}, actions={ACTION: 15}), baseline)
    rate = dimension(assessment, RiskMetric.ACTION_RATE)
    assert rate.status is DimensionStatus.MEASURED
    assert rate.observed == 15.0
    assert rate.baseline_mean == 10.0
    assert rate.baseline_stddev == 2.0
    assert rate.upper_bound == 14.0
    assert assessment.status is AssessmentStatus.WITHIN_BASELINE
    assert assessment.factors == ()


def test_a_rate_exactly_at_the_bound_does_not_fire() -> None:
    """The comparison is strict: a rate *at* its bound is inside the baseline.

    The bound is where the ordinary spread ends, and the boundary belongs to ordinary.
    """
    baseline = frame(
        hours=WEEK_HOURS,
        requests={index: (8 if index % 2 else 12) for index in range(WEEK_HOURS)},
        executions=dict.fromkeys(range(WEEK_HOURS), 9),
        actions={ACTION: 10 * WEEK_HOURS},
    )
    assessment = assess(frame(hours=1, requests={0: 14}, actions={ACTION: 14}), baseline)
    assert assessment.anomaly is False
    assert dimension(assessment, RiskMetric.ACTION_RATE).observed == 14.0


def test_the_rate_is_measured_over_its_whole_window_not_per_bucket() -> None:
    """A thirty-minute window holding twenty requests is a rate of forty an hour.

    The observation's span is the divisor, so a short window is not compared against hourly
    counts without being scaled to hours first. The baseline here is ten an hour, so twenty
    in half an hour is a twofold rate — hence the factor, despite the raw counts (20) being
    below the raw baseline totals.
    """
    observation = ActivityFrame(
        start=END - timedelta(minutes=30),
        end=END,
        buckets=(
            BucketCounts(
                bucket=END - timedelta(hours=1),
                events=20,
                requests=20,
                executions=0,
                failures=0,
                denials=0,
                approval_required=0,
                replays=0,
            ),
        ),
        actions={ACTION: 20},
        resources={},
    )
    assessment = assess(observation, steady_baseline())
    rate = dimension(assessment, RiskMetric.ACTION_RATE)
    assert rate.observed == 40.0
    assert assessment.factors[0].type is DetectionType.ACTION_RATE_SPIKE


# ── Ratios ───────────────────────────────────────────────────────────────────


def test_a_failure_rate_spike_uses_completions_as_its_denominator() -> None:
    """Ten requests and nine executions an hour, then an hour of one success and three failures.

    The baseline never fails, so its mean failure rate is zero and its bound is zero — and a
    ratio above a zero bound fires, because "it never used to fail and now a quarter of its
    completions fail" is the finding, not an artefact of a degenerate bound. The change-ratio
    rule is skipped in exactly this case, which is stated in the evidence as a mean of zero.
    """
    assessment = assess(
        frame(
            hours=1,
            requests={0: 10},
            executions={0: 1},
            failures={0: 3},
            actions={ACTION: 10},
        ),
        steady_baseline(),
    )
    assert DetectionType.FAILURE_RATE_SPIKE in [factor.type for factor in assessment.factors]
    factor = next(
        item for item in assessment.factors if item.type is DetectionType.FAILURE_RATE_SPIKE
    )
    assert factor.observed == 0.75  # 3 failures / 4 completions
    assert factor.baseline_mean == 0.0
    assert factor.upper_bound == 0.0
    assert factor.observation_samples == 4
    assert factor.baseline_samples == WEEK_HOURS


def test_a_denial_rate_spike_uses_requests_as_its_denominator() -> None:
    """The same shape for refusals: eight denials out of forty requests is a rate of 0.2.

    The baseline's rate is 0.1 (one denial in every ten requests), the bound is 0.1, so the
    observation is above the bound and at least twice the mean.
    """
    assessment = assess(
        frame(
            hours=1,
            requests={0: 40},
            denials={0: 8},
            actions={ACTION: 40},
        ),
        steady_baseline(denials_per_hour=1),
    )
    assert DetectionType.DENIAL_RATE_SPIKE in [factor.type for factor in assessment.factors]
    factor = next(
        item for item in assessment.factors if item.type is DetectionType.DENIAL_RATE_SPIKE
    )
    assert factor.observed == 0.2
    assert factor.baseline_mean == pytest.approx(0.1)
    assert factor.observation_samples == 40


def test_a_ratio_needs_a_denominator_in_the_observation() -> None:
    """One completion, and it failed, is not a failure rate of 1.0.

    The observation minimum exists so that a handful of events cannot produce a ratio that
    looks like a total failure — ``1 of 1`` and ``300 of 300`` are the same number and not
    the same evidence. The dimension reports why it could not be measured rather than
    answering anyway.
    """
    observation = frame(hours=1, requests={0: 10}, executions={0: 1}, actions={ACTION: 10})
    assessment = assess(observation, steady_baseline())
    failure_rate = dimension(assessment, RiskMetric.FAILURE_RATE)
    assert failure_rate.status is DimensionStatus.INSUFFICIENT_DATA
    assert failure_rate.reason is InsufficiencyReason.OBSERVATION_INSUFFICIENT_SAMPLES
    assert failure_rate.observed is None
    assert assessment.factors == ()


def test_a_ratio_needs_buckets_that_have_a_denominator() -> None:
    """A baseline that never completed anything has no failure *rate* to compare against.

    Skipping zero-denominator buckets rather than scoring them as zero is what stops an
    idle week from looking flawless: three failures in four completions would otherwise be
    reported as infinitesimally above a baseline of 0.0 that was never measured.
    """
    idle = frame(
        hours=WEEK_HOURS,
        requests=dict.fromkeys(range(WEEK_HOURS), 10),
        actions={ACTION: 10 * WEEK_HOURS},
    )
    assessment = assess(
        frame(hours=1, requests={0: 10}, executions={0: 1}, failures={0: 3}, actions={ACTION: 10}),
        idle,
    )
    failure_rate = dimension(assessment, RiskMetric.FAILURE_RATE)
    assert failure_rate.status is DimensionStatus.INSUFFICIENT_DATA
    assert failure_rate.reason is InsufficiencyReason.BASELINE_INSUFFICIENT_SAMPLES
    assert failure_rate.baseline_samples == 0


# ── First occurrences ────────────────────────────────────────────────────────


def test_an_action_the_baseline_never_records_is_reported_with_its_identifiers() -> None:
    """One unfamiliar action is one weak factor, and the level says so: LOW.

    The evidence names the action and counts it — an identifier the organization's own rows
    state — and the level is the weakest non-zero one, because first use is weak evidence.
    """
    observation = frame(
        hours=1,
        requests={0: 10},
        executions={0: 9},
        actions={ACTION: 9, "agent.rotate_credential": 1},
    )
    assessment = assess(observation, steady_baseline())
    novel = next(item for item in assessment.factors if item.type is DetectionType.NOVEL_ACTION)
    assert novel.observed == 1.0
    assert novel.threshold_occurrences == DEFAULT_PARAMETERS.min_novel_occurrences
    assert [item.value for item in novel.items] == ["agent.rotate_credential"]
    assert novel.items[0].occurrences == 1
    assert novel.items[0].kind.value == "action"
    assert assessment.risk_level is RiskLevel.LOW
    assert assessment.detection_type is DetectionType.NOVEL_ACTION


def test_two_first_occurrences_are_worth_more_than_one() -> None:
    """A novel action *and* a novel resource: two weak factors, so MEDIUM.

    Neither is a rate deviation with a measured bound; between them they are enough
    corroboration to reach the middle level, and no further.
    """
    observation = frame(
        hours=1,
        requests={0: 10},
        executions={0: 9},
        actions={ACTION: 9, "agent.rotate_credential": 1},
        resources={ResourceKey("agent", "dddddddd-dddd-4ddd-8ddd-dddddddddddd"): 1},
    )
    baseline = with_resources(
        steady_baseline(),
        {ResourceKey("agent", "cccccccc-cccc-4ccc-8ccc-cccccccccccc"): 10 * WEEK_HOURS},
    )
    assessment = assess(observation, baseline)
    found = {factor.type for factor in assessment.factors}
    assert {DetectionType.NOVEL_ACTION, DetectionType.NOVEL_RESOURCE} <= found
    assert assessment.risk_level is RiskLevel.MEDIUM


def test_a_resource_finding_names_the_resource_and_its_type() -> None:
    """Two resource kinds can share an identifier, so the evidence carries both."""
    resource_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    observation = frame(
        hours=1,
        requests={0: 10},
        executions={0: 9},
        actions={ACTION: 10},
        resources={ResourceKey("agent", resource_id): 1},
    )
    baseline = with_resources(
        steady_baseline(),
        {ResourceKey("agent", "cccccccc-cccc-4ccc-8ccc-cccccccccccc"): 10 * WEEK_HOURS},
    )
    assessment = assess(observation, baseline)
    novel = next(item for item in assessment.factors if item.type is DetectionType.NOVEL_RESOURCE)
    assert novel.items[0].value == resource_id
    assert novel.items[0].resource_type == "agent"
    assert novel.items[0].kind.value == "resource"


def test_an_unusual_hour_is_reported_with_the_hour_it_names() -> None:
    """Activity at an hour the baseline is never active in, named as a clock hour.

    The baseline here is active in hours 00 to 11 of each day and silent otherwise; the
    observation's buckets fall at 12:00 and later, which the baseline never covers. The
    evidence says *which* hour — ``12`` — because "at an unusual time" without the time
    would be a finding nobody could check.
    """
    start = END - timedelta(days=7)
    buckets = []
    for index in range(WEEK_HOURS):
        hour = (start + timedelta(hours=index)).hour
        active = hour < 10
        buckets.append(
            BucketCounts(
                bucket=start + timedelta(hours=index),
                events=10 if active else 0,
                requests=10 if active else 0,
                executions=0,
                failures=0,
                denials=0,
                approval_required=0,
                replays=0,
            )
        )
    baseline = ActivityFrame(
        start=start,
        end=END,
        buckets=tuple(buckets),
        actions={ACTION: 10 * 10 * 7},
        resources={},
    )
    observation = frame(hours=1, requests={0: 10}, actions={ACTION: 10})
    assessment = assess(observation, baseline)
    unusual = dimension(assessment, RiskMetric.UNUSUAL_TIME)
    assert unusual.status is DimensionStatus.DEVIATION
    factor = next(item for item in assessment.factors if item.type is DetectionType.UNUSUAL_TIME)
    assert [item.value for item in factor.items] == [f"{END.hour - 1:02d}"]
    assert factor.baseline_samples == 10


def test_an_unusual_hour_needs_a_baseline_that_covers_hours() -> None:
    """A baseline that only ever acted in three hours cannot say which hours are unusual."""
    start = END - timedelta(hours=3)
    baseline = ActivityFrame(
        start=start,
        end=END,
        buckets=tuple(
            BucketCounts(
                bucket=start + timedelta(hours=index),
                events=10,
                requests=10,
                executions=0,
                failures=0,
                denials=0,
                approval_required=0,
                replays=0,
            )
            for index in range(3)
        ),
        actions={ACTION: 30},
        resources={},
    )
    observation = frame(hours=1, requests={0: 10}, actions={ACTION: 10})
    assert (
        dimension(assess(observation, baseline), RiskMetric.ACTION_RATE).reason
        is InsufficiencyReason.BASELINE_TOO_SHORT
    )
    unusual = dimension(assess(observation, baseline), RiskMetric.UNUSUAL_TIME)
    assert unusual.reason in {
        InsufficiencyReason.BASELINE_NO_HOURS,
        InsufficiencyReason.BASELINE_EMPTY,
    }


# ── Levels ───────────────────────────────────────────────────────────────────


def test_two_strong_factors_reach_high() -> None:
    """A rate spike and a failure-rate spike together: two independent measurements.

    Both are rate deviations with their own bounds, so the level is HIGH without either of
    them being extreme — corroboration, not intensity, is what moves the level.
    """
    observation = frame(
        hours=1,
        requests={0: 40},
        executions={0: 1},
        failures={0: 3},
        actions={ACTION: 40},
    )
    assessment = assess(observation, steady_baseline())
    found = [factor.type for factor in assessment.factors]
    assert found == [DetectionType.ACTION_RATE_SPIKE, DetectionType.FAILURE_RATE_SPIKE]
    assert assessment.risk_level is RiskLevel.HIGH


def test_three_strong_factors_with_an_extreme_one_reach_critical() -> None:
    """Rate, failure rate and denial rate all deviating, with the rate extreme: CRITICAL.

    CRITICAL is the top of the vocabulary and the top row of the level table, and it is
    still a statement about evidence: three measured comparisons, one of them far outside
    its own bound. Nothing about this row claims intent, compromise or incident.
    """
    observation = frame(
        hours=1,
        requests={0: 40},
        executions={0: 1},
        failures={0: 3},
        denials={0: 10},
        actions={ACTION: 40},
    )
    assessment = assess(observation, steady_baseline(denials_per_hour=1))
    found = [factor.type for factor in assessment.factors]
    assert found == [
        DetectionType.ACTION_RATE_SPIKE,
        DetectionType.FAILURE_RATE_SPIKE,
        DetectionType.DENIAL_RATE_SPIKE,
    ]
    assert assessment.risk_level is RiskLevel.CRITICAL
    assert assessment.detection_type is DetectionType.ACTION_RATE_SPIKE


def test_three_strong_factors_without_an_extreme_one_stop_at_high() -> None:
    """The same three factors, none of them extreme: HIGH rather than CRITICAL.

    Extent matters at the top of the table and nowhere else, which is why the table has two
    rows for three strong factors rather than a single one.
    """
    observation = frame(
        hours=1,
        requests={0: 25},
        executions={0: 1},
        failures={0: 3},
        denials={0: 5},
        actions={ACTION: 25},
    )
    assessment = assess(observation, steady_baseline(denials_per_hour=1))
    assert len(assessment.factors) == 3
    assert assessment.risk_level is RiskLevel.HIGH


def test_the_factor_order_is_fixed_so_the_head_is_stable() -> None:
    """Factors are emitted in ``FACTOR_ORDER`` regardless of which fired first."""
    observation = frame(
        hours=1,
        requests={0: 40},
        executions={0: 4},
        actions={ACTION: 39, "agent.rotate_credential": 1},
    )
    assessment = assess(observation, steady_baseline())
    assert [factor.type for factor in assessment.factors] == [
        candidate for candidate in FACTOR_ORDER if candidate in {f.type for f in assessment.factors}
    ]
    assert assessment.detection_type is assessment.factors[0].type


# ── Determinism ──────────────────────────────────────────────────────────────


def test_the_same_windows_produce_the_same_assessment() -> None:
    """Twice over the same frames is twice the same answer, field for field.

    The engine reads no clock and holds no state: a dataset has one assessment, which is
    what lets a record be deduplicated on its identity alone.
    """
    observation = frame(
        hours=1,
        requests={0: 40},
        executions={0: 1},
        failures={0: 3},
        actions={ACTION: 40, "agent.rotate_credential": 1},
    )
    baseline = steady_baseline()
    first = assess(observation, baseline)
    second = assess(observation, baseline)
    assert first == second
    assert first.factors == second.factors
    assert first.risk_level is second.risk_level


def test_parameters_are_used_where_they_are_documented() -> None:
    """A stricter change ratio suppresses a deviation the defaults would keep.

    Nothing about the dataset changes between the two calls — only the threshold, which is
    exactly the knob the parameters exist to be.
    """
    observation = frame(hours=1, requests={0: 25}, actions={ACTION: 25})
    baseline = steady_baseline()
    default = assess(observation, baseline)
    strict = assess(
        observation,
        baseline,
        parameters=DetectionParameters(rate_change_ratio=3.0),
    )
    assert default.factors != ()
    assert strict.factors == ()
    assert strict.status is AssessmentStatus.WITHIN_BASELINE


def test_a_minimum_sample_floor_keeps_small_numbers_out_of_the_findings() -> None:
    """The novel-occurrence floor is a floor, not a formality.

    With a floor of five, a single first use is not reported: the engine is configured to
    wait for a pattern rather than to report every first time an agent does something new.
    """
    observation = frame(
        hours=1,
        requests={0: 5},
        executions={0: 4},
        actions={ACTION: 4, "agent.rotate_credential": 1},
    )
    parameters = DetectionParameters(min_novel_occurrences=5)
    assessment = assess(observation, steady_baseline(), parameters=parameters)
    assert DetectionType.NOVEL_ACTION not in {factor.type for factor in assessment.factors}


def test_a_frame_with_nothing_in_it_is_not_a_finding() -> None:
    """Silence is measured against silence: no events anywhere means nothing to compare.

    An observation window with no activity at all is a real thing to assess — an agent that
    stopped — and against a baseline that has activity it is a *drop*, which the first test
    in this section covers. Against a baseline with none it is nothing at all.
    """
    quiet = frame(hours=WEEK_HOURS)
    assessment = assess(frame(hours=1), quiet)
    assert assessment.status is AssessmentStatus.INSUFFICIENT_DATA
    assert assessment.anomaly is False


def test_totals_come_from_the_buckets() -> None:
    """The frame's totals are the sum of its buckets, so the two cannot disagree."""
    built = frame(hours=3, requests={0: 1, 1: 2}, executions={2: 3}, failures={2: 1})
    totals: WindowTotals = built.totals
    assert totals.requests == 3
    assert totals.executions == 3
    assert totals.failures == 1
    assert totals.completed == 4
    assert totals.events == 7
