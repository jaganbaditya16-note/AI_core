"""The engine: two frames in, one explainable assessment out.

This module is where a comparison actually happens, and it is deliberately pure: it takes
one agent's :class:`~aicore_api.core.risk.ActivityFrame` for the observation window, one
for the baseline, a set of parameters, and returns an
:class:`~aicore_api.risk.engine.Assessment`. No database, no clock, no configuration
lookup, no randomness — the same two frames always produce the same assessment, which is
what lets the tests state a baseline as a list of numbers and assert the arithmetic.

The shape of a conclusion is OBSERVATION → BASELINE → DEVIATION → EVIDENCE → LEVEL, and
every step is in the returned record.

**Observation.** The frame's totals and its hourly buckets, summed from one query per
window, so the totals and the distribution cannot disagree.

**Baseline.** The same measurement over the baseline window, expressed as a distribution
of *full* hourly buckets (a partial edge bucket is dropped: it holds less than an hour and
would make the same baseline depend on the second of the day it was computed). A mean and
a population standard deviation are the whole of the statistics — no fitting, no model,
nothing a reader cannot recompute with a calculator from the numbers in the response.

**Deviation.** Six dimensions, each with its own guard rails, each either measured or
refused with a reason. A rate deviation needs *both* a statistical bound crossed and a
change of at least ``rate_change_ratio`` against the baseline mean, because three standard
deviations around a small mean is a small number. A first-occurrence dimension needs a
baseline to have been somewhere first.

**Evidence and level.** Every dimension is reported whether or not it deviated, every
factor carries the numbers it was computed from, and the level is read off a five-row
table over the *counts* of factors — see ``core.risk.assess_risk_level``. There is no
score anywhere in this module, and no factor that could only be explained by prose.

What the engine cannot do, by construction: it cannot see a request, cannot be given a
threshold, cannot read a row it is not handed, cannot write anything, and cannot act. Its
worst case is a wrong number in a response.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from aicore_api.core.risk import (
    DEFAULT_PARAMETERS,
    STRONG_DETECTION_TYPES,
    ActivityFrame,
    AssessmentStatus,
    DetectionParameters,
    DetectionType,
    DimensionStatus,
    EntityType,
    InsufficiencyReason,
    RiskLevel,
    RiskMetric,
    assess_risk_level,
    deviation_is_extreme,
    mean,
    population_stddev,
)

__all__ = [
    "Assessment",
    "Dimension",
    "Factor",
    "FactorItem",
    "FactorItemKind",
    "assess_agent",
]


class FactorItemKind(StrEnum):
    """What kind of thing a factor's evidence names.

    A closed vocabulary rather than free-form text: an item is an action identifier, a
    resource, or a clock hour, and a client can render all three without parsing anything.
    """

    ACTION = "action"
    RESOURCE = "resource"
    HOUR = "hour"


@dataclass(frozen=True, slots=True)
class FactorItem:
    """One named piece of a factor: what was used, and how often.

    ``value`` is the identifier as the trail states it — an action's identifier from the
    closed catalogue, a resource identifier from this organization's own rows, or a clock
    hour. Nothing here is a payload, and nothing here is a client's.
    """

    kind: FactorItemKind
    value: str
    occurrences: int
    resource_type: str | None = None


@dataclass(frozen=True, slots=True)
class Factor:
    """One deviation, with the numbers it was computed from.

    Every field is either a measured quantity or the threshold it was compared against, so
    the factor can be checked rather than believed. ``items`` is empty for the two rate
    metrics (there is nothing to name) and carries the identifiers for the first-occurrence
    ones.
    """

    type: DetectionType
    metric: RiskMetric
    observed: float
    baseline_mean: float | None
    baseline_stddev: float | None
    upper_bound: float | None
    lower_bound: float | None
    threshold_multiple: float | None
    threshold_occurrences: int | None
    baseline_samples: int
    observation_samples: int
    items: tuple[FactorItem, ...] = ()


@dataclass(frozen=True, slots=True)
class Dimension:
    """One metric's examination: what was measured, against what, and to what end.

    A dimension that could not be measured says which condition stopped it
    (:class:`~aicore_api.core.risk.InsufficiencyReason`) rather than reporting zeros, and a
    dimension that was measured and did not deviate keeps its numbers — because "the rate
    was inside its bounds" is an answer, and a response that omitted it would leave a
    reader unable to tell quiet from unexamined.
    """

    metric: RiskMetric
    status: DimensionStatus
    reason: InsufficiencyReason | None
    observed: float | None
    baseline_mean: float | None
    baseline_stddev: float | None
    upper_bound: float | None
    lower_bound: float | None
    baseline_samples: int
    observation_samples: int
    threshold_multiple: float | None = None
    detection_types: tuple[DetectionType, ...] = ()


@dataclass(frozen=True, slots=True)
class Assessment:
    """What the engine concluded about one agent over one window.

    ``status`` is the summary a caller checks first; ``dimensions`` is the whole
    examination; ``factors`` is what carried the level. The level describes the evidence
    and never the entity — see :class:`~aicore_api.core.risk.RiskLevel`.
    """

    entity_type: EntityType
    entity_id: uuid.UUID
    status: AssessmentStatus
    anomaly: bool
    risk_level: RiskLevel
    dimensions: tuple[Dimension, ...]
    factors: tuple[Factor, ...]

    @property
    def detection_type(self) -> DetectionType | None:
        """The head of the ordered factors, or ``None`` when nothing fired.

        Not a separate decision: the factors are ordered (rate deviations first, then
        first-occurrence findings, each group in the vocabulary's own order) so this is a
        stable summary of the list rather than a second claim about it.
        """
        return self.factors[0].type if self.factors else None


# ── Dimension building blocks ────────────────────────────────────────────────


def _insufficient(metric: RiskMetric, reason: InsufficiencyReason) -> Dimension:
    """A dimension that could not be measured, saying why."""
    return Dimension(
        metric=metric,
        status=DimensionStatus.INSUFFICIENT_DATA,
        reason=reason,
        observed=None,
        baseline_mean=None,
        baseline_stddev=None,
        upper_bound=None,
        lower_bound=None,
        baseline_samples=0,
        observation_samples=0,
    )


def _rate_bounds(
    samples: list[float], parameters: DetectionParameters
) -> tuple[float, float, float, float]:
    """The mean, the standard deviation and the two bounds a rate comparison uses.

    A bound is the mean plus or minus ``deviation_multiple`` standard deviations, and the
    lower bound is floored at zero: a count of events per hour cannot be negative, and a
    lower bound below zero would be a threshold nothing could ever cross.
    """
    average = mean(samples)
    spread = population_stddev(samples)
    upper = average + parameters.deviation_multiple * spread
    lower = max(0.0, average - parameters.deviation_multiple * spread)
    return average, spread, upper, lower


def _action_rate_dimension(
    *,
    observation: ActivityFrame,
    baseline: ActivityFrame,
    parameters: DetectionParameters,
) -> tuple[Dimension, Factor | None]:
    """Requests per hour, against the baseline's hourly distribution."""
    metric = RiskMetric.ACTION_RATE
    samples = [float(bucket.requests) for bucket in baseline.full_buckets()]
    baseline_events = baseline.totals.requests
    observed_rate = observation.totals.requests / observation.span_hours

    if len(samples) < parameters.min_baseline_buckets:
        return _insufficient(metric, InsufficiencyReason.BASELINE_TOO_SHORT), None
    if baseline_events < parameters.min_baseline_events:
        return _insufficient(metric, InsufficiencyReason.BASELINE_EMPTY), None

    average, spread, upper, lower = _rate_bounds(samples, parameters)
    if average <= 0:
        # Every baseline bucket is zero: there is no rate to be above or below, and
        # dividing by it would turn "no history" into "infinite deviation".
        return _insufficient(metric, InsufficiencyReason.BASELINE_NO_SIGNAL), None

    factor: Factor | None = None
    if observed_rate > upper and observed_rate >= average * parameters.rate_change_ratio:
        factor = Factor(
            type=DetectionType.ACTION_RATE_SPIKE,
            metric=metric,
            observed=observed_rate,
            baseline_mean=average,
            baseline_stddev=spread,
            upper_bound=upper,
            lower_bound=lower,
            threshold_multiple=parameters.deviation_multiple,
            threshold_occurrences=None,
            baseline_samples=len(samples),
            observation_samples=observation.totals.requests,
        )
    elif observed_rate < lower and observed_rate <= average / parameters.rate_change_ratio:
        factor = Factor(
            type=DetectionType.ACTION_RATE_DROP,
            metric=metric,
            observed=observed_rate,
            baseline_mean=average,
            baseline_stddev=spread,
            upper_bound=upper,
            lower_bound=lower,
            threshold_multiple=parameters.deviation_multiple,
            threshold_occurrences=None,
            baseline_samples=len(samples),
            observation_samples=observation.totals.requests,
        )

    dimension = Dimension(
        metric=metric,
        status=DimensionStatus.DEVIATION if factor else DimensionStatus.MEASURED,
        reason=None,
        observed=observed_rate,
        baseline_mean=average,
        baseline_stddev=spread,
        upper_bound=upper,
        lower_bound=lower,
        baseline_samples=len(samples),
        observation_samples=observation.totals.requests,
        threshold_multiple=parameters.deviation_multiple,
        detection_types=(factor.type,) if factor else (),
    )
    return dimension, factor


def _ratio_dimension(
    *,
    metric: RiskMetric,
    detection_type: DetectionType,
    observation: ActivityFrame,
    baseline: ActivityFrame,
    parameters: DetectionParameters,
) -> tuple[Dimension, Factor | None]:
    """A share of a whole — failures over completions, or refusals over requests.

    Only buckets where the denominator is non-zero contribute a sample: an hour with no
    completions has no failure *rate*, and counting it as zero would report a quiet hour as
    a flawless one. The observation side needs a minimum sample for the mirror-image
    reason: one request that was refused is not a denial rate of 1.0.
    """
    samples: list[float] = []
    for bucket in baseline.full_buckets():
        numerator, denominator = _ratio_parts(bucket, metric)
        if denominator > 0:
            samples.append(numerator / denominator)

    observed_numerator, observed_denominator = _ratio_parts(observation.totals, metric)
    if observed_denominator < parameters.min_observed_samples:
        return (
            _insufficient(metric, InsufficiencyReason.OBSERVATION_INSUFFICIENT_SAMPLES),
            None,
        )
    if len(samples) < parameters.min_ratio_samples:
        return (
            _insufficient(metric, InsufficiencyReason.BASELINE_INSUFFICIENT_SAMPLES),
            None,
        )

    average, spread, upper, lower = _rate_bounds(samples, parameters)
    observed_ratio = observed_numerator / observed_denominator

    # Two conditions, both required. The statistical one says the observation is outside
    # the baseline's spread; the ratio one says it is a *change* rather than a small
    # number that happens to be far from a smaller one. When the baseline never recorded a
    # failure the bound is zero and there is no multiple to require, which is stated in
    # the evidence as a mean of zero rather than hidden behind an epsilon.
    fires = observed_ratio > upper and (
        average <= 0 or observed_ratio >= average * parameters.rate_change_ratio
    )
    factor = (
        Factor(
            type=detection_type,
            metric=metric,
            observed=observed_ratio,
            baseline_mean=average,
            baseline_stddev=spread,
            upper_bound=upper,
            lower_bound=lower,
            threshold_multiple=parameters.deviation_multiple,
            threshold_occurrences=None,
            baseline_samples=len(samples),
            observation_samples=observed_denominator,
        )
        if fires
        else None
    )
    dimension = Dimension(
        metric=metric,
        status=DimensionStatus.DEVIATION if factor else DimensionStatus.MEASURED,
        reason=None,
        observed=observed_ratio,
        baseline_mean=average,
        baseline_stddev=spread,
        upper_bound=upper,
        lower_bound=lower,
        baseline_samples=len(samples),
        observation_samples=observed_denominator,
        threshold_multiple=parameters.deviation_multiple,
        detection_types=(factor.type,) if factor else (),
    )
    return dimension, factor


class _RatioCounts(Protocol):
    """The counts a ratio is built from, as both a bucket and a window's totals provide.

    Declared as read-only properties because the things that satisfy it are frozen: a
    protocol that demanded settable attributes would exclude every dataclass in this
    package, which is exactly backwards.
    """

    @property
    def failures(self) -> int:
        """Executions that reached the adapter and did not complete."""

    @property
    def denials(self) -> int:
        """Requests refused by any layer."""

    @property
    def completed(self) -> int:
        """Executions that finished."""

    @property
    def requests(self) -> int:
        """Requests admitted to the pipeline."""


def _ratio_parts(counts: _RatioCounts, metric: RiskMetric) -> tuple[int, int]:
    """``(numerator, denominator)`` for one bucket or one window, by metric."""
    if metric is RiskMetric.FAILURE_RATE:
        return counts.failures, counts.completed
    return counts.denials, counts.requests


def _novel_action_dimension(
    *,
    observation: ActivityFrame,
    baseline: ActivityFrame,
    parameters: DetectionParameters,
) -> tuple[Dimension, Factor | None]:
    """Actions the observation used that the baseline never records."""
    metric = RiskMetric.NOVEL_ACTION
    baseline_samples = sum(baseline.actions.values())
    if baseline_samples < parameters.min_baseline_events:
        return _insufficient(metric, InsufficiencyReason.BASELINE_EMPTY), None
    if not baseline.actions:
        return _insufficient(metric, InsufficiencyReason.BASELINE_NO_HISTORY), None

    novel = {
        action: count
        for action, count in observation.actions.items()
        if action not in baseline.actions and count >= parameters.min_novel_occurrences
    }
    observed = float(sum(novel.values()))
    items = tuple(
        FactorItem(kind=FactorItemKind.ACTION, value=action, occurrences=count)
        for action, count in sorted(novel.items())
    )
    factor = (
        Factor(
            type=DetectionType.NOVEL_ACTION,
            metric=metric,
            observed=observed,
            baseline_mean=None,
            baseline_stddev=None,
            upper_bound=None,
            lower_bound=None,
            threshold_multiple=None,
            threshold_occurrences=parameters.min_novel_occurrences,
            baseline_samples=baseline_samples,
            observation_samples=sum(observation.actions.values()),
            items=items,
        )
        if items
        else None
    )
    dimension = Dimension(
        metric=metric,
        status=DimensionStatus.DEVIATION if factor else DimensionStatus.MEASURED,
        reason=None,
        observed=observed,
        baseline_mean=None,
        baseline_stddev=None,
        upper_bound=None,
        lower_bound=None,
        baseline_samples=baseline_samples,
        observation_samples=sum(observation.actions.values()),
        detection_types=(factor.type,) if factor else (),
    )
    return dimension, factor


def _novel_resource_dimension(
    *,
    observation: ActivityFrame,
    baseline: ActivityFrame,
    parameters: DetectionParameters,
) -> tuple[Dimension, Factor | None]:
    """Resources the observation addressed that the baseline never records."""
    metric = RiskMetric.NOVEL_RESOURCE
    baseline_samples = sum(baseline.resources.values())
    if baseline_samples < parameters.min_baseline_events:
        return _insufficient(metric, InsufficiencyReason.BASELINE_EMPTY), None
    if not baseline.resources:
        return _insufficient(metric, InsufficiencyReason.BASELINE_NO_HISTORY), None

    novel = {
        key: count
        for key, count in observation.resources.items()
        if key not in baseline.resources and count >= parameters.min_novel_occurrences
    }
    observed = float(sum(novel.values()))
    items = tuple(
        FactorItem(
            kind=FactorItemKind.RESOURCE,
            value=str(key.resource_id),
            occurrences=count,
            resource_type=key.resource_type,
        )
        for key, count in sorted(novel.items())
    )
    factor = (
        Factor(
            type=DetectionType.NOVEL_RESOURCE,
            metric=metric,
            observed=observed,
            baseline_mean=None,
            baseline_stddev=None,
            upper_bound=None,
            lower_bound=None,
            threshold_multiple=None,
            threshold_occurrences=parameters.min_novel_occurrences,
            baseline_samples=baseline_samples,
            observation_samples=sum(observation.resources.values()),
            items=items,
        )
        if items
        else None
    )
    dimension = Dimension(
        metric=metric,
        status=DimensionStatus.DEVIATION if factor else DimensionStatus.MEASURED,
        reason=None,
        observed=observed,
        baseline_mean=None,
        baseline_stddev=None,
        upper_bound=None,
        lower_bound=None,
        baseline_samples=baseline_samples,
        observation_samples=sum(observation.resources.values()),
        detection_types=(factor.type,) if factor else (),
    )
    return dimension, factor


def _unusual_time_dimension(
    *,
    observation: ActivityFrame,
    baseline: ActivityFrame,
    parameters: DetectionParameters,
) -> tuple[Dimension, Factor | None]:
    """Clock hours the observation is active in that the baseline never is.

    The weakest dimension in the engine, and it says so: it needs a baseline that both
    holds enough events and covers enough distinct hours, because "this agent was active at
    03:00" only means something if its history says which hours it is active in. It is a
    first-occurrence finding, so it can never carry a level above ``low`` on its own.
    """
    metric = RiskMetric.UNUSUAL_TIME
    baseline_hours = baseline.active_hours
    baseline_events = baseline.totals.events
    if baseline_events < parameters.min_baseline_events:
        return _insufficient(metric, InsufficiencyReason.BASELINE_EMPTY), None
    if len(baseline_hours) < parameters.min_distinct_hours:
        return _insufficient(metric, InsufficiencyReason.BASELINE_NO_HOURS), None

    unusual = {
        hour: count
        for hour, count in observation.events_by_active_hour().items()
        if hour not in baseline_hours
    }
    observed = float(sum(unusual.values()))
    items = tuple(
        FactorItem(kind=FactorItemKind.HOUR, value=f"{hour:02d}", occurrences=count)
        for hour, count in sorted(unusual.items())
        if count >= parameters.min_novel_occurrences
    )
    factor = (
        Factor(
            type=DetectionType.UNUSUAL_TIME,
            metric=metric,
            observed=observed,
            baseline_mean=None,
            baseline_stddev=None,
            upper_bound=None,
            lower_bound=None,
            threshold_multiple=None,
            threshold_occurrences=parameters.min_novel_occurrences,
            baseline_samples=len(baseline_hours),
            observation_samples=observation.totals.events,
            items=items,
        )
        if items
        else None
    )
    dimension = Dimension(
        metric=metric,
        status=DimensionStatus.DEVIATION if factor else DimensionStatus.MEASURED,
        reason=None,
        observed=observed,
        baseline_mean=None,
        baseline_stddev=None,
        upper_bound=None,
        lower_bound=None,
        baseline_samples=len(baseline_hours),
        observation_samples=observation.totals.events,
        detection_types=(factor.type,) if factor else (),
    )
    return dimension, factor


#: The order the dimensions are reported in: rate deviations first, then first-occurrence
#: findings — the same order the factors are collected in, so the response reads the way
#: the level was computed. Written as data so the report order is one fact rather than an
#: accident of call order.
DIMENSION_ORDER: tuple[RiskMetric, ...] = (
    RiskMetric.ACTION_RATE,
    RiskMetric.FAILURE_RATE,
    RiskMetric.DENIAL_RATE,
    RiskMetric.NOVEL_ACTION,
    RiskMetric.NOVEL_RESOURCE,
    RiskMetric.UNUSUAL_TIME,
)

#: The order factors are collected in, strongest first. A rate deviation with a measured
#: bound comes before a first-occurrence finding, and within each group the vocabulary's
#: own order decides, so the list — and therefore the ``detection_type`` at its head — is
#: stable across runs and cannot depend on dictionary iteration.
FACTOR_ORDER: tuple[DetectionType, ...] = (
    DetectionType.ACTION_RATE_SPIKE,
    DetectionType.ACTION_RATE_DROP,
    DetectionType.FAILURE_RATE_SPIKE,
    DetectionType.DENIAL_RATE_SPIKE,
    DetectionType.NOVEL_ACTION,
    DetectionType.NOVEL_RESOURCE,
    DetectionType.UNUSUAL_TIME,
)


def assess_agent(
    *,
    agent_id: uuid.UUID,
    observation: ActivityFrame,
    baseline: ActivityFrame,
    parameters: DetectionParameters = DEFAULT_PARAMETERS,
) -> Assessment:
    """Assess one agent over one observation window against one baseline.

    The six dimensions are always reported, in :data:`DIMENSION_ORDER`, whether or not they
    produced a factor. The level follows from the factor *counts* alone, and the status
    follows from what happened: a deviation makes it ``deviating``, a measurable window
    with no deviation makes it ``within_baseline``, and a window where nothing could be
    measured makes it ``insufficient_data`` — never an anomaly, which is the whole point of
    the cold-start rule.
    """
    dimensions: list[Dimension] = []
    factors: list[Factor] = []

    rate_dimension, rate_factor = _action_rate_dimension(
        observation=observation, baseline=baseline, parameters=parameters
    )
    dimensions.append(rate_dimension)
    if rate_factor is not None:
        factors.append(rate_factor)

    for metric, detection_type in (
        (RiskMetric.FAILURE_RATE, DetectionType.FAILURE_RATE_SPIKE),
        (RiskMetric.DENIAL_RATE, DetectionType.DENIAL_RATE_SPIKE),
    ):
        dimension, factor = _ratio_dimension(
            metric=metric,
            detection_type=detection_type,
            observation=observation,
            baseline=baseline,
            parameters=parameters,
        )
        dimensions.append(dimension)
        if factor is not None:
            factors.append(factor)

    for builder in (_novel_action_dimension, _novel_resource_dimension, _unusual_time_dimension):
        dimension, factor = builder(
            observation=observation, baseline=baseline, parameters=parameters
        )
        dimensions.append(dimension)
        if factor is not None:
            factors.append(factor)

    by_type = {factor.type: factor for factor in factors}
    ordered = tuple(
        by_type[detection_type] for detection_type in FACTOR_ORDER if detection_type in by_type
    )

    strong = sum(1 for factor in ordered if factor.type in STRONG_DETECTION_TYPES)
    weak = len(ordered) - strong
    extreme = any(
        deviation_is_extreme(
            detection_type=factor.type,
            observed=factor.observed,
            baseline_mean=(factor.baseline_mean if factor.baseline_mean is not None else 0.0),
            upper_bound=factor.upper_bound,
            parameters=parameters,
        )
        for factor in ordered
        if factor.type in STRONG_DETECTION_TYPES
    )
    level = assess_risk_level(strong=strong, weak=weak, extreme=extreme)

    if ordered:
        status = AssessmentStatus.DEVIATING
    elif any(dimension.status is DimensionStatus.MEASURED for dimension in dimensions):
        status = AssessmentStatus.WITHIN_BASELINE
    else:
        status = AssessmentStatus.INSUFFICIENT_DATA

    return Assessment(
        entity_type=EntityType.AGENT,
        entity_id=agent_id,
        status=status,
        anomaly=bool(ordered),
        risk_level=level,
        dimensions=tuple(dimensions),
        factors=ordered,
    )
