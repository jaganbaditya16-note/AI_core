"""The vocabulary, the thresholds and the arithmetic of an assessment.

Phase 10 answers one question about one entity over one window: *how does what happened
differ from what usually happens?* Everything in this module exists to make that question
answerable in exactly one way, twice in a row, and — more importantly — to make the answer
**checkable by the person reading it**.

Four commitments shape the code.

**Every conclusion is reproducible from published numbers.** A finding is never a bare
score. Each dimension reports the quantity it measured, the baseline's mean and spread over
a stated number of hourly samples, and the bound the measurements were compared against;
each factor reports the same figures plus the items it rests on. A reader who disagrees can
recompute the bound from ``mean``, ``deviation_multiple`` and the sample count and see the
comparison for themselves.

**The statistics are total, and their degenerate cases are named.** A baseline with one
sample has no spread; a mean of zero has no ratio; a bucket with no executions has no
failure *rate* rather than a rate of zero. Each of those is a distinct, closed
:class:`InsufficiencyReason` — reported instead of extrapolated, and never converted into a
finding. This is the section a reviewer should read first: the way a detector lies is by
turning "not enough data" into "anomaly".

**Thresholds are server configuration, not input.** The parameters below are defaults that
a deployment can override through settings; nothing in the API accepts a threshold, a mean,
a bound, a level or a window from a client, and there is no request field named after any of
them.

**The vocabulary is closed.** Seven detection types, six metrics, five levels, four
baselines, three statuses, seven reasons for having no measurement. New members are added
when a rule can compute them from data the trail actually holds — never because a name
sounds plausible.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

from aicore_api.core.audit import AuditEventType
from aicore_api.core.monitoring import (
    MonitoringWindow,
    MonitoringWindowError,
    ResolvedWindow,
    TimeInterval,
    bucket_start,
    resolve_window,
)

if TYPE_CHECKING:  # pragma: no cover - import cycle discipline
    from aicore_api.config import Settings

__all__ = [
    "ACTION_PIPELINE_TYPES",
    "BASELINE_SPANS",
    "DEFAULT_BASELINE",
    "DEFAULT_PARAMETERS",
    "DETECTION_METRICS",
    "LEVEL_RULES",
    "MAX_BASELINE_WINDOW",
    "MIN_BASELINE_BUCKETS",
    "RISK_SCHEMA_VERSION",
    "STRONG_DETECTION_TYPES",
    "WEAK_DETECTION_TYPES",
    "ActivityFrame",
    "AssessmentStatus",
    "Baseline",
    "BaselineWindow",
    "BucketCounts",
    "DetectionParameters",
    "DetectionType",
    "DimensionStatus",
    "EntityType",
    "InsufficiencyReason",
    "ResourceKey",
    "RiskError",
    "RiskLevel",
    "RiskMetric",
    "RiskThresholdError",
    "RiskWindowError",
    "WindowTotals",
    "assess_risk_level",
    "deviation_is_extreme",
    "hour_bucket",
    "is_full_bucket",
    "mean",
    "population_stddev",
    "resolve_baseline",
    "resolve_observation",
]

#: The action-pipeline events this engine analyses, derived from the audit vocabulary rather
#: than listed again: a frame is the pipeline, and an event type outside it is not this
#: engine's subject. Derived so that a type added to the pipeline is analysed on the day it
#: is added, and a type removed stops being analysed on the day it is removed.
ACTION_PIPELINE_TYPES: frozenset[AuditEventType] = frozenset(
    {
        AuditEventType.ACTION_REQUESTED,
        AuditEventType.ACTION_DENIED,
        AuditEventType.ACTION_REQUIRE_APPROVAL,
        AuditEventType.ACTION_EXECUTED,
        AuditEventType.ACTION_FAILED,
        AuditEventType.ACTION_REPLAYED,
    }
)

#: The version of the assessment shape this module produces. It is part of a detection's
#: identity: if the meaning of a factor changes, records written under the old meaning stay
#: distinguishable from records written under the new one instead of quietly disagreeing.
RISK_SCHEMA_VERSION = 1

#: The unit every baseline is measured in. One hour, matching the clock: a baseline is a
#: distribution of hourly bucket counts, which is why the sample minimums below are counts
#: of hours.
BUCKET = timedelta(hours=1)


class RiskError(ValueError):
    """A risk request or configuration that cannot be honoured."""


class RiskWindowError(RiskError):
    """An observation window or a baseline that cannot be resolved."""


class RiskThresholdError(RiskError):
    """A detection parameter outside the range the arithmetic supports."""


class EntityType(StrEnum):
    """What an assessment is about.

    One member, and it is the only subject the trail can attribute events to. The type is a
    field rather than an assumption because a detection record outlives the code that wrote
    it: a later phase that assesses something else must be able to say so in the row.
    """

    AGENT = "agent"


class RiskMetric(StrEnum):
    """The six quantities this engine measures, one per dimension of an assessment.

    A metric states *what was measured*, not what was found: ``action_rate`` is a rate of
    action requests per hour whether or not it deviated, and the deviation — if there is one
    — is a :class:`DetectionType` naming which direction it went.
    """

    ACTION_RATE = "action_rate"
    FAILURE_RATE = "failure_rate"
    DENIAL_RATE = "denial_rate"
    NOVEL_ACTION = "novel_action"
    NOVEL_RESOURCE = "novel_resource"
    UNUSUAL_TIME = "unusual_time"


class DetectionType(StrEnum):
    """The closed set of deviations this engine will report.

    Seven members, and each one is computable from what the trail actually stores: two
    directions of the action rate, a spike in each of the two ratios, a first use of an
    action or a resource, and activity in an hour the entity is never active in. Anything
    else — a "suspicious pattern", a "lateral movement", a "possible compromise" — would be
    a name with no measurement behind it, which is the thing this phase exists not to ship.
    """

    ACTION_RATE_SPIKE = "action_rate_spike"
    ACTION_RATE_DROP = "action_rate_drop"
    FAILURE_RATE_SPIKE = "failure_rate_spike"
    DENIAL_RATE_SPIKE = "denial_rate_spike"
    NOVEL_ACTION = "novel_action"
    NOVEL_RESOURCE = "novel_resource"
    UNUSUAL_TIME = "unusual_time"


#: Which metric each detection type is produced by. The mapping is the reason a factor's
#: ``type`` and its ``metric`` can never disagree.
DETECTION_METRICS: Mapping[DetectionType, RiskMetric] = MappingProxyType(
    {
        DetectionType.ACTION_RATE_SPIKE: RiskMetric.ACTION_RATE,
        DetectionType.ACTION_RATE_DROP: RiskMetric.ACTION_RATE,
        DetectionType.FAILURE_RATE_SPIKE: RiskMetric.FAILURE_RATE,
        DetectionType.DENIAL_RATE_SPIKE: RiskMetric.DENIAL_RATE,
        DetectionType.NOVEL_ACTION: RiskMetric.NOVEL_ACTION,
        DetectionType.NOVEL_RESOURCE: RiskMetric.NOVEL_RESOURCE,
        DetectionType.UNUSUAL_TIME: RiskMetric.UNUSUAL_TIME,
    }
)

#: The detection types that carry a statistical bound: a quantity was measured, a baseline
#: distribution gave it a threshold, and the measurement crossed it. These are the strong
#: evidence, and their *count* is what the level ladder below counts.
STRONG_DETECTION_TYPES: frozenset[DetectionType] = frozenset(
    {
        DetectionType.ACTION_RATE_SPIKE,
        DetectionType.ACTION_RATE_DROP,
        DetectionType.FAILURE_RATE_SPIKE,
        DetectionType.DENIAL_RATE_SPIKE,
    }
)

#: The detection types that report a first occurrence or an uncovered clock hour. Real
#: evidence — an agent doing something it has never done is worth stating — but weak on its
#: own, because novelty is not a rate and cannot be measured against one.
WEAK_DETECTION_TYPES: frozenset[DetectionType] = frozenset(
    {
        DetectionType.NOVEL_ACTION,
        DetectionType.NOVEL_RESOURCE,
        DetectionType.UNUSUAL_TIME,
    }
)


class DimensionStatus(StrEnum):
    """How one metric's examination ended.

    ``measured`` means the comparison ran and stayed inside the baseline's bounds;
    ``deviation`` means it ran and crossed them; ``insufficient_data`` means it could not run
    at all, and the dimension says why. There is no fourth state: a dimension is either a
    number or a stated refusal.
    """

    MEASURED = "measured"
    DEVIATION = "deviation"
    INSUFFICIENT_DATA = "insufficient_data"


class InsufficiencyReason(StrEnum):
    """Why a dimension has no measurement.

    Seven closed reasons, each of which a reader can act on. They exist so that "we did not
    look" and "there was nothing to look at" and "there was not enough of it" are three
    different statements rather than a null.
    """

    #: Fewer full hourly buckets in the baseline than the minimum.
    BASELINE_TOO_SHORT = "baseline_too_short"
    #: Fewer events in the baseline window than the minimum.
    BASELINE_EMPTY = "baseline_empty"
    #: The baseline holds no usable history for this metric: no actions to compare against,
    #: or a mean of zero with no scale to deviate from.
    BASELINE_NO_SIGNAL = "baseline_no_signal"
    #: Fewer baseline buckets carrying a defined ratio than the minimum.
    BASELINE_INSUFFICIENT_SAMPLES = "baseline_insufficient_samples"
    #: Fewer observations in the *observation* window than the minimum, so a ratio computed
    #: from it would be a number about two events rather than about behaviour.
    OBSERVATION_INSUFFICIENT_SAMPLES = "observation_insufficient_samples"
    #: The baseline does not cover enough distinct clock hours to say which hours are usual.
    BASELINE_NO_HOURS = "baseline_no_hours"
    #: The baseline holds no actions or resources at all, so nothing can be novel.
    BASELINE_NO_HISTORY = "baseline_no_history"


class AssessmentStatus(StrEnum):
    """The outcome of one assessment, stated before its details.

    ``insufficient_data`` is the one that matters most: an entity the platform has not
    watched enough is *not* assessed as anomalous for being new. A deviation makes the
    status ``deviating``; a comparison that ran and found nothing makes it
    ``within_baseline``; a window in which nothing could be compared makes it
    ``insufficient_data``.
    """

    INSUFFICIENT_DATA = "insufficient_data"
    WITHIN_BASELINE = "within_baseline"
    DEVIATING = "deviating"


class RiskLevel(StrEnum):
    """How much corroborated evidence an assessment carries.

    Five members, assigned by a published table over *counts of factors* — see
    :func:`assess_risk_level`. It is not a probability, not a confidence and not an incident
    severity: ``high`` means "several independent measurements deviate from this entity's own
    history", which is a statement about the data. Nothing here is a claim about intent, and
    nothing here is a diagnosis.
    """

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BaselineWindow(StrEnum):
    """The history an observation is compared against.

    Four named spans, all anchored so that the baseline *ends where the observation
    begins*. That is what keeps an observation out of its own baseline: the engine never
    subtracts a window from itself, and the database states the same rule as a constraint
    on the stored record.

    There is deliberately no ``all`` and no ``since registration``: a baseline with no
    maximum is a query whose cost grows with the tenant's age, which is the unbounded scan
    Phase 9 refused and this phase refuses for the same reason. Thirty days is the ceiling,
    and a longer history is a reporting job with its own storage.
    """

    ONE_DAY = "24h"
    SEVEN_DAYS = "7d"
    FOURTEEN_DAYS = "14d"
    THIRTY_DAYS = "30d"


#: How long each baseline spans. A whole number of days, because a baseline that ended
#: mid-afternoon would compare a morning-heavy observation against a mostly-night
#: baseline for no reason a reader could see.
BASELINE_SPANS: Mapping[BaselineWindow, timedelta] = MappingProxyType(
    {
        BaselineWindow.ONE_DAY: timedelta(days=1),
        BaselineWindow.SEVEN_DAYS: timedelta(days=7),
        BaselineWindow.FOURTEEN_DAYS: timedelta(days=14),
        BaselineWindow.THIRTY_DAYS: timedelta(days=30),
    }
)

#: The baseline a request gets when it does not name one. A week: enough buckets for a
#: distribution to mean something (168 hours), and short enough that a deliberate change
#: in an entity's behaviour stops being a deviation within a fortnight rather than a month.
DEFAULT_BASELINE = BaselineWindow.SEVEN_DAYS

#: The longest baseline this build will compute. Equal to the longest named span, and
#: stated separately so that "we cap history at a month" is one grep away.
MAX_BASELINE_WINDOW = timedelta(days=30)

#: The minimum number of full hourly buckets a rate comparison needs. Twelve: a
#: distribution needs more than a handful of samples to have a standard deviation worth
#: comparing against, and a week of history provides 167 or 168 of them.
MIN_BASELINE_BUCKETS = 12


@dataclass(frozen=True, slots=True)
class DetectionParameters:
    """The thresholds a comparison uses, all of them server-side.

    Defaults are documented; a deployment changes them through configuration
    (:meth:`from_settings`), and a request changes nothing — there is no field anywhere in
    the API for a mean, a bound, a threshold, a level or a confidence, so tuning the
    detector is not something a caller can attempt.

    Every threshold is a *floor on evidence* as much as a cut-off: the sample minimums
    exist so that the engine answers ``insufficient_data`` rather than reporting a ratio
    computed from two events as though it were a rate.
    """

    #: How many standard deviations from the baseline mean the observation must be to
    #: cross a bound. Two is the conventional "outside the ordinary spread"; it is not a
    #: probability and is not reported as one.
    deviation_multiple: float = 2.0
    #: When a rate deviation is *extreme*: the observation is at least this many times its
    #: own bound (or this fraction of the mean, for a drop). One input to the level table.
    extreme_multiple: float = 3.0
    #: The ratio between the observation and the baseline mean required in addition to
    #: the bound. Statistical significance at small counts is not interesting on its own:
    #: three standard deviations around a mean of two per hour is eight events, which is a
    #: quiet afternoon rather than a finding.
    rate_change_ratio: float = 2.0
    #: Minimum full hourly buckets in the baseline.
    min_baseline_buckets: int = MIN_BASELINE_BUCKETS
    #: Minimum events in the baseline window before any rate is compared.
    min_baseline_events: int = 20
    #: Minimum baseline buckets carrying a defined ratio, for the two ratio dimensions.
    min_ratio_samples: int = 8
    #: Minimum events in the *observation* window before a ratio is computed. Without it,
    #: "one request, one refusal" would be reported as a denial rate of 1.0.
    min_observed_samples: int = 4
    #: Minimum distinct clock hours the baseline must cover before an hour can be unusual.
    min_distinct_hours: int = 4
    #: How many occurrences of a novel action or resource it takes to report one. One:
    #: the first use of something an entity has never used is a deviation from its own
    #: history, and it is reported as the weak evidence it is rather than as nothing.
    min_novel_occurrences: int = 1

    def __post_init__(self) -> None:
        """Refuse parameters the arithmetic cannot support."""
        if self.deviation_multiple < 0:
            raise RiskThresholdError("deviation_multiple must not be negative")
        if self.extreme_multiple < 1:
            raise RiskThresholdError(
                "extreme_multiple must be at least 1: an extreme deviation is at least its "
                "own bound, and a bound of zero has no multiple at all"
            )
        if self.rate_change_ratio <= 1:
            raise RiskThresholdError(
                "rate_change_ratio must be greater than 1: a deviation the size of the "
                "baseline mean is not a change in behaviour"
            )
        if self.min_baseline_buckets < 1:
            raise RiskThresholdError("min_baseline_buckets must be at least 1")
        if self.min_baseline_events < 1:
            raise RiskThresholdError("min_baseline_events must be at least 1")
        if self.min_ratio_samples < 1:
            raise RiskThresholdError("min_ratio_samples must be at least 1")
        if self.min_observed_samples < 1:
            raise RiskThresholdError("min_observed_samples must be at least 1")
        if not 0 <= self.min_distinct_hours <= 24:
            raise RiskThresholdError("min_distinct_hours must be between 0 and 24")
        if self.min_novel_occurrences < 1:
            raise RiskThresholdError("min_novel_occurrences must be at least 1")

    @classmethod
    def from_settings(cls, settings: Settings) -> DetectionParameters:
        """The parameters a deployment configured.

        The mapping is explicit rather than reflective: every threshold is named in both
        places, so adding one to the settings without deciding what it does to a
        comparison is not possible by accident.
        """
        return cls(
            deviation_multiple=settings.risk_deviation_multiple,
            extreme_multiple=settings.risk_extreme_multiple,
            rate_change_ratio=settings.risk_rate_change_ratio,
            min_baseline_buckets=settings.risk_min_baseline_buckets,
            min_baseline_events=settings.risk_min_baseline_events,
            min_ratio_samples=settings.risk_min_ratio_samples,
            min_observed_samples=settings.risk_min_observed_samples,
            min_distinct_hours=settings.risk_min_distinct_hours,
            min_novel_occurrences=settings.risk_min_novel_occurrences,
        )


#: The parameters this build uses unless a deployment says otherwise.
DEFAULT_PARAMETERS = DetectionParameters()


@dataclass(frozen=True, slots=True)
class Baseline:
    """A decided baseline: which named span, and the interval it covers.

    ``end`` is the observation's start, always — the constructor refuses anything else,
    because the two windows are only independent if one of them cannot contain the other.
    """

    name: BaselineWindow
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        """Refuse a baseline that is naive, empty, mislabelled or too long."""
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise RiskWindowError(
                "a baseline is timezone-aware: a naive bound would be read against the "
                "server's locale, and two servers would disagree about the same history"
            )
        if self.end <= self.start:
            raise RiskWindowError("a baseline ends after it starts")
        span = self.end - self.start
        if span != BASELINE_SPANS[self.name]:
            raise RiskWindowError(
                f"a baseline named {self.name.value!r} spans "
                f"{BASELINE_SPANS[self.name].days} days, not {span.days} days and "
                f"{span.seconds // 3600} hours"
            )

    @property
    def buckets(self) -> int:
        """How many hourly buckets the span holds. Exact, because spans are whole days."""
        return int((self.end - self.start) / BUCKET)


def resolve_baseline(
    *, name: BaselineWindow | str | None = None, observation_start: datetime
) -> Baseline:
    """The baseline for an observation that starts at ``observation_start``.

    Anchored rather than centred or trailing-from-now: the baseline ends exactly where the
    observation begins, which is the only arrangement in which "the observation is not in
    its own baseline" is structural. ``observation_start`` comes from the resolved
    observation window — never from a client's clock on its own.
    """
    if name is None:
        name = DEFAULT_BASELINE
    try:
        resolved = BaselineWindow(name)
    except ValueError as exc:
        declared = ", ".join(member.value for member in BaselineWindow)
        raise RiskWindowError(f"{name!r} is not a declared baseline; declared: {declared}") from exc
    if observation_start.tzinfo is None:
        raise RiskWindowError("the observation start must be timezone-aware")
    return Baseline(
        name=resolved,
        start=observation_start - BASELINE_SPANS[resolved],
        end=observation_start,
    )


def resolve_observation(
    *,
    window: MonitoringWindow | str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    now: datetime | None = None,
) -> ResolvedWindow:
    """The observation window, using Phase 9's vocabulary and rules.

    The same five named spans, the same ``custom`` escape hatch, the same refusals (a
    naive timestamp, one open end, a range longer than a month, a bound sent without
    ``custom``) — an assessment and a measurement must agree about what "the last hour"
    means, and the surest way to make them agree is for both to resolve it in one place.

    One rule is added here. Phase 9 permits a zero-length window, because "how many events
    happened between 10:00 and 10:00" has an answer: none. A *rate* does not — the divisor
    is the span — so this phase refuses an empty interval rather than reporting a rate of
    zero per hour for a window that is not an hour.
    """
    try:
        resolved = resolve_window(window=window, start_time=start_time, end_time=end_time, now=now)
    except MonitoringWindowError as exc:
        raise RiskWindowError(str(exc)) from exc
    if resolved.end <= resolved.start:
        raise RiskWindowError(
            "an observation window must have a duration: a rate over no time is not a "
            "measurement, so a window that starts and ends at the same instant is refused"
        )
    return resolved


# ── The arithmetic ────────────────────────────────────────────────────────────


def mean(values: Iterable[float]) -> float:
    """The arithmetic mean, or ``0.0`` for no values.

    Total by construction: an empty baseline is a condition the caller checks with
    :class:`InsufficiencyReason`, and the arithmetic itself must not raise on the way
    there.
    """
    samples = list(values)
    if not samples:
        return 0.0
    return sum(samples) / len(samples)


def population_stddev(values: Iterable[float]) -> float:
    """The population standard deviation, or ``0.0`` when there is no spread to measure.

    Population rather than sample: the buckets *are* the baseline, not a sample drawn
    from a longer history — there is no larger population being estimated, so there is no
    reason to inflate the spread. Zero variance (every bucket identical) is therefore a
    standard deviation of zero and an upper bound equal to the mean, which is a real
    statement: "this entity does exactly this much, every hour". A single sample has no
    spread either, and returns ``0.0`` rather than dividing by zero; the sample minimums
    above are what stop that value from being *used*, not this function.
    """
    samples = list(values)
    if len(samples) < 2:
        return 0.0
    average = mean(samples)
    variance = sum((sample - average) ** 2 for sample in samples) / len(samples)
    return variance**0.5


def hour_bucket(moment: datetime) -> datetime:
    """The UTC hour bucket an instant falls in. Phase 9's flooring, reused.

    Reused rather than reimplemented so that a bucket in a risk response and a bucket in a
    monitoring series are the same interval by construction; ``test_risk.py`` asserts the
    two agree for a spread of instants and session timezones.
    """
    return bucket_start(moment, TimeInterval.HOUR)


def is_full_bucket(bucket: datetime, *, start: datetime, end: datetime) -> bool:
    """Whether an hourly bucket lies entirely inside ``[start, end]``.

    Only full buckets become baseline samples. The first and last bucket of a window that
    is not hour-aligned hold less than an hour of history, so counting them would lower
    the mean for a reason that has nothing to do with the entity's behaviour — and, worse,
    it would make the same baseline depend on the second of the day it was computed.
    """
    return bucket >= start and bucket + BUCKET <= end


def deviation_is_extreme(
    *,
    detection_type: DetectionType,
    observed: float,
    baseline_mean: float,
    upper_bound: float | None,
    parameters: DetectionParameters = DEFAULT_PARAMETERS,
) -> bool:
    """Whether a rate deviation is extreme, as the level table defines it.

    Extreme means "far outside", measured against the deviation's own threshold: a spike
    is extreme when it is at least ``extreme_multiple`` times the upper bound it crossed,
    a drop when it is at most a ``extreme_multiple``-th of the mean it fell from. A bound
    or a mean of zero has no multiple to take, and such a deviation is never extreme —
    the conservative direction, since "several times an unmeasurable amount" is not a
    larger amount.
    """
    if detection_type is DetectionType.ACTION_RATE_SPIKE:
        return (
            upper_bound is not None
            and upper_bound > 0
            and observed >= (upper_bound * parameters.extreme_multiple)
        )
    if detection_type is DetectionType.ACTION_RATE_DROP:
        return baseline_mean > 0 and observed <= baseline_mean / parameters.extreme_multiple
    if detection_type in {
        DetectionType.FAILURE_RATE_SPIKE,
        DetectionType.DENIAL_RATE_SPIKE,
    }:
        return (
            upper_bound is not None
            and upper_bound > 0
            and observed >= (upper_bound * parameters.extreme_multiple)
        )
    return False


#: The level table, as data: the condition that assigns each level on the left, the level
#: on the right, and the first row that matches wins. It is a table rather than a formula
#: because a formula would need a score, and a score is exactly the thing this phase
#: refuses to publish: every row below is a sentence about *how many measured things
#: deviated*, and a reader can check which row a response fell into.
LEVEL_RULES: tuple[tuple[str, RiskLevel], ...] = (
    ("strong >= 3 and extreme", RiskLevel.CRITICAL),
    ("strong >= 2", RiskLevel.HIGH),
    ("strong == 1 and extreme and weak >= 1", RiskLevel.HIGH),
    ("strong == 1 and (extreme or weak >= 1)", RiskLevel.MEDIUM),
    ("weak >= 2", RiskLevel.MEDIUM),
    ("strong == 1 or weak == 1", RiskLevel.LOW),
    ("otherwise", RiskLevel.NONE),
)


def assess_risk_level(*, strong: int, weak: int, extreme: bool) -> RiskLevel:
    """The level for a set of factors, by the table above.

    ``strong`` is the number of distinct rate deviations (each with a measured bound),
    ``weak`` the number of distinct first-occurrence findings, and ``extreme`` whether any
    strong deviation is extreme. Corroboration between independent measurements is what
    moves the level upward; a single deviation is reported at a low level however large it
    is, because largeness is what ``extreme`` states and it is folded into the rows above
    rather than being a level of its own.

    The table is total: every combination of non-negative counts and a boolean lands on
    exactly one row.
    """
    if strong < 0 or weak < 0:  # pragma: no cover - callers pass counts
        raise RiskThresholdError("factor counts are not negative")
    if strong >= 3 and extreme:
        return RiskLevel.CRITICAL
    if strong >= 2:
        return RiskLevel.HIGH
    if strong == 1 and extreme and weak >= 1:
        return RiskLevel.HIGH
    if strong == 1 and (extreme or weak >= 1):
        return RiskLevel.MEDIUM
    if weak >= 2:
        return RiskLevel.MEDIUM
    if strong == 1 or weak == 1:
        return RiskLevel.LOW
    return RiskLevel.NONE


# ── The frames two windows are compared as ────────────────────────────────────


@dataclass(frozen=True, slots=True)
class BucketCounts:
    """One UTC clock hour of one entity's action-pipeline activity.

    The frame's atom, and the only thing a baseline distribution is made of. ``events`` is
    the sum of the five kinds named beside it, so a bucket cannot report a total that its
    own breakdown disagrees with; the breakdown is what the two ratio dimensions read.
    """

    bucket: datetime
    events: int
    requests: int
    executions: int
    failures: int
    denials: int
    approval_required: int
    replays: int

    @property
    def completed(self) -> int:
        """Executions that finished in this hour: successes plus failures.

        The denominator of the hour's failure rate. Computed rather than stored for the
        same reason a frame's totals are: two counts that could disagree is one count too
        many.
        """
        return self.executions + self.failures


@dataclass(frozen=True, slots=True, order=True)
class ResourceKey:
    """A resource as the trail names it: a type and an identifier.

    Ordered so that a set of them sorts the same way twice — the evidence lists in a
    response are built by sorting, and a response whose item order depended on set
    iteration would not be reproducible.
    """

    resource_type: str
    resource_id: uuid.UUID

    def __str__(self) -> str:
        """The pair as the single string an evidence item carries."""
        return f"{self.resource_type}:{self.resource_id}"


@dataclass(frozen=True, slots=True)
class WindowTotals:
    """The sums of a frame's buckets, computed once and reported as the measurement."""

    events: int
    requests: int
    executions: int
    failures: int
    denials: int
    approval_required: int
    replays: int

    @property
    def completed(self) -> int:
        """Executions that finished: the denominator of the failure rate.

        ``executions + failures`` rather than a separate count, because those are the two
        terminal outcomes the pipeline records and a third count could disagree with them.
        """
        return self.executions + self.failures


@dataclass(frozen=True, slots=True)
class ActivityFrame:
    """One entity's action-pipeline activity over one window.

    The unit both sides of a comparison are expressed in: an observation frame and a
    baseline frame are the same shape, so the engine's arithmetic cannot accidentally treat
    one of them differently from the other.

    The frame is *the action pipeline* — requests, decisions, outcomes and replays. Lifecycle
    events are not in it: a registration or an asset change is not a unit of an agent's
    operating pattern, and mixing the two would make a rate mean two different things in two
    windows. ``events`` is therefore a count of pipeline events, and the two novelty
    dimensions read exactly the same population.
    """

    start: datetime
    end: datetime
    buckets: tuple[BucketCounts, ...]
    actions: Mapping[str, int]
    resources: Mapping[ResourceKey, int]

    def __post_init__(self) -> None:
        """Refuse a frame whose span cannot produce a rate."""
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise RiskWindowError(
                "a frame is timezone-aware: a naive bound would be read against the "
                "server's locale, and two servers would disagree about the same history"
            )
        if self.end <= self.start:
            raise RiskWindowError(
                "a frame must have a duration: a rate over no time is not a measurement"
            )

    @property
    def span_hours(self) -> float:
        """How long the frame covers, in hours. The divisor of every rate."""
        return (self.end - self.start).total_seconds() / 3600

    @property
    def totals(self) -> WindowTotals:
        """Every count in the window, summed from its buckets.

        Summed here rather than carried alongside so the totals cannot disagree with the
        distribution they are the summary of.
        """
        return WindowTotals(
            events=sum(bucket.events for bucket in self.buckets),
            requests=sum(bucket.requests for bucket in self.buckets),
            executions=sum(bucket.executions for bucket in self.buckets),
            failures=sum(bucket.failures for bucket in self.buckets),
            denials=sum(bucket.denials for bucket in self.buckets),
            approval_required=sum(bucket.approval_required for bucket in self.buckets),
            replays=sum(bucket.replays for bucket in self.buckets),
        )

    @property
    def active_hours(self) -> frozenset[int]:
        """The UTC clock hours this entity was active in.

        Read from the buckets, which PostgreSQL floored in UTC, so the answer does not
        depend on the session's timezone or the caller's. Activity only: an hour nobody did
        anything in is not an hour this entity was active in.
        """
        return frozenset(bucket.bucket.hour for bucket in self.buckets if bucket.events > 0)

    def events_by_active_hour(self) -> dict[int, int]:
        """How many events fell in each active clock hour, in UTC.

        The evidence behind an unusual-hour finding, computed from the same buckets as
        :attr:`active_hours` so the two cannot name different hours.
        """
        counted: dict[int, int] = {}
        for bucket in self.buckets:
            if bucket.events > 0:
                counted[bucket.bucket.hour] = counted.get(bucket.bucket.hour, 0) + bucket.events
        return counted

    def full_buckets(self) -> tuple[BucketCounts, ...]:
        """The buckets that lie entirely inside the window.

        Only these become baseline samples: a partial edge bucket holds less than an hour
        of history, and counting it would make the same baseline depend on the second of
        the day it was computed rather than on what the entity did.
        """
        return tuple(
            bucket
            for bucket in self.buckets
            if is_full_bucket(bucket.bucket, start=self.start, end=self.end)
        )
