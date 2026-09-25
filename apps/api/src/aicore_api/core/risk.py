"""The anomaly and risk engine: vocabulary, windows, statistics, detection and risk.

Phase 9 counts. This module is the pure half of Phase 10's answer to the next question —
*is any of it unusual, and how much should that matter?* — and, like Phase 9's core, it is
deliberately the half that touches nothing: no database, no clock, no request, no network.
Everything that decides whether a number is anomalous lives here, as arithmetic over
aggregates that the repository computed in PostgreSQL, so every rule can be tested with
plain values and every conclusion can be reproduced from its evidence.

    DISCOVER → IDENTITY → PERMISSION → POLICY → ACTION FIREWALL
      → CONTROLLED EXECUTION → AUDIT → MONITORING → **ANOMALY & RISK**

Phase 10 is the last box, and it is analytical only. Six decisions are encoded here rather
than left to call sites.

**The baseline and the observation never overlap.** :func:`resolve_analysis_windows` puts
the observation window at ``[as_of - observation, as_of)`` and the baseline immediately
before it, ``[observation_start - baseline, observation_start)``. Both are half-open, so an
event at exactly ``observation_start`` is in the observation and not in the baseline — the
baseline can never contain the thing it is being compared with. Both lengths come from
closed vocabularies (:class:`BaselineWindow`, :class:`ObservationWindow`): there is no
"all history" and no caller-chosen span, so every analysis is a bounded scan.

**Windows are aligned, so an analysis is reproducible.** ``as_of`` is a whole UTC hour and
never in the future. The same ``as_of`` over the same (append-only) trail produces the same
windows, the same aggregates and the same detections, which is what makes persisted
detections deduplicable by a fingerprint rather than by guesswork.

**Insufficient history is a state, not a verdict.** An entity whose baseline is too thin
(:data:`MIN_BASELINE_EVENTS`, :data:`MIN_HISTORY_SLOTS`, :data:`MIN_HISTORY_SPAN`,
:data:`MIN_ACTIVE_SLOTS`) is reported as :attr:`AnalysisStatus.INSUFFICIENT_HISTORY`, with
anomaly state :attr:`AnomalyState.UNDETERMINED`, risk :attr:`RiskLevel.NONE` and the
reasons it could not be assessed. It is never called anomalous because it is new, and no
baseline is fabricated for it — a brand-new agent would otherwise be "novel" at everything.

**Missing is not zero, and zero is not missing.** Slots before an entity's first baseline
event are *missing* (this build cannot tell "idle" from "did not exist yet") and are left
out of its statistics; slots after it with no events are *zero* and are counted. Zero
variance, empty baselines and sparse observations each have an explicit rule below rather
than a division that happens to work.

**The statistics are the ones a reviewer can redo by hand.** Mean and population standard
deviation over per-slot counts, a fixed ``k = 3`` and an absolute floor for rate changes;
fixed deltas for failure and denial rates; set difference for novelty; a zero-baseline-hour
rule for time; a peak-bucket comparison for frequency. No model, no score, no weight.

**Risk is a level with reasons, never a number.** :class:`RiskLevel` has five values and
every level above ``NONE`` is derived by a stated table (:data:`BASE_RISK`) and stated
escalations, each recorded as a :class:`RiskFactor`. There is no numeric risk score
anywhere in this phase, and nothing here — or anywhere the phase reaches — authorizes,
blocks, executes, suspends, approves, alerts or remediates. A detection is a finding; what
to do about it is a person's decision, taken through the phases that already own action.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any

__all__ = [
    "BASE_RISK",
    "BURST_BUCKET",
    "DEFAULT_BASELINE_WINDOW",
    "DEFAULT_OBSERVATION_WINDOW",
    "DETECTION_FACTORS",
    "DETECTION_SCHEMA_VERSION",
    "MAX_EVIDENCE_BYTES",
    "MIN_ACTIVE_SLOTS",
    "MIN_BASELINE_EVENTS",
    "MIN_HISTORY_SLOTS",
    "MIN_HISTORY_SPAN",
    "RISK_ENGINE_VERSION",
    "AgentAnalysis",
    "AgentProfile",
    "AnalysisStatus",
    "AnalysisWindows",
    "AnomalyState",
    "BaselineStatistics",
    "BaselineWindow",
    "CheckReason",
    "CheckStatus",
    "Detection",
    "DetectionCheck",
    "DetectionType",
    "EntityType",
    "FactorEffect",
    "InsufficientReason",
    "ObservationWindow",
    "RiskError",
    "RiskEvidenceError",
    "RiskFactor",
    "RiskFactorCode",
    "RiskLevel",
    "RiskWindowError",
    "analyze_agent",
    "baseline_statistics",
    "detection_fingerprint",
    "ensure_safe_evidence",
    "floor_to_hour",
    "raise_level",
    "resolve_analysis_windows",
]

#: The version of the detection rules below. Part of every fingerprint and every stored
#: row, so a rule change produces new detections instead of silently reinterpreting old
#: ones. Bumped when a threshold, a minimum or a formula changes.
RISK_ENGINE_VERSION = 1

#: The shape of a stored detection row. Bumped when a column is added or changes meaning.
DETECTION_SCHEMA_VERSION = 1


# ── Errors ────────────────────────────────────────────────────────────────────


class RiskError(ValueError):
    """An analysis request this build will not answer.

    A ``ValueError`` because every cause is a request that is well-formed but meaningless —
    an ``as_of`` in the future, a naive timestamp, a window pair that does not fit — and the
    routes translate it into a 422 naming the problem. Answering with an empty analysis
    would make a mistake look like "nothing unusual", which is the one answer a risk
    engine must never give by accident.
    """


class RiskWindowError(RiskError):
    """A baseline/observation window pair that cannot be resolved."""


class RiskEvidenceError(RuntimeError):
    """Evidence that is not a small structure of safe values.

    A ``RuntimeError`` (a defect, never a client error): evidence is built here from
    aggregates, so evidence that fails the check means the builder is wrong, and the
    failure must be loud rather than a secret quietly reaching a response or a table.
    """


# ── Windows ───────────────────────────────────────────────────────────────────


class BaselineWindow(StrEnum):
    """How much history an entity is compared against. Bounded, and closed.

    Seven days is the shortest span that contains every weekday once; thirty is the same
    ceiling Phase 9 applies to a custom monitoring range, so the longest analysis is the
    same bounded scan of one organization's slice of the trail that monitoring already
    performs. There is no ``all``: a baseline priced by how long a tenant has existed is
    the query this phase must never be able to run.
    """

    SEVEN_DAYS = "7d"
    FOURTEEN_DAYS = "14d"
    THIRTY_DAYS = "30d"


class ObservationWindow(StrEnum):
    """The recent interval being assessed against the baseline.

    Each divides every baseline length exactly, so the baseline splits into a whole number
    of slots of the observation's length and "the observation" and "one baseline slot" are
    comparable quantities by construction.
    """

    ONE_HOUR = "1h"
    SIX_HOURS = "6h"
    TWENTY_FOUR_HOURS = "24h"


BASELINE_SPANS: Mapping[BaselineWindow, timedelta] = MappingProxyType(
    {
        BaselineWindow.SEVEN_DAYS: timedelta(days=7),
        BaselineWindow.FOURTEEN_DAYS: timedelta(days=14),
        BaselineWindow.THIRTY_DAYS: timedelta(days=30),
    }
)

OBSERVATION_SPANS: Mapping[ObservationWindow, timedelta] = MappingProxyType(
    {
        ObservationWindow.ONE_HOUR: timedelta(hours=1),
        ObservationWindow.SIX_HOURS: timedelta(hours=6),
        ObservationWindow.TWENTY_FOUR_HOURS: timedelta(hours=24),
    }
)

#: What an analysis uses when the request names nothing: two weeks of history against the
#: last complete day. Two weeks holds every weekday twice, which is the shortest baseline in
#: which one unusual day cannot be half of the evidence.
DEFAULT_BASELINE_WINDOW = BaselineWindow.FOURTEEN_DAYS
DEFAULT_OBSERVATION_WINDOW = ObservationWindow.TWENTY_FOUR_HOURS


def floor_to_hour(moment: datetime) -> datetime:
    """The start of the UTC hour ``moment`` falls in."""
    if moment.tzinfo is None:
        raise RiskWindowError("floor_to_hour needs a timezone-aware instant")
    return moment.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


@dataclass(frozen=True, slots=True)
class AnalysisWindows:
    """The two intervals of one analysis, resolved and aligned.

    Half-open throughout: the baseline is ``[baseline_start, baseline_end)`` and the
    observation is ``[observation_start, observation_end)``, with
    ``baseline_end == observation_start``. That equality is checked on construction, so an
    instance whose baseline overlaps its observation — or leaves a gap before it — cannot
    exist.
    """

    baseline: BaselineWindow
    observation: ObservationWindow
    baseline_start: datetime
    baseline_end: datetime
    observation_start: datetime
    observation_end: datetime

    def __post_init__(self) -> None:
        for moment in (
            self.baseline_start,
            self.baseline_end,
            self.observation_start,
            self.observation_end,
        ):
            if moment.tzinfo is None:
                raise RiskWindowError("analysis windows are timezone-aware")
        if self.baseline_end != self.observation_start:
            raise RiskWindowError(
                "the baseline ends exactly where the observation starts: it must neither "
                "overlap the observation nor leave a gap before it"
            )
        if self.baseline_end - self.baseline_start != BASELINE_SPANS[self.baseline]:
            raise RiskWindowError("the baseline bounds do not match the named baseline window")
        if self.observation_end - self.observation_start != OBSERVATION_SPANS[self.observation]:
            raise RiskWindowError(
                "the observation bounds do not match the named observation window"
            )

    @property
    def as_of(self) -> datetime:
        """The instant the analysis is as of: the exclusive end of the observation."""
        return self.observation_end

    @property
    def slot(self) -> timedelta:
        """How long one baseline slot is — exactly the observation's length."""
        return OBSERVATION_SPANS[self.observation]

    @property
    def slot_seconds(self) -> int:
        """:attr:`slot` in whole seconds, the unit the SQL buckets by."""
        return int(self.slot.total_seconds())

    @property
    def slots(self) -> int:
        """How many observation-length slots the baseline holds (7 to 720)."""
        return int(BASELINE_SPANS[self.baseline] / self.slot)


def resolve_analysis_windows(
    *,
    baseline: BaselineWindow | str | None = None,
    observation: ObservationWindow | str | None = None,
    as_of: datetime | None = None,
    now: datetime,
) -> AnalysisWindows:
    """Decide which two intervals an analysis compares.

    ``now`` is the server's clock and is required: this function never reads one. With no
    ``as_of`` the analysis is as of the start of the current UTC hour — the observation is
    the last *complete* hour(s), so an analysis never assesses an interval that is still
    filling up. An explicit ``as_of`` must be a whole UTC hour, timezone-aware and not in
    the future: investigating last Tuesday is allowed, assessing tomorrow is not, and a
    misaligned instant is refused rather than silently floored, because a caller who asked
    about 10:30 and was answered about 10:00 would be reading a different window than the
    one they think they are reading.
    """
    try:
        resolved_baseline = BaselineWindow(baseline or DEFAULT_BASELINE_WINDOW)
    except ValueError as exc:
        allowed = ", ".join(window.value for window in BaselineWindow)
        raise RiskWindowError(f"baseline must be one of: {allowed}") from exc
    try:
        resolved_observation = ObservationWindow(observation or DEFAULT_OBSERVATION_WINDOW)
    except ValueError as exc:
        allowed = ", ".join(window.value for window in ObservationWindow)
        raise RiskWindowError(f"observation must be one of: {allowed}") from exc

    if now.tzinfo is None:
        raise RiskWindowError("the server clock must be timezone-aware")
    current_hour = floor_to_hour(now)

    if as_of is None:
        end = current_hour
    else:
        if as_of.tzinfo is None:
            raise RiskWindowError(
                "as_of must be timezone-aware: a naive instant would be read against "
                "whatever the server's locale happens to be"
            )
        end = as_of.astimezone(UTC)
        if end != floor_to_hour(end):
            raise RiskWindowError(
                "as_of must be a whole UTC hour (minutes, seconds and fractions all zero), "
                "so every analysis of the same interval compares the same windows"
            )
        if end > current_hour:
            raise RiskWindowError(
                "as_of must not be later than the start of the current UTC hour: an "
                "observation window that is still filling up cannot be assessed"
            )

    observation_start = end - OBSERVATION_SPANS[resolved_observation]
    return AnalysisWindows(
        baseline=resolved_baseline,
        observation=resolved_observation,
        baseline_start=observation_start - BASELINE_SPANS[resolved_baseline],
        baseline_end=observation_start,
        observation_start=observation_start,
        observation_end=end,
    )


# ── The closed vocabularies ───────────────────────────────────────────────────


class EntityType(StrEnum):
    """What an analysis is about. One value, because one entity has attributable history.

    Action requests name an agent in ``audit_events.agent_id``; that is the only subject the
    trail attributes behaviour to. A request that names no agent is counted by monitoring
    and is not analysed per entity here (see ``docs/risk.md``, *Limitations*).
    """

    AGENT = "agent"


class DetectionType(StrEnum):
    """Every anomaly this build can report, and nothing else.

    Each is implemented from columns the audit trail actually carries — ``event_type``,
    ``agent_id``, ``action``, ``resource_type``/``resource_id`` and ``occurred_at`` — and
    none reads event metadata. The declaration order is the order checks run and
    detections are listed in.
    """

    #: More action requests in the observation than the agent's baseline supports.
    ACTION_RATE_SPIKE = "action_rate_spike"
    #: Far fewer action requests than the baseline supports.
    ACTION_RATE_DROP = "action_rate_drop"
    #: A larger share of completed executions failed than in the baseline.
    FAILURE_RATE_SPIKE = "failure_rate_spike"
    #: A larger share of requests was refused by the firewall than in the baseline.
    DENIAL_RATE_SPIKE = "denial_rate_spike"
    #: A registered action the agent never requested during the baseline.
    NOVEL_ACTION = "novel_action"
    #: A target the agent never addressed during the baseline.
    NOVEL_RESOURCE = "novel_resource"
    #: Activity in UTC hours of the day with no baseline activity at all.
    UNUSUAL_TIME = "unusual_time"
    #: A burst: the busiest five minutes of the observation far exceed the baseline's.
    UNUSUAL_FREQUENCY = "unusual_frequency"


class AnalysisStatus(StrEnum):
    """Whether an entity could be assessed at all."""

    ANALYZED = "analyzed"
    INSUFFICIENT_HISTORY = "insufficient_history"


class AnomalyState(StrEnum):
    """The conclusion, stated with its uncertainty.

    ``UNDETERMINED`` is the cold-start answer: not "normal" (nothing was compared), and
    certainly not "anomalous" (being new is not being unusual).
    """

    ANOMALOUS = "anomalous"
    NOT_ANOMALOUS = "not_anomalous"
    UNDETERMINED = "undetermined"


class InsufficientReason(StrEnum):
    """Why an entity's history is too thin to assess. Every one that applies is reported."""

    NO_BASELINE_ACTIVITY = "no_baseline_activity"
    BASELINE_EVENTS_BELOW_MINIMUM = "baseline_events_below_minimum"
    HISTORY_SPAN_BELOW_MINIMUM = "history_span_below_minimum"
    ACTIVE_SLOTS_BELOW_MINIMUM = "active_slots_below_minimum"


class CheckStatus(StrEnum):
    """What one detection check concluded for one entity."""

    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    #: The entity has history, but not enough of the kind this check needs.
    INSUFFICIENT_DATA = "insufficient_data"
    #: The entity as a whole could not be assessed; no check ran.
    NOT_EVALUATED = "not_evaluated"


class CheckReason(StrEnum):
    """Why a check could not conclude. Closed, so a client can switch on it."""

    ENTITY_HISTORY_INSUFFICIENT = "entity_history_insufficient"
    BASELINE_MEAN_BELOW_DROP_MARGIN = "baseline_mean_below_drop_margin"
    BASELINE_SAMPLE_BELOW_MINIMUM = "baseline_sample_below_minimum"
    OBSERVED_SAMPLE_BELOW_MINIMUM = "observed_sample_below_minimum"
    BASELINE_RESOURCE_SET_UNSTABLE = "baseline_resource_set_unstable"
    BASELINE_HOURS_SATURATED = "baseline_hours_saturated"


class RiskLevel(StrEnum):
    """The only risk levels there are. Ordered; never a number underneath."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: The order of :class:`RiskLevel`, lowest first. Used to compare and raise levels; not a
#: score, and never published as one.
_LEVEL_ORDER: tuple[RiskLevel, ...] = tuple(RiskLevel)


def raise_level(level: RiskLevel, steps: int) -> RiskLevel:
    """``level`` raised by ``steps``, capped at ``CRITICAL``. ``NONE`` is never raised."""
    if steps < 0:
        raise ValueError("a risk level is only ever raised")
    if level is RiskLevel.NONE:
        return level
    return _LEVEL_ORDER[min(_LEVEL_ORDER.index(level) + steps, len(_LEVEL_ORDER) - 1)]


def _max_level(levels: Sequence[RiskLevel]) -> RiskLevel:
    """The highest of ``levels``, or ``NONE`` for none."""
    return max(levels, key=_LEVEL_ORDER.index, default=RiskLevel.NONE)


class RiskFactorCode(StrEnum):
    """Every reason a risk level can be above ``NONE``.

    Eight *base* factors, one per detection type, and three *escalations*. A level is the
    base level of the detection's type, raised one step per escalation that applies — see
    :data:`BASE_RISK` and :func:`analyze_agent`. Nothing else moves a level.
    """

    ACTIVITY_SPIKE = "activity_spike"
    ACTIVITY_DROP = "activity_drop"
    FAILURE_RATE_ELEVATED = "failure_rate_elevated"
    DENIAL_RATE_ELEVATED = "denial_rate_elevated"
    NOVEL_ACTION_USED = "novel_action_used"
    NOVEL_RESOURCE_TARGETED = "novel_resource_targeted"
    OFF_HOURS_ACTIVITY = "off_hours_activity"
    BURST_ACTIVITY = "burst_activity"
    #: The measurement exceeded twice the distance its threshold allows.
    EXTREME_DEVIATION = "extreme_deviation"
    #: The entity has detections of at least two different types in the same observation.
    MULTIPLE_DETECTION_TYPES = "multiple_detection_types"
    #: The entity has detections of at least four different types in the same observation.
    BROAD_BEHAVIOUR_CHANGE = "broad_behaviour_change"


class FactorEffect(StrEnum):
    """How a factor contributes: it sets the starting level, or raises it one step."""

    BASE = "base"
    ESCALATION = "escalation"


#: The base risk level of each detection type — the decision table, in one place.
#:
#: The reasoning, briefly (``docs/risk.md`` has it in full): refusals by the firewall,
#: first use of an action, a volume spike and a burst are what probing or misuse looks
#: like, so they start at ``MEDIUM``; a new target, activity at an unusual hour, more
#: failures or less activity are more often operational than hostile, so they start at
#: ``LOW``. No type starts at ``HIGH`` — reaching it takes an escalation, which is to say
#: more evidence.
BASE_RISK: Mapping[DetectionType, RiskLevel] = MappingProxyType(
    {
        DetectionType.ACTION_RATE_SPIKE: RiskLevel.MEDIUM,
        DetectionType.ACTION_RATE_DROP: RiskLevel.LOW,
        DetectionType.FAILURE_RATE_SPIKE: RiskLevel.LOW,
        DetectionType.DENIAL_RATE_SPIKE: RiskLevel.MEDIUM,
        DetectionType.NOVEL_ACTION: RiskLevel.MEDIUM,
        DetectionType.NOVEL_RESOURCE: RiskLevel.LOW,
        DetectionType.UNUSUAL_TIME: RiskLevel.LOW,
        DetectionType.UNUSUAL_FREQUENCY: RiskLevel.MEDIUM,
    }
)

#: The base factor each detection type contributes.
DETECTION_FACTORS: Mapping[DetectionType, RiskFactorCode] = MappingProxyType(
    {
        DetectionType.ACTION_RATE_SPIKE: RiskFactorCode.ACTIVITY_SPIKE,
        DetectionType.ACTION_RATE_DROP: RiskFactorCode.ACTIVITY_DROP,
        DetectionType.FAILURE_RATE_SPIKE: RiskFactorCode.FAILURE_RATE_ELEVATED,
        DetectionType.DENIAL_RATE_SPIKE: RiskFactorCode.DENIAL_RATE_ELEVATED,
        DetectionType.NOVEL_ACTION: RiskFactorCode.NOVEL_ACTION_USED,
        DetectionType.NOVEL_RESOURCE: RiskFactorCode.NOVEL_RESOURCE_TARGETED,
        DetectionType.UNUSUAL_TIME: RiskFactorCode.OFF_HOURS_ACTIVITY,
        DetectionType.UNUSUAL_FREQUENCY: RiskFactorCode.BURST_ACTIVITY,
    }
)


# ── Minimum-data rules and thresholds ─────────────────────────────────────────
#
# Every number that decides an outcome, named and documented once. ``docs/risk.md``
# repeats them, and ``test_risk_contract.py`` asserts the document and the code agree.

#: An entity needs at least this many action requests in its baseline to be assessed.
MIN_BASELINE_EVENTS = 20
#: …spread over at least this many slots of history (from its first baseline slot)…
MIN_HISTORY_SLOTS = 7
#: …covering at least this much time…
MIN_HISTORY_SPAN = timedelta(days=1)
#: …with activity in at least this many distinct slots, so one burst is not a baseline.
MIN_ACTIVE_SLOTS = 3

#: Rate change: the observation must differ from the baseline mean by more than
#: ``max(RATE_SIGMA * stddev, RATE_MIN_DELTA)`` requests.
RATE_SIGMA = 3
RATE_MIN_DELTA = 5

#: Failure and denial rates: the observed share must exceed the baseline share by at least
#: this much (an absolute difference of proportions)…
SHARE_DELTA = 0.25
#: …which is "extreme" at this difference…
SHARE_EXTREME_DELTA = 0.5
#: …over at least this many observed failures or denials…
SHARE_MIN_OBSERVED_EVENTS = 3
#: …out of at least this many observed completions or requests…
SHARE_MIN_OBSERVED_SAMPLE = 5
#: …against a baseline of at least this many completions or requests.
SHARE_MIN_BASELINE_SAMPLE = 10

#: Novel resource: only assessed when the baseline targets are *reused* — at least this
#: many requests per distinct target on average. An agent that addresses a new target on
#: most requests has no stable target set, and "new target" is its normal.
RESOURCE_REUSE_MIN_RATIO = 2

#: Unusual time: at least this many observed requests in UTC hours of the day with no
#: baseline activity at all…
UNUSUAL_TIME_MIN_EVENTS = 3
#: …and only for an entity active in at most this many of the 24 hours during the
#: baseline. An agent busy around the clock has no unusual hour.
UNUSUAL_TIME_MAX_ACTIVE_HOURS = 20

#: Unusual frequency: requests are bucketed into five-minute intervals, and the busiest
#: observed bucket must reach ``max(BURST_RATIO * baseline_peak, baseline_peak +
#: BURST_MIN_DELTA)``.
BURST_BUCKET = timedelta(minutes=5)
BURST_RATIO = 2
BURST_MIN_DELTA = 5

#: The most items one evidence list carries (novel actions, novel targets, hours). The full
#: count is always stated beside it, so a truncated list is visibly truncated.
MAX_EVIDENCE_ITEMS = 16

#: The largest serialized evidence document. The table enforces a larger backstop.
MAX_EVIDENCE_BYTES = 8192

#: Decimal places published for derived values (means, deviations, shares).
_PRECISION = 6


# ── Inputs: what the repository computed ──────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AgentProfile:
    """One agent's history over one analysis, as aggregates PostgreSQL computed.

    Nothing here is a raw event. Every field is a count (or a sum of squared counts) over
    ``action.requested`` and the pipeline's outcome events inside the analysis windows,
    so the profile of a busy agent is the same size as the profile of a quiet one — which
    is what keeps the analysis bounded however much history the tenant has.

    Slot fields describe the baseline split into :attr:`AnalysisWindows.slots` slots of the
    observation's length, numbered from 0 at ``baseline_start``.
    """

    agent_id: uuid.UUID
    #: Action requests in the baseline, and the sum of squared per-slot counts.
    baseline_requests: int = 0
    baseline_sum_squares: int = 0
    #: The first baseline slot with activity (``None`` when the baseline is empty).
    first_active_slot: int | None = None
    #: How many baseline slots had at least one request.
    active_slots: int = 0
    #: Refusals, successful executions and failed executions in the baseline.
    baseline_denials: int = 0
    baseline_executions: int = 0
    baseline_failures: int = 0
    #: The same four, in the observation.
    observed_requests: int = 0
    observed_denials: int = 0
    observed_executions: int = 0
    observed_failures: int = 0
    #: Distinct actions requested in the baseline and in the observation; how many of the
    #: observed ones the baseline never named, and the first of those in sorted order
    #: (at most :data:`MAX_EVIDENCE_ITEMS`). Novelty is computed in PostgreSQL, so the
    #: profile stays one row per agent however many actions an agent requests.
    baseline_distinct_actions: int = 0
    observed_distinct_actions: int = 0
    novel_action_count: int = 0
    novel_actions: tuple[str, ...] = ()
    #: The same, for targets (``"<resource_type>:<uuid>"``).
    baseline_distinct_resources: int = 0
    observed_distinct_resources: int = 0
    novel_resource_count: int = 0
    novel_resources: tuple[str, ...] = ()
    #: Requests per UTC hour of day (index 0-23), in the baseline and the observation.
    baseline_hours: tuple[int, ...] = (0,) * 24
    observed_hours: tuple[int, ...] = (0,) * 24
    #: The largest number of requests in one five-minute bucket, per period.
    baseline_peak: int = 0
    observed_peak: int = 0

    def __post_init__(self) -> None:
        if len(self.baseline_hours) != 24 or len(self.observed_hours) != 24:
            raise ValueError("an hour profile has exactly 24 entries")
        if len(self.novel_actions) > MAX_EVIDENCE_ITEMS or len(self.novel_resources) > (
            MAX_EVIDENCE_ITEMS
        ):
            raise ValueError(f"a novelty sample holds at most {MAX_EVIDENCE_ITEMS} items")
        if len(self.novel_actions) > self.novel_action_count or len(self.novel_resources) > (
            self.novel_resource_count
        ):
            raise ValueError("a novelty sample cannot be larger than the novelty count")


# ── Outputs ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RiskFactor:
    """One reason a level is what it is.

    ``BASE`` factors carry the ``level`` they set; ``ESCALATION`` factors carry the number
    of ``steps`` they add. ``detection_type`` names the detection a factor came from, and
    ``count`` is the number of distinct detection types for the two breadth escalations.
    """

    code: RiskFactorCode
    effect: FactorEffect
    level: RiskLevel | None = None
    steps: int | None = None
    detection_type: DetectionType | None = None
    count: int | None = None

    def as_dict(self) -> dict[str, Any]:
        """The factor as JSON-safe data, with absent fields omitted."""
        rendered: dict[str, Any] = {"code": self.code.value, "effect": self.effect.value}
        if self.level is not None:
            rendered["level"] = self.level.value
        if self.steps is not None:
            rendered["steps"] = self.steps
        if self.detection_type is not None:
            rendered["detection_type"] = self.detection_type.value
        if self.count is not None:
            rendered["count"] = self.count
        return rendered


@dataclass(frozen=True, slots=True)
class Detection:
    """One anomaly: its type, its level, why the level, and the evidence for it."""

    detection_type: DetectionType
    risk_level: RiskLevel
    risk_factors: tuple[RiskFactor, ...]
    evidence: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.risk_level is RiskLevel.NONE:
            raise RiskError("a detection always carries a risk level above none")
        if not self.risk_factors:
            raise RiskError("a detection above none must state the factors that put it there")


@dataclass(frozen=True, slots=True)
class DetectionCheck:
    """What one detection type concluded for one entity, including "could not tell"."""

    detection_type: DetectionType
    status: CheckStatus
    reason: CheckReason | None = None


@dataclass(frozen=True, slots=True)
class BaselineStatistics:
    """Mean and spread of per-slot request counts over an entity's history slots.

    Computed from exact integer sums (see :func:`baseline_statistics`), so the same counts
    always produce the same numbers, bit for bit.
    """

    history_slots: int
    events: int
    mean: float
    stddev: float

    @property
    def zero_variance(self) -> bool:
        """Every history slot held the same count."""
        return self.stddev == 0.0


@dataclass(frozen=True, slots=True)
class AgentAnalysis:
    """Everything the engine concluded about one agent in one analysis."""

    agent_id: uuid.UUID
    status: AnalysisStatus
    anomaly_state: AnomalyState
    risk_level: RiskLevel
    risk_factors: tuple[RiskFactor, ...]
    insufficient_reasons: tuple[InsufficientReason, ...]
    statistics: BaselineStatistics | None
    profile: AgentProfile
    checks: tuple[DetectionCheck, ...]
    detections: tuple[Detection, ...]

    def __post_init__(self) -> None:
        if self.risk_level is not RiskLevel.NONE and not self.risk_factors:
            raise RiskError("every risk level above none carries the factors behind it")
        if self.status is AnalysisStatus.INSUFFICIENT_HISTORY and (
            self.detections or self.anomaly_state is not AnomalyState.UNDETERMINED
        ):
            raise RiskError(
                "an entity with insufficient history is undetermined and has no detections"
            )
        if (self.anomaly_state is AnomalyState.ANOMALOUS) != bool(self.detections):
            raise RiskError("an entity is anomalous exactly when it has a detection")


# ── Statistics ────────────────────────────────────────────────────────────────


def _rounded(value: float) -> float:
    return round(value, _PRECISION)


def baseline_statistics(*, events: int, sum_squares: int, history_slots: int) -> BaselineStatistics:
    """Population mean and standard deviation of per-slot counts, from their sums.

    ``events`` is the sum of the per-slot counts, ``sum_squares`` the sum of their squares
    and ``history_slots`` how many slots they are spread over — *including* the slots with
    zero requests after the entity's first activity, which is where missing data and zero
    part ways. The variance is computed as ``(n * sum_sq - total**2) / n**2`` in exact integers, so
    rounding cannot make it negative and zero variance is an exact equality, not a float
    that happens to be tiny.
    """
    if history_slots <= 0:
        raise RiskError("baseline statistics need at least one history slot")
    if events < 0 or sum_squares < 0:
        raise RiskError("counts are never negative")
    numerator = history_slots * sum_squares - events * events
    if numerator < 0:
        raise RiskError("the sum of squares is inconsistent with the sum of counts")
    return BaselineStatistics(
        history_slots=history_slots,
        events=events,
        mean=_rounded(events / history_slots),
        stddev=_rounded(math.sqrt(numerator) / history_slots),
    )


def _share(part: int, whole: int) -> float | None:
    """``part / whole``, or ``None`` when there is nothing to divide by."""
    if whole == 0:
        return None
    return _rounded(part / whole)


# ── Evidence safety ───────────────────────────────────────────────────────────

#: Strings evidence may contain: enum values and registered action identifiers, UUIDs,
#: ``type:uuid`` target references and ISO-8601 UTC instants. Everything the engine writes
#: matches one of these; a value that matches none of them did not come from the engine.
_SAFE_STRING = re.compile(
    r"^(?:"
    r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*"  # identifiers, enum values, action ids
    r"|[0-9]+[a-z]{1,2}"  # window names: 7d, 24h
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # uuid
    r"|[a-z]+:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # target ref
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00"  # UTC instant
    r")$"
)
_SAFE_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _check_evidence_value(value: object, path: str) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RiskEvidenceError(f"evidence value at {path} is not a finite number")
        return
    if isinstance(value, str):
        if len(value) > 64 or not _SAFE_STRING.match(value):
            raise RiskEvidenceError(
                f"evidence value at {path} is not an identifier, a UUID or a UTC instant; "
                "evidence carries measurements, never payloads"
            )
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or not _SAFE_KEY.match(key):
                raise RiskEvidenceError(f"evidence key {key!r} at {path} is not an identifier")
            _check_evidence_value(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_EVIDENCE_ITEMS:
            raise RiskEvidenceError(f"evidence list at {path} is longer than {MAX_EVIDENCE_ITEMS}")
        for index, item in enumerate(value):
            _check_evidence_value(item, f"{path}[{index}]")
        return
    raise RiskEvidenceError(f"evidence value at {path} is a {type(value).__name__}")


def ensure_safe_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    """Refuse evidence that is anything but a small structure of safe values.

    The engine never reads event metadata, so no argument, credential or payload can reach
    its evidence in the first place. This is the second wall: every string must look like
    something the engine itself produces (an identifier, a UUID, a UTC instant), keys must
    be identifiers, lists are short and the whole document is bounded. A value that fails
    is a defect in the builder, and it is raised rather than trimmed.
    """
    _check_evidence_value(evidence, "evidence")
    rendered = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    if len(rendered.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        raise RiskEvidenceError(f"evidence serializes to more than {MAX_EVIDENCE_BYTES} bytes")
    return evidence


# ── Fingerprints ──────────────────────────────────────────────────────────────


def _instant(moment: datetime) -> str:
    """An instant as evidence states it: ISO-8601, UTC, whole seconds."""
    return moment.astimezone(UTC).replace(microsecond=0).isoformat()


def detection_fingerprint(
    *,
    entity_type: EntityType,
    entity_id: uuid.UUID,
    detection_type: DetectionType,
    windows: AnalysisWindows,
    engine_version: int = RISK_ENGINE_VERSION,
) -> str:
    """The identity of one detection: the same finding always has the same fingerprint.

    A detection *is* "this entity, this type, over these exact windows, under these rules",
    so that is exactly what is hashed — never a measured value, which would make a
    fingerprint depend on arithmetic rather than on what was assessed. Repeating an
    analysis with the same ``as_of`` therefore reproduces the fingerprint, and the store
    keeps one row for it however many times the analysis runs. A different observation
    window is a different assessment and a different fingerprint, on purpose.
    """
    key = {
        "engine_version": engine_version,
        "entity_type": entity_type.value,
        "entity_id": str(entity_id),
        "detection_type": detection_type.value,
        "baseline": windows.baseline.value,
        "observation": windows.observation.value,
        "baseline_start": _instant(windows.baseline_start),
        "baseline_end": _instant(windows.baseline_end),
        "observation_start": _instant(windows.observation_start),
        "observation_end": _instant(windows.observation_end),
    }
    rendered = json.dumps(key, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


# ── Detection ─────────────────────────────────────────────────────────────────


def _evidence(
    *,
    detection_type: DetectionType,
    agent_id: uuid.UUID,
    windows: AnalysisWindows,
    statistics: BaselineStatistics,
    profile: AgentProfile,
    measurement: Mapping[str, Any],
    comparison: Mapping[str, Any],
    risk_factors: Sequence[RiskFactor],
) -> Mapping[str, Any]:
    """The evidence document every detection carries, in one shape.

    Seven sections: which rules, which entity, the baseline used, the observation window,
    what was measured, what it was compared with, and the risk factors — which is
    everything a reader needs to redo the decision by hand.
    """
    evidence = {
        "engine_version": RISK_ENGINE_VERSION,
        "detection_type": detection_type.value,
        "entity": {"type": EntityType.AGENT.value, "id": str(agent_id)},
        "baseline": {
            "window": windows.baseline.value,
            "start": _instant(windows.baseline_start),
            "end": _instant(windows.baseline_end),
            "slot_seconds": windows.slot_seconds,
            "slots": windows.slots,
            "history_slots": statistics.history_slots,
            "active_slots": profile.active_slots,
            "requests": profile.baseline_requests,
        },
        "observation": {
            "window": windows.observation.value,
            "start": _instant(windows.observation_start),
            "end": _instant(windows.observation_end),
            "requests": profile.observed_requests,
        },
        "measurement": dict(measurement),
        "comparison": dict(comparison),
        "risk_factors": [factor.as_dict() for factor in risk_factors],
    }
    return MappingProxyType(dict(ensure_safe_evidence(evidence)))


def _detection_factors(
    detection_type: DetectionType, *, extreme: bool
) -> tuple[RiskLevel, tuple[RiskFactor, ...]]:
    """A detection's level and factors: its type's base level, plus one step if extreme."""
    base = BASE_RISK[detection_type]
    factors = [
        RiskFactor(
            code=DETECTION_FACTORS[detection_type],
            effect=FactorEffect.BASE,
            level=base,
            detection_type=detection_type,
        )
    ]
    level = base
    if extreme:
        factors.append(
            RiskFactor(
                code=RiskFactorCode.EXTREME_DEVIATION,
                effect=FactorEffect.ESCALATION,
                steps=1,
                detection_type=detection_type,
            )
        )
        level = raise_level(level, 1)
    return level, tuple(factors)


@dataclass(frozen=True, slots=True)
class _Finding:
    """A check's positive result, before it is dressed as a :class:`Detection`."""

    detection_type: DetectionType
    extreme: bool
    measurement: Mapping[str, Any]
    comparison: Mapping[str, Any]


def _rate_checks(
    profile: AgentProfile, statistics: BaselineStatistics
) -> tuple[list[DetectionCheck], list[_Finding]]:
    """ACTION_RATE_SPIKE and ACTION_RATE_DROP: mean +- max(k * stddev, floor)."""
    mean, stddev = statistics.mean, statistics.stddev
    margin = _rounded(max(RATE_SIGMA * stddev, float(RATE_MIN_DELTA)))
    observed = profile.observed_requests
    z_score = None if statistics.zero_variance else _rounded((observed - mean) / stddev)
    measurement = {
        "observed_requests": observed,
        "baseline_mean": mean,
        "baseline_stddev": stddev,
        "z_score": z_score,
    }
    method = "mean_stddev_fixed_floor" if statistics.zero_variance else "mean_stddev"
    checks: list[DetectionCheck] = []
    findings: list[_Finding] = []

    upper = _rounded(mean + margin)
    if observed > upper:
        checks.append(DetectionCheck(DetectionType.ACTION_RATE_SPIKE, CheckStatus.DETECTED))
        findings.append(
            _Finding(
                DetectionType.ACTION_RATE_SPIKE,
                extreme=observed > mean + 2 * margin,
                measurement=measurement,
                comparison={
                    "method": method,
                    "operator": "greater_than",
                    "threshold": upper,
                    "sigma": RATE_SIGMA,
                    "min_delta": RATE_MIN_DELTA,
                    "margin": margin,
                    "zero_variance": statistics.zero_variance,
                    "extreme_threshold": _rounded(mean + 2 * margin),
                },
            )
        )
    else:
        checks.append(DetectionCheck(DetectionType.ACTION_RATE_SPIKE, CheckStatus.NOT_DETECTED))

    lower = _rounded(mean - margin)
    if lower <= 0:
        # A drop below a non-positive threshold is unreachable: the baseline mean is too
        # small for "far fewer" to be distinguishable from an ordinary quiet slot.
        checks.append(
            DetectionCheck(
                DetectionType.ACTION_RATE_DROP,
                CheckStatus.INSUFFICIENT_DATA,
                CheckReason.BASELINE_MEAN_BELOW_DROP_MARGIN,
            )
        )
    elif observed < lower:
        checks.append(DetectionCheck(DetectionType.ACTION_RATE_DROP, CheckStatus.DETECTED))
        findings.append(
            _Finding(
                DetectionType.ACTION_RATE_DROP,
                extreme=observed < mean - 2 * margin,
                measurement=measurement,
                comparison={
                    "method": method,
                    "operator": "less_than",
                    "threshold": lower,
                    "sigma": RATE_SIGMA,
                    "min_delta": RATE_MIN_DELTA,
                    "margin": margin,
                    "zero_variance": statistics.zero_variance,
                    "extreme_threshold": _rounded(mean - 2 * margin),
                },
            )
        )
    else:
        checks.append(DetectionCheck(DetectionType.ACTION_RATE_DROP, CheckStatus.NOT_DETECTED))
    return checks, findings


def _share_check(
    detection_type: DetectionType,
    *,
    baseline_part: int,
    baseline_whole: int,
    observed_part: int,
    observed_whole: int,
    part_name: str,
    whole_name: str,
) -> tuple[DetectionCheck, _Finding | None]:
    """FAILURE_RATE_SPIKE and DENIAL_RATE_SPIKE: a fixed rise in a proportion."""
    if baseline_whole < SHARE_MIN_BASELINE_SAMPLE:
        return (
            DetectionCheck(
                detection_type,
                CheckStatus.INSUFFICIENT_DATA,
                CheckReason.BASELINE_SAMPLE_BELOW_MINIMUM,
            ),
            None,
        )
    if observed_whole < SHARE_MIN_OBSERVED_SAMPLE:
        return (
            DetectionCheck(
                detection_type,
                CheckStatus.INSUFFICIENT_DATA,
                CheckReason.OBSERVED_SAMPLE_BELOW_MINIMUM,
            ),
            None,
        )
    baseline_share = baseline_part / baseline_whole
    observed_share = observed_part / observed_whole
    delta = observed_share - baseline_share
    if observed_part < SHARE_MIN_OBSERVED_EVENTS or delta < SHARE_DELTA:
        return DetectionCheck(detection_type, CheckStatus.NOT_DETECTED), None
    return (
        DetectionCheck(detection_type, CheckStatus.DETECTED),
        _Finding(
            detection_type,
            extreme=delta >= SHARE_EXTREME_DELTA,
            measurement={
                f"baseline_{part_name}": baseline_part,
                f"baseline_{whole_name}": baseline_whole,
                f"observed_{part_name}": observed_part,
                f"observed_{whole_name}": observed_whole,
                "baseline_share": _rounded(baseline_share),
                "observed_share": _rounded(observed_share),
                "share_delta": _rounded(delta),
            },
            comparison={
                "method": "share_difference",
                "operator": "greater_than_or_equal",
                "threshold": SHARE_DELTA,
                "extreme_threshold": SHARE_EXTREME_DELTA,
                "min_observed_events": SHARE_MIN_OBSERVED_EVENTS,
                "min_observed_sample": SHARE_MIN_OBSERVED_SAMPLE,
                "min_baseline_sample": SHARE_MIN_BASELINE_SAMPLE,
            },
        ),
    )


def _novelty_check(
    detection_type: DetectionType,
    *,
    novel_count: int,
    novel_sample: Sequence[str],
    observed_distinct: int,
    baseline_distinct: int,
    item_name: str,
) -> tuple[DetectionCheck, _Finding | None]:
    """NOVEL_ACTION and NOVEL_RESOURCE: what the observation named that the baseline never did."""
    if novel_count == 0:
        return DetectionCheck(detection_type, CheckStatus.NOT_DETECTED), None
    return (
        DetectionCheck(detection_type, CheckStatus.DETECTED),
        _Finding(
            detection_type,
            extreme=False,
            measurement={
                f"novel_{item_name}": sorted(novel_sample)[:MAX_EVIDENCE_ITEMS],
                "novel_count": novel_count,
                f"observed_distinct_{item_name}": observed_distinct,
                f"baseline_distinct_{item_name}": baseline_distinct,
            },
            comparison={"method": "set_difference", "operator": "not_in_baseline"},
        ),
    )


def _time_check(profile: AgentProfile) -> tuple[DetectionCheck, _Finding | None]:
    """UNUSUAL_TIME: observed requests in UTC hours with no baseline activity."""
    active_hours = [hour for hour in range(24) if profile.baseline_hours[hour] > 0]
    if len(active_hours) > UNUSUAL_TIME_MAX_ACTIVE_HOURS:
        return (
            DetectionCheck(
                DetectionType.UNUSUAL_TIME,
                CheckStatus.INSUFFICIENT_DATA,
                CheckReason.BASELINE_HOURS_SATURATED,
            ),
            None,
        )
    unusual_hours = [
        hour
        for hour in range(24)
        if profile.observed_hours[hour] > 0 and profile.baseline_hours[hour] == 0
    ]
    unusual_requests = sum(profile.observed_hours[hour] for hour in unusual_hours)
    if unusual_requests < UNUSUAL_TIME_MIN_EVENTS:
        return DetectionCheck(DetectionType.UNUSUAL_TIME, CheckStatus.NOT_DETECTED), None
    return (
        DetectionCheck(DetectionType.UNUSUAL_TIME, CheckStatus.DETECTED),
        _Finding(
            DetectionType.UNUSUAL_TIME,
            extreme=False,
            measurement={
                # Up to 23 hours can qualify; evidence lists are capped, the count is not.
                "unusual_hours_utc": unusual_hours[:MAX_EVIDENCE_ITEMS],
                "unusual_hour_count": len(unusual_hours),
                "unusual_requests": unusual_requests,
                "baseline_active_hours_utc": active_hours[:MAX_EVIDENCE_ITEMS],
                "baseline_active_hour_count": len(active_hours),
            },
            comparison={
                "method": "zero_baseline_hour_of_day",
                "operator": "greater_than_or_equal",
                "threshold": UNUSUAL_TIME_MIN_EVENTS,
                "max_baseline_active_hours": UNUSUAL_TIME_MAX_ACTIVE_HOURS,
                "timezone": "utc",
            },
        ),
    )


def _frequency_check(profile: AgentProfile) -> tuple[DetectionCheck, _Finding | None]:
    """UNUSUAL_FREQUENCY: the busiest observed five minutes against the baseline's busiest."""
    threshold = max(BURST_RATIO * profile.baseline_peak, profile.baseline_peak + BURST_MIN_DELTA)
    if profile.observed_peak < threshold:
        return DetectionCheck(DetectionType.UNUSUAL_FREQUENCY, CheckStatus.NOT_DETECTED), None
    return (
        DetectionCheck(DetectionType.UNUSUAL_FREQUENCY, CheckStatus.DETECTED),
        _Finding(
            DetectionType.UNUSUAL_FREQUENCY,
            extreme=profile.observed_peak >= 2 * threshold,
            measurement={
                "observed_peak_requests": profile.observed_peak,
                "baseline_peak_requests": profile.baseline_peak,
                "bucket_seconds": int(BURST_BUCKET.total_seconds()),
            },
            comparison={
                "method": "peak_bucket",
                "operator": "greater_than_or_equal",
                "threshold": threshold,
                "ratio": BURST_RATIO,
                "min_delta": BURST_MIN_DELTA,
                "extreme_threshold": 2 * threshold,
            },
        ),
    )


def _insufficient_reasons(
    profile: AgentProfile, windows: AnalysisWindows
) -> tuple[tuple[InsufficientReason, ...], int]:
    """The cold-start rules. Returns every reason that applies, and the history length."""
    if profile.first_active_slot is None or profile.baseline_requests == 0:
        return (InsufficientReason.NO_BASELINE_ACTIVITY,), 0
    history_slots = windows.slots - profile.first_active_slot
    reasons: list[InsufficientReason] = []
    if profile.baseline_requests < MIN_BASELINE_EVENTS:
        reasons.append(InsufficientReason.BASELINE_EVENTS_BELOW_MINIMUM)
    if history_slots < MIN_HISTORY_SLOTS or windows.slot * history_slots < MIN_HISTORY_SPAN:
        reasons.append(InsufficientReason.HISTORY_SPAN_BELOW_MINIMUM)
    if profile.active_slots < MIN_ACTIVE_SLOTS:
        reasons.append(InsufficientReason.ACTIVE_SLOTS_BELOW_MINIMUM)
    return tuple(reasons), history_slots


def analyze_agent(profile: AgentProfile, windows: AnalysisWindows) -> AgentAnalysis:
    """Assess one agent's observation against its baseline. Pure and deterministic.

    The order is the policy:

    1. **Cold start.** If the baseline is too thin, stop: the agent is
       ``insufficient_history`` / ``undetermined`` / ``none``, every check is
       ``not_evaluated``, and the reasons are listed. No statistic is computed.
    2. **Checks.** Each detection type runs over the aggregates and reports ``detected``,
       ``not_detected`` or ``insufficient_data`` with a reason — so "we could not tell" is
       never mistaken for "nothing unusual".
    3. **Risk.** Each detection's level is its type's base level, one step higher when the
       measurement was extreme. The agent's level is the highest detection level, one step
       higher for detections of two or more types, and one more for four or more. Every
       step is a recorded factor.
    """
    reasons, history_slots = _insufficient_reasons(profile, windows)
    if reasons:
        return AgentAnalysis(
            agent_id=profile.agent_id,
            status=AnalysisStatus.INSUFFICIENT_HISTORY,
            anomaly_state=AnomalyState.UNDETERMINED,
            risk_level=RiskLevel.NONE,
            risk_factors=(),
            insufficient_reasons=reasons,
            statistics=None,
            profile=profile,
            checks=tuple(
                DetectionCheck(
                    detection_type,
                    CheckStatus.NOT_EVALUATED,
                    CheckReason.ENTITY_HISTORY_INSUFFICIENT,
                )
                for detection_type in DetectionType
            ),
            detections=(),
        )

    statistics = baseline_statistics(
        events=profile.baseline_requests,
        sum_squares=profile.baseline_sum_squares,
        history_slots=history_slots,
    )

    checks: list[DetectionCheck] = []
    findings: list[_Finding] = []

    rate_checks, rate_findings = _rate_checks(profile, statistics)
    checks.extend(rate_checks)
    findings.extend(rate_findings)

    for check, finding in (
        _share_check(
            DetectionType.FAILURE_RATE_SPIKE,
            baseline_part=profile.baseline_failures,
            baseline_whole=profile.baseline_executions + profile.baseline_failures,
            observed_part=profile.observed_failures,
            observed_whole=profile.observed_executions + profile.observed_failures,
            part_name="failures",
            whole_name="completions",
        ),
        _share_check(
            DetectionType.DENIAL_RATE_SPIKE,
            baseline_part=profile.baseline_denials,
            baseline_whole=profile.baseline_requests,
            observed_part=profile.observed_denials,
            observed_whole=profile.observed_requests,
            part_name="denials",
            whole_name="requests",
        ),
        _novelty_check(
            DetectionType.NOVEL_ACTION,
            novel_count=profile.novel_action_count,
            novel_sample=profile.novel_actions,
            observed_distinct=profile.observed_distinct_actions,
            baseline_distinct=profile.baseline_distinct_actions,
            item_name="actions",
        ),
    ):
        checks.append(check)
        if finding is not None:
            findings.append(finding)

    if profile.baseline_distinct_resources * RESOURCE_REUSE_MIN_RATIO > profile.baseline_requests:
        checks.append(
            DetectionCheck(
                DetectionType.NOVEL_RESOURCE,
                CheckStatus.INSUFFICIENT_DATA,
                CheckReason.BASELINE_RESOURCE_SET_UNSTABLE,
            )
        )
    else:
        check, finding = _novelty_check(
            DetectionType.NOVEL_RESOURCE,
            novel_count=profile.novel_resource_count,
            novel_sample=profile.novel_resources,
            observed_distinct=profile.observed_distinct_resources,
            baseline_distinct=profile.baseline_distinct_resources,
            item_name="resources",
        )
        checks.append(check)
        if finding is not None:
            findings.append(finding)

    for check, finding in (_time_check(profile), _frequency_check(profile)):
        checks.append(check)
        if finding is not None:
            findings.append(finding)

    order = list(DetectionType)
    checks.sort(key=lambda item: order.index(item.detection_type))
    findings.sort(key=lambda item: order.index(item.detection_type))

    detections: list[Detection] = []
    agent_factors: list[RiskFactor] = []
    for finding in findings:
        level, factors = _detection_factors(finding.detection_type, extreme=finding.extreme)
        agent_factors.extend(factors)
        detections.append(
            Detection(
                detection_type=finding.detection_type,
                risk_level=level,
                risk_factors=factors,
                evidence=_evidence(
                    detection_type=finding.detection_type,
                    agent_id=profile.agent_id,
                    windows=windows,
                    statistics=statistics,
                    profile=profile,
                    measurement=finding.measurement,
                    comparison=finding.comparison,
                    risk_factors=factors,
                ),
            )
        )

    risk_level = _max_level([detection.risk_level for detection in detections])
    distinct_types = len({detection.detection_type for detection in detections})
    if distinct_types >= 2:
        agent_factors.append(
            RiskFactor(
                code=RiskFactorCode.MULTIPLE_DETECTION_TYPES,
                effect=FactorEffect.ESCALATION,
                steps=1,
                count=distinct_types,
            )
        )
        risk_level = raise_level(risk_level, 1)
    if distinct_types >= 4:
        agent_factors.append(
            RiskFactor(
                code=RiskFactorCode.BROAD_BEHAVIOUR_CHANGE,
                effect=FactorEffect.ESCALATION,
                steps=1,
                count=distinct_types,
            )
        )
        risk_level = raise_level(risk_level, 1)

    return AgentAnalysis(
        agent_id=profile.agent_id,
        status=AnalysisStatus.ANALYZED,
        anomaly_state=AnomalyState.ANOMALOUS if detections else AnomalyState.NOT_ANOMALOUS,
        risk_level=risk_level,
        risk_factors=tuple(agent_factors),
        insufficient_reasons=(),
        statistics=statistics,
        profile=profile,
        checks=tuple(checks),
        detections=tuple(detections),
    )
