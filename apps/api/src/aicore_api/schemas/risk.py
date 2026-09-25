"""Risk contract: how an assessment is stated, in a response and in a stored row.

Phase 10's read surface is four endpoints and one recording endpoint, and these are their
shapes. Four rules shape them.

**Observed facts and interpretations are different fields.** ``observed``,
``baseline_mean``, ``upper_bound`` and ``items`` are measurements. ``status``,
``anomaly``, ``risk_level`` and ``factors`` are the engine's reading of them, each
reproducible from the measurements beside it. Nothing here says an agent *is* anything: the
strongest statement this schema can carry is "these numbers are outside these bounds, and
they carry this much corroboration".

**Nothing is arbitrary JSON.** Every field is a scalar, a stated time, a declared
enumeration, or a list of the models below — including the evidence and factors a stored
detection carries, which are re-validated through these same models when they are read
back. There is no free-form document, no map with open keys, and no field whose meaning
depends on another field's value.

**There is no score and no verdict word.** No ``score``, no ``severity``, no ``confidence``,
no ``health``: a level is a label from a closed vocabulary, assigned by a published table
over factor counts, and a client that wants to disagree can read the table and the factors.
``test_openapi_contract.py`` asserts the forbidden words are absent from every schema here.

**The windows are part of the answer.** Every assessment states the observation interval
and the baseline it was compared against, including how many hourly samples the baseline
contributed, so "this rate is unusual" can always be checked against "unusual compared to
what, and over how long".
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aicore_api.core.risk import (
    ActivityFrame,
    AssessmentStatus,
    BaselineWindow,
    DetectionParameters,
    DetectionType,
    DimensionStatus,
    EntityType,
    InsufficiencyReason,
    RiskLevel,
    RiskMetric,
    WindowTotals,
)
from aicore_api.risk.engine import (
    Assessment,
    Dimension,
    Factor,
    FactorItem,
    FactorItemKind,
)

__all__ = [
    "RiskAgentListResponse",
    "RiskAnalysisRequest",
    "RiskAnalysisResponse",
    "RiskAssessmentRead",
    "RiskBaselineRead",
    "RiskDetectionListResponse",
    "RiskDetectionRead",
    "RiskDetectionWindowRead",
    "RiskDimensionRead",
    "RiskFactorItemRead",
    "RiskFactorRead",
    "RiskObservationRead",
    "RiskParametersRead",
    "RiskWindowRead",
    "evidence_document",
    "factors_document",
]


class RiskWindowRead(BaseModel):
    """An interval a response measured, as the server resolved it.

    Bounds are inclusive and timezone-aware, and the end of a named observation window is
    the server's clock at the moment of the request — so a client that renders "the last
    hour" labels it from this rather than from its own clock.
    """

    start: datetime = Field(description="Inclusive lower bound, in UTC.")
    end: datetime = Field(description="Inclusive upper bound, in UTC.")


class RiskParametersRead(BaseModel):
    """The thresholds the assessment was computed with.

    Stated in the response because an assessment without its parameters cannot be checked:
    a reader who disagrees with a bound can see which multiple produced it, and an operator
    can confirm that a deployment's configured thresholds are the ones in force. Every value
    here is server-side configuration — no request can set one.
    """

    deviation_multiple: float = Field(description="Baseline standard deviations to a bound.")
    extreme_multiple: float = Field(description="Multiple of a bound that counts as extreme.")
    rate_change_ratio: float = Field(description="Multiple of the baseline mean also required.")
    min_baseline_buckets: int
    min_baseline_events: int
    min_ratio_samples: int
    min_observed_samples: int
    min_distinct_hours: int
    min_novel_occurrences: int

    @classmethod
    def from_parameters(cls, parameters: DetectionParameters) -> RiskParametersRead:
        """The parameters, as the response states them."""
        return cls(**{field: getattr(parameters, field) for field in cls.model_fields})


class RiskObservationRead(BaseModel):
    """What the observation window contained for this entity, and which window it was.

    The interval comes first because it is the first thing to check: every count and every
    rate below it is about these two instants and no others. Then the counts of the action
    pipeline — requests, refusals, executions, failures, replays, approval requirements —
    plus the clock hours the activity fell in and how long the window is. The hours are here
    because an unusual-hour finding without them would name an hour the response does not
    otherwise mention.
    """

    start: datetime = Field(description="Inclusive lower bound of the observed window, in UTC.")
    end: datetime = Field(description="Inclusive upper bound of the observed window, in UTC.")
    events: int = Field(description="Action-pipeline events attributed to this entity.")
    requests: int
    executions: int
    failures: int
    denials: int
    approval_required: int
    replays: int
    completed: int = Field(description="Executions that finished: successes + failures.")
    action_count: int = Field(description="Distinct action identifiers used.")
    resource_count: int = Field(description="Distinct resources addressed.")
    active_hours: list[int] = Field(description="UTC clock hours with activity, ascending.")
    span_hours: float = Field(description="How long the observation window is, in hours.")

    @classmethod
    def from_frame(cls, frame: ActivityFrame) -> RiskObservationRead:
        """The frame's totals and coverage, as the response states them."""
        totals: WindowTotals = frame.totals
        return cls(
            start=frame.start,
            end=frame.end,
            events=totals.events,
            requests=totals.requests,
            executions=totals.executions,
            failures=totals.failures,
            denials=totals.denials,
            approval_required=totals.approval_required,
            replays=totals.replays,
            completed=totals.completed,
            action_count=len(frame.actions),
            resource_count=len(frame.resources),
            active_hours=sorted(frame.active_hours),
            span_hours=frame.span_hours,
        )


class RiskBaselineRead(BaseModel):
    """What the observation was compared against.

    ``window`` is the named span, and the bounds are what that resolved to: the baseline
    ends where the observation begins, always. ``hourly_buckets`` is how many full hours
    contributed samples — the number behind every bound in the response — and
    ``active_hours`` is the coverage the unusual-hour dimension needs before it will say
    anything at all.
    """

    window: BaselineWindow = Field(description="The named span this baseline is.")
    start: datetime
    end: datetime
    events: int
    requests: int
    executions: int
    failures: int
    denials: int
    approval_required: int
    completed: int
    action_count: int
    resource_count: int
    hourly_buckets: int = Field(description="Full hourly buckets that became samples.")
    active_hours: list[int]

    @classmethod
    def from_frame(cls, frame: ActivityFrame, *, window: BaselineWindow) -> RiskBaselineRead:
        """The baseline frame's totals and coverage, as the response states them."""
        totals: WindowTotals = frame.totals
        return cls(
            window=window,
            start=frame.start,
            end=frame.end,
            events=totals.events,
            requests=totals.requests,
            executions=totals.executions,
            failures=totals.failures,
            denials=totals.denials,
            approval_required=totals.approval_required,
            completed=totals.completed,
            action_count=len(frame.actions),
            resource_count=len(frame.resources),
            hourly_buckets=len(frame.full_buckets()),
            active_hours=sorted(frame.active_hours),
        )


class RiskDimensionRead(BaseModel):
    """One metric's examination, whether or not it deviated.

    A dimension that could not be measured reports ``insufficient_data`` with a closed
    ``reason`` and no numbers: zeros would read as a measurement of zero. A dimension that
    was measured keeps every number the comparison used, so a reader can recompute the
    bound is ``baseline_mean`` plus or minus ``threshold_multiple`` times the spread, and
    the two results are reported as ``upper_bound`` and ``lower_bound`` rather than left
    for a reader to derive.
    """

    metric: RiskMetric
    status: DimensionStatus
    reason: InsufficiencyReason | None = Field(
        default=None, description="Why the metric could not be measured; null when it was."
    )
    observed: float | None = Field(
        default=None, description="The measured quantity, in the metric's own unit."
    )
    baseline_mean: float | None = None
    baseline_stddev: float | None = None
    upper_bound: float | None = None
    lower_bound: float | None = None
    threshold_multiple: float | None = None
    baseline_samples: int = Field(
        default=0, description="Baseline observations behind the comparison."
    )
    observation_samples: int = Field(
        default=0, description="Observed events the measurement rests on."
    )
    detection_types: list[DetectionType] = Field(
        default_factory=list, description="The factors this dimension produced."
    )

    @classmethod
    def from_dimension(cls, dimension: Dimension) -> RiskDimensionRead:
        """One dimension, as the response and the stored evidence state it."""
        return cls(
            metric=dimension.metric,
            status=dimension.status,
            reason=dimension.reason,
            observed=dimension.observed,
            baseline_mean=dimension.baseline_mean,
            baseline_stddev=dimension.baseline_stddev,
            upper_bound=dimension.upper_bound,
            lower_bound=dimension.lower_bound,
            threshold_multiple=dimension.threshold_multiple,
            baseline_samples=dimension.baseline_samples,
            observation_samples=dimension.observation_samples,
            detection_types=list(dimension.detection_types),
        )


class RiskFactorItemRead(BaseModel):
    """One named piece of a factor: an action, a resource or a clock hour.

    ``value`` is the identifier as the organization's own rows state it; ``resource_type``
    is set only for a resource item, because two resource kinds can share an identifier.
    Nothing here is a payload and nothing here is a client's.
    """

    kind: FactorItemKind
    value: str = Field(max_length=128)
    occurrences: int
    resource_type: str | None = Field(
        default=None, max_length=32, description="Set for resource items, null otherwise."
    )

    @classmethod
    def from_item(cls, item: FactorItem) -> RiskFactorItemRead:
        """One evidence item, as the response and the stored record state it."""
        return cls(
            kind=item.kind,
            value=item.value,
            occurrences=item.occurrences,
            resource_type=item.resource_type,
        )


class RiskFactorRead(BaseModel):
    """One deviation, with the numbers it was computed from.

    Rate factors carry the baseline statistics and the bound that was crossed; first-use
    factors carry the threshold count that applied and the identifiers themselves. Both
    carry ``baseline_samples`` and ``observation_samples``, because a rate computed from
    three events and one computed from three hundred should not look alike.
    """

    type: DetectionType
    metric: RiskMetric
    observed: float
    baseline_mean: float | None = None
    baseline_stddev: float | None = None
    upper_bound: float | None = None
    lower_bound: float | None = None
    threshold_multiple: float | None = None
    threshold_occurrences: int | None = None
    baseline_samples: int
    observation_samples: int
    items: list[RiskFactorItemRead] = Field(default_factory=list)

    @classmethod
    def from_factor(cls, factor: Factor) -> RiskFactorRead:
        """One factor, as the response and the stored record state it."""
        return cls(
            type=factor.type,
            metric=factor.metric,
            observed=factor.observed,
            baseline_mean=factor.baseline_mean,
            baseline_stddev=factor.baseline_stddev,
            upper_bound=factor.upper_bound,
            lower_bound=factor.lower_bound,
            threshold_multiple=factor.threshold_multiple,
            threshold_occurrences=factor.threshold_occurrences,
            baseline_samples=factor.baseline_samples,
            observation_samples=factor.observation_samples,
            items=[RiskFactorItemRead.from_item(item) for item in factor.items],
        )


class RiskAssessmentRead(BaseModel):
    """``GET /risk/agents/{agent_id}``: one agent's assessment, in full.

    Every dimension is present whether or not it produced a factor, so the response says
    what was looked for and not only what was found. ``status`` and ``anomaly`` are the
    engine's conclusion; ``dimensions``, ``factors`` and ``parameters`` are everything that
    conclusion was computed from.
    """

    organization_id: uuid.UUID
    entity_type: EntityType
    entity_id: uuid.UUID
    status: AssessmentStatus
    anomaly: bool = Field(
        description="Whether any factor fired. A deviation, never a claim about intent."
    )
    risk_level: RiskLevel = Field(description="How much corroborated evidence the factors carry.")
    detection_type: DetectionType | None = Field(
        default=None, description="The head of the ordered factors; null when none fired."
    )
    observation: RiskObservationRead
    baseline: RiskBaselineRead
    dimensions: list[RiskDimensionRead]
    factors: list[RiskFactorRead]
    parameters: RiskParametersRead
    generated_at: datetime = Field(description="The server's clock when the assessment was made.")

    @classmethod
    def from_assessment(
        cls,
        *,
        organization_id: uuid.UUID,
        assessment: Assessment,
        observation: RiskObservationRead,
        baseline: RiskBaselineRead,
        parameters: DetectionParameters,
        generated_at: datetime,
    ) -> RiskAssessmentRead:
        """The assessment, as the API states it."""
        return cls(
            organization_id=organization_id,
            entity_type=assessment.entity_type,
            entity_id=assessment.entity_id,
            status=assessment.status,
            anomaly=assessment.anomaly,
            risk_level=assessment.risk_level,
            detection_type=assessment.detection_type,
            observation=observation,
            baseline=baseline,
            dimensions=[
                RiskDimensionRead.from_dimension(dimension) for dimension in assessment.dimensions
            ],
            factors=[RiskFactorRead.from_factor(factor) for factor in assessment.factors],
            parameters=RiskParametersRead.from_parameters(parameters),
            generated_at=generated_at,
        )


class RiskDetectionWindowRead(BaseModel):
    """The intervals a recorded assessment compared.

    The baseline's ``end`` is the observation's ``start`` by construction, and the window
    label says how long the baseline is — so a stored record explains its own arithmetic
    without reference to the request that produced it.
    """

    start: datetime
    end: datetime


class RiskEvidenceRead(BaseModel):
    """The measurements a recorded assessment rests on.

    Stored in the detection row and returned with it: the window totals, the parameters in
    force, and every dimension with its numbers and its refusals. A record is therefore
    checkable years later without re-running the query, and without trusting a summary.
    """

    observation: RiskObservationRead
    baseline: RiskBaselineRead
    parameters: RiskParametersRead
    dimensions: list[RiskDimensionRead]


class RiskDetectionRead(BaseModel):
    """One stored assessment, exactly as it was recorded.

    ``detected_at`` is when the engine looked; the two intervals are what it looked at. The
    evidence and factors are re-validated through the same models the live assessment uses,
    so a stored record and a computed one cannot drift into different shapes.
    """

    id: uuid.UUID
    organization_id: uuid.UUID
    detected_at: datetime
    entity_type: EntityType
    entity_id: uuid.UUID
    status: AssessmentStatus
    anomaly: bool
    risk_level: RiskLevel
    detection_type: DetectionType | None = None
    observation: RiskDetectionWindowRead
    baseline: RiskDetectionWindowRead
    baseline_window: BaselineWindow
    schema_version: int
    evidence: RiskEvidenceRead
    factors: list[RiskFactorRead]


class RiskAgentListResponse(BaseModel):
    """``GET /risk/agents``: one page of assessments.

    Ordered by the registry's own listing — newest registration first — so the order does
    not depend on what the engine found. The engine does not rank: an assessment is not a
    league table, and a page that reordered itself by level would make paging skip and
    repeat rows.
    """

    organization_id: uuid.UUID
    observation: RiskWindowRead
    baseline_window: BaselineWindow
    generated_at: datetime
    items: list[RiskAssessmentRead]
    limit: int
    offset: int
    count: int = Field(description="Assessments in this page.")
    total: int | None = Field(default=None, description="Registered agents; null unless requested.")


class RiskDetectionListResponse(BaseModel):
    """``GET /risk/detections``: one page of recorded assessments, newest first.

    ``total`` is present only when the caller asked for it, because it costs a second pass.
    """

    organization_id: uuid.UUID
    items: list[RiskDetectionRead]
    limit: int
    offset: int
    count: int
    total: int | None = None


class RiskAnalysisRequest(BaseModel):
    """``POST /risk/analysis``: which agent to assess, and nothing else.

    One field, and it is an identifier. There is deliberately no field for a threshold, a
    baseline, a level, an anomaly, a confidence or a window: the observation window comes
    from the query string (and must be explicit), the baseline is a named span, and every
    analytical value is derived server-side from the trail. ``extra="forbid"`` means a body
    that tries to add one is a 422 rather than a silently ignored field.
    """

    model_config = ConfigDict(extra="forbid")

    agent_id: uuid.UUID = Field(
        description=(
            "The registered agent to assess. An identifier this organization does not hold "
            "is answered exactly like one that does not exist."
        )
    )


class RiskAnalysisResponse(BaseModel):
    """``POST /risk/analysis``: the assessment, and whether it was recorded.

    ``recorded`` is false when the identical assessment was already stored — same agent,
    same observation window, same baseline, same schema version. Re-asking a closed window
    is therefore safe: it returns the record that exists instead of writing a second one,
    and the response says which of the two happened.
    """

    organization_id: uuid.UUID
    recorded: bool = Field(description="True when this request created the record.")
    detection: RiskDetectionRead
    assessment: RiskAssessmentRead


def evidence_document(
    *,
    observation: RiskObservationRead,
    baseline: RiskBaselineRead,
    parameters: RiskParametersRead,
    assessment: Assessment,
) -> dict[str, Any]:
    """The evidence document stored with a detection.

    Built from the same models the response uses — through
    :meth:`RiskEvidenceRead.model_dump` — so what is stored and what is returned are one
    shape, validated by one schema, rather than two renderings that have to be kept in step
    by hand.
    """
    evidence = RiskEvidenceRead(
        observation=observation,
        baseline=baseline,
        parameters=parameters,
        dimensions=[
            RiskDimensionRead.from_dimension(dimension) for dimension in assessment.dimensions
        ],
    )
    return evidence.model_dump(mode="json")


def factors_document(assessment: Assessment) -> list[dict[str, Any]]:
    """The factors array stored with a detection, in the order the engine produced."""
    return [
        RiskFactorRead.from_factor(factor).model_dump(mode="json") for factor in assessment.factors
    ]
