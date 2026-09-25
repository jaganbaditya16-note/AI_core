"""Risk contract: explainable analyses and recorded detections, read-only.

Phase 10 publishes what the anomaly engine concluded and *why*. Three rules shape it.

**Response models only.** There is no request body anywhere in this contract: no client
submits an anomaly state, a risk level, a baseline, a statistic, a detection type, evidence
or a risk factor. Every field below is computed by the server from the organization's own
audit trail, so there is nothing to spoof.

**Every level is explained.** A risk level is one of ``none``/``low``/``medium``/``high``/
``critical`` — never a number — and any level above ``none`` arrives with the structured
factors that produced it. A detection carries its evidence: the entity, both windows, the
measured values and the comparison that fired, in a fixed shape (``docs/risk.md``).

**"Could not tell" is not "nothing unusual".** An agent without enough history is
``insufficient_history`` / ``undetermined`` / ``none`` with the reasons listed, and each
check says whether it ran, and if not, why. Evidence never contains a payload, an argument,
a credential or a token: the engine never reads the trail's metadata.

A detection is a finding for a person to read. It is not an incident, and nothing in this
contract acknowledges, assigns, resolves or acts on one.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from aicore_api.core.risk import (
    AnalysisStatus,
    AnomalyState,
    BaselineWindow,
    CheckReason,
    CheckStatus,
    DetectionType,
    EntityType,
    FactorEffect,
    InsufficientReason,
    ObservationWindow,
    RiskFactorCode,
    RiskLevel,
)

__all__ = [
    "AnomalyDetectionListResponse",
    "AnomalyDetectionRead",
    "RiskAgentAnalysisRead",
    "RiskAgentBehaviourRead",
    "RiskAnalysisResponse",
    "RiskBaselineStatisticsRead",
    "RiskCheckRead",
    "RiskDetectionRead",
    "RiskFactorRead",
    "RiskObservationRead",
    "RiskWindowsRead",
]


class RiskWindowsRead(BaseModel):
    """The two intervals an analysis compared, resolved by the server.

    Half-open and adjacent: ``baseline_end == observation_start``, so no event is in both.
    The baseline is split into ``slots`` slots of ``slot_seconds`` (the observation's
    length), which is what the rate statistics are computed over.
    """

    baseline: BaselineWindow = Field(description="The named baseline window.")
    baseline_start: datetime = Field(description="Inclusive start of the baseline, UTC.")
    baseline_end: datetime = Field(description="Exclusive end of the baseline, UTC.")
    observation: ObservationWindow = Field(description="The named observation window.")
    observation_start: datetime = Field(description="Inclusive start of the observation, UTC.")
    observation_end: datetime = Field(
        description="Exclusive end of the observation, UTC: the analysis's as_of."
    )
    slot_seconds: int = Field(description="Length of one baseline slot, in seconds.")
    slots: int = Field(description="How many slots the baseline holds.")


class RiskFactorRead(BaseModel):
    """One reason a risk level is what it is.

    A ``base`` factor sets a ``level``; an ``escalation`` factor adds ``steps``.
    """

    code: RiskFactorCode = Field(description="What the factor is.")
    effect: FactorEffect = Field(description="Whether it sets a level or raises one.")
    level: RiskLevel | None = Field(default=None, description="The level a base factor sets.")
    steps: int | None = Field(default=None, description="Steps an escalation adds.")
    detection_type: DetectionType | None = Field(
        default=None, description="The detection the factor came from, when it has one."
    )
    count: int | None = Field(
        default=None, description="Distinct detection types, for the breadth escalations."
    )


class RiskCheckRead(BaseModel):
    """What one detection type concluded for one agent — including that it could not tell."""

    detection_type: DetectionType
    status: CheckStatus
    reason: CheckReason | None = Field(
        default=None, description="Why the check was not evaluated or had too little data."
    )


class RiskBaselineStatisticsRead(BaseModel):
    """Mean and population standard deviation of per-slot request counts.

    Computed over the agent's *history slots*: every baseline slot from its first activity
    onwards, empty ones included. ``null`` in the analysis when history is insufficient —
    a baseline is never fabricated.
    """

    history_slots: int
    events: int
    mean: float
    stddev: float
    zero_variance: bool = Field(description="Every history slot held the same count.")


class RiskObservationRead(BaseModel):
    """What the agent did in the observation window."""

    requests: int = Field(description="``action.requested`` events.")
    denials: int = Field(description="``action.denied`` events.")
    executions: int = Field(description="``action.executed`` events.")
    failures: int = Field(description="``action.failed`` events.")


class RiskAgentBehaviourRead(BaseModel):
    """The agent's action, target and time behaviour, baseline against observation.

    Counts only: the engine publishes how many distinct actions and targets an agent used
    and in how many UTC hours it was active, never the arguments it used them with.
    """

    baseline_requests: int
    baseline_active_slots: int
    baseline_distinct_actions: int
    observed_distinct_actions: int
    novel_action_count: int
    baseline_distinct_resources: int
    observed_distinct_resources: int
    novel_resource_count: int
    baseline_active_hours_utc: int = Field(description="UTC hours of day with baseline activity.")
    observed_active_hours_utc: int = Field(description="UTC hours of day with observed activity.")
    baseline_peak_requests: int = Field(description="Busiest 5-minute bucket in the baseline.")
    observed_peak_requests: int = Field(description="Busiest 5-minute bucket in the observation.")


class RiskDetectionRead(BaseModel):
    """One anomaly found by an analysis, with the evidence that explains it."""

    detection_type: DetectionType
    risk_level: RiskLevel = Field(description="Never ``none``: a detection always has a level.")
    risk_factors: list[RiskFactorRead] = Field(min_length=1)
    evidence: dict[str, Any] = Field(
        description=(
            "Server-generated: engine_version, detection_type, entity, baseline, "
            "observation, measurement, comparison and risk_factors. Never a payload."
        )
    )
    fingerprint: str = Field(
        description="SHA-256 of entity, type, windows and engine version: the dedup key."
    )


class RiskAgentAnalysisRead(BaseModel):
    """Everything the engine concluded about one agent in one analysis."""

    entity_type: EntityType
    agent_id: uuid.UUID
    status: AnalysisStatus
    anomaly_state: AnomalyState
    risk_level: RiskLevel
    risk_factors: list[RiskFactorRead] = Field(
        description="Why the level is what it is; empty exactly when the level is none."
    )
    insufficient_reasons: list[InsufficientReason] = Field(
        description="The cold-start rules that were not met; empty when analysed."
    )
    baseline_statistics: RiskBaselineStatisticsRead | None
    observation: RiskObservationRead
    behaviour: RiskAgentBehaviourRead
    checks: list[RiskCheckRead]
    detections: list[RiskDetectionRead]


class RiskAnalysisResponse(BaseModel):
    """One page of on-demand analyses. Computed per request; nothing is stored."""

    organization_id: uuid.UUID
    engine_version: int
    windows: RiskWindowsRead
    items: list[RiskAgentAnalysisRead]
    limit: int
    offset: int
    count: int
    total: int | None = Field(description="The total number of agents, when requested.")


class AnomalyDetectionRead(BaseModel):
    """One recorded detection. Immutable: there is no status to change and no owner."""

    id: uuid.UUID
    organization_id: uuid.UUID
    schema_version: int
    engine_version: int
    detected_at: datetime
    entity_type: EntityType
    entity_id: uuid.UUID
    detection_type: DetectionType
    analysis_status: AnalysisStatus
    anomaly_state: AnomalyState
    risk_level: RiskLevel
    windows: RiskWindowsRead
    evidence: dict[str, Any]
    risk_factors: list[RiskFactorRead]
    fingerprint: str


class AnomalyDetectionListResponse(BaseModel):
    """One page of recorded detections, newest first."""

    organization_id: uuid.UUID
    items: list[AnomalyDetectionRead]
    limit: int
    offset: int
    count: int
    total: int | None = Field(description="The filtered total, when requested.")
