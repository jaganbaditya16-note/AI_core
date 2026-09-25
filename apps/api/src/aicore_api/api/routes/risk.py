"""Risk routes: three ``GET`` endpoints that explain, and that is the whole surface.

Phase 10 answers "is anything *unusual*, and how concerning is it?" from the audit trail.
Every route here is a read. There is no route that records, edits, acknowledges, resolves,
suppresses or acts on a detection — recording is an operator command
(``python -m aicore_api.risk.cli``), and acting is not something this phase does at all.
A detection is information for a person; it is not an incident, not an alert, and never an
input to authorization, policy or the firewall.

**Why ``audit.read``, and only it.** An analysis is computed from the trail — agent ids,
action names, targets and times — so it cannot be granted to anyone who could not read the
trail, which is the reasoning Phase 9 applied to monitoring. ``security.read`` alone would
hand the analyst (who holds it without ``audit.read``) exactly that history in derived
form. And one permission per route is Phase 5's rule. The holders of ``audit.read`` — the
owner and the security administrator — are the roles a detection is for; no permission is
added and no role changes.

**Why the windows are a dependency.** Every analysis needs the same decision — which
baseline, which observation, as of when? — and a caller who gets it wrong gets the same
422 everywhere. The server's clock is read there, once per request, and nowhere else.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from aicore_api.auth.authorization import OrganizationContext
from aicore_api.auth.dependencies import SessionDep, require_permission
from aicore_api.core.permissions import Permission
from aicore_api.core.risk import (
    DEFAULT_BASELINE_WINDOW,
    DEFAULT_OBSERVATION_WINDOW,
    OBSERVATION_SPANS,
    RISK_ENGINE_VERSION,
    AgentAnalysis,
    AnalysisWindows,
    BaselineWindow,
    DetectionType,
    EntityType,
    ObservationWindow,
    RiskError,
    RiskLevel,
    detection_fingerprint,
    resolve_analysis_windows,
)
from aicore_api.db.models.anomaly_detection import AnomalyDetection
from aicore_api.db.repositories.anomaly_detections import AnomalyDetectionRepository
from aicore_api.db.repositories.risk_history import MAX_ANALYSIS_PAGE, RiskHistoryRepository
from aicore_api.risk.service import RiskAnalysisService
from aicore_api.schemas.risk import (
    AnomalyDetectionListResponse,
    AnomalyDetectionRead,
    RiskAgentAnalysisRead,
    RiskAgentBehaviourRead,
    RiskAnalysisResponse,
    RiskBaselineStatisticsRead,
    RiskCheckRead,
    RiskDetectionRead,
    RiskFactorRead,
    RiskObservationRead,
    RiskWindowsRead,
)

router = APIRouter(prefix="/organizations", tags=["risk"])

#: The one requirement of every route, and the context the handler receives.
ReadRisk = Annotated[OrganizationContext, Depends(require_permission(Permission.AUDIT_READ))]

_MAX_OFFSET = 100_000
_DETECTION_NOT_FOUND = "Anomaly detection not found"

_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"description": "Missing or invalid credentials"},
    403: {"description": "The caller lacks audit.read"},
    404: {"description": "The organization (or the detection) does not exist for the caller"},
    422: {
        "description": (
            "A window outside its vocabulary, an as_of that is naive, not a whole UTC hour "
            "or in the future, or a filter value outside its vocabulary"
        )
    },
}


def resolve_risk_windows(
    baseline: Annotated[
        BaselineWindow, Query(description="The baseline window: 7d, 14d or 30d")
    ] = DEFAULT_BASELINE_WINDOW,
    observation: Annotated[
        ObservationWindow, Query(description="The observation window: 1h, 6h or 24h")
    ] = DEFAULT_OBSERVATION_WINDOW,
    as_of: Annotated[
        datetime | None,
        Query(
            description=(
                "Exclusive end of the observation: a whole UTC hour, timezone-aware, not in "
                "the future. Defaults to the start of the current UTC hour."
            )
        ),
    ] = None,
) -> AnalysisWindows:
    """Turn the query string into the analysis windows, or refuse the request with 422."""
    try:
        return resolve_analysis_windows(
            baseline=baseline, observation=observation, as_of=as_of, now=datetime.now(UTC)
        )
    except RiskError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc


WindowsDep = Annotated[AnalysisWindows, Depends(resolve_risk_windows)]


def _windows_read(windows: AnalysisWindows) -> RiskWindowsRead:
    return RiskWindowsRead(
        baseline=windows.baseline,
        baseline_start=windows.baseline_start,
        baseline_end=windows.baseline_end,
        observation=windows.observation,
        observation_start=windows.observation_start,
        observation_end=windows.observation_end,
        slot_seconds=windows.slot_seconds,
        slots=windows.slots,
    )


def _analysis_read(analysis: AgentAnalysis, windows: AnalysisWindows) -> RiskAgentAnalysisRead:
    profile = analysis.profile
    statistics = analysis.statistics
    return RiskAgentAnalysisRead(
        entity_type=EntityType.AGENT,
        agent_id=analysis.agent_id,
        status=analysis.status,
        anomaly_state=analysis.anomaly_state,
        risk_level=analysis.risk_level,
        risk_factors=[RiskFactorRead(**factor.as_dict()) for factor in analysis.risk_factors],
        insufficient_reasons=list(analysis.insufficient_reasons),
        baseline_statistics=None
        if statistics is None
        else RiskBaselineStatisticsRead(
            history_slots=statistics.history_slots,
            events=statistics.events,
            mean=statistics.mean,
            stddev=statistics.stddev,
            zero_variance=statistics.zero_variance,
        ),
        observation=RiskObservationRead(
            requests=profile.observed_requests,
            denials=profile.observed_denials,
            executions=profile.observed_executions,
            failures=profile.observed_failures,
        ),
        behaviour=RiskAgentBehaviourRead(
            baseline_requests=profile.baseline_requests,
            baseline_active_slots=profile.active_slots,
            baseline_distinct_actions=profile.baseline_distinct_actions,
            observed_distinct_actions=profile.observed_distinct_actions,
            novel_action_count=profile.novel_action_count,
            baseline_distinct_resources=profile.baseline_distinct_resources,
            observed_distinct_resources=profile.observed_distinct_resources,
            novel_resource_count=profile.novel_resource_count,
            baseline_active_hours_utc=sum(1 for count in profile.baseline_hours if count),
            observed_active_hours_utc=sum(1 for count in profile.observed_hours if count),
            baseline_peak_requests=profile.baseline_peak,
            observed_peak_requests=profile.observed_peak,
        ),
        checks=[
            RiskCheckRead(
                detection_type=check.detection_type, status=check.status, reason=check.reason
            )
            for check in analysis.checks
        ],
        detections=[
            RiskDetectionRead(
                detection_type=detection.detection_type,
                risk_level=detection.risk_level,
                risk_factors=[
                    RiskFactorRead(**factor.as_dict()) for factor in detection.risk_factors
                ],
                evidence=dict(detection.evidence),
                fingerprint=detection_fingerprint(
                    entity_type=EntityType.AGENT,
                    entity_id=analysis.agent_id,
                    detection_type=detection.detection_type,
                    windows=windows,
                ),
            )
            for detection in analysis.detections
        ],
    )


def _stored_windows(row: AnomalyDetection) -> RiskWindowsRead:
    observation = ObservationWindow(row.observation_window)
    span = OBSERVATION_SPANS[observation]
    return RiskWindowsRead(
        baseline=BaselineWindow(row.baseline_window),
        baseline_start=row.baseline_start,
        baseline_end=row.baseline_end,
        observation=observation,
        observation_start=row.observation_start,
        observation_end=row.observation_end,
        slot_seconds=int(span.total_seconds()),
        slots=int((row.baseline_end - row.baseline_start) / span),
    )


def _detection_read(row: AnomalyDetection) -> AnomalyDetectionRead:
    return AnomalyDetectionRead.model_validate(
        {
            "id": row.id,
            "organization_id": row.organization_id,
            "schema_version": row.schema_version,
            "engine_version": row.engine_version,
            "detected_at": row.detected_at,
            "entity_type": row.entity_type,
            "entity_id": row.entity_id,
            "detection_type": row.detection_type,
            "analysis_status": row.analysis_status,
            "anomaly_state": row.anomaly_state,
            "risk_level": row.risk_level,
            "windows": _stored_windows(row),
            "evidence": row.evidence,
            "risk_factors": row.risk_factors,
            "fingerprint": row.fingerprint,
        }
    )


def _store(context: OrganizationContext, session: Session) -> AnomalyDetectionRepository:
    """The detection store for this request's tenant — from the authorized context only."""
    return AnomalyDetectionRepository(session, context.organization_id)


@router.get(
    "/{organization_id}/risk/analysis",
    response_model=RiskAnalysisResponse,
    summary="Analyse the organization's agents for anomalies, on demand",
    responses=_RESPONSES,
)
def read_risk_analysis(
    context: ReadRisk,
    session: SessionDep,
    windows: WindowsDep,
    agent_id: Annotated[
        uuid.UUID | None,
        Query(description="Narrow to one agent; a foreign or unknown id has no rows"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_ANALYSIS_PAGE)] = 50,
    offset: Annotated[int, Query(ge=0, le=_MAX_OFFSET)] = 0,
    total: Annotated[bool, Query(description="Include the total; costs a query")] = False,
) -> RiskAnalysisResponse:
    """One page of agents (by identifier), each compared against its own baseline.

    Computed from bounded aggregates on every request and never stored. An agent with too
    little history is reported as ``insufficient_history`` rather than guessed about.
    """
    service = RiskAnalysisService(RiskHistoryRepository(session, context.organization_id))
    page = service.analyze(windows, limit=limit, offset=offset, agent_id=agent_id, total=total)
    return RiskAnalysisResponse(
        organization_id=context.organization_id,
        engine_version=RISK_ENGINE_VERSION,
        windows=_windows_read(windows),
        items=[_analysis_read(item, windows) for item in page.items],
        limit=limit,
        offset=offset,
        count=len(page.items),
        total=page.total,
    )


@router.get(
    "/{organization_id}/risk/detections",
    response_model=AnomalyDetectionListResponse,
    summary="List the organization's recorded anomaly detections",
    responses=_RESPONSES,
)
def list_anomaly_detections(
    context: ReadRisk,
    session: SessionDep,
    agent_id: Annotated[uuid.UUID | None, Query(description="Only this agent's detections")] = None,
    detection_type: Annotated[DetectionType | None, Query()] = None,
    risk_level: Annotated[RiskLevel | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=_MAX_OFFSET)] = 0,
    total: Annotated[bool, Query(description="Include the filtered total")] = False,
) -> AnomalyDetectionListResponse:
    """Recorded detections, newest first. Filters narrow; a foreign id selects nothing."""
    store = _store(context, session)
    rows = store.list(
        limit=limit,
        offset=offset,
        agent_id=agent_id,
        detection_type=detection_type,
        risk_level=risk_level,
    )
    counted = (
        store.count(agent_id=agent_id, detection_type=detection_type, risk_level=risk_level)
        if total
        else None
    )
    return AnomalyDetectionListResponse(
        organization_id=context.organization_id,
        items=[_detection_read(row) for row in rows],
        limit=limit,
        offset=offset,
        count=len(rows),
        total=counted,
    )


@router.get(
    "/{organization_id}/risk/detections/{detection_id}",
    response_model=AnomalyDetectionRead,
    summary="Read one recorded anomaly detection",
    responses=_RESPONSES,
)
def read_anomaly_detection(
    context: ReadRisk, session: SessionDep, detection_id: uuid.UUID
) -> AnomalyDetectionRead:
    """One detection of this organization. Another tenant's detection is a plain 404."""
    row = _store(context, session).get(detection_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_DETECTION_NOT_FOUND)
    return _detection_read(row)
