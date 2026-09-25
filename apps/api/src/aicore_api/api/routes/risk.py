"""Risk routes: four reads and one recording, and that is the whole surface.

Phase 10 answers "does this agent's behaviour differ from its own history, and by how
much?" — and stops there. Every read route is a ``GET``; the one ``POST`` records an
assessment and can write to nothing but the detection table. There is no route here that
acts on a finding: no acknowledgement, no suppression, no escalation, no incident, no
notification, no containment, and no way to change what the engine computed. A detection is
evidence with a number attached; the phases that own response are later phases, and none of
them is half-built here.

**Why reads need ``security.read`` and recording needs ``security.create``.** Reading a
finding is reading security information, which Phase 2 already has a permission for, and
Phase 9 left ``security.read`` reserved for exactly this subject. *Recording* one writes a
row, so it gets its own capability rather than riding on the read: an analyst reads the
engine's output, and a security administrator records it. No new resource and no new action
was invented for it — ``security.create`` is the existing vocabulary's own pair.

**Why the windows are a dependency.** Every route needs the same two decisions — which
interval is observed, and which baseline it is compared against — and a caller who gets
either wrong should get the same 422 everywhere. Resolving them once, before any handler
runs, is also what keeps the repository unable to see an unbounded request: by the time a
handler runs, both windows exist. The clock is read once per request, inside the resolver,
so a response's windows and its ``generated_at`` describe one instant.

**Why recording demands explicit bounds.** A named window means "the last hour, as of when
you asked", which is a different interval on every request — recording that would write a
new detection each time somebody looked. ``window=custom`` with both bounds states the
interval, so the same interval is the same record, and re-asking is a no-op the response
reports rather than a duplicate it shrugs at.

**What is deliberately absent.** No ``/risk/run`` that scans history, no scheduling, no
background worker, no threshold or configuration endpoint (thresholds are server
configuration, and a client that could set one could tune the detector), no comparison
endpoint, no bulk recording, and no ranking: ``/risk/agents`` is ordered the way the
registry lists agents, not by what was found.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.orm import Session

from aicore_api.auth.authorization import OrganizationContext
from aicore_api.auth.dependencies import SessionDep, require_permission
from aicore_api.core.domain_errors import NotFoundError
from aicore_api.core.monitoring import DEFAULT_WINDOW, MonitoringWindow, ResolvedWindow
from aicore_api.core.permissions import Permission
from aicore_api.core.risk import (
    DEFAULT_BASELINE,
    AssessmentStatus,
    Baseline,
    BaselineWindow,
    DetectionParameters,
    DetectionType,
    RiskLevel,
    RiskWindowError,
    resolve_baseline,
    resolve_observation,
)
from aicore_api.db.repositories.agents import AgentRepository
from aicore_api.db.repositories.risk import DetectionRepository, RiskRepository
from aicore_api.risk.service import AssessmentBundle, RiskService
from aicore_api.schemas.risk import (
    RiskAgentListResponse,
    RiskAnalysisRequest,
    RiskAnalysisResponse,
    RiskAssessmentRead,
    RiskDetectionListResponse,
    RiskDetectionRead,
    RiskDetectionWindowRead,
    RiskEvidenceRead,
    RiskFactorRead,
    RiskWindowRead,
)

router = APIRouter(prefix="/organizations", tags=["risk"])

#: Reading findings: the permission Phase 2 created for security information, and the one
#: Phase 9's documentation reserved for this phase's subject.
ReadRisk = Annotated[OrganizationContext, Depends(require_permission(Permission.SECURITY_READ))]

#: Recording one: a write, and therefore its own capability. Checked before the handler
#: runs, so a caller without it cannot even learn what would have been recorded.
RecordRisk = Annotated[OrganizationContext, Depends(require_permission(Permission.SECURITY_CREATE))]

#: The same ceiling the other listings use, for the row-shaped collection.
_MAX_LIMIT = 200

#: A page of *assessments* is capped lower than a page of rows: each item carries six
#: dimensions, the baseline it was compared against and the thresholds in force, so a
#: hundred is already more than a person reads in one answer.
_MAX_ASSESSMENTS = 100
_DEFAULT_ASSESSMENTS = 25

#: Detections carry their evidence too, for the same reason, but a feed is meant to be
#: scrolled: fifty a page, and the caller can ask for more up to the same ceiling.
_DEFAULT_DETECTIONS = 50

_MAX_OFFSET = 100_000

_AGENT_NOT_FOUND = "agent not found"
_DETECTION_NOT_FOUND = "detection not found"

_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"description": "Missing or invalid credentials"},
    403: {
        "description": (
            "The caller lacks security.read (for a read) or security.create (for recording)"
        )
    },
    404: {"description": "The organization does not exist or the caller is not a member"},
    422: {
        "description": (
            "A window is malformed (a naive timestamp, an inverted or empty range, a range "
            "longer than a month), or a filter value is outside its vocabulary"
        )
    },
}

_RECORDING_RESPONSES: dict[int | str, dict[str, Any]] = {
    **_RESPONSES,
    200: {
        "description": (
            "The identical assessment was already recorded; the record that exists is "
            "returned and nothing was written"
        )
    },
    201: {"description": "The assessment was recorded"},
}


@dataclass(frozen=True, slots=True)
class RiskWindows:
    """The two intervals a request is about, and the instant they were resolved against.

    ``now`` is the server's clock, read once. For a named observation window it is also the
    window's end; for an explicit one the caller chose the end and ``now`` is only the
    moment of the request — which is what makes a response's ``generated_at`` honest either
    way, and what a recorded row's ``detected_at`` is taken from.
    """

    observation: ResolvedWindow
    baseline: Baseline
    now: datetime


def resolve_risk_windows(
    window: Annotated[
        MonitoringWindow,
        Query(description="A named observation window, or 'custom' with start_time and end_time"),
    ] = DEFAULT_WINDOW,
    start_time: Annotated[
        datetime | None,
        Query(description="Inclusive lower bound; required with window=custom, timezone-aware"),
    ] = None,
    end_time: Annotated[
        datetime | None,
        Query(description="Inclusive upper bound; required with window=custom, timezone-aware"),
    ] = None,
    baseline: Annotated[
        BaselineWindow,
        Query(description="How much history the observation is compared against"),
    ] = DEFAULT_BASELINE,
) -> RiskWindows:
    """Resolve both windows, or refuse the request with the reason.

    The observation window uses Phase 9's vocabulary and rules — the same named spans, the
    same refusals, the same ``custom`` escape hatch — plus one of this phase's own: a window
    with no duration is refused, because a rate whose divisor is zero is not a measurement.
    The baseline is a named span anchored so that it ends where the observation begins,
    which is what keeps an observation out of its own baseline.
    """
    moment = datetime.now(UTC)
    try:
        observation = resolve_observation(
            window=window, start_time=start_time, end_time=end_time, now=moment
        )
        resolved_baseline = resolve_baseline(name=baseline, observation_start=observation.start)
    except RiskWindowError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return RiskWindows(observation=observation, baseline=resolved_baseline, now=moment)


WindowsDep = Annotated[RiskWindows, Depends(resolve_risk_windows)]


def resolve_risk_parameters(request: Request) -> DetectionParameters:
    """The thresholds in force, from the application's settings.

    A deployment configures them; a request cannot see them, let alone set one. There is no
    endpoint that reads or writes them, and no query parameter named after any of them —
    tuning the detector is a deployment decision, not a client one.
    """
    return DetectionParameters.from_settings(request.app.state.settings)


ParametersDep = Annotated[DetectionParameters, Depends(resolve_risk_parameters)]


def _service(
    context: OrganizationContext, session: Session, parameters: DetectionParameters
) -> RiskService:
    """The risk service for one request: this tenant's trail and records, one session.

    Constructed per request with the organization the authorized context resolved, and the
    parameters the application was configured with. Nothing about it comes from the query
    string or the body.
    """
    return RiskService(
        risk=RiskRepository(session, context.organization_id),
        detections=DetectionRepository(session, context.organization_id),
        agents=AgentRepository(session, context.organization_id),
        parameters=parameters,
    )


def _window_read(bundle: AssessmentBundle) -> RiskWindowRead:
    """The resolved observation interval, as a response states it."""
    return RiskWindowRead(start=bundle.observation.start, end=bundle.observation.end)


def _assessment_read(
    *, organization_id: uuid.UUID, bundle: AssessmentBundle, generated_at: datetime
) -> RiskAssessmentRead:
    """One assessment, as the API states it."""
    return RiskAssessmentRead.from_assessment(
        organization_id=organization_id,
        assessment=bundle.assessment,
        observation=bundle.observation_read(),
        baseline=bundle.baseline_read(),
        parameters=bundle.parameters,
        generated_at=generated_at,
    )


def _detection_read(record: Any) -> RiskDetectionRead:
    """A stored detection, re-validated through the same models the live assessment uses."""
    return RiskDetectionRead(
        id=record.id,
        organization_id=record.organization_id,
        detected_at=record.detected_at,
        entity_type=record.entity_type,
        entity_id=record.entity_id,
        status=record.status,
        anomaly=record.anomaly,
        risk_level=record.risk_level,
        detection_type=record.detection_type,
        observation=RiskDetectionWindowRead(
            start=record.observation_start, end=record.observation_end
        ),
        baseline=RiskDetectionWindowRead(start=record.baseline_start, end=record.baseline_end),
        baseline_window=record.baseline_window,
        schema_version=record.schema_version,
        evidence=RiskEvidenceRead.model_validate(record.evidence),
        factors=[RiskFactorRead.model_validate(factor) for factor in record.factors],
    )


@router.get(
    "/{organization_id}/risk/agents",
    response_model=RiskAgentListResponse,
    summary="Assess a page of the agent registry against its own baseline",
    responses=_RESPONSES,
)
def read_risk_agents(
    context: ReadRisk,
    session: SessionDep,
    parameters: ParametersDep,
    windows: WindowsDep,
    limit: Annotated[int, Query(ge=1, le=_MAX_ASSESSMENTS)] = _DEFAULT_ASSESSMENTS,
    offset: Annotated[int, Query(ge=0, le=_MAX_OFFSET)] = 0,
    total: Annotated[bool, Query(description="Include the registry's agent count")] = False,
) -> RiskAgentListResponse:
    """Every agent in one page of the registry, assessed over the same two windows.

    The population is the registry, so an agent that has been silent gets an assessment that
    says so. The order is the registry's own (newest registration first) rather than the
    engine's: nothing here ranks agents, and a page that reordered itself by level would
    make paging skip and repeat rows.
    """
    bundles, registry_total = _service(context, session, parameters).assess_page(
        observation=windows.observation,
        baseline_window=windows.baseline,
        limit=limit,
        offset=offset,
    )
    return RiskAgentListResponse(
        organization_id=context.organization_id,
        observation=(RiskWindowRead(start=windows.observation.start, end=windows.observation.end)),
        baseline_window=windows.baseline.name,
        generated_at=windows.now,
        items=[
            _assessment_read(
                organization_id=context.organization_id, bundle=bundle, generated_at=windows.now
            )
            for bundle in bundles
        ],
        limit=limit,
        offset=offset,
        count=len(bundles),
        total=registry_total if total else None,
    )


@router.get(
    "/{organization_id}/risk/agents/{agent_id}",
    response_model=RiskAssessmentRead,
    summary="Assess one registered agent",
    responses=_RESPONSES,
)
def read_risk_agent(
    agent_id: uuid.UUID,
    context: ReadRisk,
    session: SessionDep,
    parameters: ParametersDep,
    windows: WindowsDep,
) -> RiskAssessmentRead:
    """One agent's assessment, or 404 — never a hint that a foreign agent exists.

    An agent that exists but has no history gets a complete assessment whose status says
    ``insufficient_data``: the cold start is stated, not hidden, and it is never a deviation.
    """
    try:
        bundle = _service(context, session, parameters).assess_agent(
            agent_id=agent_id,
            observation=windows.observation,
            baseline_window=windows.baseline,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_AGENT_NOT_FOUND) from exc
    return _assessment_read(
        organization_id=context.organization_id, bundle=bundle, generated_at=windows.now
    )


@router.get(
    "/{organization_id}/risk/detections",
    response_model=RiskDetectionListResponse,
    summary="List recorded assessments",
    responses=_RESPONSES,
)
def read_risk_detections(
    context: ReadRisk,
    session: SessionDep,
    parameters: ParametersDep,
    limit: Annotated[int, Query(ge=1, le=_MAX_LIMIT)] = _DEFAULT_DETECTIONS,
    offset: Annotated[int, Query(ge=0, le=_MAX_OFFSET)] = 0,
    agent_id: Annotated[
        uuid.UUID | None, Query(description="Only records about this agent")
    ] = None,
    detection_type: Annotated[
        DetectionType | None, Query(description="Only records whose primary factor is this")
    ] = None,
    risk_level: Annotated[RiskLevel | None, Query(description="Only records at this level")] = None,
    assessment_status: Annotated[
        AssessmentStatus | None, Query(description="Only records with this status")
    ] = None,
    total: Annotated[bool, Query(description="Include the number of matching records")] = False,
) -> RiskDetectionListResponse:
    """The organization's detection records, newest first, one page at a time.

    Filters narrow the page; they never reach across tenants, and an ``agent_id`` from
    another organization simply matches nothing. ``limit`` and ``offset`` are bounded so a
    client cannot ask for the whole history at once.
    """
    service = _service(context, session, parameters)
    records = service.detections(
        limit=limit,
        offset=offset,
        agent_id=agent_id,
        detection_type=None if detection_type is None else detection_type.value,
        risk_level=None if risk_level is None else risk_level.value,
        status=assessment_status,
    )
    return RiskDetectionListResponse(
        organization_id=context.organization_id,
        items=[_detection_read(record) for record in records],
        limit=limit,
        offset=offset,
        count=len(records),
        total=(
            service.detection_count(
                agent_id=agent_id,
                detection_type=None if detection_type is None else detection_type.value,
                risk_level=None if risk_level is None else risk_level.value,
                status=assessment_status,
            )
            if total
            else None
        ),
    )


@router.get(
    "/{organization_id}/risk/detections/{detection_id}",
    response_model=RiskDetectionRead,
    summary="Read one recorded assessment",
    responses=_RESPONSES,
)
def read_risk_detection(
    detection_id: uuid.UUID,
    context: ReadRisk,
    session: SessionDep,
    parameters: ParametersDep,
) -> RiskDetectionRead:
    """One record by identifier, or 404 — the same answer for unknown and for foreign."""
    try:
        record = _service(context, session, parameters).detection(detection_id)
    except NotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=_DETECTION_NOT_FOUND
        ) from exc
    return _detection_read(record)


@router.post(
    "/{organization_id}/risk/analysis",
    response_model=RiskAnalysisResponse,
    summary="Record an assessment of one agent",
    responses=_RECORDING_RESPONSES,
    status_code=status.HTTP_201_CREATED,
)
def record_risk_analysis(
    payload: RiskAnalysisRequest,
    response: Response,
    context: RecordRisk,
    session: SessionDep,
    parameters: ParametersDep,
    windows: WindowsDep,
) -> RiskAnalysisResponse:
    """Assess one agent and record the result, once per closed window.

    The observation window must be explicit (``window=custom`` with both bounds): a named
    window is a different interval on every request, and recording one would write a new
    detection each time somebody looked. The record's identity is the agent and the two
    intervals, so asking twice returns the record that exists — ``recorded: false`` — rather
    than a duplicate.

    Nothing about the assessment comes from the body beyond which agent it is about: no
    threshold, level, mean or bound is accepted, and a body that tries to send one is a 422.

    ``201`` when this request wrote the record, ``200`` when the record already existed;
    ``recorded`` in the body carries the same fact for a client that reads only the payload.
    """
    if windows.observation.name is not MonitoringWindow.CUSTOM:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "recording an assessment requires an explicit window: pass window=custom with "
                "start_time and end_time, so that the record describes a stated interval "
                "rather than 'the last hour as of whenever this was asked'"
            ),
        )
    service = _service(context, session, parameters)
    try:
        bundle = service.assess_agent(
            agent_id=payload.agent_id,
            observation=windows.observation,
            baseline_window=windows.baseline,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_AGENT_NOT_FOUND) from exc

    record, created = service.record(bundle)
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return RiskAnalysisResponse(
        organization_id=context.organization_id,
        recorded=created,
        detection=_detection_read(record),
        assessment=_assessment_read(
            organization_id=context.organization_id, bundle=bundle, generated_at=windows.now
        ),
    )
