"""Human-in-the-loop security investigation with NVIDIA Nemotron on Nebius."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from aicore_api.auth.authorization import OrganizationContext
from aicore_api.auth.dependencies import SessionDep, require_permission
from aicore_api.config import get_settings
from aicore_api.core.intelligence import IntelligenceUnavailable, investigate
from aicore_api.core.permissions import Permission
from aicore_api.db.repositories.anomaly_detections import AnomalyDetectionRepository
from aicore_api.schemas.intelligence import InvestigationRequest, InvestigationResponse

router = APIRouter(prefix="/organizations", tags=["intelligence"])
ReadSecurity = Annotated[OrganizationContext, Depends(require_permission(Permission.AUDIT_READ))]


@router.post(
    "/{organization_id}/risk/detections/{detection_id}/investigate",
    response_model=InvestigationResponse,
    summary="Ask NVIDIA Nemotron to explain a deterministic anomaly finding",
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "The caller lacks audit.read"},
        404: {"description": "The detection does not exist for this organization"},
        503: {"description": "Nebius Token Factory is not configured or unavailable"},
    },
)
def investigate_detection(
    context: ReadSecurity,
    session: SessionDep,
    detection_id: str,
    body: InvestigationRequest,
) -> InvestigationResponse:
    """Generate advisory context without giving the model control of AICore.

    Only the deterministic detection evidence stored by Phase 10 is sent. The route never
    accepts action arguments, credentials, arbitrary audit metadata or an execution command.
    The model's output is informational and cannot enter authorization or the firewall.
    """
    try:
        row = AnomalyDetectionRepository(session, context.organization_id).get(detection_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection not found") from exc
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection not found")

    evidence = {
        "detection_type": row.detection_type,
        "analysis_status": row.analysis_status,
        "anomaly_state": row.anomaly_state,
        "risk_level": row.risk_level,
        "entity_type": row.entity_type,
        "entity_id": str(row.entity_id),
        "windows": {
            "baseline_start": row.baseline_start.isoformat(),
            "baseline_end": row.baseline_end.isoformat(),
            "observation_start": row.observation_start.isoformat(),
            "observation_end": row.observation_end.isoformat(),
        },
        "evidence": row.evidence,
        "risk_factors": row.risk_factors,
    }

    try:
        result = investigate(settings=get_settings(), evidence=evidence, question=body.question)
    except IntelligenceUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Nebius Token Factory inference is unavailable",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    return InvestigationResponse(
        detection_id=str(row.id),
        model=result.model,
        summary=result.summary,
        observations=result.observations,
        hypotheses=result.hypotheses,
        reviewer_questions=result.reviewer_questions,
        confidence=result.confidence,
        limitations=result.limitations,
    )
