"""Advisory incident investigation through NVIDIA Nemotron on Nebius Token Factory.

The route is intentionally outside the action firewall's execution path. It can explain a
recorded anomaly, but it cannot approve, authorize, mutate, or execute anything. The model
sees only bounded, server-generated detection evidence.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from aicore_api.auth.authorization import OrganizationContext
from aicore_api.auth.dependencies import SessionDep, require_permission
from aicore_api.config import get_settings
from aicore_api.core.permissions import Permission
from aicore_api.core.request_context import get_current_request_id
from aicore_api.db.repositories.anomaly_detections import AnomalyDetectionRepository
from aicore_api.nebius.investigator import (
    InvestigatorUnavailableError,
    InvestigatorUpstreamError,
    investigate,
)
from aicore_api.schemas.investigation import InvestigationRead

router = APIRouter(prefix="/organizations", tags=["investigation"])
ReadInvestigation = Annotated[
    OrganizationContext, Depends(require_permission(Permission.AUDIT_READ))
]


@router.post(
    "/{organization_id}/risk/detections/{detection_id}/investigation",
    response_model=InvestigationRead,
    summary="Ask Nemotron for a bounded advisory investigation of a recorded anomaly",
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "The caller lacks audit.read"},
        404: {"description": "Detection does not exist for this organization"},
        503: {"description": "Nebius Token Factory is not configured or unavailable"},
    },
)
def investigate_detection(
    context: ReadInvestigation,
    session: SessionDep,
    detection_id: uuid.UUID,
) -> InvestigationRead:
    """Return a model-generated investigation brief without taking action.

    The detection is loaded through the tenant-scoped repository. The model receives no
    request arguments, credentials, audit payloads, or arbitrary database rows. A foreign
    tenant's detection is indistinguishable from a missing detection.
    """
    row = AnomalyDetectionRepository(session, context.organization_id).get(detection_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly detection not found")

    detection: dict[str, Any] = {
        "detection_id": str(row.id),
        "detection_type": row.detection_type,
        "risk_level": row.risk_level,
        "analysis_status": row.analysis_status,
        "anomaly_state": row.anomaly_state,
        "detected_at": row.detected_at.isoformat(),
        "entity_type": row.entity_type,
        "entity_id": str(row.entity_id),
        "baseline_window": row.baseline_window,
        "observation_window": row.observation_window,
        "baseline_start": row.baseline_start.isoformat(),
        "baseline_end": row.baseline_end.isoformat(),
        "observation_start": row.observation_start.isoformat(),
        "observation_end": row.observation_end.isoformat(),
        "evidence": row.evidence,
        "risk_factors": row.risk_factors,
    }

    try:
        result = investigate(
            get_settings(),
            detection,
            correlation_id=get_current_request_id(),
        )
    except InvestigatorUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "nebius_not_configured", "message": str(exc)},
        ) from exc
    except InvestigatorUpstreamError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "nebius_unavailable", "message": str(exc)},
        ) from exc

    return InvestigationRead(
        detection_id=str(row.id),
        detection_type=row.detection_type,
        risk_level=row.risk_level,
        summary=result.brief.summary,
        why_it_matters=result.brief.why_it_matters,
        hypotheses=result.brief.hypotheses,
        checks=result.brief.checks,
        recommended_containment=result.brief.recommended_containment,
        confidence=result.brief.confidence,
        uncertainties=result.brief.uncertainties,
        do_not_do=result.brief.do_not_do,
        model=result.model,
        correlation_id=result.correlation_id,
        input_truncated=result.input_truncated,
        action_taken=False,
    )
