"""Tenant-scoped incident operations.

Incident prose is explicitly user-authored. Evidence is reference-only and never copies
raw audit payloads, credentials or action arguments.
"""
from __future__ import annotations
import uuid
from datetime import UTC, datetime
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from aicore_api.auth.authorization import OrganizationContext
from aicore_api.auth.dependencies import PrincipalDep, SessionDep, require_permission
from aicore_api.core.permissions import Permission
from aicore_api.db.repositories.incidents import IncidentRepository
from aicore_api.schemas.incidents import EvidenceCreateRequest, EvidenceRead, IncidentCreateRequest, IncidentRead, IncidentTransitionRequest, IncidentUpdateRequest

router = APIRouter(prefix="/organizations", tags=["incidents"])
ReadIncidents = Annotated[OrganizationContext, Depends(require_permission(Permission.INCIDENT_READ))]
ManageIncidents = Annotated[OrganizationContext, Depends(require_permission(Permission.INCIDENT_UPDATE))]
CreateIncidents = Annotated[OrganizationContext, Depends(require_permission(Permission.INCIDENT_CREATE))]


def _read(row, evidence=()):
    return IncidentRead(
        id=row.id, organization_id=row.organization_id, title=row.title, description=row.description,
        status=row.status, severity=row.severity, created_by=row.created_by,
        source_detection_id=row.source_detection_id, created_at=row.created_at,
        updated_at=row.updated_at, closed_at=row.closed_at,
        evidence=[EvidenceRead.model_validate(e, from_attributes=True) for e in evidence],
    )

@router.post("/{organization_id}/incidents", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
def create_incident(context: CreateIncidents, principal: PrincipalDep, session: SessionDep, payload: IncidentCreateRequest):
    repo = IncidentRepository(session, context.organization_id)
    row = repo.create(title=payload.title, description=payload.description, severity=payload.severity, created_by=principal.user_id, source_detection_id=payload.source_detection_id)
    return _read(row, repo.evidence(row.id))

@router.get("/{organization_id}/incidents", response_model=list[IncidentRead])
def list_incidents(context: ReadIncidents, session: SessionDep, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
    repo = IncidentRepository(session, context.organization_id)
    return [_read(row) for row in repo.list(limit=limit, offset=offset)]

@router.get("/{organization_id}/incidents/{incident_id}", response_model=IncidentRead)
def get_incident(context: ReadIncidents, session: SessionDep, incident_id: uuid.UUID):
    repo = IncidentRepository(session, context.organization_id)
    row = repo.get(incident_id)
    return _read(row, repo.evidence(row.id))

@router.patch("/{organization_id}/incidents/{incident_id}", response_model=IncidentRead)
def update_incident(context: ManageIncidents, session: SessionDep, incident_id: uuid.UUID, payload: IncidentUpdateRequest):
    repo = IncidentRepository(session, context.organization_id)
    row = repo.get(incident_id)
    if payload.title is not None: row.title = payload.title
    if payload.description is not None: row.description = payload.description
    with repo.writing(): session.flush()
    return _read(row, repo.evidence(row.id))

@router.post("/{organization_id}/incidents/{incident_id}/transition", response_model=IncidentRead)
def transition_incident(context: ManageIncidents, session: SessionDep, incident_id: uuid.UUID, payload: IncidentTransitionRequest):
    repo = IncidentRepository(session, context.organization_id)
    row = repo.transition(incident_id, payload.status)
    return _read(row, repo.evidence(row.id))

@router.post("/{organization_id}/incidents/{incident_id}/evidence", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
def add_evidence(context: ManageIncidents, session: SessionDep, incident_id: uuid.UUID, payload: EvidenceCreateRequest):
    # Metadata is deliberately bounded and reference-only. Never accept a copied payload.
    if len(payload.metadata) > 12 or any(len(k) > 64 for k in payload.metadata):
        raise HTTPException(status_code=422, detail="evidence metadata is too large")
    row = IncidentRepository(session, context.organization_id).add_evidence(
        incident_id=incident_id, reference_type=payload.reference_type, reference_id=payload.reference_id,
        label=payload.label, metadata=payload.metadata, detection_id=payload.detection_id,
    )
    return EvidenceRead.model_validate(row, from_attributes=True)
