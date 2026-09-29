"""Human approval queue.

Approvals are reviewer decisions, not execution authority. A reviewer can only approve
another membership in the same tenant. Consumption is single-use and requires the exact
request fingerprint; execution must still re-enter the current action firewall.
"""
from __future__ import annotations
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query, status
from aicore_api.auth.authorization import OrganizationContext
from aicore_api.auth.dependencies import PrincipalDep, SessionDep, require_permission
from aicore_api.core.permissions import Permission
from aicore_api.db.repositories.incidents import ApprovalRepository
from aicore_api.schemas.incidents import ApprovalCreateRequest, ApprovalDecisionRequest, ApprovalRead

router = APIRouter(prefix="/organizations", tags=["approvals"])
ReadApprovals = Annotated[OrganizationContext, Depends(require_permission(Permission.INCIDENT_READ))]
RequestApprovals = Annotated[OrganizationContext, Depends(require_permission(Permission.ACTION_EXECUTE))]
ReviewApprovals = Annotated[OrganizationContext, Depends(require_permission(Permission.ACTION_APPROVE))]

TTL = timedelta(hours=1)

def _read(row):
    return ApprovalRead.model_validate(row, from_attributes=True)

@router.post("/{organization_id}/approvals", response_model=ApprovalRead, status_code=status.HTTP_201_CREATED)
def request_approval(context: RequestApprovals, session: SessionDep, payload: ApprovalCreateRequest):
    # The exact action fingerprint is supplied by the trusted action client and is never
    # interpreted here. The execution path later recomputes and matches it before consume.
    row = ApprovalRepository(session, context.organization_id).create(
        requester_membership_id=context.membership_id,
        action_id=payload.action,
        target_id=payload.target_id,
        environment=payload.environment,
        idempotency_key=payload.idempotency_key,
        action_fingerprint=payload.action_fingerprint,
        policy_digest=payload.policy_digest,
        expires_at=datetime.now(UTC) + TTL,
    )
    return _read(row)

@router.get("/{organization_id}/approvals", response_model=list[ApprovalRead])
def list_approvals(context: ReadApprovals, session: SessionDep, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
    return [_read(r) for r in ApprovalRepository(session, context.organization_id).list(limit=limit, offset=offset)]

@router.post("/{organization_id}/approvals/{approval_id}/decision", response_model=ApprovalRead)
def decide_approval(context: ReviewApprovals, principal: PrincipalDep, session: SessionDep, approval_id: uuid.UUID, payload: ApprovalDecisionRequest):
    repo = ApprovalRepository(session, context.organization_id)
    now = datetime.now(UTC)
    try:
        if payload.decision == "approve":
            row = repo.approve(approval_id, reviewer_membership_id=context.membership_id, now=now)
        else:
            row = repo.deny(approval_id, reviewer_membership_id=context.membership_id, now=now)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _read(row)
