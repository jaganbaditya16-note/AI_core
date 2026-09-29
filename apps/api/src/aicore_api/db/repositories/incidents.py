"""Tenant-scoped persistence for incidents and single-use approvals."""
from __future__ import annotations
import uuid
from datetime import UTC, datetime
from typing import Any
from sqlalchemy import update
from aicore_api.core.domain_errors import NotFoundError
from aicore_api.db.models.incident import ApprovalRequest, ApprovalStatus, Incident, IncidentEvidence, IncidentStatus
from aicore_api.db.repositories.organizations import OrganizationScopedRepository

class IncidentRepository(OrganizationScopedRepository):
    def create(self, *, title: str, description: str, severity: str, created_by: uuid.UUID, source_detection_id: uuid.UUID | None = None) -> Incident:
        row=Incident(organization_id=self.organization_id,title=title.strip(),description=description,severity=severity,created_by=created_by,source_detection_id=source_detection_id)
        with self.writing(): self.session.add(row); self.session.flush()
        return row
    def get(self, incident_id: uuid.UUID) -> Incident:
        row=self.execute(self._scoped(Incident).where(Incident.id==incident_id)).scalar_one_or_none()
        if row is None: raise NotFoundError("incident not found")
        return row
    def list(self, *, limit:int=50, offset:int=0)->list[Incident]:
        return list(self.execute(self._scoped(Incident).order_by(Incident.created_at.desc(),Incident.id.desc()).limit(limit).offset(offset)).scalars().all())
    def transition(self, incident_id:uuid.UUID, status:IncidentStatus)->Incident:
        row=self.get(incident_id); allowed={IncidentStatus.OPEN:{IncidentStatus.ACKNOWLEDGED},IncidentStatus.ACKNOWLEDGED:{IncidentStatus.INVESTIGATING},IncidentStatus.INVESTIGATING:{IncidentStatus.CONTAINED,IncidentStatus.RESOLVED},IncidentStatus.CONTAINED:{IncidentStatus.RESOLVED},IncidentStatus.RESOLVED:{IncidentStatus.CLOSED},IncidentStatus.CLOSED:set()}; current=IncidentStatus(row.status)
        if status not in allowed[current]: raise ValueError(f"invalid incident transition {current.value} -> {status.value}")
        row.status=status.value
        if status is IncidentStatus.CLOSED: row.closed_at=datetime.now(UTC)
        with self.writing(): self.session.flush()
        return row
    def add_evidence(self, *, incident_id:uuid.UUID, reference_type:str, reference_id:uuid.UUID, label:str, metadata:dict[str,Any], detection_id:uuid.UUID|None=None)->IncidentEvidence:
        self.get(incident_id)
        row=IncidentEvidence(organization_id=self.organization_id,incident_id=incident_id,detection_id=detection_id,reference_type=reference_type,reference_id=reference_id,label=label.strip(),evidence_metadata=metadata)
        with self.writing(): self.session.add(row); self.session.flush()
        return row
    def evidence(self, incident_id:uuid.UUID)->list[IncidentEvidence]:
        self.get(incident_id)
        return list(self.execute(self._scoped(IncidentEvidence).where(IncidentEvidence.incident_id==incident_id).order_by(IncidentEvidence.id)).scalars().all())

class ApprovalRepository(OrganizationScopedRepository):
    def create(self, **values:Any)->ApprovalRequest:
        row=ApprovalRequest(organization_id=self.organization_id,**values)
        with self.writing(): self.session.add(row); self.session.flush()
        return row
    def get(self, approval_id:uuid.UUID)->ApprovalRequest:
        row=self.execute(self._scoped(ApprovalRequest).where(ApprovalRequest.id==approval_id)).scalar_one_or_none()
        if row is None: raise NotFoundError("approval request not found")
        return row
    def approve(self, approval_id:uuid.UUID, *, reviewer_membership_id:uuid.UUID, now:datetime)->ApprovalRequest:
        row=self.get(approval_id)
        if row.requester_membership_id==reviewer_membership_id: raise ValueError("self-approval is not permitted")
        if row.status!=ApprovalStatus.PENDING.value: raise ValueError("approval request is not pending")
        if now>=row.expires_at: row.status=ApprovalStatus.EXPIRED.value; self.session.flush(); raise ValueError("approval request has expired")
        row.status=ApprovalStatus.APPROVED.value; row.reviewer_membership_id=reviewer_membership_id; row.approved_at=now; self.session.flush(); return row
    def deny(self, approval_id:uuid.UUID, *, reviewer_membership_id:uuid.UUID, now:datetime)->ApprovalRequest:
        row=self.get(approval_id)
        if row.requester_membership_id==reviewer_membership_id: raise ValueError("self-review is not permitted")
        if row.status!=ApprovalStatus.PENDING.value: raise ValueError("approval request is not pending")
        if now>=row.expires_at: row.status=ApprovalStatus.EXPIRED.value; self.session.flush(); raise ValueError("approval request has expired")
        row.status=ApprovalStatus.DENIED.value; row.reviewer_membership_id=reviewer_membership_id; row.denied_at=now; self.session.flush(); return row
    def consume(self, approval_id:uuid.UUID, *, requester_membership_id:uuid.UUID, fingerprint:str, now:datetime)->ApprovalRequest:
        statement=update(ApprovalRequest).where(ApprovalRequest.organization_id==self.organization_id,ApprovalRequest.id==approval_id,ApprovalRequest.requester_membership_id==requester_membership_id,ApprovalRequest.action_fingerprint==fingerprint,ApprovalRequest.status==ApprovalStatus.APPROVED.value,ApprovalRequest.consumed_at.is_(None),ApprovalRequest.expires_at>now).values(consumed_at=now).returning(ApprovalRequest)
        row=self.execute(statement).scalar_one_or_none()
        if row is None: raise ValueError("approval is invalid, expired, already consumed, or does not match this request")
        self.session.flush(); return row
    def list(self, *, limit:int=50, offset:int=0)->list[ApprovalRequest]:
        return list(self.execute(self._scoped(ApprovalRequest).order_by(ApprovalRequest.created_at.desc(),ApprovalRequest.id.desc()).limit(limit).offset(offset)).scalars().all())
