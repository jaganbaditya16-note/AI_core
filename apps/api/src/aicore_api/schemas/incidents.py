"""Bounded API contracts for incident operations and human approvals."""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from aicore_api.db.models.incident import ApprovalStatus, IncidentStatus

class IncidentCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=10000)
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    source_detection_id: uuid.UUID | None = None

class IncidentUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, min_length=1, max_length=10000)

class IncidentTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: IncidentStatus

class EvidenceCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reference_type: str = Field(pattern="^(anomaly_detection|audit_event)$")
    reference_id: uuid.UUID
    label: str = Field(min_length=1, max_length=160)
    metadata: dict[str, Any] = Field(default_factory=dict)
    detection_id: uuid.UUID | None = None

class EvidenceRead(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    reference_type: str
    reference_id: uuid.UUID
    label: str
    metadata: dict[str, Any]

class IncidentRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    description: str
    status: IncidentStatus
    severity: str
    created_by: uuid.UUID
    source_detection_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    evidence: list[EvidenceRead] = Field(default_factory=list)

class ApprovalCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(min_length=1, max_length=64)
    target_id: uuid.UUID
    environment: str = Field(min_length=1, max_length=32)
    idempotency_key: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    action_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern="^(approve|deny)$")

class ApprovalRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    requester_membership_id: uuid.UUID
    reviewer_membership_id: uuid.UUID | None
    action_id: str
    target_id: uuid.UUID
    environment: str
    idempotency_key: str
    action_fingerprint: str
    policy_digest: str
    status: ApprovalStatus
    expires_at: datetime
    approved_at: datetime | None
    denied_at: datetime | None
    consumed_at: datetime | None
    created_at: datetime
