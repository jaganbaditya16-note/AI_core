"""Incident and human-approval persistence models."""
from __future__ import annotations
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column
from aicore_api.db.base import APP_SCHEMA, Base, TenantOwnedMixin, TimestampMixin, UUIDPrimaryKeyMixin

class IncidentStatus(StrEnum):
    OPEN="open"; ACKNOWLEDGED="acknowledged"; INVESTIGATING="investigating"; CONTAINED="contained"; RESOLVED="resolved"; CLOSED="closed"
class ApprovalStatus(StrEnum):
    PENDING="pending"; APPROVED="approved"; DENIED="denied"; EXPIRED="expired"; CANCELLED="cancelled"

class Incident(UUIDPrimaryKeyMixin, TimestampMixin, TenantOwnedMixin, Base):
    __tablename__="incidents"
    title: Mapped[str]=mapped_column(String(160), nullable=False)
    description: Mapped[str]=mapped_column(Text, nullable=False)
    status: Mapped[str]=mapped_column(String(24), nullable=False, server_default=IncidentStatus.OPEN.value)
    severity: Mapped[str]=mapped_column(String(16), nullable=False, server_default="medium")
    created_by: Mapped[uuid.UUID]=mapped_column(ForeignKey(f"{APP_SCHEMA}.users.id", ondelete="RESTRICT"), nullable=False)
    source_detection_id: Mapped[uuid.UUID|None]=mapped_column(ForeignKey(f"{APP_SCHEMA}.anomaly_detections.id", ondelete="SET NULL"), nullable=True)
    closed_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__=(
        CheckConstraint("status IN ('open','acknowledged','investigating','contained','resolved','closed')", name="status_valid"),
        CheckConstraint("severity IN ('low','medium','high','critical')", name="severity_valid"),
        CheckConstraint("char_length(btrim(title)) BETWEEN 1 AND 160", name="title_length"),
        CheckConstraint("char_length(description) BETWEEN 1 AND 10000", name="description_length"),
    )

class IncidentEvidence(UUIDPrimaryKeyMixin, TenantOwnedMixin, Base):
    __tablename__="incident_evidence"
    incident_id: Mapped[uuid.UUID]=mapped_column(ForeignKey(f"{APP_SCHEMA}.incidents.id", ondelete="CASCADE"), nullable=False)
    detection_id: Mapped[uuid.UUID|None]=mapped_column(ForeignKey(f"{APP_SCHEMA}.anomaly_detections.id", ondelete="RESTRICT"), nullable=True)
    reference_type: Mapped[str]=mapped_column(String(32), nullable=False)
    reference_id: Mapped[uuid.UUID]=mapped_column(PGUUID(as_uuid=True), nullable=False)
    label: Mapped[str]=mapped_column(String(160), nullable=False)
    # Python attribute deliberately avoids SQLAlchemy's reserved Declarative `metadata` name.
    evidence_metadata: Mapped[dict[str, Any]]=mapped_column("metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    __table_args__=(
        UniqueConstraint("organization_id","incident_id","reference_type","reference_id",name="uq_incident_evidence_reference"),
        CheckConstraint("reference_type IN ('anomaly_detection','audit_event')",name="reference_type_valid"),
        CheckConstraint("jsonb_typeof(metadata) = 'object'",name="metadata_object"),
    )

class ApprovalRequest(UUIDPrimaryKeyMixin, TimestampMixin, TenantOwnedMixin, Base):
    __tablename__="approval_requests"
    requester_membership_id: Mapped[uuid.UUID]=mapped_column(ForeignKey(f"{APP_SCHEMA}.memberships.id",ondelete="RESTRICT"),nullable=False)
    reviewer_membership_id: Mapped[uuid.UUID|None]=mapped_column(ForeignKey(f"{APP_SCHEMA}.memberships.id",ondelete="RESTRICT"),nullable=True)
    action_id: Mapped[str]=mapped_column(String(64),nullable=False)
    target_id: Mapped[uuid.UUID]=mapped_column(PGUUID(as_uuid=True),nullable=False)
    environment: Mapped[str]=mapped_column(String(32),nullable=False)
    idempotency_key: Mapped[str]=mapped_column(String(128),nullable=False)
    action_fingerprint: Mapped[str]=mapped_column(String(64),nullable=False)
    policy_digest: Mapped[str]=mapped_column(String(64),nullable=False)
    status: Mapped[str]=mapped_column(String(16),nullable=False,server_default=ApprovalStatus.PENDING.value)
    expires_at: Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False)
    approved_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    denied_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    consumed_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True),nullable=True)
    __table_args__=(
        UniqueConstraint("organization_id","requester_membership_id","idempotency_key",name="uq_approval_request_idempotency"),
        CheckConstraint("status IN ('pending','approved','denied','expired','cancelled')",name="status_valid"),
        CheckConstraint("action_fingerprint ~ '^[0-9a-f]{64}$'",name="fingerprint_shape"),
        CheckConstraint("policy_digest ~ '^[0-9a-f]{64}$'",name="policy_digest_shape"),
    )
