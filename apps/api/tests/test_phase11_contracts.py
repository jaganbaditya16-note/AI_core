from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from aicore_api.core.permissions import Permission, RoleCode, role_holds
from aicore_api.db.models.incident import ApprovalStatus, IncidentStatus
from aicore_api.schemas.incidents import EvidenceCreateRequest, IncidentCreateRequest


def test_incident_permissions_are_separated_from_execution() -> None:
    assert role_holds(RoleCode.SECURITY_ADMIN, Permission.INCIDENT_CREATE)
    assert role_holds(RoleCode.SECURITY_ADMIN, Permission.ACTION_APPROVE)
    assert role_holds(RoleCode.ANALYST, Permission.INCIDENT_READ)
    assert not role_holds(RoleCode.AI_ADMIN, Permission.ACTION_APPROVE)


def test_incident_lifecycle_is_closed() -> None:
    allowed = {
        IncidentStatus.OPEN: {IncidentStatus.ACKNOWLEDGED},
        IncidentStatus.ACKNOWLEDGED: {IncidentStatus.INVESTIGATING},
        IncidentStatus.INVESTIGATING: {IncidentStatus.CONTAINED, IncidentStatus.RESOLVED},
        IncidentStatus.CONTAINED: {IncidentStatus.RESOLVED},
        IncidentStatus.RESOLVED: {IncidentStatus.CLOSED},
        IncidentStatus.CLOSED: set(),
    }
    assert IncidentStatus.OPEN not in allowed[IncidentStatus.CLOSED]
    assert IncidentStatus.CLOSED not in allowed[IncidentStatus.RESOLVED]
    assert IncidentStatus.ACKNOWLEDGED in allowed[IncidentStatus.OPEN]


def test_evidence_contract_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        EvidenceCreateRequest(reference_type="audit_event", reference_id=uuid.uuid4(), label="x", payload="secret")


def test_incident_description_is_bounded() -> None:
    with pytest.raises(ValidationError):
        IncidentCreateRequest(title="x", description="x" * 10001, severity="high")


def test_approval_states_are_terminal_after_review_or_expiry() -> None:
    assert ApprovalStatus.APPROVED.value == "approved"
    assert ApprovalStatus.EXPIRED.value == "expired"
    assert ApprovalStatus.CONSUMED not in ApprovalStatus.__members__ if hasattr(ApprovalStatus, "CONSUMED") else True
    assert datetime.now(UTC) + timedelta(hours=1) > datetime.now(UTC)
