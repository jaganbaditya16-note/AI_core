"""SQLAlchemy model registry for Alembic and runtime metadata."""
from __future__ import annotations

from aicore_api.db.models.action_execution import ActionExecution
from aicore_api.db.models.agent import Agent
from aicore_api.db.models.anomaly_detection import AnomalyDetection
from aicore_api.db.models.api_token import ApiToken
from aicore_api.db.models.asset import Asset
from aicore_api.db.models.audit_event import AuditEvent
from aicore_api.db.models.incident import ApprovalRequest, ApprovalStatus, Incident, IncidentEvidence, IncidentStatus
from aicore_api.db.models.membership import Membership, MembershipStatus
from aicore_api.db.models.organization import NAME_MAX_LENGTH, SLUG_MAX_LENGTH, Organization, OrganizationStatus
from aicore_api.db.models.policy import Policy, PolicyVersion
from aicore_api.db.models.rbac import Permission, Role, role_permissions
from aicore_api.db.models.user import User, UserStatus, normalize_email

__all__ = [
    "NAME_MAX_LENGTH", "SLUG_MAX_LENGTH", "ActionExecution", "Agent", "AnomalyDetection",
    "ApiToken", "Asset", "AuditEvent", "ApprovalRequest", "ApprovalStatus", "Incident",
    "IncidentEvidence", "IncidentStatus", "Membership", "MembershipStatus", "Organization",
    "OrganizationStatus", "Permission", "Policy", "PolicyVersion", "Role", "User",
    "UserStatus", "normalize_email", "role_permissions",
]
