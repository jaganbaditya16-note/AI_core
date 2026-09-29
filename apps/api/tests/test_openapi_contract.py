"""Published API contract tests for the current AICore phases.

These assertions deliberately test both positive and negative security boundaries:
new Phase 11 incident/approval capabilities are published, while execution remains
owned by the existing action firewall and the audit trail remains read-only.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[3]
SHARED_TYPES = REPO_ROOT / "packages" / "types" / "src" / "index.ts"


EXPECTED_INCIDENT_SCHEMAS = {
    "IncidentCreateRequest": {"title", "description", "severity", "source_detection_id"},
    "IncidentUpdateRequest": {"title", "description"},
    "IncidentTransitionRequest": {"status"},
    "EvidenceCreateRequest": {"reference_type", "reference_id", "label", "metadata", "detection_id"},
    "EvidenceRead": {"id", "incident_id", "reference_type", "reference_id", "label", "metadata"},
    "IncidentRead": {
        "id", "organization_id", "title", "description", "status", "severity",
        "created_by", "source_detection_id", "created_at", "updated_at", "closed_at", "evidence",
    },
    "ApprovalCreateRequest": {
        "action", "target_id", "environment", "idempotency_key", "action_fingerprint", "policy_digest",
    },
    "ApprovalDecisionRequest": {"decision"},
    "ApprovalRead": {
        "id", "organization_id", "requester_membership_id", "reviewer_membership_id", "action_id",
        "target_id", "environment", "idempotency_key", "action_fingerprint", "policy_digest",
        "status", "expires_at", "approved_at", "denied_at", "consumed_at", "created_at",
    },
}

INCIDENT_ROUTES = (
    "/organizations/{organization_id}/incidents",
    "/organizations/{organization_id}/incidents/{incident_id}",
    "/organizations/{organization_id}/incidents/{incident_id}/transition",
    "/organizations/{organization_id}/incidents/{incident_id}/evidence",
)

APPROVAL_ROUTES = (
    "/organizations/{organization_id}/approvals",
    "/organizations/{organization_id}/approvals/{approval_id}/decision",
)


def _openapi(client: TestClient) -> tuple[dict, dict]:
    document = client.get("/openapi.json")
    assert document.status_code == 200
    body = document.json()
    return body["paths"], body["components"]["schemas"]


def test_openapi_document_is_served(client: TestClient) -> None:
    paths, _ = _openapi(client)
    assert "/health" in paths
    assert "/health/ready" in paths
    assert "/me" in paths


def test_permission_vocabulary_includes_phase11_without_expanding_execution() -> None:
    """Incident management and approval are separate capabilities from execution."""
    # This test reads the OpenAPI document through the normal application fixture below.
    # Kept as a marker so the security boundary is explicit in the test module.


def test_permission_vocabulary_is_published(client: TestClient) -> None:
    _, schemas = _openapi(client)
    resources = set(schemas["Resource"]["enum"])
    actions = set(schemas["Action"]["enum"])

    assert resources == {
        "organization", "user", "role", "audit", "security", "asset", "agent", "policy", "action", "incident"
    }
    assert actions == {"read", "create", "update", "delete", "manage", "execute", "approve"}

    # Phase 11 adds approval but does not invent new execution/control verbs.
    assert "execute" in actions
    assert "approve" in actions
    assert "incident" in resources
    assert "kill" not in actions
    assert "block" not in actions
    assert "intercept" not in actions
    assert "control" not in actions
    assert "firewall" not in resources
    assert "enforce" not in actions

    properties = schemas["PermissionRead"]["properties"]
    assert properties["resource"] == {"$ref": "#/components/schemas/Resource"}
    assert properties["action"] == {"$ref": "#/components/schemas/Action"}


def test_incident_and_approval_schemas_are_published(client: TestClient) -> None:
    _, schemas = _openapi(client)
    for name, fields in EXPECTED_INCIDENT_SCHEMAS.items():
        assert name in schemas, name
        assert set(schemas[name]["properties"]) == fields, name

    assert set(schemas["IncidentStatus"]["enum"]) == {
        "open", "acknowledged", "investigating", "contained", "resolved", "closed"
    }
    assert set(schemas["ApprovalStatus"]["enum"]) == {
        "pending", "approved", "denied", "expired", "cancelled"
    }


def test_incident_and_approval_routes_are_protected_and_not_execution_routes(client: TestClient) -> None:
    paths, _ = _openapi(client)

    for route in INCIDENT_ROUTES:
        assert route in paths, route
        methods = paths[route]
        assert "post" in methods or "get" in methods or "patch" in methods
        for operation in methods.values():
            assert "401" in operation["responses"], route

    for route in APPROVAL_ROUTES:
        assert route in paths, route
        for operation in paths[route].values():
            assert "401" in operation["responses"], route

    executing = [
        f"{method.upper()} {path}"
        for path, methods in paths.items()
        for method in methods
        if "execute" in path and method in {"get", "post", "patch", "put", "delete"}
    ]
    assert executing == ["POST /organizations/{organization_id}/actions/execute"]


def test_action_execution_request_cannot_supply_authorization_or_approval(client: TestClient) -> None:
    _, schemas = _openapi(client)
    published = set(schemas["ActionExecuteRequest"]["properties"])
    assert not published & {
        "organization_id", "principal_id", "membership_id", "user_id", "role", "roles",
        "permission", "permissions", "correlation_id", "request_id", "executor", "executor_id",
        "adapter", "module", "function", "command", "script", "shell", "url", "endpoint",
        "approved", "approval", "reviewer", "approval_id",
    }

    assert set(schemas["ActionSensitivity"]["enum"]) == {"routine", "controlled", "sensitive"}
    assert set(schemas["FirewallOutcome"]["enum"]) == {"allow", "deny", "require_approval"}


def test_audit_trail_remains_read_only(client: TestClient) -> None:
    paths, schemas = _openapi(client)
    audit_paths = {path: methods for path, methods in paths.items() if "audit" in path}
    assert set(audit_paths) == {"/organizations/{organization_id}/audit-events"}
    assert set(audit_paths["/organizations/{organization_id}/audit-events"]) == {"get"}

    assert "AuditEventRead" in schemas
    assert "AuditEventListResponse" in schemas
    assert "AuditEventType" in schemas


def test_monitoring_remains_read_only(client: TestClient) -> None:
    paths, schemas = _openapi(client)
    monitoring_paths = {path: methods for path, methods in paths.items() if "monitoring" in path}
    assert len(monitoring_paths) == 5
    for path, methods in monitoring_paths.items():
        assert set(methods) == {"get"}, path
        assert {"200", "401", "403", "404", "422"} <= set(methods["get"]["responses"]), path

    for name in (
        "MonitoringSummaryResponse", "MonitoringAgentRead", "MonitoringAgentListResponse",
        "MonitoringActionRead", "MonitoringActionListResponse", "MonitoringPolicyResponse",
        "MonitoringTrendResponse", "MonitoringWindowRead", "ExecutionHealthRead",
        "DenialSummaryRead", "MonitoringDecisionsRead", "MonitoringPolicyLifecycleRead", "TrendBucketRead",
    ):
        assert name in schemas


def test_protected_core_routes_document_unauthorized_response(client: TestClient) -> None:
    paths, _ = _openapi(client)
    for route in (
        "/me",
        "/organizations/{organization_id}",
        "/organizations/{organization_id}/members",
        "/organizations/{organization_id}/roles",
        "/organizations/{organization_id}/permissions",
        "/organizations/{organization_id}/assets",
        "/organizations/{organization_id}/agents",
        "/organizations/{organization_id}/audit-events",
        "/organizations/{organization_id}/incidents",
        "/organizations/{organization_id}/approvals",
    ):
        assert "401" in paths[route]["get"]["responses"] if "get" in paths[route] else "401" in paths[route]["post"]["responses"]


def test_execution_route_documents_every_refusal(client: TestClient) -> None:
    paths, _ = _openapi(client)
    operation = paths["/organizations/{organization_id}/actions/execute"]["post"]
    for status_code in ("401", "403", "404", "409", "422", "500"):
        assert status_code in operation["responses"], status_code
    description = operation["responses"]["403"]["description"].lower()
    assert "policy" in description
    assert "approval" in description


def test_shared_typescript_mirror_still_contains_all_core_contracts() -> None:
    """The frontend mirror must retain the pre-Phase-11 contracts while backend-only
    incident/approval workflows are consumed through the API until their UI types are
    promoted explicitly.
    """
    source = SHARED_TYPES.read_text(encoding="utf-8")
    for name in (
        "HealthResponse", "ReadinessResponse", "MeResponse", "Asset", "Agent",
        "ActionExecuteRequest", "ActionExecutionResponse", "AuditEvent", "MonitoringSummaryResponse",
        "RiskAgentAnalysisRead", "AnomalyDetectionRead",
    ):
        assert f"interface {name} " in source, name
    for value in (
        "require_approval", "approval_required", "action.requested", "action.replayed", "unusual_frequency",
    ):
        assert f'"{value}"' in source, value


def test_phase11_request_schemas_forbid_client_owned_security_fields(client: TestClient) -> None:
    _, schemas = _openapi(client)
    for name in ("IncidentCreateRequest", "IncidentUpdateRequest", "IncidentTransitionRequest", "EvidenceCreateRequest"):
        assert "organization_id" not in schemas[name]["properties"], name
        assert "created_by" not in schemas[name]["properties"], name
    assert "reviewer_membership_id" not in schemas["ApprovalCreateRequest"]["properties"]
    assert "status" not in schemas["ApprovalCreateRequest"]["properties"]


def test_phase11_incident_and_approval_paths_have_validation_errors(client: TestClient) -> None:
    paths, _ = _openapi(client)
    for route in INCIDENT_ROUTES + APPROVAL_ROUTES:
        for operation in paths[route].values():
            assert "422" in operation["responses"], route
