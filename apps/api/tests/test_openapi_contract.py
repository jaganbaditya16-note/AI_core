"""The published contract must match the shared TypeScript types.

`packages/types` mirrors these schemas by hand; this test fails when the two
drift, which is the cheapest possible guard short of code generation.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[3]
SHARED_TYPES = REPO_ROOT / "packages" / "types" / "src" / "index.ts"

EXPECTED_HEALTH_FIELDS = {"status", "service", "version", "environment"}
EXPECTED_READINESS_FIELDS = {"status", "checks"}
EXPECTED_ORGANIZATION_FIELDS = {"id", "name", "slug", "status", "created_at", "updated_at"}
EXPECTED_ORGANIZATION_CREATE_FIELDS = {"name", "slug"}

#: Phase 2's published shapes, and the fields each one carries. Field names are
#: snake_case in both mirrors: this file mirrors the contract rather than
#: translating it into a client-side view model.
EXPECTED_IDENTITY_SCHEMAS = {
    "UserRead": {"id", "email", "full_name", "status"},
    "OrganizationSummary": {"id", "name", "slug", "status"},
    "RoleSummary": {"code", "name"},
    "MembershipRead": {"organization", "role", "status", "permissions"},
    "MeResponse": {"user", "memberships"},
    "MemberRead": {"user", "role", "status", "created_at"},
    "MemberListResponse": {"organization_id", "members"},
    "RoleRead": {"code", "name", "description", "permissions"},
    "RoleListResponse": {"organization_id", "roles"},
    "PermissionRead": {"code", "description"},
    "PermissionListResponse": {"organization_id", "permissions"},
}


def test_openapi_document_is_served(client: TestClient) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    document = response.json()
    assert document["info"]["title"] == "AICore API"
    assert "/health" in document["paths"]
    assert "/health/ready" in document["paths"]


def test_health_schema_fields(client: TestClient) -> None:
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    assert set(schemas["HealthResponse"]["properties"]) == EXPECTED_HEALTH_FIELDS
    assert set(schemas["ReadinessResponse"]["properties"]) == EXPECTED_READINESS_FIELDS


def test_organization_schema_fields(client: TestClient) -> None:
    """The tenant contract is published, so it is mirrored too."""
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    assert set(schemas["OrganizationRead"]["properties"]) == EXPECTED_ORGANIZATION_FIELDS
    assert set(schemas["OrganizationCreate"]["properties"]) == EXPECTED_ORGANIZATION_CREATE_FIELDS


def test_identity_schema_fields(client: TestClient) -> None:
    """The identity contract is published, and carries no credential field."""
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    for name, fields in EXPECTED_IDENTITY_SCHEMAS.items():
        assert name in schemas, name
        assert set(schemas[name]["properties"]) == fields, name

    # A response model must never grow a field for a secret.
    for name in ("UserRead", "MeResponse", "MembershipRead"):
        published = set(schemas[name]["properties"])
        assert not published & {"token", "token_hash", "password", "secret"}, name


def test_protected_routes_document_their_refusals(client: TestClient) -> None:
    """OpenAPI must tell a client that credentials are required, and how it fails."""
    paths = client.get("/openapi.json").json()["paths"]

    # Every protected route can answer 401: no usable credential.
    for route in (
        "/me",
        "/organizations/{organization_id}",
        "/organizations/{organization_id}/members",
        "/organizations/{organization_id}/roles",
        "/organizations/{organization_id}/permissions",
    ):
        assert "401" in paths[route]["get"]["responses"], route

    # A tenant-scoped route can also answer 403 (the role lacks the permission, or
    # the membership is suspended) and 404 (no such organization — which is also
    # what a non-member receives, so the two are deliberately indistinguishable).
    for route in (
        "/organizations/{organization_id}",
        "/organizations/{organization_id}/members",
        "/organizations/{organization_id}/roles",
        "/organizations/{organization_id}/permissions",
    ):
        responses = paths[route]["get"]["responses"]
        assert "403" in responses, route
        assert "404" in responses, route


def test_readiness_documents_the_503_response(client: TestClient) -> None:
    ready = client.get("/openapi.json").json()["paths"]["/health/ready"]["get"]["responses"]

    assert "503" in ready


def test_shared_typescript_mirror_matches_schemas() -> None:
    """packages/types must declare exactly the fields the API publishes."""
    source = SHARED_TYPES.read_text(encoding="utf-8")

    report_fields = {"reachable", "checkedAt", "errors"}
    mirrored = (
        EXPECTED_HEALTH_FIELDS
        | EXPECTED_READINESS_FIELDS
        | EXPECTED_ORGANIZATION_FIELDS
        | report_fields
        | {field for fields in EXPECTED_IDENTITY_SCHEMAS.values() for field in fields}
    )
    for field in sorted(mirrored):
        assert field in source, f"packages/types is missing '{field}'"

    # Every published identity shape has an interface in the mirror.
    for name in ("MeResponse", "Membership", "Member", "Role", "Permission"):
        assert f"interface {name} " in source, f"packages/types is missing '{name}'"

    # Guard against a domain model creeping into phases that are not implemented.
    for not_yet in ("Agent", "Policy", "Incident", "ActionFirewall", "ModelRegistry"):
        assert f"interface {not_yet}" not in source, f"packages/types declares {not_yet}"
