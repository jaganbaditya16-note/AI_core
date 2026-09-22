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


#: Phase 3's published shapes. The inventory carries the same 16 fields on read as
#: on every other read of an asset, and the request models publish what a client is
#: allowed to send — never `id`, `organization_id`, `created_at` or
#: `discovery_source`, which the server owns.
EXPECTED_ASSET_SCHEMAS = {
    "AssetRead": {
        "id",
        "organization_id",
        "name",
        "description",
        "asset_type",
        "status",
        "environment",
        "discovery_state",
        "risk_classification",
        "owner",
        "metadata",
        "discovery_source",
        "last_seen_at",
        "external_identifier",
        "created_at",
        "updated_at",
    },
    "AssetListResponse": {"organization_id", "items", "count", "limit", "offset", "total"},
    "AssetOwnerRead": {"membership_id", "user_id", "full_name", "email"},
    "AssetOwnerListResponse": {"organization_id", "owners"},
}

EXPECTED_ASSET_REQUEST_FIELDS = {
    "AssetCreate": {
        "name",
        "description",
        "asset_type",
        "status",
        "environment",
        "discovery_state",
        "risk_classification",
        "owner_user_id",
        "metadata",
        "external_identifier",
    },
    "AssetUpdateRequest": {
        "name",
        "description",
        "status",
        "environment",
        "discovery_state",
        "risk_classification",
        "owner_user_id",
        "metadata",
        "external_identifier",
    },
}

#: Phase 4's published shapes. An agent read is the registry's fields plus the
#: record's, and the request models publish what a client may send — never
#: `identity_id`, `asset_id` or `organization_id`, which the server owns. The owner
#: shape is the inventory's ``AssetOwnerRead``: one owner contract, not two.
EXPECTED_AGENT_SCHEMAS = {
    "AgentRead": {
        "id",
        "organization_id",
        "identity_id",
        "asset_id",
        "display_name",
        "description",
        "category",
        "version",
        "framework",
        "build_revision",
        "status",
        "environment",
        "identity_metadata",
        "owner",
        "created_at",
        "updated_at",
    },
    "AgentListResponse": {"organization_id", "items", "count", "limit", "offset", "total"},
}

EXPECTED_AGENT_REQUEST_FIELDS = {
    "AgentCreate": {
        "display_name",
        "description",
        "category",
        "version",
        "status",
        "environment",
        "framework",
        "build_revision",
        "identity_metadata",
        "owner_user_id",
        "external_identifier",
    },
    "AgentUpdateRequest": {
        "display_name",
        "description",
        "category",
        "version",
        "status",
        "environment",
        "framework",
        "build_revision",
        "identity_metadata",
        "owner_user_id",
    },
}

AGENT_ROUTES = (
    "/organizations/{organization_id}/agents",
    "/organizations/{organization_id}/agents/identity/{identity_id}",
    "/organizations/{organization_id}/agents/{agent_id}",
)


ASSET_ROUTES = (
    "/organizations/{organization_id}/assets",
    "/organizations/{organization_id}/assets/owners",
    "/organizations/{organization_id}/assets/{asset_id}",
)


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


def test_asset_schema_fields(client: TestClient) -> None:
    """The inventory contract is published, and the server-owned fields are not inputs."""
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    for name, fields in EXPECTED_ASSET_SCHEMAS.items():
        assert name in schemas, name
        assert set(schemas[name]["properties"]) == fields, name

    for name, fields in EXPECTED_ASSET_REQUEST_FIELDS.items():
        assert name in schemas, name
        assert set(schemas[name]["properties"]) == fields, name

    for name in EXPECTED_ASSET_REQUEST_FIELDS:
        published = set(schemas[name]["properties"])
        assert not published & {"id", "organization_id", "created_at", "discovery_source"}, name


def test_agent_schema_fields(client: TestClient) -> None:
    """The registry contract is published, and identity is not an input."""
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    for name, fields in EXPECTED_AGENT_SCHEMAS.items():
        assert name in schemas, name
        assert set(schemas[name]["properties"]) == fields, name

    for name, fields in EXPECTED_AGENT_REQUEST_FIELDS.items():
        assert name in schemas, name
        assert set(schemas[name]["properties"]) == fields, name

    for name in EXPECTED_AGENT_REQUEST_FIELDS:
        published = set(schemas[name]["properties"])
        assert not published & {
            "id",
            "identity_id",
            "asset_id",
            "organization_id",
            "created_at",
            "updated_at",
        }, name


def test_the_agent_vocabularies_are_published(client: TestClient) -> None:
    """A client can read the category vocabulary from the document, not from prose."""
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    assert set(schemas["AgentCategory"]["enum"]) == {
        "assistant",
        "workflow",
        "autonomous",
        "coding",
        "customer_support",
        "data",
        "security",
        "other",
    }
    # An agent's lifecycle states are the inventory's: one vocabulary, not two.
    assert set(schemas["AssetStatus"]["enum"]) == {"draft", "active", "suspended", "retired"}


def test_the_asset_vocabularies_are_published(client: TestClient) -> None:
    """A client can read the closed vocabularies from the document, not from prose."""
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    assert set(schemas["AssetType"]["enum"]) == {
        "agent",
        "application",
        "model",
        "tool",
        "mcp_server",
        "api",
        "data_source",
    }
    assert set(schemas["AssetStatus"]["enum"]) == {"draft", "active", "suspended", "retired"}
    assert set(schemas["DiscoveryState"]["enum"]) == {"managed", "unknown", "shadow"}


def test_protected_routes_document_their_refusals(client: TestClient) -> None:
    """OpenAPI must tell a client that credentials are required, and how it fails."""
    paths = client.get("/openapi.json").json()["paths"]

    # Every protected route can answer 401: no usable credential.
    for method, route in (
        ("get", "/me"),
        ("get", "/organizations/{organization_id}"),
        ("get", "/organizations/{organization_id}/members"),
        ("get", "/organizations/{organization_id}/roles"),
        ("get", "/organizations/{organization_id}/permissions"),
        *((verb, route) for route in ASSET_ROUTES for verb in ("get",)),
        *((verb, route) for route in AGENT_ROUTES for verb in ("get",)),
    ):
        assert "401" in paths[route][method]["responses"], route

    for method, route in (
        ("post", "/organizations/{organization_id}/assets"),
        ("get", "/organizations/{organization_id}/assets/{asset_id}"),
        ("patch", "/organizations/{organization_id}/assets/{asset_id}"),
        ("delete", "/organizations/{organization_id}/assets/{asset_id}"),
        ("post", "/organizations/{organization_id}/agents"),
        ("get", "/organizations/{organization_id}/agents/{agent_id}"),
        ("patch", "/organizations/{organization_id}/agents/{agent_id}"),
        ("delete", "/organizations/{organization_id}/agents/{agent_id}"),
    ):
        assert "401" in paths[route][method]["responses"], route

    # A tenant-scoped route can also answer 403 (the role lacks the permission, or
    # the membership is suspended) and 404 (no such organization — which is also
    # what a non-member receives, so the two are deliberately indistinguishable).
    for route in (
        "/organizations/{organization_id}",
        "/organizations/{organization_id}/members",
        "/organizations/{organization_id}/roles",
        "/organizations/{organization_id}/permissions",
        *ASSET_ROUTES,
        *AGENT_ROUTES,
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
        | {field for fields in EXPECTED_ASSET_SCHEMAS.values() for field in fields}
        | {field for fields in EXPECTED_AGENT_SCHEMAS.values() for field in fields}
    )
    for field in sorted(mirrored):
        assert field in source, f"packages/types is missing '{field}'"

    # Every published shape has an interface in the mirror.
    for name in (
        "MeResponse",
        "Membership",
        "Member",
        "Role",
        "Permission",
        "Asset",
        "AssetListResponse",
        "AssetOwner",
        "AssetOwnerListResponse",
        "Agent",
        "AgentListResponse",
        "AgentIdentityMetadata",
    ):
        assert f"interface {name} " in source, f"packages/types is missing '{name}'"

    # …and every closed asset vocabulary is enumerated there rather than left as
    # a bare `string`, so a client that switches on the type is checked by tsc.
    for name in (
        "AssetType",
        "AssetStatus",
        "DiscoveryState",
        "RiskClassification",
        "AgentCategory",
    ):
        assert f"export type {name} =" in source, f"packages/types is missing '{name}'"
    for value in (
        "mcp_server",
        "data_source",
        "shadow",
        "retired",
        "unassessed",
        "customer_support",
        "autonomous",
    ):
        assert f'"{value}"' in source, f"packages/types is missing the literal {value!r}"

    # Guard against a domain model creeping into phases that are not implemented.
    # Agent is no longer on this list — Phase 4 implemented it. Everything the later
    # phases own still has to stay out of the shared contract until it exists.
    for not_yet in (
        "Policy",
        "PolicyDecision",
        "Incident",
        "ActionFirewall",
        "RuntimeSession",
        "Approval",
    ):
        assert f"interface {not_yet}" not in source, f"packages/types declares {not_yet}"
