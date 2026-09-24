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
    "PermissionRead": {"code", "resource", "action", "description"},
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

#: Phase 7's published shapes, and the fields each one carries. The request is the
#: whole client-side surface of the firewall, and it is the *negative* half that
#: matters: no executor, module, function, URL, command, permission, role or
#: organization field exists, because the server takes those from code, the credential
#: and the path.
EXPECTED_ACTION_SCHEMAS = {
    "ActionExecuteRequest": {
        "action",
        "target_id",
        "environment",
        "arguments",
        "idempotency_key",
        "agent_id",
    },
    "ActionTargetRead": {"resource", "id"},
    "FirewallDecisionRead": {"outcome", "reason"},
    "ActionOutcomeRead": {"summary", "findings", "details", "adapter", "digest"},
    "ActionExecutionResponse": {
        "organization_id",
        "action_id",
        "action_sensitivity",
        "target",
        "agent_id",
        "permission_required",
        "principal_role",
        "environment",
        "firewall",
        "authorization",
        "policy",
        "effective",
        "executed",
        "replayed",
        "execution_id",
        "idempotency_key",
        "correlation_id",
        "executed_at",
        "result",
    },
}


#: Phase 8's published shapes. The read side is the whole client surface of the audit
#: trail, and it is a *response* model: there is no request schema and no write route,
#: because a client cannot create, change or delete an event. The negative half is the
#: point — the trail publishes no actor, decision, organization, timestamp or
#: correlation field that a caller could have supplied.
EXPECTED_AUDIT_SCHEMAS = {
    "AuditEventRead": {
        "id",
        "organization_id",
        "event_type",
        "schema_version",
        "occurred_at",
        "actor_type",
        "actor_id",
        "actor_membership_id",
        "agent_id",
        "resource_type",
        "resource_id",
        "action",
        "decision",
        "outcome",
        "correlation_id",
        "request_id",
        "source",
        "metadata",
    },
    "AuditEventListResponse": {
        "organization_id",
        "items",
        "limit",
        "offset",
        "count",
        "total",
    },
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

#: Phase 8: one path, and it only reads. A write route here would be a way to
#: fabricate history, so the absence is asserted rather than assumed.
AUDIT_ROUTES = ("/organizations/{organization_id}/audit-events",)


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


def test_the_permission_vocabulary_is_published(client: TestClient) -> None:
    """A client reads `resource` and `action` as closed vocabularies, not as strings.

    Phase 5 published the two halves of a permission identifier; this asserts the
    document a client actually receives. Phase 7 added one pair to it — ``action`` and
    ``execute``, which together name the single capability that runs a registered
    action — and this is where the *negative* half is asserted too: no other resource
    may be executed, and no control-plane verb this build cannot perform may appear.
    """
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    assert set(schemas["Resource"]["enum"]) == {
        "organization",
        "user",
        "role",
        "audit",
        "security",
        "asset",
        "agent",
        "policy",
        "action",
    }
    assert set(schemas["Action"]["enum"]) == {
        "read",
        "create",
        "update",
        "delete",
        "manage",
        "execute",
    }

    # The document must not advertise a capability the build does not have. ``execute``
    # is deliberately absent from this list: it exists (Phase 7), on one resource, and
    # the test below pins that down rather than forbidding the word.
    forbidden = {"approve", "kill", "block", "intercept", "control", "firewall", "enforce"}
    assert not forbidden & set(schemas["Action"]["enum"])
    assert not forbidden & set(schemas["Resource"]["enum"])

    # ``execute`` is published on ``action`` and on nothing else: a client reading the
    # vocabulary cannot conclude that agents or policies may be executed.
    assert set(schemas["Resource"]["enum"]) & {"action"} == {"action"}
    assert "agent.execute" not in str(schemas["PermissionRead"])

    properties = schemas["PermissionRead"]["properties"]
    assert properties["resource"] == {"$ref": "#/components/schemas/Resource"}
    assert properties["action"] == {"$ref": "#/components/schemas/Action"}


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
        *((verb, route) for route in AUDIT_ROUTES for verb in ("get",)),
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
        *AUDIT_ROUTES,
    ):
        responses = paths[route]["get"]["responses"]
        assert "403" in responses, route
        assert "404" in responses, route


def test_the_action_firewall_contract_is_published(client: TestClient) -> None:
    """A client can read the request's shape, and it cannot state what the server owns.

    The negative half is the assertion that matters here. The execution body names an
    action, a target, an environment, arguments, an idempotency key and optionally an
    agent — never an executor, a module, a function, a URL, a command, a permission, a
    role or an organization. Those come from code, the credential and the path, and a
    body that tries to add one is refused rather than ignored.
    """
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    for name, fields in EXPECTED_ACTION_SCHEMAS.items():
        assert name in schemas, name
        assert set(schemas[name]["properties"]) == fields, name

    published = set(schemas["ActionExecuteRequest"]["properties"])
    assert not published & {
        "organization_id",
        "principal_id",
        "membership_id",
        "user_id",
        "role",
        "roles",
        "permission",
        "permissions",
        "correlation_id",
        "request_id",
        "executor",
        "executor_id",
        "adapter",
        "module",
        "function",
        "command",
        "script",
        "shell",
        "url",
        "endpoint",
        "approved",
        "approval",
    }, "the execution request publishes a field the server owns"

    # The vocabularies a client needs are enumerated, not left as bare strings.
    assert set(schemas["ActionSensitivity"]["enum"]) == {"routine", "controlled", "sensitive"}
    assert set(schemas["FirewallOutcome"]["enum"]) == {"allow", "deny", "require_approval"}
    assert set(schemas["FirewallReason"]["enum"]) == {
        "allowed",
        "authorization_denied",
        "policy_denied",
        "policy_requires_approval",
        "target_not_found",
        "environment_mismatch",
    }


def test_the_audit_trail_contract_is_read_only(client: TestClient) -> None:
    """The trail is queried, never written: the document is the proof.

    Every field the trail publishes is server-produced — a client sends a filter and
    receives events. There is no create, update or delete schema and no second audit
    path, so a caller cannot fabricate an event or rewrite one, and the absence of
    those shapes is what a client reading only the document can see.
    """
    document = client.get("/openapi.json").json()
    schemas = document["components"]["schemas"]
    paths = document["paths"]

    for name, fields in EXPECTED_AUDIT_SCHEMAS.items():
        assert name in schemas, name
        assert set(schemas[name]["properties"]) == fields, name

    audit_paths = {path: methods for path, methods in paths.items() if "audit" in path}
    assert set(audit_paths) == set(AUDIT_ROUTES)
    for methods in audit_paths.values():
        assert set(methods) == {"get"}, methods

    # The vocabularies are enumerated in the document rather than described in prose,
    # so a client switching on an event type is checked against the real list.
    assert set(schemas["AuditEventType"]["enum"]) == {
        "asset.created",
        "asset.updated",
        "asset.deleted",
        "asset.discovered",
        "agent.registered",
        "agent.updated",
        "agent.deleted",
        "policy.created",
        "policy.updated",
        "policy.version_published",
        "policy.status_changed",
        "policy.deleted",
        "action.requested",
        "action.denied",
        "action.require_approval",
        "action.executed",
        "action.replayed",
        "action.failed",
    }
    assert set(schemas["AuditOutcome"]["enum"]) == {
        "success",
        "failed",
        "blocked",
        "not_executed",
        "replayed",
        "pending",
    }
    assert set(schemas["AuditResourceType"]["enum"]) == {"asset", "agent", "policy"}
    assert set(schemas["ActorType"]["enum"]) == {"human", "system"}
    assert set(schemas["AuditSource"]["enum"]) == {"api", "ingestion"}
    # One decision vocabulary for the trail, the policy engine and the firewall.
    assert set(schemas["AuditDecision"]["enum"]) == set(schemas["FirewallOutcome"]["enum"])


def test_the_execution_route_documents_every_refusal(client: TestClient) -> None:
    """The one route that can execute something says how it fails, in the document.

    A client that reads only the OpenAPI document must be able to tell that a refusal
    is a refusal: the route publishes 401, 403, 404, 409, 422 and 500, and the 403
    description names the reasons a decision can come out as anything other than
    ``allow``.
    """
    paths = client.get("/openapi.json").json()["paths"]
    operation = paths["/organizations/{organization_id}/actions/execute"]["post"]

    for status_code in ("401", "403", "404", "409", "422", "500"):
        assert status_code in operation["responses"], status_code

    forbidden = operation["responses"]["403"]["description"]
    assert "policy" in forbidden.lower()
    assert "approval" in forbidden.lower()

    # There is exactly one execution operation in the application, and it is this one.
    executing = [
        f"{method.upper()} {path}"
        for path, methods in paths.items()
        for method in methods
        if "execute" in path and method in {"get", "post", "patch", "put", "delete"}
    ]
    assert executing == ["POST /organizations/{organization_id}/actions/execute"]


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
        | {field for fields in EXPECTED_ACTION_SCHEMAS.values() for field in fields}
        | {field for fields in EXPECTED_AUDIT_SCHEMAS.values() for field in fields}
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
        "Policy",
        "PolicyCondition",
        "PolicyListResponse",
        "PolicyVersion",
        "PolicyVersionListResponse",
        "PolicyDecision",
        "PolicyEvaluateRequest",
        "PolicyEvaluateResponse",
        "EffectivePolicyDecision",
        "ActionExecuteRequest",
        "ActionExecutionResponse",
        "ActionOutcome",
        "ActionTarget",
        "FirewallDecision",
        "AuditEvent",
        "AuditEventListResponse",
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
        "PermissionResource",
        "PermissionAction",
        "PolicyEffect",
        "PolicyStatus",
        "PolicyConditionField",
        "PolicyConditionOperator",
        "ActionSensitivity",
        "FirewallOutcome",
        "FirewallReason",
        "AuditEventType",
        "AuditResourceType",
        "ActorType",
        "AuditSource",
        "AuditDecision",
        "AuditOutcome",
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
        "manage",
        "security",
        "policy",
        "require_approval",
        "not_applicable",
        "agent_age_days",
        "is_resource_owner",
        "execute",
        "action",
        "routine",
        "allowed",
        "authorization_denied",
        "policy_denied",
        "policy_requires_approval",
        "target_not_found",
        "environment_mismatch",
        "approval_required",
        "idempotency_conflict",
        "execution_failed",
        "asset.discovered",
        "agent.registered",
        "policy.version_published",
        "action.requested",
        "action.replayed",
        "not_executed",
        "replayed",
        "pending",
        "ingestion",
    ):
        assert f'"{value}"' in source, f"packages/types is missing the literal {value!r}"

    # Guard against a domain model creeping into phases that are not implemented.
    # Agent and Policy are no longer on this list — Phase 4 and Phase 6 implemented
    # them — and neither is the action firewall, whose decision and execution shapes
    # are mirrored above. What stays out is everything the later phases own, including
    # the two things named after the firewall that this build deliberately does not
    # have: an ``ActionFirewall`` as a manageable object (rules, status, toggles — the
    # control center's) and any approval workflow. Phase 7 publishes a decision and a
    # result, not a thing to administer.
    for not_yet in (
        "Incident",
        "ActionFirewall",
        "RuntimeSession",
        "Approval",
        "ApprovalRequest",
        "PolicyEnforcement",
        "KillSwitch",
    ):
        assert f"interface {not_yet}" not in source, f"packages/types declares {not_yet}"
