"""Authorization: what a role may do, decided and enforced by the server.

Phase 1 asked "which tenant owns this row?". Phase 2 asks the harder question —
"may *this caller* touch it?" — and the answer is computed from the caller's
membership, the role recorded for it, and the explicit permissions that role
grants. Nothing here trusts the client: the organization comes from the path, the
caller from the credential, and the permission check runs before the handler.

The tests fall into four groups:

- **The catalog** — each role's permissions, and the fact that no role holds more
  than its job needs.
- **Enforcement** — a viewer cannot administer, an analyst cannot administer, a
  security admin gets security and nothing wider, and the owner gets what the
  catalog says.
- **Isolation** — a member of one organization cannot read another's, cannot
  discover that it exists, and cannot get there by editing an identifier.
- **Structure** — every protected route declares the permission it enforces, and
  no handler anywhere compares a role name.

Group four is the one that keeps this file honest over time: the other three would
still pass if somebody added an unprotected route tomorrow.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from aicore_api.auth.dependencies import get_principal
from aicore_api.auth.dependencies import require_permission as build_requirement
from aicore_api.config import Settings
from aicore_api.core.permissions import ROLE_PERMISSIONS, Permission, RoleCode, permissions_for
from aicore_api.main import create_app
from identity_fixture import Identity, suspend_membership

ORG = "/organizations/{organization_id}"

#: The authorization surface: every route that names an organization, and the
#: permission it must enforce. A route added without an entry here fails
#: ``test_the_authorized_surface_is_what_the_routes_declare``.
#: Every tenant-scoped route and the permission it declares. Phase 3 added the six
#: inventory routes and Phase 4 the six registry routes; Phase 5 added no route at
#: all — it changed how a requirement is *decided* (a resource/action vocabulary and
#: a structured decision), not what the surface is. Phase 7 adds exactly one: the
#: action firewall's execution endpoint, guarded by ``action.execute``. The list stays
#: literal on purpose, because a literal expectation is what notices when a route
#: acquires a permission it should not have, or loses the one it needs.
EXPECTED_REQUIREMENTS: dict[tuple[str, str], set[Permission]] = {
    ("GET", "/organizations/{organization_id}"): {Permission.ORGANIZATION_READ},
    ("GET", "/organizations/{organization_id}/members"): {Permission.USER_READ},
    ("GET", "/organizations/{organization_id}/roles"): {Permission.ROLE_READ},
    ("GET", "/organizations/{organization_id}/permissions"): {Permission.ROLE_READ},
    ("GET", "/organizations/{organization_id}/assets"): {Permission.ASSET_READ},
    ("POST", "/organizations/{organization_id}/assets"): {Permission.ASSET_CREATE},
    ("GET", "/organizations/{organization_id}/assets/owners"): {Permission.ASSET_READ},
    ("GET", "/organizations/{organization_id}/assets/{asset_id}"): {Permission.ASSET_READ},
    ("PATCH", "/organizations/{organization_id}/assets/{asset_id}"): {Permission.ASSET_UPDATE},
    ("DELETE", "/organizations/{organization_id}/assets/{asset_id}"): {Permission.ASSET_DELETE},
    ("GET", "/organizations/{organization_id}/agents"): {Permission.AGENT_READ},
    ("POST", "/organizations/{organization_id}/agents"): {Permission.AGENT_CREATE},
    ("GET", "/organizations/{organization_id}/agents/identity/{identity_id}"): {
        Permission.AGENT_READ
    },
    ("GET", "/organizations/{organization_id}/agents/{agent_id}"): {Permission.AGENT_READ},
    ("PATCH", "/organizations/{organization_id}/agents/{agent_id}"): {Permission.AGENT_UPDATE},
    ("DELETE", "/organizations/{organization_id}/agents/{agent_id}"): {Permission.AGENT_DELETE},
    ("GET", "/organizations/{organization_id}/policies"): {Permission.POLICY_READ},
    ("POST", "/organizations/{organization_id}/policies"): {Permission.POLICY_CREATE},
    # The dry run reads policies, so reading them is what it requires. There is no
    # ``policy.evaluate``: evaluation is not a capability a role is granted, and the
    # one route that exposes it hands back a report rather than an outcome.
    ("POST", "/organizations/{organization_id}/policies/evaluate"): {Permission.POLICY_READ},
    ("GET", "/organizations/{organization_id}/policies/{policy_id}"): {Permission.POLICY_READ},
    ("GET", "/organizations/{organization_id}/policies/{policy_id}/versions"): {
        Permission.POLICY_READ
    },
    ("PATCH", "/organizations/{organization_id}/policies/{policy_id}"): {Permission.POLICY_UPDATE},
    ("DELETE", "/organizations/{organization_id}/policies/{policy_id}"): {Permission.POLICY_DELETE},
    # The one route that can execute something, and the one permission that guards it.
    # There is no per-action permission: the *authorization* question (may this person
    # run registered actions here?) is one question, and the contextual one (should this
    # action, on this target, run?) is Phase 6's, through a policy on this target.
    ("POST", "/organizations/{organization_id}/actions/execute"): {Permission.ACTION_EXECUTE},
    # The trail is a read, guarded by the permission Phase 2 declared for it. Phase 8
    # added no capability to the vocabulary: the owner and the security administrator
    # already held ``audit.read``, and the administrator deliberately does not — oversight
    # is not administration.
    ("GET", "/organizations/{organization_id}/audit-events"): {Permission.AUDIT_READ},
    # Monitoring is the same record, counted. Phase 9 added no permission either: a
    # measurement is a sum over rows the caller can already read, so inventing
    # ``monitoring.read`` would guard nothing and — granted to a role that lacks
    # ``audit.read`` — would hand that role the trail's contents in aggregate. Every view
    # is a read, so every view requires the read permission.
    ("GET", "/organizations/{organization_id}/monitoring/summary"): {Permission.AUDIT_READ},
    ("GET", "/organizations/{organization_id}/monitoring/agents"): {Permission.AUDIT_READ},
    ("GET", "/organizations/{organization_id}/monitoring/actions"): {Permission.AUDIT_READ},
    ("GET", "/organizations/{organization_id}/monitoring/policies"): {Permission.AUDIT_READ},
    ("GET", "/organizations/{organization_id}/monitoring/trends"): {Permission.AUDIT_READ},
    # Risk analysis reads the same trail as two windows and compares them. Phase 10 added
    # exactly one capability, and only for the one route that writes: computing a finding
    # is a read of rows the caller can already read (``security.read``), while *recording*
    # one is a durable claim about an agent, so it is its own grant
    # (``security.create``) held by the owner and the security administrator — never by
    # the analyst.
    ("GET", "/organizations/{organization_id}/risk/agents"): {Permission.SECURITY_READ},
    ("GET", "/organizations/{organization_id}/risk/agents/{agent_id}"): {Permission.SECURITY_READ},
    ("GET", "/organizations/{organization_id}/risk/detections"): {Permission.SECURITY_READ},
    (
        "GET",
        "/organizations/{organization_id}/risk/detections/{detection_id}",
    ): {Permission.SECURITY_READ},
    ("POST", "/organizations/{organization_id}/risk/analysis"): {Permission.SECURITY_CREATE},
}

TENANT_ROUTES = list(EXPECTED_REQUIREMENTS)

#: Routes that address one entity. Asked with an id that does not exist they answer
#: 404 — "authorized, but there is no such asset" — which is what distinguishes a
#: permitted request from a denied one.
ITEM_ROUTES = [
    route
    for route in TENANT_ROUTES
    if any(
        f"{{{name}}}" in route[1]
        for name in ("asset_id", "agent_id", "identity_id", "policy_id", "detection_id")
    )
]

#: Routes a fully permitted member can read outright: the collections, not the
#: single-entity routes and not the create route, which needs a body.
READ_ROUTES = [route for route in TENANT_ROUTES if route not in ITEM_ROUTES and route[0] == "GET"]

#: Everything that must refuse an anonymous caller. Health probes are absent on
#: purpose: an orchestrator asks those without credentials.
PROTECTED_ROUTES = [*TENANT_ROUTES, ("GET", "/me")]


def _url(path: str, organization_id: uuid.UUID, item_id: uuid.UUID | None = None) -> str:
    """Render a route template, filling in an item id when the route names one."""
    rendered = path.replace("{organization_id}", str(organization_id))
    for placeholder in ("asset_id", "agent_id", "identity_id", "policy_id", "detection_id"):
        rendered = rendered.replace(f"{{{placeholder}}}", str(item_id or uuid.uuid4()))
    return rendered


def _sweep(
    client: TestClient,
    method: str,
    path: str,
    organization_id: uuid.UUID,
    item_id: uuid.UUID | None = None,
) -> Any:
    """Send a *well-formed* request, so that authorization is what is under test.

    A validation failure and a refusal can look alike in a sweep like this, and an
    assertion cannot tell which one it saw — so the bodies are valid and the status
    is the only variable. The body follows the collection being addressed: an
    inventory record, a registered agent, a policy definition and a dry-run request
    are four different shapes.
    """
    agent_route = "/agents" in path
    policy_route = "/policies" in path
    evaluate_route = path.endswith("/policies/evaluate")
    execute_route = path.endswith("/actions/execute")
    analysis_route = path.endswith("/risk/analysis")
    body: dict[str, Any] | None = None
    if analysis_route:
        # The one POST whose query string is also validated, because the window it records
        # must be explicit: a stated interval, hour-aligned here so the sweep is arithmetic
        # rather than "whatever the clock did". The body names an agent this organization
        # does not have, so a permitted caller gets a 404 about the target — which is the
        # distinction the sweep is looking for.
        end = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
        return client.request(
            method,
            _url(path, organization_id, item_id),
            json={"agent_id": str(uuid.uuid4())},
            params={
                "window": "custom",
                "start_time": (end - timedelta(hours=1)).isoformat(),
                "end_time": end.isoformat(),
                "baseline": "7d",
            },
        )
    if method == "POST":
        if execute_route:
            # Well-formed like the rest: a registered action, a target this
            # organization does not have, the environment the sweeps register in,
            # and a key. The answer is then a 404 about the target, which is the
            # point of the sweep — authorization is what is under test.
            body = {
                "action": "agent.posture_check",
                "target_id": str(uuid.uuid4()),
                "environment": "production",
                "arguments": {},
                "idempotency_key": f"sweep-{uuid.uuid4().hex}",
            }
        elif evaluate_route:
            body = {
                "resource": "agent",
                "action": "update",
                "facts": {"environment": "production"},
            }
        elif policy_route:
            body = {
                "name": "Authorization Sweep",
                "description": "A well-formed body, so the sweep tests authorization.",
                "resource": "agent",
                "action": "update",
                "effect": "deny",
                "priority": 100,
                "conditions": [
                    {"field": "environment", "operator": "equals", "value": "production"}
                ],
            }
        elif agent_route:
            body = {"display_name": "Authorization Sweep", "category": "other", "version": "1.0"}
        else:
            body = {"name": "Authorization Sweep", "asset_type": "model"}
    elif method == "PATCH":
        if policy_route:
            body = {"description": "Swept by the authorization suite."}
        elif agent_route:
            body = {"version": "1.0.1"}
        else:
            body = {"risk_classification": "low"}
    return client.request(method, _url(path, organization_id, item_id), json=body)


# ── The catalog ───────────────────────────────────────────────────────────────


def test_every_role_declares_at_least_one_permission() -> None:
    """A role that grants nothing is a role nobody can use; a typo would look like one."""
    for role_code in RoleCode:
        assert ROLE_PERMISSIONS[role_code], f"{role_code} grants nothing"


def test_unknown_roles_fail_closed() -> None:
    """An unknown role raises; it never resolves to "no permissions" or "all of them"."""
    with pytest.raises(ValueError, match="unknown role"):
        permissions_for("auditor_shadow")


def _roles_holding(permission: Permission) -> set[RoleCode]:
    """The roles that hold ``permission``, straight from the catalog."""
    return {role_code for role_code, granted in ROLE_PERMISSIONS.items() if permission in granted}


def test_the_sensitive_permissions_are_held_by_the_roles_that_need_them() -> None:
    """Administration is not handed out for convenience.

    Written as "exactly these roles, no others" rather than "at least": widening a
    role is the change this test exists to catch, and a superset assertion would
    quietly allow it. Each line is a decision the phase made on purpose.
    """
    # Changing who may do what is the owner's alone.
    assert _roles_holding(Permission.ROLE_MANAGE) == {RoleCode.OWNER}
    # Changing the organization itself is general administration.
    assert _roles_holding(Permission.ORGANIZATION_UPDATE) == {RoleCode.OWNER, RoleCode.ADMIN}
    # Managing people is administration, not security or analysis.
    assert _roles_holding(Permission.USER_MANAGE) == {RoleCode.OWNER, RoleCode.ADMIN}
    # The audit trail is for the owner and the security administrator.
    assert _roles_holding(Permission.AUDIT_READ) == {RoleCode.OWNER, RoleCode.SECURITY_ADMIN}
    # Reading security data is also what an analyst does for a living.
    assert _roles_holding(Permission.SECURITY_READ) == {
        RoleCode.OWNER,
        RoleCode.SECURITY_ADMIN,
        RoleCode.ANALYST,
    }
    # Running a registered action is administration, on purpose: the party that may
    # examine a posture through a registered, read-only assessment is the administrator
    # and the security administrator — never the AI administrator, whose work the
    # policies constrain, and never a reader or an analyst.
    assert _roles_holding(Permission.ACTION_EXECUTE) == {
        RoleCode.OWNER,
        RoleCode.ADMIN,
        RoleCode.SECURITY_ADMIN,
    }
    # Reading the role catalog is not the same as managing it: administration sees
    # what roles exist, and nobody else needs the catalog to do their job.
    assert _roles_holding(Permission.ROLE_READ) == {RoleCode.OWNER, RoleCode.ADMIN}
    # Every role can see the organization it belongs to and who its members are
    # read-only; that is the floor, and it is deliberately the only universal one.
    for role_code in RoleCode:
        assert Permission.ORGANIZATION_READ in ROLE_PERMISSIONS[role_code]


# ── Enforcement, role by role ─────────────────────────────────────────────────


@pytest.mark.parametrize("role_code", [role.value for role in RoleCode])
def test_the_api_reports_exactly_what_the_catalog_grants(
    role_code: str, database_client: TestClient, identity_factory, authenticate
) -> None:
    """``GET /me`` is the runtime view of the catalog — the seeded rows, resolved.

    This is where the database seed, the resolver and the catalog in code have to
    agree; a role that lost a permission in a migration shows up here.
    """
    identity: Identity = identity_factory(role_code=role_code)

    memberships = authenticate(identity).get("/me").json()["memberships"]

    assert memberships[0]["role"]["code"] == role_code
    assert memberships[0]["permissions"] == sorted(
        permission.value for permission in ROLE_PERMISSIONS[RoleCode(role_code)]
    )


def test_the_owner_reaches_every_route(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """The owner holds every permission the phase enforces, so nothing is a 403."""
    identity: Identity = identity_factory(role_code="owner")
    client = authenticate(identity)

    for method, path in READ_ROUTES:
        response = _sweep(client, method, path, identity.organization_id)
        assert response.status_code == 200, f"{method} {path}: {response.text}"

    # Registering is the one write the owner can make outright, in every collection.
    asset = _sweep(client, "POST", f"{ORG}/assets", identity.organization_id)
    assert asset.status_code == 201, asset.text
    agent = _sweep(client, "POST", f"{ORG}/agents", identity.organization_id)
    assert agent.status_code == 201, agent.text
    policy = _sweep(client, "POST", f"{ORG}/policies", identity.organization_id)
    assert policy.status_code == 201, policy.text
    evaluated = client.post(
        f"{ORG.format(organization_id=identity.organization_id)}/policies/evaluate",
        json={"resource": "agent", "action": "update", "facts": {"environment": "production"}},
    )
    assert evaluated.status_code == 200, evaluated.text
    executed = _sweep(client, "POST", f"{ORG}/actions/execute", identity.organization_id)
    assert executed.status_code == 404, executed.text
    asset_id = uuid.UUID(asset.json()["id"])
    agent_id = uuid.UUID(agent.json()["id"])
    identity_id = uuid.UUID(agent.json()["identity_id"])

    # The item routes are reached with an id that does not exist — and with one
    # that does. Both matter: the first proves the owner is not denied (404 rather
    # than 403), the second that the routes actually work for them.
    for method, path in ITEM_ROUTES:
        absent = _sweep(client, method, path, identity.organization_id)
        assert absent.status_code == 404, f"{method} {path}: {absent.text}"

    asset_item = f"{ORG}/assets/{{asset_id}}"
    assert _sweep(client, "GET", asset_item, identity.organization_id, asset_id).status_code == 200
    assert (
        _sweep(client, "PATCH", asset_item, identity.organization_id, asset_id).status_code == 200
    )
    assert (
        _sweep(client, "DELETE", asset_item, identity.organization_id, asset_id).status_code == 204
    )

    agent_item = f"{ORG}/agents/{{agent_id}}"
    assert _sweep(client, "GET", agent_item, identity.organization_id, agent_id).status_code == 200
    assert (
        _sweep(client, "PATCH", agent_item, identity.organization_id, agent_id).status_code == 200
    )
    assert (
        _sweep(
            client,
            "GET",
            f"{ORG}/agents/identity/{{identity_id}}",
            identity.organization_id,
            identity_id,
        ).status_code
        == 200
    )
    assert (
        _sweep(client, "DELETE", agent_item, identity.organization_id, agent_id).status_code == 204
    )

    policy_id = uuid.UUID(policy.json()["policy_id"])
    policy_item = f"{ORG}/policies/{{policy_id}}"
    assert (
        _sweep(client, "GET", policy_item, identity.organization_id, policy_id).status_code == 200
    )
    versions = _sweep(
        client,
        "GET",
        f"{ORG}/policies/{{policy_id}}/versions",
        identity.organization_id,
        policy_id,
    )
    assert versions.status_code == 200, versions.text
    assert [entry["version"] for entry in versions.json()["items"]] == [policy.json()["version"]]
    assert (
        _sweep(client, "PATCH", policy_item, identity.organization_id, policy_id).status_code == 200
    )
    assert (
        _sweep(client, "DELETE", policy_item, identity.organization_id, policy_id).status_code
        == 204
    )


def test_a_viewer_may_read_the_organization_and_nothing_else(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """Read-only means read-only: the organization, not its directory or catalog."""
    identity: Identity = identity_factory(role_code="viewer")
    client = authenticate(identity)
    path = ORG.format(organization_id=identity.organization_id)

    assert client.get(path).status_code == 200
    for denied in (f"{path}/members", f"{path}/roles", f"{path}/permissions"):
        response = client.get(denied)
        assert response.status_code == 403, denied
        assert response.json()["error"]["code"] == "forbidden"


def test_an_analyst_reads_analysis_inputs_but_does_not_administer(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """The analyst's read of security data does not extend to administration."""
    identity: Identity = identity_factory(role_code="analyst")
    client = authenticate(identity)
    path = ORG.format(organization_id=identity.organization_id)

    body = client.get("/me").json()
    assert body["memberships"][0]["permissions"] == [
        Permission.AGENT_READ.value,
        Permission.ASSET_READ.value,
        Permission.ORGANIZATION_READ.value,
        Permission.SECURITY_READ.value,
    ]

    assert client.get(path).status_code == 200
    assert client.get(f"{path}/members").status_code == 403
    assert client.get(f"{path}/roles").status_code == 403


def test_a_security_admin_gets_security_permissions_and_nothing_wider(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """Security work needs audit and security data — not role management."""
    identity: Identity = identity_factory(role_code="security_admin")
    client = authenticate(identity)
    path = ORG.format(organization_id=identity.organization_id)

    granted = set(client.get("/me").json()["memberships"][0]["permissions"])
    assert granted == {
        Permission.AGENT_READ.value,
        Permission.AGENT_UPDATE.value,
        Permission.ASSET_READ.value,
        Permission.ASSET_UPDATE.value,
        Permission.ORGANIZATION_READ.value,
        Permission.USER_READ.value,
        Permission.AUDIT_READ.value,
        Permission.SECURITY_READ.value,
        # Phase 10: the one write the security administrator makes — recording a finding
        # the engine computed. It is the same role that already edits policies, and the
        # same capability the owner holds; no other role records anything.
        Permission.SECURITY_CREATE.value,
        Permission.POLICY_READ.value,
        Permission.POLICY_CREATE.value,
        Permission.POLICY_UPDATE.value,
        Permission.ACTION_EXECUTE.value,
    }

    # Reading the member directory is part of investigating an incident.
    assert client.get(f"{path}/members").status_code == 200
    # Managing the role catalog is not; neither is changing the organization.
    assert client.get(f"{path}/roles").status_code == 403
    assert client.get(f"{path}/permissions").status_code == 403


def test_an_ai_admin_administers_ai_assets_and_not_security(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """AI administration is not a licence to read security data."""
    identity: Identity = identity_factory(role_code="ai_admin")
    client = authenticate(identity)
    path = ORG.format(organization_id=identity.organization_id)

    granted = set(client.get("/me").json()["memberships"][0]["permissions"])
    assert granted == {
        Permission.AGENT_CREATE.value,
        Permission.AGENT_READ.value,
        Permission.AGENT_UPDATE.value,
        Permission.ASSET_CREATE.value,
        Permission.ASSET_READ.value,
        Permission.ASSET_UPDATE.value,
        Permission.ORGANIZATION_READ.value,
        Permission.USER_READ.value,
    }
    assert Permission.SECURITY_READ.value not in granted
    assert Permission.AUDIT_READ.value not in granted
    # Stewardship of the inventory and its agents is not authority to erase the
    # record of either.
    assert Permission.ASSET_DELETE.value not in granted
    assert Permission.AGENT_DELETE.value not in granted

    assert client.get(f"{path}/members").status_code == 200
    assert client.get(f"{path}/roles").status_code == 403


def test_an_admin_reads_the_catalog_but_does_not_manage_it(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """General administration reads roles; only the owner changes them."""
    identity: Identity = identity_factory(role_code="admin")
    client = authenticate(identity)
    path = ORG.format(organization_id=identity.organization_id)

    assert client.get(f"{path}/roles").status_code == 200
    assert client.get(f"{path}/members").status_code == 200

    granted = set(client.get("/me").json()["memberships"][0]["permissions"])
    assert Permission.ROLE_READ.value in granted
    assert Permission.ROLE_MANAGE.value not in granted


def test_a_suspended_membership_is_refused_everywhere(
    database_client: TestClient, identity_factory, authenticate, integration_engine: Engine
) -> None:
    """Suspension revokes access immediately, without deleting the membership."""
    identity: Identity = identity_factory(role_code="owner")
    client = authenticate(identity)
    suspend_membership(integration_engine, identity)

    for method, path in TENANT_ROUTES:
        response = _sweep(client, method, path, identity.organization_id)
        assert response.status_code == 403, f"{method} {path}"
        assert response.json()["error"]["code"] == "forbidden"


# ── Isolation ─────────────────────────────────────────────────────────────────


def test_membership_in_one_organization_grants_nothing_in_another(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """This is the phase's central security claim, checked on every route."""
    member: Identity = identity_factory(role_code="owner")
    stranger: Identity = identity_factory(role_code="owner")
    client = authenticate(stranger)

    asset_id = uuid.uuid4()
    for method, path in TENANT_ROUTES:
        own = _sweep(client, method, path, stranger.organization_id, asset_id)
        other = _sweep(client, method, path, member.organization_id, asset_id)

        # In its own organization the stranger is never *denied* — the exact status
        # is each route's own business, and the asset routes' tests pin theirs; in
        # the other organization every route answers the same 404.
        assert own.status_code != 403, f"{method} {path}: {own.text}"
        assert other.status_code == 404, f"{method} {path}: {other.text}"
        assert other.json()["error"]["code"] == "not_found"


def test_an_inaccessible_organization_is_indistinguishable_from_a_missing_one(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """No existence oracle: 403 would confirm the tenant exists, and that is a leak.

    The bodies must match apart from the request id, which is unique per request.
    """
    member: Identity = identity_factory(role_code="owner")
    stranger: Identity = identity_factory(role_code="owner")
    client = authenticate(stranger)
    existing = ORG.format(organization_id=member.organization_id)
    missing = ORG.format(organization_id=uuid.uuid4())

    def answer(path: str) -> dict[str, object]:
        body = client.get(path).json()
        error = dict(body["error"])
        error.pop("request_id")
        return error

    assert answer(existing) == answer(missing)


def test_editing_the_organization_identifier_cannot_authorize_anything(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """A client controls the URL, so the URL must never be the grant.

    Asked with one credential: the organization it belongs to works, the other does
    not — and a malformed identifier is refused by validation rather than reaching
    a query.
    """
    identity: Identity = identity_factory(role_code="owner")
    other: Identity = identity_factory(role_code="owner")
    client = authenticate(identity)

    assert client.get(ORG.format(organization_id=identity.organization_id)).status_code == 200
    assert client.get(ORG.format(organization_id=other.organization_id)).status_code == 404

    malformed = client.get("/organizations/not-a-uuid")
    assert malformed.status_code == 422
    assert malformed.json()["error"]["code"] == "validation_error"

    another_members_directory = client.get(f"/organizations/{other.organization_id}/members")
    assert another_members_directory.status_code == 404
    # The refusal must not describe the other tenant in words either.
    assert other.organization_slug not in another_members_directory.text


def test_an_anonymous_caller_reaches_no_protected_route(client: TestClient) -> None:
    """The refusal happens before any handler runs, on the hermetic app (no database)."""
    for method, path in PROTECTED_ROUTES:
        response = client.request(method, _url(path, uuid.uuid4()))

        assert response.status_code == 401, f"{method} {path}"
        assert response.headers["www-authenticate"] == "Bearer"
        assert response.json()["error"]["code"] == "unauthorized"


# ── Structure: the rules that keep the rules true ─────────────────────────────


def _declared_permissions(route: APIRoute) -> set[Permission]:
    """The permissions a route requires, read from its dependency tree."""
    found: set[Permission] = set()
    stack = list(route.dependant.dependencies)
    while stack:
        dependant = stack.pop()
        permission = getattr(dependant.call, "required_permission", None)
        if permission is not None:
            found.add(permission)
        stack.extend(dependant.dependencies)
    return found


def _api_routes(app: FastAPI) -> list[APIRoute]:
    """Every route the running application will serve, in declaration order.

    FastAPI keeps included routers lazy, so the expansion goes through the same
    helper it uses itself rather than reading ``app.routes`` (which lists the
    includes, not the routes).
    """
    routes = []
    for context in iter_route_contexts(app.routes):
        route = context.original_route
        if isinstance(route, APIRoute):
            routes.append(route)
    return routes


def test_the_authorized_surface_is_what_the_routes_declare(settings: Settings) -> None:
    """Every tenant-scoped route names its permission, and no route is unprotected.

    The assertion is deliberately two-sided: the expected map must match, and every
    route that mentions an organization must appear in it. Adding a tenant route
    without a requirement therefore fails this test rather than shipping a hole.
    """
    app = create_app(settings)
    declared: dict[tuple[str, str], set[Permission]] = {}

    for route in _api_routes(app):
        for method in sorted(route.methods):
            if method in {"HEAD", "OPTIONS"}:
                continue
            declared[(method, route.path)] = _declared_permissions(route)

    tenant_routes = {
        key: permissions for key, permissions in declared.items() if "{organization_id}" in key[1]
    }
    assert tenant_routes == EXPECTED_REQUIREMENTS

    # Nothing outside the tenant routes may require a permission either: a
    # permission on a non-tenant route would mean an organization was resolved
    # from somewhere other than the path.
    others = {
        key for key, permissions in declared.items() if permissions and key not in tenant_routes
    }
    assert others == set(), f"unexpected permission requirements: {others}"


def test_the_only_routes_without_authentication_are_probes_and_provisioning(
    settings: Settings,
) -> None:
    """Exactly three paths may be reached without a credential, and no others.

    ``/health`` and ``/health/ready`` exist for orchestrators, which have no
    credentials. ``POST /organizations`` is Phase 1's tenant-provisioning route,
    which Phase 2 could not authorize without inventing a platform administrator;
    it stays development/test only (see ``test_organizations_api``) and is a 404
    everywhere else. Anything else appearing here means a domain route shipped
    without authentication, which is the failure this asserts against.
    """
    app = create_app(settings)
    without_authentication: set[str] = set()

    for route in _api_routes(app):
        if _dependency_calls(route) & {get_principal}:
            continue
        without_authentication.update(
            route.path for method in route.methods if method not in {"HEAD", "OPTIONS"}
        )

    assert without_authentication == {"/health", "/health/ready", "/organizations"}


def _dependency_calls(route: APIRoute) -> set[object]:
    """Every callable in a route's dependency tree."""
    found: set[object] = set()
    stack = list(route.dependant.dependencies)
    while stack:
        dependant = stack.pop()
        found.add(dependant.call)
        stack.extend(dependant.dependencies)
    return found


def test_handlers_do_not_branch_on_role_names() -> None:
    """Authorization is a permission question, asked in one place.

    A handler that reads ``role.code`` is how role checks creep back in: they
    cannot be audited from the catalog, and every one of them is a second
    definition of who may do what. Only :mod:`aicore_api.core.permissions` — and
    the CLI, which provisions roles rather than deciding anything — may name a
    role.
    """
    from pathlib import Path

    package = Path(__file__).resolve().parents[1] / "src" / "aicore_api"
    guarded_modules = [package / "api", package / "auth"]
    role_names = [role.value for role in RoleCode]
    offenders: list[str] = []

    for directory in guarded_modules:
        for path in sorted(directory.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            for role_name in role_names:
                if f'"{role_name}"' in source or f"'{role_name}'" in source:
                    offenders.append(f"{path.name}: {role_name!r}")
            if "RoleCode" in source:
                offenders.append(f"{path.name}: RoleCode")

    assert offenders == [], f"role names in authorization code: {offenders}"


def test_a_route_can_only_ask_for_permissions_that_exist() -> None:
    """The requirement helper is typed, and every permission it names is in the catalog."""
    from aicore_api.core.permissions import all_permissions

    assert set(all_permissions()) == set(Permission)
    for permission in Permission:
        requirement = build_requirement(permission)
        assert requirement.required_permission is permission
