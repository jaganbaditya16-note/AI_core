"""The authorization decision: deterministic, structured, and instance-aware.

Phase 5's foundation is one question — *may this principal use this permission in
this organization, for this row?* — answered as a value rather than as a branch
inside a handler. These tests assert the properties that make that value worth
having:

- **It is decided from database facts.** Membership, role and permission come from
  rows; nothing is inferred from a token, a header or a name.
- **It is total.** Every input produces ALLOW or DENY with a machine-readable
  reason, including the cases that used to be exceptions: an unknown role denies
  rather than exploding mid-request. The HTTP boundary still raises for that one,
  because a deployment whose catalog the code cannot reason about must be loud.
- **It never leaks.** A caller who is not a member learns nothing: the denial is
  the same one an organization that does not exist would produce, and it carries
  no identifier from the other tenant.
- **Tenancy is part of the question.** Holding the permission is not enough for a
  row in another organization, and ownership is reported without ever widening an
  ALLOW — Phase 5 grants nothing for owning something.
- **It is deterministic and local.** No model call, no network client, no clock,
  no randomness: the decision path is a pure function of rows and enums, which is
  asserted structurally as well as behaviourally.

The last section exercises the routes: an item route authorizes the row it
loaded, not only the permission it declared, so a repository that lost its tenant
filter (a bug, not a policy) fails closed with the same 404 a missing row gets.
"""

from __future__ import annotations

import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from aicore_api.api.scope import require_instance_scope
from aicore_api.auth.authorization import (
    DecisionReason,
    OrganizationContext,
    ResourceScope,
    authorize,
    authorize_instance,
    decide,
    resolve_organization_context,
)
from aicore_api.auth.principal import Principal
from aicore_api.core.permissions import Action, Permission, Resource
from aicore_api.db.repositories.agents import AgentRepository
from aicore_api.db.repositories.assets import AssetRepository
from aicore_api.db.repositories.memberships import MembershipRepository
from aicore_api.main import create_app
from identity_fixture import Identity, suspend_membership

#: The modules the decision is made in. The structural test below reads them.
DECISION_PATH = (
    Path("apps/api/src/aicore_api/auth/authorization.py"),
    Path("apps/api/src/aicore_api/auth/dependencies.py"),
    Path("apps/api/src/aicore_api/core/permissions.py"),
)


def _principal(identity: Identity) -> Principal:
    """The authenticated caller, as :mod:`aicore_api.auth.providers` would build it."""
    return Principal(
        user_id=identity.user_id,
        email=identity.email,
        full_name="Test Person",
        status="active",
    )


def _stub_membership(**overrides: Any) -> Any:
    """A membership-shaped object, for the cases the database will not produce."""
    fields: dict[str, Any] = {
        "id": uuid.uuid4(),
        "user_id": uuid.uuid4(),
        "status": "active",
        "role": SimpleNamespace(code="owner"),
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


# ── The decision, from database facts ─────────────────────────────────────────


def test_an_active_member_holding_the_permission_is_allowed(
    integration_session: Session, identity_factory
) -> None:
    """The ordinary case, with every identifier the decision was made from."""
    identity = identity_factory(role_code="ai_admin")
    decision = authorize(
        integration_session,
        _principal(identity),
        identity.organization_id,
        Permission.AGENT_UPDATE,
    )

    assert decision.allowed
    assert decision.denied is False
    assert decision.reason is DecisionReason.ALLOWED
    assert decision.resource is Resource.AGENT
    assert decision.action is Action.UPDATE
    assert decision.permission is Permission.AGENT_UPDATE
    assert decision.organization_id == identity.organization_id
    assert decision.role_code == "ai_admin"
    assert decision.membership_id == identity.membership_id
    assert decision.instance_organization_id is None
    assert "ALLOW" in repr(decision)


def test_a_member_without_the_permission_is_denied(
    integration_session: Session, identity_factory
) -> None:
    """Read-only means read-only, and the denial says which kind of refusal it is."""
    identity = identity_factory(role_code="viewer")
    decision = authorize(
        integration_session,
        _principal(identity),
        identity.organization_id,
        Permission.ASSET_CREATE,
    )

    assert decision.denied
    assert decision.reason is DecisionReason.MISSING_PERMISSION
    assert decision.role_code == "viewer"
    assert decision.membership_id == identity.membership_id
    assert "DENY" in repr(decision)


def test_asking_only_whether_someone_is_a_member_is_allowed_for_an_active_member(
    integration_session: Session, identity_factory
) -> None:
    """Some routes need membership and nothing more; that is still a decision."""
    identity = identity_factory(role_code="analyst")
    decision = authorize(integration_session, _principal(identity), identity.organization_id)

    assert decision.allowed
    assert decision.reason is DecisionReason.ALLOWED_MEMBERSHIP
    assert decision.permission is None
    assert decision.resource is None
    assert decision.action is None


def test_a_caller_who_is_not_a_member_is_denied_without_learning_whether_the_tenant_exists(
    integration_session: Session, identity_factory
) -> None:
    """The outsider's denial is identical for a tenant that exists and one that does not.

    Only the organization id they asked about differs, because they supplied it;
    everything else — reason, role, membership — is empty, so a record of the
    decision cannot leak a foreign tenant's identifiers either.
    """
    member = identity_factory(role_code="owner")
    outsider = identity_factory(role_code="owner")

    existing = authorize(
        integration_session, _principal(outsider), member.organization_id, Permission.ASSET_READ
    )
    invented = authorize(
        integration_session, _principal(outsider), uuid.uuid4(), Permission.ASSET_READ
    )

    assert existing.denied and invented.denied
    assert existing.reason is DecisionReason.NO_MEMBERSHIP
    assert existing.role_code is None
    assert existing.membership_id is None
    # Everything except the id the caller supplied is identical — so a record of
    # the decision cannot hint at the tenant they were probing for.
    assert replace(existing, organization_id=None) == replace(invented, organization_id=None)


def test_a_suspended_membership_is_denied(
    integration_session: Session, identity_factory, integration_engine: Engine
) -> None:
    """Suspension is an authorization fact, not a deletion: the member is told so."""
    identity = identity_factory(role_code="owner")
    suspend_membership(integration_engine, identity)

    decision = authorize(
        integration_session, _principal(identity), identity.organization_id, Permission.ASSET_READ
    )

    assert decision.denied
    assert decision.reason is DecisionReason.MEMBERSHIP_INACTIVE
    assert decision.role_code == "owner"
    assert decision.membership_id == identity.membership_id


def test_an_unknown_role_denies_in_the_decision_and_raises_at_the_boundary(
    integration_session: Session, identity_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A role the code cannot reason about fails closed — and loudly, not silently.

    The decision layer is total (it answers DENY), while the HTTP boundary raises:
    a database whose catalog and code disagree is a deployment defect, and a quiet
    403 would hide it. Both halves are asserted here.
    """
    identity = identity_factory(role_code="owner")
    shadow_role = _stub_membership(status="active", role=SimpleNamespace(code="auditor_shadow"))

    decision = decide(
        shadow_role,
        organization_id=identity.organization_id,
        permission=Permission.ASSET_READ,
    )
    assert decision.denied
    assert decision.reason is DecisionReason.UNKNOWN_ROLE
    assert decision.role_code == "auditor_shadow"

    monkeypatch.setattr(
        MembershipRepository, "find_for_user", lambda self, user_id: shadow_role, raising=True
    )
    with pytest.raises(ValueError, match="not in the code catalog"):
        resolve_organization_context(
            integration_session,
            _principal(identity),
            identity.organization_id,
            required=Permission.ASSET_READ,
        )


def test_the_same_question_always_has_the_same_answer(
    integration_session: Session, identity_factory
) -> None:
    """Determinism, asserted rather than assumed: no clock, no randomness, no LLM."""
    identity = identity_factory(role_code="security_admin")
    principal = _principal(identity)

    decisions = [
        authorize(integration_session, principal, identity.organization_id, Permission.AGENT_UPDATE)
        for _ in range(5)
    ]

    assert all(decision == decisions[0] for decision in decisions)
    assert decisions[0].allowed


# ── The instance dimension ────────────────────────────────────────────────────


def test_a_row_in_another_organization_is_denied_even_with_the_permission(
    integration_session: Session, identity_factory
) -> None:
    """Permission is not enough: tenancy is part of the question."""
    identity = identity_factory(role_code="owner")
    other_organization = identity_factory(role_code="owner").organization_id

    decision = authorize(
        integration_session,
        _principal(identity),
        identity.organization_id,
        Permission.ASSET_DELETE,
        scope=ResourceScope(organization_id=other_organization),
    )

    assert decision.denied
    assert decision.reason is DecisionReason.RESOURCE_OUTSIDE_TENANT
    assert decision.instance_organization_id == other_organization
    assert decision.organization_id == identity.organization_id


def test_ownership_is_reported_and_never_widens_a_decision(
    integration_session: Session, identity_factory
) -> None:
    """Owning a row is a fact a later phase may read; it grants nothing here."""
    owner = identity_factory(role_code="owner")
    stranger_membership = identity_factory(role_code="owner").membership_id

    owned_by_caller = authorize(
        integration_session,
        _principal(owner),
        owner.organization_id,
        Permission.AGENT_UPDATE,
        scope=ResourceScope(
            organization_id=owner.organization_id, owner_membership_id=owner.membership_id
        ),
    )
    assert owned_by_caller.allowed
    assert owned_by_caller.principal_is_owner is True

    owned_by_someone_else = authorize(
        integration_session,
        _principal(owner),
        owner.organization_id,
        Permission.AGENT_UPDATE,
        scope=ResourceScope(
            organization_id=owner.organization_id, owner_membership_id=stranger_membership
        ),
    )
    assert owned_by_someone_else.allowed
    assert owned_by_someone_else.principal_is_owner is False

    # The same owner, asking for something their role does not grant: still denied.
    viewer = identity_factory(role_code="viewer")
    denied = authorize(
        integration_session,
        _principal(viewer),
        viewer.organization_id,
        Permission.AGENT_DELETE,
        scope=ResourceScope(
            organization_id=viewer.organization_id, owner_membership_id=viewer.membership_id
        ),
    )
    assert denied.denied
    assert denied.reason is DecisionReason.MISSING_PERMISSION
    assert denied.principal_is_owner is True


def test_an_unowned_row_reports_no_ownership_fact(
    integration_session: Session, identity_factory
) -> None:
    """An inventory record need not have an owner; the decision says so instead of guessing."""
    identity = identity_factory(role_code="owner")
    decision = authorize(
        integration_session,
        _principal(identity),
        identity.organization_id,
        Permission.ASSET_READ,
        scope=ResourceScope(organization_id=identity.organization_id),
    )

    assert decision.allowed
    assert decision.principal_is_owner is None


def test_a_scope_can_be_read_from_a_real_row(
    integration_session: Session, identity_factory, agents
) -> None:
    """``ResourceScope.of`` reads the tenant facts off a row, without a query."""
    record = agents.register(display_name="Scoped Agent")
    assert record is not None

    row = AgentRepository(integration_session, agents.organization_id).find(record.id)
    assert row is not None
    scope = ResourceScope.of(row)

    assert scope.organization_id == agents.organization_id
    # The registration named no owner, so the row states none.
    assert scope.owner_membership_id is None

    # …and the row's own organization is the one the caller is authorized in.
    decision = authorize(
        integration_session,
        _principal(identity_factory(role_code="owner", organization_id=agents.organization_id)),
        agents.organization_id,
        Permission.AGENT_READ,
        scope=scope,
    )
    assert decision.allowed


def test_a_row_that_cannot_state_its_organization_is_refused() -> None:
    """An unscoped row is exactly where a tenant check would be meaningless."""
    with pytest.raises(TypeError, match="does not state an organization_id"):
        ResourceScope.of(object())

    with pytest.raises(TypeError, match="does not state an organization_id"):
        ResourceScope.of(SimpleNamespace(organization_id="not-a-uuid"))

    with pytest.raises(TypeError, match="owner_membership_id"):
        ResourceScope.of(
            SimpleNamespace(organization_id=uuid.uuid4(), owner_membership_id="not-a-uuid")
        )


def test_the_context_carries_the_decision_that_produced_it(
    integration_session: Session, identity_factory
) -> None:
    """A handler can answer "why was this allowed?" without re-deriving it."""
    identity = identity_factory(role_code="admin")
    context = resolve_organization_context(
        integration_session,
        _principal(identity),
        identity.organization_id,
        required=Permission.ROLE_READ,
    )

    assert isinstance(context, OrganizationContext)
    assert context.decision is not None
    assert context.decision.allowed
    assert context.decision.permission is Permission.ROLE_READ
    assert context.decision.membership_id == identity.membership_id
    assert context.membership_id == identity.membership_id
    assert Permission.ROLE_READ.value in context.permission_codes()


def test_authorize_instance_re_asserts_the_permission_and_the_tenant(
    integration_session: Session, identity_factory
) -> None:
    """The pure instance check: permission + row, with no further database access."""
    owner = identity_factory(role_code="owner")
    context = resolve_organization_context(
        integration_session,
        _principal(owner),
        owner.organization_id,
        required=Permission.ASSET_READ,
    )
    own_row = ResourceScope(organization_id=owner.organization_id)
    foreign_row = ResourceScope(organization_id=identity_factory(role_code="owner").organization_id)

    allowed = authorize_instance(context, own_row, permission=Permission.ASSET_READ)
    assert allowed.allowed
    assert allowed.reason is DecisionReason.ALLOWED

    outside = authorize_instance(context, foreign_row, permission=Permission.ASSET_READ)
    assert outside.denied
    assert outside.reason is DecisionReason.RESOURCE_OUTSIDE_TENANT

    viewer = identity_factory(role_code="viewer")
    viewer_context = resolve_organization_context(
        integration_session,
        _principal(viewer),
        viewer.organization_id,
        required=Permission.ASSET_READ,
    )
    undeclared = authorize_instance(
        viewer_context,
        ResourceScope(organization_id=viewer.organization_id),
        permission=Permission.ASSET_CREATE,
    )
    assert undeclared.denied
    assert undeclared.reason is DecisionReason.MISSING_PERMISSION


# ── The HTTP boundary: a loaded row is authorized, not just filtered ──────────


def test_require_instance_scope_maps_denials_to_the_published_status_codes(
    integration_session: Session, identity_factory
) -> None:
    """404 for another tenant's row, 403 for a permission the caller does not hold."""
    owner = identity_factory(role_code="owner")
    context = resolve_organization_context(
        integration_session,
        _principal(owner),
        owner.organization_id,
        required=Permission.ASSET_READ,
    )
    foreign = SimpleNamespace(organization_id=identity_factory(role_code="owner").organization_id)

    with pytest.raises(HTTPException) as outside:
        require_instance_scope(
            context, foreign, permission=Permission.ASSET_READ, detail="Asset not found"
        )
    assert outside.value.status_code == 404
    assert outside.value.detail == "Asset not found"

    viewer = identity_factory(role_code="viewer")
    viewer_context = resolve_organization_context(
        integration_session,
        _principal(viewer),
        viewer.organization_id,
        required=Permission.ASSET_READ,
    )
    with pytest.raises(HTTPException) as denied:
        require_instance_scope(
            viewer_context,
            SimpleNamespace(organization_id=viewer.organization_id),
            permission=Permission.ASSET_UPDATE,
            detail="Asset not found",
        )
    assert denied.value.status_code == 403


def test_an_asset_route_refuses_a_row_that_is_not_in_the_callers_organization(
    database_client: TestClient,
    owner_identity: Identity,
    identity_factory,
    authenticate,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The check is reachable, not decorative: a foreign row is a 404 on every verb.

    The repository is made to return a row from another tenant — the shape of a
    bug where a tenant filter is dropped. Without the instance check the route
    would serve it, because the row is loaded and the caller holds the permission.
    """
    client = authenticate(owner_identity)
    path = f"/organizations/{owner_identity.organization_id}/assets"
    created = client.post(path, json={"name": "Guarded Asset", "asset_type": "model"})
    assert created.status_code == 201, created.text
    asset_id = created.json()["id"]

    foreign = SimpleNamespace(
        id=uuid.UUID(asset_id),
        organization_id=identity_factory(role_code="owner").organization_id,
        owner_membership_id=None,
    )
    monkeypatch.setattr(AssetRepository, "find", lambda self, find_id: foreign)

    requests = (
        ("get", None),
        ("patch", {"risk_classification": "low"}),
        ("delete", None),
    )
    for method, body in requests:
        response = (
            getattr(client, method)(f"{path}/{asset_id}")
            if body is None
            else getattr(client, method)(f"{path}/{asset_id}", json=body)
        )
        assert response.status_code == 404, f"{method}: {response.text}"
        assert response.json()["error"]["code"] == "not_found"
        assert "Guarded Asset" not in response.text


def test_an_agent_route_refuses_a_row_that_is_not_in_the_callers_organization(
    database_client: TestClient,
    owner_identity: Identity,
    identity_factory,
    authenticate,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The registry's item and identity routes carry the same guard."""
    client = authenticate(owner_identity)
    path = f"/organizations/{owner_identity.organization_id}/agents"
    created = client.post(
        path, json={"display_name": "Guarded Agent", "category": "other", "version": "1.0.0"}
    )
    assert created.status_code == 201, created.text
    agent_id = created.json()["id"]
    identity_id = created.json()["identity_id"]

    foreign = SimpleNamespace(
        id=uuid.UUID(agent_id),
        organization_id=identity_factory(role_code="owner").organization_id,
        owner_membership_id=None,
    )
    monkeypatch.setattr(AgentRepository, "find", lambda self, find_id: foreign)
    monkeypatch.setattr(AgentRepository, "find_by_identity", lambda self, find_id: foreign)

    for url in (
        f"{path}/{agent_id}",
        f"{path}/identity/{identity_id}",
    ):
        response = client.get(url)
        assert response.status_code == 404, response.text
        assert response.json()["error"]["code"] == "not_found"

    for method, body in (("patch", {"version": "2.0.0"}), ("delete", None)):
        response = (
            getattr(client, method)(f"{path}/{agent_id}")
            if body is None
            else getattr(client, method)(f"{path}/{agent_id}", json=body)
        )
        assert response.status_code == 404, f"{method}: {response.text}"


# ── Structure: the rules that keep the rules true ─────────────────────────────


def _api_routes(app: Any) -> list[APIRoute]:
    """Every route the application serves, through FastAPI's own expansion."""
    return [
        context.original_route
        for context in iter_route_contexts(app.routes)
        if isinstance(context.original_route, APIRoute)
    ]


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


#: Which resource a path addresses, checked in order. `/permissions` maps to the
#: role resource on purpose: the catalogue is read through ``role.read``, because a
#: permission only means something as part of a role.
PATH_RESOURCES = (
    # Order matters here, and this entry has to come first: several resource prefixes are
    # *contained in* another route's path — ``/monitoring/agents`` ends with ``/agents``
    # and ``/monitoring/actions`` ends with ``/actions`` — and the first match wins. A
    # monitoring route is a read of the trail, so its resource is the audit one; if this
    # entry moved below the others, the sweep would demand ``agent.read`` of a view that
    # is guarded by ``audit.read``.
    ("/monitoring", Resource.AUDIT),
    ("/assets", Resource.ASSET),
    ("/agents", Resource.AGENT),
    ("/policies", Resource.POLICY),
    ("/actions", Resource.ACTION),
    ("/audit-events", Resource.AUDIT),
    ("/members", Resource.USER),
    ("/roles", Resource.ROLE),
    ("/permissions", Resource.ROLE),
)

#: A route's method and the action its permission must name.
METHOD_ACTIONS = {
    "GET": Action.READ,
    "POST": Action.CREATE,
    "PATCH": Action.UPDATE,
    "DELETE": Action.DELETE,
}

#: Routes where the method deliberately does *not* name the action, each with the
#: permission it must declare instead. ``POST`` normally means "create", and a route
#: here is the exception a reviewer should see rather than an accident the rule would
#: have caught: the dry run carries a request body, so it is a POST, and it reads
#: policies — it is the one POST in the application that cannot change anything. The
#: execution endpoint is a POST that *runs* a registered action, and the action it
#: names is ``execute`` rather than ``create``: nothing is created, and one permission
#: guards the whole catalogue.
METHOD_ACTION_EXCEPTIONS: dict[tuple[str, str], Permission] = {
    ("POST", "/organizations/{organization_id}/policies/evaluate"): Permission.POLICY_READ,
    ("POST", "/organizations/{organization_id}/actions/execute"): Permission.ACTION_EXECUTE,
}


def test_every_tenant_route_declares_one_permission_that_matches_its_resource_and_method(
    settings,
) -> None:
    """A route's requirement is checked against what the route *is*.

    Reading the identifier's two halves and comparing them with the path and the
    HTTP method is what catches the plausible mistake — an ``asset.read`` on a
    route that writes agents — which "the route declares *a* permission" would let
    through.
    """
    app = create_app(settings)
    tenant_routes = [route for route in _api_routes(app) if "{organization_id}" in route.path]

    assert tenant_routes, "the application serves no tenant-scoped routes"

    for route in tenant_routes:
        methods = route.methods - {"HEAD", "OPTIONS"}
        assert len(methods) == 1, route.path
        method = methods.pop()

        declared = _declared_permissions(route)
        assert len(declared) == 1, f"{method} {route.path} declares {declared}"
        permission = declared.pop()

        exception = METHOD_ACTION_EXCEPTIONS.get((method, route.path))
        expected_action = exception.action if exception is not None else METHOD_ACTIONS[method]
        assert permission.action is expected_action, f"{method} {route.path}: {permission}"
        if exception is not None:
            # An exception names the permission exactly, not merely its action.
            assert permission is exception, f"{method} {route.path}: {permission}"

        expected_resource = next(
            (resource for prefix, resource in PATH_RESOURCES if prefix in route.path),
            Resource.ORGANIZATION,
        )
        assert permission.resource is expected_resource, f"{method} {route.path}: {permission}"

    # Every declared exception has to be a route that exists, so the table cannot rot
    # into a licence for a route that was renamed or removed.
    declared_exceptions = {
        (method, route.path)
        for route in tenant_routes
        for method in route.methods - {"HEAD", "OPTIONS"}
        if (method, route.path) in METHOD_ACTION_EXCEPTIONS
    }
    assert declared_exceptions == set(METHOD_ACTION_EXCEPTIONS)


def test_the_decision_path_contains_no_model_call_and_no_network_client() -> None:
    """Authorization is deterministic: no LLM, no HTTP client, no clock, no dice.

    The rule the phase states, asserted where it can be enforced cheaply: the
    source of the decision path may not reach for an SDK, a transport, the clock
    or a random number generator. A decision that could differ between two
    identical calls would not be a decision.
    """
    forbidden = (
        "openai",
        "anthropic",
        "nemotron",
        "nebius",
        "httpx",
        "requests",
        "urllib",
        "aiohttp",
        "socket",
        "random",
        "datetime",
        "time.time",
    )
    repo_root = Path(__file__).resolve().parents[3]
    offenders: list[str] = []

    for relative in DECISION_PATH:
        source = (repo_root / relative).read_text(encoding="utf-8").lower()
        offenders += [f"{relative.name}: {token}" for token in forbidden if token.lower() in source]

    assert offenders == [], f"the decision path reaches outside its inputs: {offenders}"


#: The policy layer's decision path: the language, the engine, the combination with
#: the authorization decision, and the repository the engine's input is loaded from.
POLICY_DECISION_PATH = (
    Path("apps/api/src/aicore_api/core/policy.py"),
    Path("apps/api/src/aicore_api/core/policy_engine.py"),
    Path("apps/api/src/aicore_api/auth/policy.py"),
    Path("apps/api/src/aicore_api/db/repositories/policies.py"),
)

#: The engine and the condition language, which are pure functions of their inputs.
#: They are held to the stricter rule below: no database, no transport, no clock.
PURE_POLICY_MODULES = POLICY_DECISION_PATH[:3]

#: SDKs, transports and entropy. ``random`` and ``secrets`` are matched as *code*
#: (``random.``, ``import random``) rather than as words, so a docstring that says
#: "no random number generator" does not trip the scan — and a call to one does.
FORBIDDEN_IN_POLICY_PATH = (
    "openai",
    "anthropic",
    "nemotron",
    "nebius",
    "httpx",
    "requests",
    "aiohttp",
    "urllib",
    "socket",
    "import random",
    "from random",
    "random.",
    "secrets.",
    "eval(",
    "exec(",
    "compile(",
    "__import__",
    "subprocess",
    "pickle",
)

#: Reading a clock is not the same as naming a timestamp type: ``evaluated_at:
#: datetime`` is an argument the caller supplies, while ``datetime.now()`` would make
#: two identical evaluations able to differ. The call is what is refused.
CLOCK_READS = (
    "datetime.now(",
    "datetime.utcnow(",
    "datetime.today(",
    "datetime.fromtimestamp(",
    "time.time(",
    "date.today(",
)

#: The engine reads rows; the *language* and the *engine* may not. Asserted
#: structurally because "no table queries in condition handlers" is easy to state and
#: easy to erode.
DATABASE_TOKENS = ("sqlalchemy", "session", "select(", "text(", "execute(", "cursor", "connect")


def _policy_sources() -> dict[Path, str]:
    """The policy decision path, read once, keyed by path."""
    repo_root = Path(__file__).resolve().parents[3]
    return {
        relative: (repo_root / relative).read_text(encoding="utf-8").lower()
        for relative in POLICY_DECISION_PATH
    }


def test_the_policy_decision_path_is_deterministic_and_self_contained() -> None:
    """A policy decision is a function of its arguments — nothing else.

    The same rule Phase 5 holds its authorization layer to, applied to Phase 6: the
    code that decides what a policy says may not call a model, open a connection,
    read the clock or execute anything a policy supplied. Evaluation is also
    side-effect free by construction — the modules here can only return values,
    because they cannot reach anything that would let them do otherwise.
    """
    sources = _policy_sources()
    offenders = [
        f"{path.name}: {token}"
        for path, source in sources.items()
        for token in (*FORBIDDEN_IN_POLICY_PATH, *CLOCK_READS)
        if token in source
    ]
    assert offenders == [], f"the policy decision path reaches outside its inputs: {offenders}"

    for relative in PURE_POLICY_MODULES:
        source = sources[relative]
        assert not [token for token in DATABASE_TOKENS if token in source], (
            f"{relative.name} must not touch the database"
        )


def test_no_route_or_handler_decides_on_its_own(database_client: TestClient) -> None:
    """The running application still refuses an anonymous caller on every route.

    A structural complement to the decision tests: whatever the decision layer says,
    nothing is reachable without going through it. The refusal happens before any
    handler body runs, which is why the app can be asked without a database.
    """
    for route in _api_routes(create_app(database_client.app.state.settings)):
        if "{organization_id}" not in route.path:
            continue
        for method in route.methods - {"HEAD", "OPTIONS"}:
            response = database_client.request(
                method, route.path.replace("{organization_id}", str(uuid.uuid4()))
            )
            assert response.status_code == 401, f"{method} {route.path}"
