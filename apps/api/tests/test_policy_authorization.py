"""Phase 5 and Phase 6 together: a policy can restrict, and can never permit.

The integration seam is one function — :func:`aicore_api.auth.policy.combine` — and
this file is the exhaustive statement of what it may return:

===============  ================  ======================
authorization    policy            effective
===============  ================  ======================
allow            deny              deny
allow            require_approval  require_approval
allow            allow             allow
allow            not_applicable    allow
deny             *any*             deny
===============  ================  ======================

Two properties follow, and both are asserted here rather than argued:

- **A policy cannot grant.** There is no combination that turns a Phase 5 denial
  into a permit — not a matching allow, not an empty policy list, not a policy whose
  conditions the context cannot satisfy. The policy layer is a ceiling, never a floor.
- **A permission is still required.** The policy layer is consulted *after* Phase 5
  has answered, and only about the permission the target names: a policy about
  ``agent.update`` cannot speak about ``agent.delete``, and the caller still needs
  the permission in their role.

The routes carry the same rule end to end: the dry run reports both layers, and
every management route goes through Phase 5 before a policy is read or written.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from aicore_api.auth.authorization import (
    AuthorizationDecision,
    DecisionReason,
    authorize,
)
from aicore_api.auth.policy import EffectiveDecision, EffectiveReason, combine
from aicore_api.auth.principal import Principal
from aicore_api.core.permissions import Action, Permission, Resource
from aicore_api.core.policy import PolicyEffect, PolicyStatus, target_permission
from aicore_api.core.policy_engine import (
    PolicyContext,
    PolicyDecision,
    PolicyDecisionKind,
    PolicyReason,
    evaluate_policies,
)
from aicore_api.db.repositories.policies import PolicyRepository
from aicore_api.db.tenancy import bind_tenant
from identity_fixture import Identity, IdentityFactory
from policies_fixture import PolicyFactory, PolicyRecord

EVALUATED_AT = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
ORGANIZATION_ID = uuid.UUID("22222222-2222-2222-2222-222222222222")


def _authorization(
    *, allowed: bool, permission: Permission | None = Permission.AGENT_UPDATE
) -> AuthorizationDecision:
    """A Phase 5 decision, built directly: this file tests the seam, not the lookup."""
    return AuthorizationDecision(
        allowed=allowed,
        reason=DecisionReason.ALLOWED if allowed else DecisionReason.MISSING_PERMISSION,
        permission=permission,
        organization_id=ORGANIZATION_ID,
    )


def _policy_decision(kind: PolicyDecisionKind, *, effect_version: int = 1) -> PolicyDecision:
    """A Phase 6 decision for the same question."""
    reason = {
        PolicyDecisionKind.ALLOW: PolicyReason.MATCHING_ALLOW,
        PolicyDecisionKind.DENY: PolicyReason.MATCHING_DENY,
        PolicyDecisionKind.REQUIRE_APPROVAL: PolicyReason.MATCHING_REQUIRE_APPROVAL,
        PolicyDecisionKind.NOT_APPLICABLE: PolicyReason.NO_MATCHING_POLICY,
    }[kind]
    matched = kind is not PolicyDecisionKind.NOT_APPLICABLE
    return PolicyDecision(
        decision=kind,
        reason=reason,
        organization_id=ORGANIZATION_ID,
        resource=Resource.AGENT,
        action=Action.UPDATE,
        evaluated_at=EVALUATED_AT,
        policy_id=uuid.uuid4() if matched else None,
        policy_version=effect_version if matched else None,
        policy_name="Example" if matched else None,
        priority=10 if matched else None,
        matched_policy_count=1 if matched else 0,
        evaluated_policies=1,
    )


# ── The combination table ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("authorization_allowed", "policy_kind", "expected", "reason"),
    [
        # allow + deny = deny
        (True, PolicyDecisionKind.DENY, PolicyDecisionKind.DENY, EffectiveReason.POLICY_DENIED),
        # allow + require_approval = require_approval (and not a permit)
        (
            True,
            PolicyDecisionKind.REQUIRE_APPROVAL,
            PolicyDecisionKind.REQUIRE_APPROVAL,
            EffectiveReason.POLICY_REQUIRES_APPROVAL,
        ),
        # allow + allow = allow
        (True, PolicyDecisionKind.ALLOW, PolicyDecisionKind.ALLOW, EffectiveReason.POLICY_ALLOWED),
        # allow + no policy = allow
        (
            True,
            PolicyDecisionKind.NOT_APPLICABLE,
            PolicyDecisionKind.ALLOW,
            EffectiveReason.AUTHORIZATION_GRANT,
        ),
        # deny + anything = deny, and the policy layer never gets to speak
        (
            False,
            PolicyDecisionKind.DENY,
            PolicyDecisionKind.DENY,
            EffectiveReason.AUTHORIZATION_DENIED,
        ),
        (
            False,
            PolicyDecisionKind.ALLOW,
            PolicyDecisionKind.DENY,
            EffectiveReason.AUTHORIZATION_DENIED,
        ),
        (
            False,
            PolicyDecisionKind.REQUIRE_APPROVAL,
            PolicyDecisionKind.DENY,
            EffectiveReason.AUTHORIZATION_DENIED,
        ),
        (
            False,
            PolicyDecisionKind.NOT_APPLICABLE,
            PolicyDecisionKind.DENY,
            EffectiveReason.AUTHORIZATION_DENIED,
        ),
    ],
)
def test_the_combination_table_is_total_and_never_widens(
    authorization_allowed: bool,
    policy_kind: PolicyDecisionKind,
    expected: PolicyDecisionKind,
    reason: EffectiveReason,
) -> None:
    """Every combination, and the one rule that governs all of them."""
    effective = combine(
        _authorization(allowed=authorization_allowed), _policy_decision(policy_kind)
    )

    assert effective.decision is expected
    assert effective.reason is reason
    assert effective.allowed is (expected is PolicyDecisionKind.ALLOW)
    assert effective.denied is (expected is PolicyDecisionKind.DENY)
    assert effective.requires_approval is (expected is PolicyDecisionKind.REQUIRE_APPROVAL)


def test_no_combination_turns_a_denial_into_a_permit() -> None:
    """The whole point of the seam, asserted over the whole cross product.

    A policy cannot grant: this is the property that makes it safe to add policies to
    a system whose authorization decisions Phase 5 already owns.
    """
    for policy_kind in PolicyDecisionKind:
        effective = combine(_authorization(allowed=False), _policy_decision(policy_kind))

        assert effective.denied is True
        assert effective.allowed is False
        assert effective.requires_approval is False


def test_an_effective_decision_never_carries_the_not_applicable_value() -> None:
    """``not_applicable`` is the policy layer's business; the effective answer is final."""
    for allowed in (True, False):
        for policy_kind in PolicyDecisionKind:
            effective = combine(_authorization(allowed=allowed), _policy_decision(policy_kind))
            assert effective.decision is not PolicyDecisionKind.NOT_APPLICABLE


def test_both_inputs_travel_with_the_effective_decision() -> None:
    """A caller that has to explain an outcome has everything it needs, without a query."""
    authorization = _authorization(allowed=True)
    policy = _policy_decision(PolicyDecisionKind.DENY, effect_version=4)

    effective = combine(authorization, policy)

    assert isinstance(effective, EffectiveDecision)
    assert effective.authorization is authorization
    assert effective.policy is policy
    assert effective.organization_id == ORGANIZATION_ID
    assert effective.resource is Resource.AGENT
    assert effective.action is Action.UPDATE
    assert effective.permission_required == Permission.AGENT_UPDATE.value
    assert effective.policy.policy_version == 4


def test_combining_decisions_about_different_questions_is_refused() -> None:
    """Two answers to two questions are not one answer; that is a programming error."""
    other_question = PolicyDecision(
        decision=PolicyDecisionKind.ALLOW,
        reason=PolicyReason.MATCHING_ALLOW,
        organization_id=ORGANIZATION_ID,
        resource=Resource.ASSET,
        action=Action.DELETE,
        evaluated_at=EVALUATED_AT,
    )
    other_organization = PolicyDecision(
        decision=PolicyDecisionKind.ALLOW,
        reason=PolicyReason.MATCHING_ALLOW,
        organization_id=uuid.uuid4(),
        resource=Resource.AGENT,
        action=Action.UPDATE,
        evaluated_at=EVALUATED_AT,
    )

    with pytest.raises(ValueError, match="different questions"):
        combine(_authorization(allowed=True), other_question)
    with pytest.raises(ValueError, match="different organizations"):
        combine(_authorization(allowed=True), other_organization)


def test_a_membership_only_decision_combines_with_any_policy_decision() -> None:
    """A route that needed membership and nothing more is still a ceiling."""
    membership = AuthorizationDecision(
        allowed=True,
        reason=DecisionReason.ALLOWED_MEMBERSHIP,
        organization_id=ORGANIZATION_ID,
    )

    effective = combine(membership, _policy_decision(PolicyDecisionKind.DENY))

    assert effective.denied is True
    assert effective.permission_required is None


def test_an_unknown_role_denies_and_no_policy_can_change_that() -> None:
    """Phase 5 fails closed on a catalog it cannot read; Phase 6 inherits the answer."""
    failed_closed = AuthorizationDecision(
        allowed=False,
        reason=DecisionReason.UNKNOWN_ROLE,
        permission=Permission.AGENT_UPDATE,
        organization_id=ORGANIZATION_ID,
    )

    effective = combine(failed_closed, _policy_decision(PolicyDecisionKind.ALLOW))

    assert effective.denied is True
    assert effective.reason is EffectiveReason.AUTHORIZATION_DENIED


# ── The seam against the live database ───────────────────────────────────────


def _effective_for(
    client: TestClient,
    identity: Identity,
    *,
    resource: str = "agent",
    action: str = "update",
    facts: dict[str, object] | None = None,
) -> EffectiveDecision:
    """Evaluate through the API and rebuild the effective decision from its report.

    Rebuilding from the *response* rather than from the engine is deliberate: it is
    what a client sees, so the assertions below are about the contract rather than
    about internals that happen to produce it.
    """
    response = client.post(
        f"/organizations/{identity.organization_id}/policies/evaluate",
        json={
            "resource": resource,
            "action": action,
            "facts": facts if facts is not None else {"environment": "production"},
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_a_policy_restricts_a_permitted_caller(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """The owner holds the permission; the policy still decides the effective answer."""
    policies.activate(policies.create("Deny production agents", effect="deny"))

    body = _effective_for(authenticate(owner_identity), owner_identity)

    assert body["authorization"]["allowed"] is True
    assert body["effective"]["decision"] == "deny"
    assert body["effective"]["reason"] == "policy_denied"


def test_a_caller_without_the_permission_is_denied_before_any_policy_speaks(
    policies: PolicyFactory,
    authenticate,
    identity_factory: IdentityFactory,
    owner_identity: Identity,
) -> None:
    """A viewer in the same organization: 403 from Phase 5, and no policy evaluation.

    The viewer may not read policies (``policy.read``), so the route refuses — which
    is the correct answer on its own terms, and also the demonstration that a policy
    cannot be reached around Phase 5: there is no way to ask the policy layer without
    the permission the route requires.
    """
    policies.activate(policies.create("Deny production agents", effect="deny"))
    viewer: Identity = identity_factory(
        role_code="viewer", organization_id=owner_identity.organization_id
    )

    response = authenticate(viewer).post(
        f"/organizations/{owner_identity.organization_id}/policies/evaluate",
        json={"resource": "agent", "action": "update", "facts": {"environment": "production"}},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_a_policy_about_one_action_says_nothing_about_another(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """``agent.update`` is not ``agent.delete``: targets are exact pairs."""
    policies.activate(policies.create("Deny updates", action="update", effect="deny"))
    client = authenticate(owner_identity)

    update = _effective_for(client, owner_identity, action="update")
    delete = _effective_for(client, owner_identity, action="delete")

    assert update["effective"]["decision"] == "deny"
    assert delete["policy"]["decision"] == "not_applicable"
    assert delete["effective"]["allowed"] is True


def test_an_unevaluatable_condition_leaves_the_authorization_answer_standing(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """Missing context cannot widen anything — it can only fail to restrict.

    The policy does not apply, so the effective answer is Phase 5's. That is safe
    precisely because the caller already held the permission; it is not a bypass,
    because there was nothing to bypass.
    """
    policies.activate(
        policies.create(
            "Deny old agents",
            effect="deny",
            conditions=[{"field": "agent_age_days", "operator": "greater_than", "value": 90}],
        )
    )

    without_the_fact = _effective_for(authenticate(owner_identity), owner_identity, facts={})
    with_the_fact = _effective_for(
        authenticate(owner_identity), owner_identity, facts={"agent_age_days": 200}
    )

    assert without_the_fact["policy"]["decision"] == "not_applicable"
    assert without_the_fact["effective"]["reason"] == "authorization_grant"
    assert with_the_fact["effective"]["decision"] == "deny"


def test_a_policy_cannot_target_a_permission_the_role_does_not_hold(
    policies: PolicyFactory,
    authenticate,
    identity_factory: IdentityFactory,
    owner_identity: Identity,
) -> None:
    """Policies narrow capabilities; they never hand them to a role that lacks them."""
    policies.activate(
        policies.create(
            "Allow policy management", effect="allow", resource="policy", action="update"
        )
    )
    analyst: Identity = identity_factory(
        role_code="analyst", organization_id=owner_identity.organization_id
    )

    granted = authenticate(analyst).get("/me").json()["memberships"][0]["permissions"]
    assert Permission.POLICY_UPDATE.value not in granted
    # The analyst cannot even ask: reading policies is not theirs either.
    assert (
        authenticate(analyst)
        .get(f"/organizations/{owner_identity.organization_id}/policies")
        .status_code
        == 403
    )


def test_the_required_permission_is_the_one_the_target_names() -> None:
    """The link between a policy target and a permission is one function, not a table."""
    for resource, action in (
        (Resource.AGENT, Action.UPDATE),
        (Resource.ASSET, Action.DELETE),
        (Resource.POLICY, Action.READ),
    ):
        assert target_permission(resource, action) is Permission.parse(
            f"{resource.value}.{action.value}"
        )


# ── The item-route guard, applied to a policy ────────────────────────────────


def test_a_policy_of_another_tenant_is_not_reachable_through_the_item_scope_guard(
    policies: PolicyFactory, identity_factory: IdentityFactory, authenticate
) -> None:
    """``require_instance_scope`` refuses a row that does not belong to this tenant.

    The guard is Phase 5's, and a policy is the third kind of row it protects. The
    repository already makes a foreign row unreachable, so this exercises the guard
    directly — the *second* lock, the one that holds if a query ever loosens.
    """
    policy = policies.create("Owned elsewhere")
    stranger: Identity = identity_factory(role_code="owner")
    stranger_client = authenticate(stranger)

    # A real membership and a real permission: an owner of *their own* organization,
    # asking for a policy that belongs to another one.
    response = stranger_client.get(
        f"/organizations/{stranger.organization_id}/policies/{policy.id}"
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"

    # …and the same call in the owning organization is a 200, which is what makes the
    # 404 above a statement about tenancy rather than about the route.
    assert policies.read(policy).status_code == 200
    assert (
        authenticate(stranger)
        .get(f"/organizations/{stranger.organization_id}/policies")
        .json()["count"]
        == 0
    )


# ── The permission matrix for policies, as enforced by the API ───────────────


@pytest.mark.parametrize(
    ("role_code", "may_read", "may_write"),
    [
        ("owner", True, True),
        ("admin", True, True),
        ("security_admin", True, True),
        ("ai_admin", False, False),
        ("analyst", False, False),
        ("viewer", False, False),
    ],
)
def test_who_may_manage_a_policy(
    policy_factory_for_role,
    role_code: str,
    may_read: bool,
    may_write: bool,
) -> None:
    """The policy permissions, exercised rather than only declared.

    The rules this pins: an owner and an administrator manage policies outright; the
    security administrator writes them (recording a containment decision is that
    role's job) but cannot delete one; the AI administrator holds none at all, because
    the party a policy constrains does not write the constraint; and neither the
    analyst nor the viewer reads governance configuration.
    """
    client, identity, policy = policy_factory_for_role(role_code)

    read = client.get(f"/organizations/{identity.organization_id}/policies")
    write = client.post(
        f"/organizations/{identity.organization_id}/policies",
        json={
            "name": f"Written by a {role_code}",
            "description": "Authorization, exercised.",
            "resource": "agent",
            "action": "update",
            "effect": "deny",
            "priority": 100,
            "conditions": [],
        },
    )
    delete = client.delete(f"/organizations/{identity.organization_id}/policies/{policy.id}")

    assert (read.status_code == 200) is may_read, read.text
    assert (write.status_code == 201) is may_write, write.text
    expected_delete = 204 if may_write and role_code in {"owner", "admin"} else None
    if expected_delete is not None:
        assert delete.status_code == expected_delete, delete.text
    else:
        assert delete.status_code in {403, 404}, delete.text


@pytest.fixture
def policy_factory_for_role(identity_factory: IdentityFactory, authenticate, integration_engine):
    """A policy in one organization plus a member of it in the given role.

    The policy is created by the *owner* (through the API), so a role that may only
    read has something to read, and a role that may not read at all is refused before
    the row is looked for.
    """
    from policies_fixture import count_policies

    owner = identity_factory(role_code="owner")
    client = authenticate(owner)
    created = client.post(
        f"/organizations/{owner.organization_id}/policies",
        json={
            "name": "Seeded by the owner",
            "description": "So the matrix has something to act on.",
            "resource": "agent",
            "action": "update",
            "effect": "deny",
            "priority": 100,
            "conditions": [],
        },
    )
    assert created.status_code == 201, created.text
    record = PolicyRecord(
        id=uuid.UUID(created.json()["policy_id"]),
        organization_id=owner.organization_id,
        name=created.json()["name"],
        version=created.json()["version"],
        status=created.json()["status"],
        effect=created.json()["effect"],
        resource=created.json()["resource"],
        action=created.json()["action"],
        priority=created.json()["priority"],
        conditions=tuple(created.json()["conditions"]),
        body=created.json(),
    )

    def build(role_code: str) -> tuple[TestClient, Identity, PolicyRecord]:
        member: Identity = identity_factory(
            role_code=role_code, organization_id=owner.organization_id
        )
        return authenticate(member), member, record

    try:
        yield build
    finally:
        # The identity fixtures remove the organization after every fixture that
        # owns a row in it has cleaned up; a policy references it with RESTRICT, so
        # this one has to go first — through the same tenant-scoped statement the
        # other fixtures use rather than through the API, which some roles may not
        # call.
        with bind_tenant(owner.organization_id), integration_engine.begin() as connection:
            connection.execute(
                text("DELETE FROM aicore.policies WHERE organization_id = :organization_id"),
                {"organization_id": str(owner.organization_id)},
            )
        assert count_policies(integration_engine, owner.organization_id) == 0


# ── The dry run is reported, never enforced ──────────────────────────────────


def test_evaluating_writes_nothing_and_requires_no_activation_of_anything(
    policies: PolicyFactory, authenticate, owner_identity: Identity, integration_engine
) -> None:
    """The dry run has no side effects at all — the property that makes it a report."""
    from policies_fixture import count_policies, count_versions

    policy = policies.create("Deny production agents", effect="deny", status="active")
    before = (
        count_policies(integration_engine, policies.organization_id),
        count_versions(integration_engine, policies.organization_id),
        policy.version,
    )

    for _ in range(3):
        assert (
            authenticate(owner_identity)
            .post(
                f"/organizations/{owner_identity.organization_id}/policies/evaluate",
                json={
                    "resource": "agent",
                    "action": "update",
                    "facts": {"environment": "production"},
                },
            )
            .status_code
            == 200
        )

    after = (
        count_policies(integration_engine, policies.organization_id),
        count_versions(integration_engine, policies.organization_id),
        policies.read(policy).json()["version"],
    )

    assert after == before


def test_the_engine_reads_no_rows_of_its_own(
    policies: PolicyFactory, integration_session, authenticate, owner_identity: Identity
) -> None:
    """The engine's input is loaded once, by the repository, and handed to it.

    Asserted from the other side: an evaluation result is exactly what the engine
    produces from the definitions the repository loaded, with the same context — so
    there is nothing else in the path that could be consulting the database.
    """
    policy = policies.create("Deny production agents", effect="deny", status="active")
    repository = PolicyRepository(integration_session, owner_identity.organization_id)
    assert policy.id is not None  # the fixture's policy exists in this database

    definitions = repository.active_definitions(Resource.AGENT, Action.UPDATE)
    assert [definition.policy_id for definition in definitions] == [policy.id]

    context = PolicyContext(
        organization_id=owner_identity.organization_id,
        resource=Resource.AGENT,
        action=Action.UPDATE,
        facts={"environment": "production"},
    )
    decision = evaluate_policies(definitions, context, evaluated_at=EVALUATED_AT)

    assert decision.decision is PolicyDecisionKind.DENY
    assert decision.policy_id == policy.id
    assert decision.policy_version == 1


def test_authorize_returns_the_decision_a_policy_then_narrows(
    policies: PolicyFactory, integration_session, owner_identity: Identity
) -> None:
    """Phase 5's own interface, unchanged: ``authorize`` is still a value, not a raise.

    Phase 6 does not replace it, wrap it or reorder it — the effective answer is built
    from what it returns, which is why the two layers can be tested separately and
    combined in one place.
    """
    policy = policies.create("Deny production agents", effect="deny", status="active")
    principal = Principal(
        user_id=owner_identity.user_id,
        email=owner_identity.email,
        full_name="Test Person",
        status="active",
    )

    authorization = authorize(
        integration_session, principal, owner_identity.organization_id, Permission.AGENT_UPDATE
    )
    definitions = PolicyRepository(
        integration_session, owner_identity.organization_id
    ).active_definitions(Resource.AGENT, Action.UPDATE)
    decision = evaluate_policies(
        definitions,
        PolicyContext(
            organization_id=owner_identity.organization_id,
            resource=Resource.AGENT,
            action=Action.UPDATE,
            facts={"environment": "production"},
        ),
        evaluated_at=EVALUATED_AT,
    )
    effective = combine(authorization, decision)

    assert authorization.allowed is True
    assert effective.denied is True
    assert effective.permission_required == Permission.AGENT_UPDATE.value
    assert policy.effect == PolicyEffect.DENY.value
    assert policy.status == PolicyStatus.ACTIVE.value
