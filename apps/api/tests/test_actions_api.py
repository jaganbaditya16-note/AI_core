"""Phase 7 over HTTP: the execution endpoint, and the enforcement it performs.

The firewall is only worth having if the route that uses it refuses in every case it
should, so these tests are written as the *enforcement proof* the phase asks for: each
of CASE A-G, every error the API publishes, and the security properties that make the
endpoint safe, asserted through the real application against the real database.

**How "the adapter ran" is proven.** The route's adapter registry is a dependency, so
these tests substitute a recording wrapper around the real reference adapter — the
same seam the application uses for wiring, not a patched module attribute. Then:

- CASE A asserts the wrapper was called **exactly once**, the response reports that
  execution, and exactly one ledger row exists;
- CASE B-G assert the wrapper was called **zero times** and that the ledger is empty,
  which is what "nothing was executed" means in a build that records every execution.

The wrapper delegates to the real adapter, so the outcome a test asserts is the
outcome production would report; nothing here fakes an authorization or a policy
decision — those come from Phase 5's service, Phase 6's engine, and the firewall.

Three groups follow the phase: the execution contract (CASE A), the refusals (CASE
B-G written as separate tests, one per way of saying no), and the security properties
(tenant isolation, IDOR, injection-shaped input, the closed request body, secret
hygiene, and the structural claim that this route is the only thing in the build that
can reach an adapter).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.testclient import TestClient

from actions_fixture import ACTION_ID, ActionFactory, execution_payload
from agents_fixture import AgentFactory, agents_path
from aicore_api.api.deps import get_action_executors
from aicore_api.core.actions import default_action_registry
from aicore_api.core.executors import (
    FINDING_NEW_REGISTRATION,
    FINDING_UNCLASSIFIED_RISK,
    ActionExecutor,
    ActionExecutorRegistry,
    ActionInvocation,
    ActionOutcome,
    AgentRegistryExecutor,
)
from aicore_api.core.permissions import Permission
from aicore_api.db.models.action_execution import ActionExecution
from aicore_api.db.models.membership import MembershipStatus
from aicore_api.main import create_app
from identity_fixture import Identity, IdentityFactory
from policies_fixture import PolicyFactory

#: The findings a freshly registered, unassessed agent in production produces, in the
#: order the reference adapter reports them. Written out rather than imported from the
#: constant list: a test that asked the adapter what it would say would agree with it.
FRESH_AGENT_FINDINGS = [FINDING_UNCLASSIFIED_RISK, FINDING_NEW_REGISTRATION]

#: Fields a client must not be able to state: the server assembles each of them from
#: the credential, the path or its own process state. ``extra="forbid"`` is what makes
#: that a 422 rather than a silently ignored key.
SERVER_OWNED_FIELDS: tuple[tuple[str, Any], ...] = (
    ("organization_id", "00000000-0000-4000-8000-000000000000"),
    ("principal_id", "00000000-0000-4000-8000-000000000000"),
    ("membership_id", "00000000-0000-4000-8000-000000000000"),
    ("correlation_id", "attacker-chosen"),
    ("role_code", "owner"),
    ("permission", "action.execute"),
    ("executor", "agent_registry"),
    ("module", "aicore_api.core.execution"),
    ("function", "execute"),
    ("command", "sh -c 'id'"),
    ("url", "http://169.254.169.254/latest/meta-data/"),
)


def _code(response: Any) -> str:
    """The error code the envelope carries, for the tests about refusals."""
    return str(response.json()["error"]["code"])


class RecordingAdapter(ActionExecutor):
    """The reference adapter, wrapped so a test can count the calls it receives.

    A subclass rather than a mock: it declares the same identifier the catalogue names
    and delegates to the real adapter, so the outcome asserted below is the outcome the
    build reports. Only the *count* is new.
    """

    executor_id = AgentRegistryExecutor.executor_id

    def __init__(self) -> None:
        self.calls: list[ActionInvocation] = []
        self._inner = AgentRegistryExecutor()

    def execute(self, invocation: ActionInvocation) -> ActionOutcome:
        self.calls.append(invocation)
        return self._inner.execute(invocation)


@pytest.fixture
def adapter(database_client: TestClient) -> Any:
    """Substitute a recording adapter registry for the duration of one test.

    Injected the way the application injects its own: through the dependency the route
    declares. Everything else — the catalogue, the firewall, the execution service, the
    ledger — is the production code path.
    """
    recording = RecordingAdapter()
    database_client.app.dependency_overrides[get_action_executors] = lambda: ActionExecutorRegistry(
        (recording,)
    )
    try:
        yield recording
    finally:
        database_client.app.dependency_overrides.pop(get_action_executors, None)


def _registered_agent(
    agents: AgentFactory,
    *,
    environment: str = "production",
    status: str = "active",
    **fields: Any,
) -> uuid.UUID:
    """Register one agent through the API and return its identifier.

    Registering rather than inserting: the target's facts are read from the row, so the
    setup has to be a row the API actually produces.
    """
    payload: dict[str, Any] = {
        "display_name": "Posture Target",
        "category": "assistant",
        "version": "1.0.0",
        "status": status,
        "environment": environment,
    }
    payload.update(fields)
    record = agents.register(**payload)
    assert record is not None
    return record.id


def _execution_policy(policies: PolicyFactory, **overrides: Any) -> Any:
    """Create and activate a policy that decides ``action.execute``.

    Activated, because a draft policy decides nothing — and this is the only way these
    tests reach the policy layer's deny and require-approval paths through HTTP.
    """
    fields: dict[str, Any] = {
        "name": f"Execution guard {uuid.uuid4().hex[:8]}",
        "resource": "action",
        "action": "execute",
        "effect": "deny",
        "conditions": [],
        "priority": 10,
    }
    fields.update(overrides)
    return policies.activate(policies.create(**fields))


# ── CASE A: an allowed action executes, exactly once ─────────────────────────


def test_case_a_an_allowed_action_executes_the_adapter_exactly_once(
    actions: ActionFactory, agents: AgentFactory, adapter: RecordingAdapter
) -> None:
    """The whole success path: decision → adapter → ledger → response."""
    target_id = _registered_agent(agents)
    key = f"case-a-{uuid.uuid4().hex}"

    response = actions.execute(target_id, idempotency_key=key)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["executed"] is True
    assert body["replayed"] is False
    assert body["action_id"] == ACTION_ID
    assert body["action_sensitivity"] == "routine"
    assert body["target"] == {"resource": "agent", "id": str(target_id)}
    assert body["permission_required"] == Permission.ACTION_EXECUTE.value
    assert body["environment"] == "production"
    assert uuid.UUID(body["execution_id"]).version == 4

    # The adapter ran once, and what it saw was the resolved invocation rather than
    # the HTTP request: identifiers, the attested target and the validated arguments.
    assert len(adapter.calls) == 1
    invocation = adapter.calls[0]
    assert invocation.organization_id == actions.organization_id
    assert invocation.target.identifier == target_id
    assert invocation.action_id == ACTION_ID
    assert invocation.argument_names == ()
    assert invocation.correlation_id == body["correlation_id"]

    # The ledger records that one execution, and it is the row the response names.
    assert actions.count_executions() == 1
    row = actions.find_execution(key)
    assert row is not None
    assert row["idempotency_key"] == key
    assert row["action_id"] == ACTION_ID
    assert str(row["target_id"]) == str(target_id)
    assert row["status"] == "executed"
    assert row["error_code"] is None
    assert row["completed_at"] is not None
    assert len(str(row["request_fingerprint"])) == 64
    assert row["outcome"]["adapter"] == "agent_registry"
    assert row["outcome"]["digest"] == body["result"]["digest"]
    assert row["outcome"]["summary"] == body["result"]["summary"]


def test_case_a_the_response_reports_what_the_adapter_and_the_layers_decided(
    actions: ActionFactory, agents: AgentFactory, adapter: RecordingAdapter
) -> None:
    """The report: the adapter's outcome, and both upstream answers that permitted it."""
    target_id = _registered_agent(agents, display_name="Support Triage")

    body = actions.executed(target_id)

    result = body["result"]
    assert result["adapter"] == "agent_registry"
    assert result["summary"] == (
        f"{ACTION_ID} assessed the recorded posture of the target as elevated (2 finding(s))"
    )
    assert result["findings"] == FRESH_AGENT_FINDINGS
    assert result["details"] == {"assessment": "elevated"}
    assert len(result["digest"]) == 64

    assert body["firewall"] == {"outcome": "allow", "reason": "allowed"}
    assert body["authorization"]["allowed"] is True
    assert body["authorization"]["permission"] == Permission.ACTION_EXECUTE.value
    assert body["policy"]["decision"] == "not_applicable"
    assert body["policy"]["applicable"] is False
    assert body["effective"]["decision"] == "allow"
    assert body["effective"]["allowed"] is True
    assert body["effective"]["denied"] is False
    assert body["principal_role"] == "owner"
    assert body["agent_id"] is None


def test_case_a_a_replayed_request_returns_the_recorded_answer_without_running_again(
    actions: ActionFactory, agents: AgentFactory, adapter: RecordingAdapter
) -> None:
    """A retry after a lost answer: the same answer, one execution, one ledger row."""
    target_id = _registered_agent(agents)
    key = f"case-a-replay-{uuid.uuid4().hex}"

    first = actions.executed(target_id, idempotency_key=key)
    second = actions.executed(target_id, idempotency_key=key)

    assert len(adapter.calls) == 1
    assert actions.count_executions() == 1
    assert first["replayed"] is False
    assert second["replayed"] is True
    assert second["execution_id"] == first["execution_id"]
    assert second["result"] == first["result"]
    assert second["result"]["digest"] == first["result"]["digest"]


def test_a_target_the_organization_does_not_have_is_a_404_that_executes_nothing(
    actions: ActionFactory, adapter: RecordingAdapter
) -> None:
    """A row that does not exist is refused before anything is evaluated or run."""
    response = actions.execute(uuid.uuid4())

    assert response.status_code == 404
    assert _code(response) == "not_found"
    assert adapter.calls == []
    assert actions.count_executions() == 0


# ── CASE B: a Phase 5 denial never reaches an adapter ────────────────────────


@pytest.mark.parametrize("role_code", ["viewer", "analyst", "ai_admin"])
def test_case_b_a_member_without_the_execution_permission_is_refused(
    actions: ActionFactory,
    agents: AgentFactory,
    adapter: RecordingAdapter,
    identity_factory: IdentityFactory,
    owner_identity: Identity,
    authenticate: Any,
    role_code: str,
) -> None:
    """Roles that read the registry still cannot run anything through it.

    ``ai_admin`` is the interesting one: it may register and maintain agents, and it
    holds no ``action.execute`` — the party whose work a policy constrains does not get
    to run the actions it governs.
    """
    target_id = _registered_agent(agents)
    member = identity_factory(role_code=role_code, organization_id=owner_identity.organization_id)
    key = f"case-b-{uuid.uuid4().hex}"

    response = authenticate(member).post(
        actions.path, json=execution_payload(target_id, idempotency_key=key)
    )

    assert response.status_code == 403, response.text
    assert _code(response) == "forbidden"
    assert adapter.calls == []
    assert actions.count_executions() == 0
    assert actions.find_execution(key) is None


def test_case_b_a_suspended_membership_is_refused(
    actions: ActionFactory,
    agents: AgentFactory,
    adapter: RecordingAdapter,
    identity_factory: IdentityFactory,
    owner_identity: Identity,
    authenticate: Any,
) -> None:
    """The credential is valid and the membership is not: still nothing executes."""
    target_id = _registered_agent(agents)
    actor = identity_factory(
        role_code="owner",
        organization_id=owner_identity.organization_id,
        membership_status=MembershipStatus.SUSPENDED,
    )

    response = authenticate(actor).post(actions.path, json=execution_payload(target_id))

    assert response.status_code == 403
    assert adapter.calls == []
    assert actions.count_executions() == 0


def test_case_b_an_unauthenticated_request_is_refused(
    actions: ActionFactory,
    agents: AgentFactory,
    adapter: RecordingAdapter,
    database_client: TestClient,
) -> None:
    """No credential, no execution — and no execution request is even interpreted."""
    target_id = _registered_agent(agents)
    database_client.headers.pop("Authorization", None)

    response = database_client.post(actions.path, json=execution_payload(target_id))

    assert response.status_code == 401
    assert _code(response) == "unauthorized"
    assert adapter.calls == []
    assert actions.count_executions() == 0


# ── CASE C: a policy denial never reaches an adapter ─────────────────────────


def test_case_c_an_active_policy_that_denies_the_action_stops_it_before_the_adapter(
    actions: ActionFactory, agents: AgentFactory, policies: PolicyFactory, adapter: RecordingAdapter
) -> None:
    """Phase 6's deny, enforced: the request is refused and nothing was run."""
    target_id = _registered_agent(agents)
    _execution_policy(policies)

    response = actions.execute(target_id)

    assert response.status_code == 403, response.text
    assert _code(response) == "policy_denied"
    details = response.json()["error"]["details"]
    assert details["decision"] == "deny"
    assert details["reason"] == "policy_denied"
    assert details["executed"] is False
    assert details["action_id"] == ACTION_ID
    assert adapter.calls == []
    assert actions.count_executions() == 0


def test_case_c_a_policy_condition_is_evaluated_against_the_resolved_caller_role(
    actions: ActionFactory, agents: AgentFactory, policies: PolicyFactory, adapter: RecordingAdapter
) -> None:
    """Facts come from the server, and a policy is decided on them.

    Two policies that differ only in the role they name: the one that matches the
    caller's *resolved* role denies an execution the other one permits. A request has no
    field for a role — a body that tried to send one is refused by the schema (see the
    body-contract test below) — so the fact can only have come from the membership.
    """
    target_id = _registered_agent(agents)
    key = f"case-c-{uuid.uuid4().hex}"
    _execution_policy(
        policies,
        name="Viewers may not run this",
        conditions=[{"field": "user_role", "operator": "equals", "value": "viewer"}],
    )

    # The policy names ``viewer``; the owner is not one, so it does not apply.
    allowed = actions.execute(target_id, idempotency_key=key)
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["policy"]["decision"] == "not_applicable"
    assert len(adapter.calls) == 1

    _execution_policy(
        policies,
        name="Owners may not run this after all",
        priority=1,
        conditions=[{"field": "user_role", "operator": "equals", "value": "owner"}],
    )
    refused = actions.execute(target_id, idempotency_key=f"{key}-2")

    assert refused.status_code == 403, refused.text
    assert _code(refused) == "policy_denied"
    assert len(adapter.calls) == 1, "the second request must not have reached the adapter"
    assert actions.count_executions() == 1


def test_case_c_the_ownership_fact_comes_from_the_instance_decision(
    actions: ActionFactory,
    agents: AgentFactory,
    policies: PolicyFactory,
    owner_identity: Identity,
    adapter: RecordingAdapter,
) -> None:
    """Phase 5's instance scope feeds Phase 6: an owner of the row is a fact, not a claim.

    The agent is registered with the owner as its owner, so ``authorize_instance``
    reports ``principal_is_owner`` and that becomes the ``is_resource_owner`` fact the
    policy is written against. Nothing about it appears in the request.
    """
    target_id = _registered_agent(agents, owner_user_id=str(owner_identity.user_id))
    _execution_policy(
        policies,
        name="Owners of the row may not assess it",
        priority=1,
        conditions=[{"field": "is_resource_owner", "operator": "equals", "value": True}],
    )

    response = actions.execute(target_id)

    assert response.status_code == 403, response.text
    assert _code(response) == "policy_denied"
    assert adapter.calls == []
    assert actions.count_executions() == 0


# ── CASE D: an approval requirement never reaches an adapter ─────────────────


def test_case_d_an_approval_requirement_is_reported_and_nothing_is_executed(
    actions: ActionFactory, agents: AgentFactory, policies: PolicyFactory, adapter: RecordingAdapter
) -> None:
    """REQUIRE_APPROVAL is a value with no workflow behind it — and never an execution."""
    target_id = _registered_agent(agents)
    _execution_policy(policies, effect="require_approval")

    response = actions.execute(target_id)

    assert response.status_code == 403, response.text
    assert _code(response) == "approval_required"
    body = response.json()
    assert "no approval workflow" in body["error"]["message"]
    assert body["error"]["details"]["decision"] == "require_approval"
    assert body["error"]["details"]["executed"] is False
    assert adapter.calls == []
    assert actions.count_executions() == 0


def test_case_d_no_approval_endpoint_exists() -> None:
    """Nothing in this build approves, rejects, queues or notifies: there is no route.

    Asserted against the application's own OpenAPI document, so a later phase that
    *does* build approvals would have to publish itself here and fail this test rather
    than quietly making the refusal above a lie.
    """
    paths = set(create_app().openapi()["paths"])
    assert not [path for path in paths if "approval" in path.lower()]
    assert not [
        path
        for path in paths
        if "actions" in path and path != "/organizations/{organization_id}/actions/execute"
    ]


# ── CASE E: an unregistered action never reaches an adapter ──────────────────


def test_case_e_an_unregistered_action_is_refused_against_the_catalogue(
    actions: ActionFactory, agents: AgentFactory, adapter: RecordingAdapter
) -> None:
    """An identifier the catalogue does not hold is refused, and the catalogue is named."""
    target_id = _registered_agent(agents)
    key = f"case-e-{uuid.uuid4().hex}"

    response = actions.execute(target_id, action="agent.execute", idempotency_key=key)

    assert response.status_code == 422, response.text
    assert _code(response) == "unknown_action"
    details = response.json()["error"]["details"]
    assert details["registered_actions"] == list(default_action_registry().action_ids())
    assert details["registered_actions"] == [ACTION_ID]
    assert adapter.calls == []
    assert actions.count_executions() == 0
    assert actions.find_execution(key) is None


@pytest.mark.parametrize(
    "action_id",
    [
        "agent",
        "agent.PostureCheck",
        "agent.posture_check; DROP TABLE aicore.agents",
        "../../../aicore_api.core.execution",
        "aicore_api.core.executors.AgentRegistryExecutor",
        "agent.posture_check\n",
        "agent..posture",
        "1agent.posture_check",
        "a" * 65,
        "",
        "agent.проверка",
    ],
)
def test_case_e_a_malformed_action_identifier_never_reaches_the_catalogue(
    actions: ActionFactory, agents: AgentFactory, adapter: RecordingAdapter, action_id: str
) -> None:
    """The identifier is a closed shape, checked at the edge.

    Nothing is resolved, imported or interpreted to answer these: the body schema
    refuses the shape before the handler runs, which is why they are validation errors
    rather than "unknown action".
    """
    target_id = _registered_agent(agents)

    response = actions.execute(target_id, action=action_id)

    assert response.status_code == 422, response.text
    assert adapter.calls == []
    assert actions.count_executions() == 0


# ── CASE F: invalid arguments never reach an adapter ────────────────────────


@pytest.mark.parametrize(
    "arguments",
    [
        {"report_detail": "everything"},
        {"report_detail": 1},
        {"report_detail": "full", "extra": "value"},
        {"command": "rm -rf /"},
        {"report_detail": {"nested": "full"}},
        {"report_detail": ["full"]},
        {"report_detail": "f" * 4096},
        {"report_detail": "$(id)"},
        {"report_detail": "full", "template": "{{7*7}}"},
    ],
)
def test_case_f_arguments_the_action_does_not_accept_are_refused(
    actions: ActionFactory,
    agents: AgentFactory,
    adapter: RecordingAdapter,
    arguments: dict[str, Any],
) -> None:
    """The action's own input schema is the argument boundary, and it refuses everything else.

    Unknown keys, wrong types, nested structures, oversized values and injection-shaped
    strings are all refused before the request is authorized — so the firewall never sees
    an argument it would have to trust.
    """
    target_id = _registered_agent(agents)
    key = f"case-f-{uuid.uuid4().hex}"

    response = actions.execute(target_id, arguments=arguments, idempotency_key=key)

    assert response.status_code == 422, response.text
    assert _code(response) == "invalid_arguments"
    assert adapter.calls == []
    assert actions.count_executions() == 0
    assert actions.find_execution(key) is None


def test_case_f_the_refusal_does_not_echo_the_value_that_was_refused(
    actions: ActionFactory, agents: AgentFactory, adapter: RecordingAdapter
) -> None:
    """A refusal names the field and the rule, never the value: arguments may be sensitive."""
    target_id = _registered_agent(agents)
    marker = "sensitive-marker-9f3c"

    response = actions.execute(target_id, arguments={"report_detail": marker})

    assert response.status_code == 422
    assert marker not in response.text


# ── CASE G: tenant isolation, IDOR and cross-tenant execution ───────────────


def test_case_g_a_target_in_another_organization_is_answered_like_a_missing_one(
    actions: ActionFactory,
    agents: AgentFactory,
    identity_factory: IdentityFactory,
    authenticate: Any,
    adapter: RecordingAdapter,
) -> None:
    """The existence of another tenant's row is not observable through this route.

    Two requests — one naming a real agent that belongs to somebody else, one naming a
    UUID that exists nowhere — produce byte-identical refusals apart from the request id.
    """
    foreign = identity_factory(role_code="owner")
    foreign_agent = authenticate(foreign).post(
        agents_path(foreign.organization_id),
        json={
            "display_name": "Foreign Agent",
            "category": "assistant",
            "version": "1.0.0",
            "environment": "production",
        },
    )
    assert foreign_agent.status_code == 201, foreign_agent.text
    foreign_agent_id = uuid.UUID(foreign_agent.json()["id"])

    across = actions.execute(foreign_agent_id, idempotency_key=f"case-g-{uuid.uuid4().hex}")
    missing = actions.execute(uuid.uuid4(), idempotency_key=f"case-g-{uuid.uuid4().hex}")

    assert across.status_code == missing.status_code == 404
    assert _code(across) == _code(missing) == "not_found"
    across_body, missing_body = across.json()["error"], missing.json()["error"]
    assert across_body["message"] == missing_body["message"]
    assert across_body["details"] is None
    assert missing_body["details"] is None
    assert adapter.calls == []
    assert actions.count_executions() == 0


def test_case_g_an_agent_attributed_from_another_organization_is_refused(
    actions: ActionFactory,
    agents: AgentFactory,
    identity_factory: IdentityFactory,
    authenticate: Any,
    adapter: RecordingAdapter,
) -> None:
    """The attributed agent is resolved in this tenant, so a foreign one is not an agent."""
    target_id = _registered_agent(agents)
    foreign = identity_factory(role_code="owner")
    foreign_agent = authenticate(foreign).post(
        agents_path(foreign.organization_id),
        json={"display_name": "Foreign Agent", "category": "assistant", "version": "1.0.0"},
    )
    assert foreign_agent.status_code == 201, foreign_agent.text

    response = actions.execute(target_id, agent_id=foreign_agent.json()["id"])

    assert response.status_code == 404
    assert _code(response) == "not_found"
    assert response.json()["error"]["message"] == "Agent not found"
    assert adapter.calls == []
    assert actions.count_executions() == 0


def test_case_g_an_attributed_agent_in_this_organization_is_accepted(
    actions: ActionFactory, agents: AgentFactory, adapter: RecordingAdapter
) -> None:
    """The positive half of the check above: a local agent is resolved and reported."""
    target_id = _registered_agent(agents)
    attributed = _registered_agent(agents, display_name="Requesting Agent")

    body = actions.executed(target_id, agent_id=str(attributed))

    assert body["agent_id"] == str(attributed)
    assert len(adapter.calls) == 1


def test_case_g_another_tenant_cannot_execute_in_this_organization(
    actions: ActionFactory,
    agents: AgentFactory,
    identity_factory: IdentityFactory,
    authenticate: Any,
    adapter: RecordingAdapter,
) -> None:
    """A valid owner of a *different* organization cannot address this one at all."""
    target_id = _registered_agent(agents)
    foreign = identity_factory(role_code="owner")

    response = authenticate(foreign).post(actions.path, json=execution_payload(target_id))

    assert response.status_code == 404
    assert adapter.calls == []
    assert actions.count_executions() == 0


def test_case_g_an_agent_identifier_from_another_tenant_is_not_a_key_to_it(
    actions: ActionFactory,
    agents: AgentFactory,
    identity_factory: IdentityFactory,
    authenticate: Any,
    adapter: RecordingAdapter,
) -> None:
    """Guessing identifiers does not cross tenants: the lookup is scoped to the tenant.

    Every id the other tenant owns — its agent, its asset, its policy, its own
    organization — is answered as though it did not exist.
    """
    target_id = _registered_agent(agents)
    foreign = identity_factory(role_code="owner")
    foreign_agent = authenticate(foreign).post(
        agents_path(foreign.organization_id),
        json={"display_name": "Foreign Agent", "category": "assistant", "version": "1.0.0"},
    )
    assert foreign_agent.status_code == 201
    foreign_body = foreign_agent.json()

    guesses = (foreign_body["id"], foreign_body["asset_id"], str(foreign.organization_id))
    for guess in guesses:
        response = actions.execute(guess)
        assert response.status_code == 404, (guess, response.text)
        assert _code(response) == "not_found"

    # The local target still works, so the refusals above are about the tenant and not
    # about the route being broken.
    assert actions.execute(target_id).status_code == 200
    assert len(adapter.calls) == 1


# ── Idempotency, and the contract of the request body ───────────────────────


def test_a_key_reused_for_a_different_request_is_a_conflict_that_runs_nothing(
    actions: ActionFactory, agents: AgentFactory, adapter: RecordingAdapter
) -> None:
    """One key, one request. A second, different request under it executes nothing."""
    target_id = _registered_agent(agents)
    other_target = _registered_agent(agents, display_name="Another Target")
    key = f"conflict-{uuid.uuid4().hex}"
    actions.executed(target_id, idempotency_key=key)
    assert len(adapter.calls) == 1

    response = actions.execute(other_target, idempotency_key=key)

    assert response.status_code == 409, response.text
    assert _code(response) == "idempotency_conflict"
    assert len(adapter.calls) == 1
    assert actions.count_executions() == 1


def test_a_caller_cannot_run_an_action_without_an_idempotency_key(
    actions: ActionFactory, agents: AgentFactory, adapter: RecordingAdapter
) -> None:
    """The key is required, not optional: a retry has to be recognisable as a retry."""
    target_id = _registered_agent(agents)
    payload = execution_payload(target_id)
    payload.pop("idempotency_key")

    response = actions.post(payload)

    assert response.status_code == 422
    assert adapter.calls == []
    assert actions.count_executions() == 0


@pytest.mark.parametrize(("field", "value"), SERVER_OWNED_FIELDS)
def test_a_body_cannot_state_a_field_the_server_owns(
    actions: ActionFactory, agents: AgentFactory, adapter: RecordingAdapter, field: str, value: Any
) -> None:
    """No tenant, no caller, no permission, no executor, no command, no URL.

    This is the boundary that keeps the request from describing *how* something runs and
    from claiming *who* is asking: every one of these fields is either derived from the
    credential and the path or does not exist in this build at all.
    """
    target_id = _registered_agent(agents)

    response = actions.execute(target_id, **{field: value})

    assert response.status_code == 422, response.text
    assert _code(response) == "validation_error"
    assert adapter.calls == []
    assert actions.count_executions() == 0


# ── Security: what the response and the ledger may contain ───────────────────


def test_the_response_never_carries_a_credential_or_echoes_the_arguments(
    actions: ActionFactory,
    agents: AgentFactory,
    owner_identity: Identity,
    adapter: RecordingAdapter,
) -> None:
    """A response is a report, not a receipt: no token, no argument echo.

    (The response does carry an ``authorization`` *section* — Phase 5's decision, which
    the phase asks to be visible — so the check is for credentials rather than for the
    word.)
    """
    target_id = _registered_agent(agents)

    response = actions.execute(target_id, arguments={"report_detail": "full"})

    assert response.status_code == 200, response.text
    body = response.text.lower()
    for forbidden in ("bearer", "token", "secret", "password", "api_key"):
        assert forbidden not in body
    assert owner_identity.token.lower() not in body
    # ``arguments`` names the field in the ledger's schema, not the payload: the request
    # body is not echoed anywhere in the response.
    assert "arguments" not in response.json()


def test_the_ledger_row_holds_the_outcome_and_no_credential(
    actions: ActionFactory,
    agents: AgentFactory,
    owner_identity: Identity,
    adapter: RecordingAdapter,
) -> None:
    """What the ledger stores, exactly: identifiers, a digest, the adapter's report.

    No token, no credential hash, no actor, no role and no decision — the ledger exists
    so a retry returns the same answer, not so a reviewer can reconstruct what happened.
    """
    target_id = _registered_agent(agents)
    key = f"ledger-{uuid.uuid4().hex}"
    actions.executed(target_id, idempotency_key=key)

    row = actions.find_execution(key)
    assert row is not None
    assert set(row) == {
        "idempotency_key",
        "action_id",
        "target_id",
        "request_fingerprint",
        "status",
        "outcome",
        "error_code",
        "created_at",
        "completed_at",
    }
    rendered = repr(row)
    for forbidden in (owner_identity.token, "Bearer", "password", "secret"):
        assert forbidden not in rendered
    assert set(row["outcome"]) == {"summary", "findings", "details", "adapter", "digest"}


def test_the_ledger_records_no_actor_and_no_refusal(
    actions: ActionFactory, agents: AgentFactory
) -> None:
    """The phase's explicit non-goal, asserted rather than promised.

    A refusal writes nothing at all, and an execution writes one row that says what ran
    and what it reported. The ledger answers "did this run twice?"; it does not answer
    "who was refused, why, or by which policy". That history is the audit trail — a
    different table, written by a different writer, reached through a read-only surface.
    """
    target_id = _registered_agent(agents)
    actions.execute(uuid.uuid4())  # a refusal

    # Nothing at all: a refused request is not an execution and leaves no execution row.
    assert actions.count_executions() == 0

    actions.executed(target_id)  # one execution
    assert actions.count_executions() == 1

    # The row is an execution mechanism, and its columns say so: nothing names a person,
    # an authorization decision, a policy, a correlation or a body of metadata.
    columns = set(ActionExecution.__table__.columns.keys())
    assert not columns & {"actor_id", "actor_type", "decision", "policy_id", "correlation_id"}
    assert "metadata" not in columns

    # Nothing later in this project is being pretended at either: no incident,
    # monitoring, alerting or webhook surface exists in this build.
    routes = [
        context.original_route
        for context in iter_route_contexts(create_app().routes)
        if isinstance(context.original_route, APIRoute)
    ]
    paths = [route.path for route in routes]
    for forbidden in ("incident", "monitor", "alert", "webhook"):
        assert not [path for path in paths if forbidden in path.lower()], forbidden

    # And the trail itself is read-only: one path, and it accepts GET alone, so nothing
    # in the API can create an event or alter one.
    audit_routes = [route for route in routes if "audit" in route.path.lower()]
    assert [route.path for route in audit_routes] == [
        "/organizations/{organization_id}/audit-events"
    ]
    assert sorted(audit_routes[0].methods or []) == ["GET"]


# ── Security: the execution path is the only one that reaches an adapter ─────


def _dependency_names(route: APIRoute) -> set[str]:
    """Every callable in a route's dependency graph, by name."""
    names: set[str] = set()
    stack = [route.dependant]
    while stack:
        dependant = stack.pop()
        if dependant.call is not None:
            names.add(getattr(dependant.call, "__name__", ""))
        stack.extend(dependant.dependencies)
    return names


def test_the_execution_route_is_the_only_route_that_can_reach_an_adapter() -> None:
    """The adapter registry is injected in exactly one place, and it is the firewall's.

    A route that reached an executor without going through the firewall would have to
    declare this dependency — the only way an adapter becomes available — so the check is
    about the wiring rather than about a convention.
    """
    # `app.routes` yields lazily-included routers; iter_route_contexts is how FastAPI
    # itself walks the effective routes (the same walk the registry's tests use).
    routes = [
        context.original_route
        for context in iter_route_contexts(create_app().routes)
        if isinstance(context.original_route, APIRoute)
    ]
    reaching = sorted(
        route.path for route in routes if "get_action_executors" in _dependency_names(route)
    )
    assert reaching == ["/organizations/{organization_id}/actions/execute"]

    # And nothing else in the surface offers to run anything: the word ``execute``
    # appears in one path, and no path offers a start, stop, kill, approve or retry.
    paths = [route.path for route in routes]
    assert len([path for path in paths if "execute" in path]) == 1
    for forbidden in ("start", "stop", "kill", "approve", "reject", "retry", "rollback"):
        assert not [path for path in paths if forbidden in path.lower()], forbidden


def test_the_catalogue_the_api_serves_is_the_one_the_firewall_decides_against() -> None:
    """One registry, resolved by the same code for the error message and the execution."""
    registry = default_action_registry()
    assert registry.action_ids() == (ACTION_ID,)
    assert registry.get(ACTION_ID) is not None
    assert registry.get(ACTION_ID).policy_target == (
        Permission.ACTION_EXECUTE.resource,
        Permission.ACTION_EXECUTE.action,
    )
