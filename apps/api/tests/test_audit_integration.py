"""Phase 8's emission points: what the platform records when it actually does something.

The vocabulary in ``core.audit`` is only worth having if the events exist, so this file
performs the operations and then reads the trail: an asset is created, updated and
deleted; an agent is registered and moved through its lifecycle; a policy is written,
revisioned, activated and removed; an integration reports an asset; an action is
admitted, refused, held, executed, replayed, failed or answered with a conflict.

Three properties get their own group of tests, because they are the ones a reviewer
should be able to check rather than take on trust.

- **Phase 7 is unchanged.** The recording adapter counts what ran: an ``ALLOW`` request
  reaches it exactly once, every refusal reaches it zero times, and the trail is written
  around a decision that was already made. A denial that became an execution, or an
  execution that happened twice because a row was written, would show up here.
- **Attribution is the server's.** The actor is the authenticated person, the
  organization is the path's, the timestamp is the database's, and the source is where
  the event came from. Nothing in a request body can say otherwise — the bodies refuse
  unknown fields outright — and the action pipeline keeps "this person asked" and "for
  this agent" as two separate facts.
- **The trail is not the ledger.** After a refusal the ledger is empty and the trail is
  not; after an execution both have something, and they say different things.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from actions_fixture import ACTION_ID, count_executions
from agents_fixture import agent_path, agents_path
from aicore_api.api.deps import get_action_executors
from aicore_api.auth.authorization import resolve_organization_context
from aicore_api.auth.principal import Principal
from aicore_api.core.assets import AssetType, Environment
from aicore_api.core.executors import (
    ActionExecutionError,
    ActionExecutor,
    ActionExecutorRegistry,
    ActionInvocation,
    ActionOutcome,
    AgentRegistryExecutor,
)
from aicore_api.core.permissions import Permission
from aicore_api.discovery import DiscoveredAsset, register_discovered_asset
from assets_fixture import asset_path, assets_path
from audit_fixture import AuditScene
from identity_fixture import Identity, IdentityFactory

#: The one registered action, as the request body names it.
EXECUTION = ACTION_ID

#: The execution route as the published document spells it — the path is a pattern, and
#: the object a test has to find is the one the route was built with.
EXECUTE_PATH = "/organizations/{organization_id}/actions/execute"


class RecordingAdapter(ActionExecutor):
    """The reference adapter, wrapped so a test can count the calls it receives.

    A subclass rather than a mock: it declares the identifier the catalogue names and
    delegates to the real adapter, so the outcome a test asserts is the outcome the build
    would report. Only the count — and, in the failure test, the verdict — is new.
    """

    executor_id = AgentRegistryExecutor.executor_id

    def __init__(self, *, failure: Exception | None = None) -> None:
        self.calls: list[ActionInvocation] = []
        self._failure = failure
        self._inner = AgentRegistryExecutor()

    def execute(self, invocation: ActionInvocation) -> ActionOutcome:
        self.calls.append(invocation)
        if self._failure is not None:
            raise self._failure
        return self._inner.execute(invocation)


@dataclass
class Adapter:
    """The recording adapter and the endpoint it is wired into."""

    recorder: RecordingAdapter
    client: TestClient

    @property
    def calls(self) -> int:
        """How many times the adapter has been asked to run anything."""
        return len(self.recorder.calls)


@pytest.fixture
def adapter(audit: AuditScene) -> Iterator[Adapter]:
    """Substitute a recording adapter for the reference one, for one test.

    The seam is the dependency the application itself uses to wire adapters, which is why
    this is a substitution rather than a patch: a test that reached in through
    ``monkeypatch`` could disagree with the wiring production uses.
    """
    recorder = RecordingAdapter()
    audit.trail.client.app.dependency_overrides[get_action_executors] = lambda: (
        ActionExecutorRegistry((recorder,))
    )
    try:
        yield Adapter(recorder=recorder, client=audit.trail.client)
    finally:
        audit.trail.client.app.dependency_overrides.pop(get_action_executors, None)


@contextmanager
def _failing_adapter(audit: AuditScene, error: Exception) -> Iterator[RecordingAdapter]:
    """An adapter that is reached and fails, for the failure test."""
    recorder = RecordingAdapter(failure=error)
    audit.trail.client.app.dependency_overrides[get_action_executors] = lambda: (
        ActionExecutorRegistry((recorder,))
    )
    try:
        yield recorder
    finally:
        audit.trail.client.app.dependency_overrides.pop(get_action_executors, None)


def _principal(identity: Identity) -> Principal:
    """The authenticated caller, as the credential provider would build it."""
    return Principal(
        user_id=identity.user_id,
        email=identity.email,
        full_name="Test Person",
        status="active",
    )


def _permission_dependency(app: Any, path: str, permission: Permission) -> Any:
    """The route's own permission dependency, found by walking the application.

    ``require_permission(...)`` builds a fresh callable per call, so the object a test has
    to override is the one the route was built with — reached by walking the dependency
    graph rather than by calling the factory again.
    """
    for context in iter_route_contexts(app.routes):
        route = context.original_route
        if not isinstance(route, APIRoute) or route.path != path:
            continue
        stack = [route.dependant]
        while stack:
            dependant = stack.pop()
            if getattr(dependant.call, "required_permission", None) is permission:
                return dependant.call
            stack.extend(dependant.dependencies)
    raise AssertionError(f"no route at {path!r} requires {permission}")


def _register_agent(
    audit: AuditScene,
    *,
    display_name: str = "Audited Agent",
    status: str = "active",
    environment: str = "production",
    request_id: str | None = None,
) -> uuid.UUID:
    """Register one agent through the API and return its identifier."""
    response = audit.trail.as_owner().post(
        agents_path(audit.organization_id),
        json={
            "display_name": display_name,
            "category": "assistant",
            "version": "1.0.0",
            "status": status,
            "environment": environment,
        },
        headers={"X-Request-ID": request_id} if request_id else None,
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


def _create_asset(audit: AuditScene, *, name: str = "Audited Asset", **fields: Any) -> uuid.UUID:
    """Create one asset through the API and return its identifier."""
    response = audit.trail.as_owner().post(
        assets_path(audit.organization_id), json={"name": name, "asset_type": "model", **fields}
    )
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


def _execute_allowed(
    audit: AuditScene, target_id: uuid.UUID, *, agent_id: uuid.UUID | None = None
) -> Mapping[str, Any]:
    """The response body of one execution request, asserted to have been allowed."""
    response = audit.actions.execute(target_id, agent_id=agent_id)
    assert response.status_code == 200, response.text
    return response.json()


# ── The inventory, the registry and the policy record ─────────────────────────


def test_creating_an_asset_records_a_persons_action(audit: AuditScene) -> None:
    asset_id = _create_asset(audit)

    events = audit.trail.stored()

    assert [event["event_type"] for event in events] == ["asset.created"]
    event = events[0]
    assert event["actor_type"] == "human"
    assert event["actor_id"] == audit.identity.user_id
    assert event["actor_membership_id"] == audit.identity.membership_id
    assert event["resource_type"] == "asset"
    assert event["resource_id"] == asset_id
    assert event["action"] == "asset.create"
    assert event["decision"] is None
    assert event["outcome"] == "success"
    assert event["source"] == "api"
    assert event["request_id"] is not None


def test_updating_an_asset_records_the_field_that_changed(audit: AuditScene) -> None:
    asset_id = _create_asset(audit)

    response = audit.trail.as_owner().patch(
        asset_path(audit.organization_id, asset_id), json={"name": "Renamed Asset"}
    )

    assert response.status_code == 200, response.text
    events = audit.trail.stored(event_type="asset.updated")
    assert len(events) == 1
    assert events[0]["metadata"] == {"fields": ["name"]}
    assert events[0]["action"] == "asset.update"
    assert events[0]["resource_id"] == asset_id


def test_deleting_an_asset_records_it_after_the_row_is_gone(audit: AuditScene) -> None:
    """The event outlives what it describes, which is the point of a durable trail."""
    asset_id = _create_asset(audit)

    response = audit.trail.as_owner().delete(asset_path(audit.organization_id, asset_id))

    assert response.status_code == 204, response.text
    events = audit.trail.stored(event_type="asset.deleted")
    assert len(events) == 1
    assert events[0]["resource_id"] == asset_id
    assert events[0]["metadata"] == {"asset_type": "model"}
    # And the row it names really is gone: the event is a record, not a foreign key.
    missing = audit.trail.as_owner().get(asset_path(audit.organization_id, asset_id))
    assert missing.status_code == 404


def test_registering_an_agent_records_the_registration_and_its_inventory_row(
    audit: AuditScene,
) -> None:
    """Two facts, two events: an agent acquired an identity, and an asset appeared."""
    _register_agent(audit, request_id="req-register")

    events = audit.trail.stored()
    assert [event["event_type"] for event in events] == ["asset.created", "agent.registered"]
    # One request, one correlation: the two rows are the same act seen twice.
    assert {event["correlation_id"] for event in events} == {"req-register"}
    assert events[1]["action"] == "agent.create"
    assert events[1]["resource_type"] == "agent"
    # A registered agent's inventory record is adopted, not merely discovered.
    assert events[0]["metadata"] == {"asset_type": "agent", "discovery_state": "managed"}


def test_moving_an_agent_through_its_lifecycle_records_each_move(audit: AuditScene) -> None:
    agent_id = _register_agent(audit)

    suspended = audit.trail.as_owner().patch(
        agent_path(audit.organization_id, agent_id), json={"status": "suspended"}
    )
    assert suspended.status_code == 200, suspended.text

    events = audit.trail.stored(event_type="agent.updated")
    assert len(events) == 1
    assert events[0]["metadata"] == {"fields": ["status"]}
    assert events[0]["resource_id"] == agent_id

    deleted = audit.trail.as_owner().delete(agent_path(audit.organization_id, agent_id))
    assert deleted.status_code == 204, deleted.text
    assert [event["action"] for event in audit.trail.stored(event_type="agent.deleted")] == [
        "agent.delete"
    ]


def test_a_policys_lifecycle_is_recorded_step_by_step(audit: AuditScene) -> None:
    """Four events, because they answer four different questions."""
    policy = audit.policies.create("Audited Policy")

    published = audit.policies.patch(policy, {"priority": 250})
    assert published.status_code == 200, published.text
    moved = audit.policies.activate(policy)
    assert moved.status == "active"
    removed = audit.policies.delete(policy.item_path)
    assert removed.status_code == 204, removed.text

    events = audit.trail.stored()
    assert [event["event_type"] for event in events] == [
        "policy.created",
        "policy.version_published",
        "policy.status_changed",
        "policy.deleted",
    ]
    assert [event["action"] for event in events] == [
        "policy.create",
        "policy.update",
        "policy.update",
        "policy.delete",
    ]
    assert {event["resource_type"] for event in events} == {"policy"}
    assert {event["resource_id"] for event in events} == {policy.id}
    # Each event carries the facts its own question needs, and no others.
    assert events[1]["metadata"]["version"] == 2
    assert events[2]["metadata"] == {"status": "active"}


def test_a_policy_edit_that_changes_nothing_records_nothing(audit: AuditScene) -> None:
    """Transactional consistency: no change, no record of one."""
    policy = audit.policies.create("Unchanged Policy")
    before = audit.trail.count()

    response = audit.policies.patch(policy, {"priority": policy.priority})

    assert response.status_code == 200, response.text
    assert audit.trail.count() == before
    assert audit.trail.stored(event_type="policy.version_published") == []


def test_a_change_that_fails_records_nothing(audit: AuditScene) -> None:
    """The record follows the change: a refused write leaves no event behind."""
    _create_asset(audit, external_identifier="urn:audit:duplicate")
    before = audit.trail.count()

    duplicate = audit.trail.as_owner().post(
        assets_path(audit.organization_id),
        json={
            "name": "Duplicate Asset",
            "asset_type": "model",
            "external_identifier": "urn:audit:duplicate",
        },
    )

    assert duplicate.status_code == 409, duplicate.text
    assert audit.trail.count() == before


def test_an_ingested_asset_is_recorded_as_a_system_event(
    audit: AuditScene, integration_session: Session
) -> None:
    """Nobody performed it, so nobody is named: the honest attribution."""
    result = register_discovered_asset(
        integration_session,
        audit.organization_id,
        DiscoveredAsset(
            source="test-collector",
            external_identifier="cluster://ingested/one",
            name="Ingested Asset",
            asset_type=AssetType.AGENT,
            environment=Environment.PRODUCTION,
        ),
    )

    events = audit.trail.stored()
    assert [event["event_type"] for event in events] == ["asset.discovered"]
    event = events[0]
    assert event["actor_type"] == "system"
    assert event["actor_id"] is None
    assert event["actor_membership_id"] is None
    assert event["source"] == "ingestion"
    assert event["request_id"] is None  # there was no request
    assert event["correlation_id"]  # but the run still groups its events
    assert event["action"] == "asset.create"
    assert event["resource_id"] == result.asset_id


def test_re_reporting_the_same_asset_records_nothing_new(
    audit: AuditScene, integration_session: Session
) -> None:
    """An integration that reports the same thing twice is not two discoveries."""
    report = DiscoveredAsset(
        source="test-collector",
        external_identifier="cluster://ingested/twice",
        name="Re-reported Asset",
        asset_type=AssetType.AGENT,
        environment=Environment.PRODUCTION,
    )
    register_discovered_asset(integration_session, audit.organization_id, report)
    first = audit.trail.count()

    again = register_discovered_asset(integration_session, audit.organization_id, report)

    assert again.created is False
    assert audit.trail.count() == first


# ── Phase 7: the pipeline, recorded around a decision that was already made ────


def test_an_allowed_request_records_admission_then_execution(
    audit: AuditScene, adapter: Adapter
) -> None:
    """Two rows for one request, and the adapter reached exactly once."""
    agent_id = _register_agent(audit)

    body = _execute_allowed(audit, agent_id)

    assert adapter.calls == 1
    assert count_executions(audit.trail.engine, audit.organization_id) == 1

    admitted = audit.trail.stored(event_type="action.requested")
    assert len(admitted) == 1
    assert len(audit.trail.stored(event_type="action.executed")) == 1
    admitted = admitted[0]
    executed = audit.trail.stored(event_type="action.executed")[0]

    assert admitted["outcome"] == "pending"
    assert admitted["decision"] is None
    assert admitted["metadata"]["argument_count"] == 0
    assert admitted["metadata"]["sensitivity"] == "routine"

    assert executed["decision"] == "allow"
    assert executed["outcome"] == "success"
    assert executed["resource_id"] == agent_id
    assert executed["action"] == EXECUTION
    assert executed["metadata"]["adapter"] == AgentRegistryExecutor.executor_id
    assert executed["metadata"]["replayed"] is False
    assert executed["agent_id"] is None
    # The response reports the same execution the trail recorded.
    assert executed["metadata"]["digest"] == body["result"]["digest"]


def test_an_execution_attributed_to_an_agent_keeps_both_facts(
    audit: AuditScene, adapter: Adapter
) -> None:
    """The person is the actor; the agent is what they acted through."""
    target_id = _register_agent(audit, display_name="Execution Target")
    agent_id = _register_agent(audit, display_name="Attributed Agent")

    _execute_allowed(audit, target_id, agent_id=str(agent_id))

    admitted = audit.trail.stored(event_type="action.requested")[0]
    executed = audit.trail.stored(event_type="action.executed")[0]

    # Two facts, both stated, neither inferred from the other.
    for event in (admitted, executed):
        assert event["actor_type"] == "human"
        assert event["actor_id"] == audit.identity.user_id
        assert event["agent_id"] == agent_id
    assert admitted["metadata"]["attributed"] is True


def test_a_denied_request_records_one_refusal_and_runs_nothing(
    audit: AuditScene, adapter: Adapter
) -> None:
    """One refusal, not one per layer that could have said no."""
    agent_id = _register_agent(audit)
    audit.policies.activate(
        audit.policies.create(
            "Deny executions", resource="action", action="execute", effect="deny", conditions=[]
        )
    )

    response = audit.actions.execute(agent_id)

    assert response.status_code == 403, response.text
    assert adapter.calls == 0
    assert count_executions(audit.trail.engine, audit.organization_id) == 0

    denied = audit.trail.stored(event_type="action.denied")
    assert len(denied) == 1
    assert denied[0]["decision"] == "deny"
    assert denied[0]["outcome"] == "blocked"
    assert denied[0]["metadata"]["reason"] == "policy_denied"
    assert audit.trail.stored(event_type="action.executed") == []
    # And the refusal is attributed: a refusal nobody is answerable for is not a record.
    assert denied[0]["actor_id"] == audit.identity.user_id
    assert denied[0]["resource_id"] == agent_id


def test_a_refusal_by_the_routes_permission_check_is_not_an_event(
    audit: AuditScene, adapter: Adapter, identity_factory: IdentityFactory, authenticate
) -> None:
    """The gate that refuses first is Phase 5's dependency, and it refuses *before* admission.

    Nothing was admitted, nothing was decided and nothing ran, so there is nothing to
    record — the trail records operations, not attempts. This is the honest boundary of
    Phase 8's coverage of refusals, and it is the reason the action route's own firewall
    is the place a refusal becomes an event.
    """
    agent_id = _register_agent(audit)
    viewer = identity_factory(role_code="viewer", organization_id=audit.organization_id)

    response = authenticate(viewer).post(
        audit.actions.path,
        json={
            "action": EXECUTION,
            "target_id": str(agent_id),
            "environment": "production",
            "arguments": {},
            "idempotency_key": f"test-{uuid.uuid4().hex}",
        },
    )

    assert response.status_code == 403, response.text
    assert adapter.calls == 0
    assert count_executions(audit.trail.engine, audit.organization_id) == 0
    assert audit.trail.stored(event_type="action.requested") == []
    assert audit.trail.stored(event_type="action.denied") == []


def test_the_firewalls_own_authorization_denial_is_recorded(
    audit: AuditScene, adapter: Adapter, identity_factory: IdentityFactory
) -> None:
    """The refusal the firewall makes *is* recorded, in the same shape as any other.

    Reaching this branch takes a caller the authorization layer has already denied, which
    the route's permission dependency would normally refuse before the handler — so the
    dependency is overridden here, and only here. Everything downstream is the real
    pipeline: the firewall decides, the route refuses and the trail records, and the
    adapter is never reached.
    """
    agent_id = _register_agent(audit)
    viewer = identity_factory(role_code="viewer", organization_id=audit.organization_id)
    with Session(audit.trail.engine) as session:
        # A real context for a real membership, resolved without demanding the permission
        # the route demands: this is exactly the input the handler is given.
        context = resolve_organization_context(session, _principal(viewer), audit.organization_id)

    app = audit.trail.client.app
    dependency = _permission_dependency(app, EXECUTE_PATH, Permission.ACTION_EXECUTE)
    app.dependency_overrides[dependency] = lambda: context
    try:
        response = audit.trail.client.post(
            audit.actions.path,
            json={
                "action": EXECUTION,
                "target_id": str(agent_id),
                "environment": "production",
                "arguments": {},
                "idempotency_key": f"test-{uuid.uuid4().hex}",
            },
            headers={"Authorization": f"Bearer {viewer.token}"},
        )
    finally:
        app.dependency_overrides.pop(dependency, None)

    assert response.status_code == 403, response.text
    assert response.json()["error"]["details"]["reason"] == "authorization_denied"
    assert adapter.calls == 0
    assert count_executions(audit.trail.engine, audit.organization_id) == 0

    denied = audit.trail.stored(event_type="action.denied")
    assert len(denied) == 1
    assert denied[0]["decision"] == "deny"
    assert denied[0]["outcome"] == "blocked"
    assert denied[0]["metadata"]["reason"] == "authorization_denied"
    assert denied[0]["actor_id"] == viewer.user_id
    assert audit.trail.stored(event_type="action.executed") == []


def test_a_policy_that_requires_approval_records_a_hold_and_runs_nothing(
    audit: AuditScene, adapter: Adapter
) -> None:
    """``require_approval`` is a value: the trail says nothing ran, and nothing did."""
    agent_id = _register_agent(audit)
    audit.policies.activate(
        audit.policies.create(
            "Hold executions",
            resource="action",
            action="execute",
            effect="require_approval",
            conditions=[],
        )
    )

    response = audit.actions.execute(agent_id)

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "approval_required"
    assert adapter.calls == 0
    assert count_executions(audit.trail.engine, audit.organization_id) == 0

    held = audit.trail.stored(event_type="action.require_approval")
    assert len(held) == 1
    assert held[0]["decision"] == "require_approval"
    assert held[0]["outcome"] == "not_executed"
    assert held[0]["metadata"]["reason"] == "policy_requires_approval"
    assert audit.trail.stored(event_type="action.executed") == []


def test_a_failed_execution_is_recorded_as_admitted_and_failed(audit: AuditScene) -> None:
    """The adapter was reached — so the trail says so, and says what came of it."""
    agent_id = _register_agent(audit)

    with _failing_adapter(audit, ActionExecutionError("the adapter could not report")) as recorder:
        response = audit.actions.execute(agent_id)

    assert response.status_code == 500, response.text
    assert len(recorder.calls) == 1

    events = audit.trail.stored()
    assert [event["event_type"] for event in events] == [
        "asset.created",
        "agent.registered",
        "action.requested",
        "action.failed",
    ]
    failed = events[-1]
    assert failed["decision"] == "allow"
    assert failed["outcome"] == "failed"
    assert failed["metadata"] == {
        "error_code": "execution_failed",
        "idempotency_key": _last_key(audit),
    }


def _last_key(audit: AuditScene) -> str:
    """The idempotency key of the most recent request this factory sent."""
    return audit.actions.created[-1]


def test_a_replay_is_recorded_as_a_replay_not_as_a_second_execution(
    audit: AuditScene, adapter: Adapter
) -> None:
    """The ledger answered instead of the adapter, and the trail says exactly that."""
    agent_id = _register_agent(audit)

    first = audit.actions.execute(agent_id, idempotency_key="test-replay")
    second = audit.actions.execute(agent_id, idempotency_key="test-replay")

    assert first.status_code == second.status_code == 200
    assert adapter.calls == 1
    assert count_executions(audit.trail.engine, audit.organization_id) == 1

    executed = audit.trail.stored(event_type="action.executed")
    replayed = audit.trail.stored(event_type="action.replayed")
    assert len(executed) == len(replayed) == 1
    assert executed[0]["metadata"]["replayed"] is False
    assert replayed[0]["metadata"]["replayed"] is True
    assert replayed[0]["outcome"] == "replayed"
    assert replayed[0]["decision"] == "allow"
    assert second.json()["replayed"] is True


def test_a_conflicting_key_records_an_admission_and_a_failure(
    audit: AuditScene, adapter: Adapter
) -> None:
    """A key reused for a different request: nothing ran, and the trail says why."""
    agent_id = _register_agent(audit)
    audit.actions.execute(agent_id, idempotency_key="test-conflict")

    conflicting = audit.actions.execute(
        agent_id, idempotency_key="test-conflict", arguments={"report_detail": "full"}
    )

    assert conflicting.status_code == 409, conflicting.text
    assert adapter.calls == 1  # only the first request reached it
    failed = audit.trail.stored(event_type="action.failed")
    assert len(failed) == 1
    assert failed[0]["metadata"]["error_code"] == "idempotency_conflict"
    assert failed[0]["outcome"] == "failed"


def test_a_request_for_an_unknown_action_records_nothing(audit: AuditScene) -> None:
    """Nothing happened, so there is nothing to record — and no invented event."""
    response = audit.trail.as_owner().post(
        audit.actions.path,
        json={
            "action": "agent.no_such_action",
            "target_id": str(uuid.uuid4()),
            "environment": "production",
            "arguments": {},
            "idempotency_key": f"test-{uuid.uuid4().hex}",
        },
    )

    assert response.status_code == 422, response.text
    assert audit.trail.count() == 0


def test_the_pipeline_records_exactly_one_decision_per_request(
    audit: AuditScene, adapter: Adapter
) -> None:
    """Whatever the answer, one request produces one decided event."""
    agent_id = _register_agent(audit)
    missing = uuid.uuid4()

    outcomes = [
        audit.actions.execute(agent_id, idempotency_key="test-one-allow"),
        audit.actions.execute(missing, idempotency_key="test-one-deny"),
    ]
    assert [response.status_code for response in outcomes] == [200, 404]

    per_request: dict[str, list[str]] = {}
    for event in audit.trail.stored():
        if event["event_type"].startswith("action."):
            per_request.setdefault(str(event["correlation_id"]), []).append(event["event_type"])

    assert len(per_request) == 2
    for types in per_request.values():
        decided = [event_type for event_type in types if event_type != "action.requested"]
        assert len(decided) == 1, types
        assert types.count("action.requested") == 1, types


def test_the_audit_trail_never_turns_a_denial_into_an_execution(
    audit: AuditScene, adapter: Adapter
) -> None:
    """Three refusals, three records, and still nothing has run."""
    agent_id = _register_agent(audit)
    audit.policies.activate(
        audit.policies.create(
            "Deny executions", resource="action", action="execute", effect="deny", conditions=[]
        )
    )

    for index in range(3):
        response = audit.actions.execute(agent_id, idempotency_key=f"test-denied-{index}")
        assert response.status_code == 403, response.text

    assert adapter.calls == 0
    assert count_executions(audit.trail.engine, audit.organization_id) == 0
    assert len(audit.trail.stored(event_type="action.denied")) == 3
    assert audit.trail.stored(event_type="action.executed") == []


def test_the_trail_is_not_the_ledger(audit: AuditScene, adapter: Adapter) -> None:
    """They answer different questions, and one of them answers about refusals."""
    agent_id = _register_agent(audit)
    missing = uuid.uuid4()

    audit.actions.execute(missing, idempotency_key="test-not-the-ledger")
    assert count_executions(audit.trail.engine, audit.organization_id) == 0
    assert len(audit.trail.stored(event_type="action.denied")) == 1

    audit.actions.execute(agent_id, idempotency_key="test-not-the-ledger-either")
    assert count_executions(audit.trail.engine, audit.organization_id) == 1
    assert len(audit.trail.stored(event_type="action.executed")) == 1
    # The ledger holds what ran; the trail holds what *happened*, refusals included.
    assert len(audit.trail.stored(event_type="action.requested")) == 2


# ── Attribution, correlation and what a request may not say ───────────────────


@pytest.mark.parametrize(
    "field",
    [
        "actor_id",
        "actor_type",
        "organization_id",
        "event_type",
        "occurred_at",
        "source",
        "decision",
        "outcome",
        "correlation_id",
        "resource_id",
        "metadata",
        "role_code",
        "permissions",
    ],
)
def test_a_lifecycle_body_cannot_supply_a_field_of_the_record(
    audit: AuditScene, field: str
) -> None:
    """The closed request models are what make "the server decides" checkable."""
    response = audit.trail.as_owner().post(
        assets_path(audit.organization_id),
        json={"name": "Spoofing Attempt", "asset_type": "model", field: "claimed"},
    )

    assert response.status_code == 422, (field, response.text)
    assert audit.trail.count() == 0


@pytest.mark.parametrize(
    "field",
    ["actor_id", "actor_type", "organization_id", "decision", "outcome", "occurred_at", "source"],
)
def test_an_execution_body_cannot_supply_a_field_of_the_record(
    audit: AuditScene, field: str
) -> None:
    """The execution body is closed too, and the trail is written from the credential."""
    agent_id = _register_agent(audit)
    before = audit.trail.count()

    response = audit.actions.post(
        {
            "action": EXECUTION,
            "target_id": str(agent_id),
            "environment": "production",
            "arguments": {},
            "idempotency_key": f"test-{uuid.uuid4().hex}",
            field: "claimed",
        }
    )

    assert response.status_code == 422, (field, response.text)
    assert audit.trail.count() == before


def test_two_people_in_one_tenant_are_recorded_as_themselves(
    audit: AuditScene, identity_factory: IdentityFactory, authenticate
) -> None:
    """Attribution is the credential's: the trail cannot be written for someone else."""
    colleague = identity_factory(role_code="owner", organization_id=audit.organization_id)

    response = authenticate(colleague).post(
        assets_path(audit.organization_id), json={"name": "Their Asset", "asset_type": "model"}
    )
    assert response.status_code == 201, response.text

    event = audit.trail.stored()[0]
    assert event["actor_id"] == colleague.user_id
    assert event["actor_membership_id"] == colleague.membership_id
    assert event["actor_id"] != audit.identity.user_id


def test_the_moment_is_the_servers_not_the_callers(audit: AuditScene) -> None:
    """A request arrives between two readings of the clock, and the row is between them."""
    before = datetime.now(UTC)
    _create_asset(audit)
    after = datetime.now(UTC)

    occurred_at = audit.trail.stored()[0]["occurred_at"]

    assert before - timedelta(seconds=1) <= occurred_at <= after + timedelta(seconds=1)
    assert occurred_at.tzinfo is not None


def test_one_request_groups_its_events_and_the_next_one_does_not(audit: AuditScene) -> None:
    """Correlation comes from the request context: two requests, two groups."""
    _create_asset(audit, name="First")
    _create_asset(audit, name="Second")

    events = audit.trail.stored()
    correlations = {event["correlation_id"] for event in events}

    assert len(correlations) == 2
    for event in events:
        assert event["correlation_id"] == event["request_id"]
        assert event["correlation_id"] is not None


def test_the_trail_stores_no_argument_it_was_given(audit: AuditScene, adapter: Adapter) -> None:
    """The summary counts arguments; it never keeps them."""
    agent_id = _register_agent(audit)

    response = audit.actions.execute(agent_id, arguments={"report_detail": "full"})
    assert response.status_code == 200, response.text

    stored = json.dumps([dict(event) for event in audit.trail.stored()], default=str)
    assert "report_detail" not in stored
    assert '"full"' not in stored

    admitted = audit.trail.stored(event_type="action.requested")[0]
    assert admitted["metadata"]["argument_count"] == 1


def test_the_audit_rows_never_carry_request_material(audit: AuditScene, adapter: Adapter) -> None:
    """A whole request's worth of trail, checked for the things that must never be in it."""
    agent_id = _register_agent(audit)
    _execute_allowed(audit, agent_id)

    stored = json.dumps([dict(event) for event in audit.trail.stored()], default=str).lower()

    assert audit.identity.token.lower() not in stored
    for forbidden in ("bearer", "authorization", "cookie", "password", "api_key"):
        assert forbidden not in stored, forbidden


def test_a_refused_lifecycle_change_is_not_an_event(audit: AuditScene, identity_factory) -> None:
    """Reading the trail is not the same as recording every attempt to read it.

    Phase 8 records what the platform *did*: an authorization decision that stopped a
    request before the operation began leaves no event, because nothing happened. The
    action pipeline is the one place a refusal is itself an event, and it says so by
    recording one — not by recording the two layers that could have refused.
    """
    viewer = identity_factory(role_code="viewer", organization_id=audit.organization_id)
    before = audit.trail.count()

    response = audit.trail.as_owner().post(
        assets_path(audit.organization_id),
        json={"name": "Not Allowed", "asset_type": "model"},
        headers={"Authorization": f"Bearer {viewer.token}"},
    )

    assert response.status_code == 403, response.text
    assert audit.trail.count() == before


def test_the_read_of_the_trail_is_not_recorded_in_the_trail(audit: AuditScene) -> None:
    """A read changes nothing: an event for it would make the record a request log."""
    _create_asset(audit)
    before = audit.trail.count()

    assert audit.trail.get().status_code == 200
    assert audit.trail.get(total=True).status_code == 200

    assert audit.trail.count() == before


def test_the_domain_event_seam_writes_one_row_with_a_session(audit: AuditScene) -> None:
    """``emit_event`` without a session is a log line; with one it is a record.

    Asserted through the seam itself, because the session is the switch and the switch is
    the whole of Phase 8's integration with the earlier phases.
    """
    from aicore_api.core.events import DomainEvent, emit_event

    asset_id = _create_asset(audit)
    before = audit.trail.count()

    event = DomainEvent(
        name="asset.updated",
        organization_id=audit.organization_id,
        resource_type="asset",
        resource_id=asset_id,
        actor_id=audit.identity.user_id,
        actor_membership_id=audit.identity.membership_id,
        data={"fields": ["name"]},
    )
    emit_event(event)  # no session: a log line and nothing more
    assert audit.trail.count() == before

    emit_event(event, session=Session(audit.trail.engine))
    assert audit.trail.count() == before + 1
    assert audit.trail.stored()[-1]["resource_id"] == asset_id


def test_the_seam_refuses_an_event_name_it_has_no_vocabulary_for(audit: AuditScene) -> None:
    """A row that says something no vocabulary admits cannot be queried or trusted."""
    from aicore_api.core.audit import AuditError
    from aicore_api.core.events import DomainEvent, emit_event

    asset_id = _create_asset(audit)
    with pytest.raises(AuditError, match="not a declared audit event type"):
        emit_event(
            DomainEvent(
                name="asset.exploded",
                organization_id=audit.organization_id,
                resource_type="asset",
                resource_id=asset_id,
                actor_id=audit.identity.user_id,
                actor_membership_id=audit.identity.membership_id,
            ),
            session=Session(audit.trail.engine),
        )

    assert audit.trail.stored(event_type="asset.created") != []


def test_the_seam_refuses_a_half_attributed_event(audit: AuditScene) -> None:
    """One identifier is not attribution: the writer refuses rather than guessing."""
    from aicore_api.core.audit import AuditError
    from aicore_api.core.events import DomainEvent, emit_event

    asset_id = _create_asset(audit)
    before = audit.trail.count()

    with pytest.raises(AuditError, match="must name both"):
        emit_event(
            DomainEvent(
                name="asset.updated",
                organization_id=audit.organization_id,
                resource_type="asset",
                resource_id=asset_id,
                actor_id=audit.identity.user_id,  # and no membership
            ),
            session=Session(audit.trail.engine),
        )

    assert audit.trail.count() == before


def test_the_registry_the_api_serves_is_the_one_the_trail_names() -> None:
    """The action id in a trail row is the catalogue's, not a string a route invented."""
    from aicore_api.core.actions import UnknownActionError, default_action_registry

    with pytest.raises(UnknownActionError):
        default_action_registry().resolve("agent.no_such_action")

    assert default_action_registry().get(EXECUTION) is not None


def test_the_ledger_and_the_trail_are_different_tables() -> None:
    """Stated where it can be checked: the two tables share nothing but their identity.

    A ledger row answers "did this run twice?"; a trail row answers "who did what, when,
    and what came of it". They are distinct records, written by different code, and the
    columns show it: no actor, no decision, no summary on one side, no fingerprint or
    error code on the other.
    """
    from aicore_api.db.models.action_execution import ActionExecution
    from aicore_api.db.models.audit_event import AuditEvent

    ledger_columns = set(ActionExecution.__table__.columns.keys())
    trail_columns = set(AuditEvent.__table__.columns.keys())

    # ``outcome`` is the one name they share, and it means different things: the ledger's
    # is the adapter's report, the trail's is what became of the event.
    assert ledger_columns & trail_columns == {"id", "organization_id", "outcome"}
    assert {"actor_id", "decision", "metadata", "correlation_id"} & ledger_columns == set()
    assert {"request_fingerprint", "error_code", "completed_at"} & trail_columns == set()
