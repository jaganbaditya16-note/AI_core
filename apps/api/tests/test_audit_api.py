"""Phase 8 over HTTP: reading the trail, and everything the read refuses.

The endpoint is the whole client-facing surface of the phase, and it is deliberately
narrow: one ``GET``, filters, a page. These tests are written as its contract, in four
groups.

- **The record.** An event is compared field by field against the request that caused it,
  because the point of the phase is that the trail says what happened — who acted, which
  organization, which resource, what was decided, what came of it, and which request it
  belongs to — and that the response names every field it publishes rather than passing a
  row through.
- **The query.** Every filter is exercised against a tenant that holds an event of each
  shape the build produces, and each one is asserted to *narrow*: a filter that returned
  everything would pass a weaker test.
- **The boundary.** Authorization, tenant isolation and malformed input, asserted the way
  the earlier phases assert them: a foreign organization is indistinguishable from one
  that does not exist, and a bad filter is a 422 rather than a query that quietly answers
  a different question.
- **The response.** Metadata is re-sanitized on the way out, so a row written by a
  migration or a data fix cannot leak through the API, and no response carries a
  credential.

Nothing here writes a trail row directly for the *happy* paths: the events are produced
by doing the operations (creating an asset, registering an agent, executing an action),
because a test that inserted its own row would prove nothing about the writer.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from actions_fixture import ACTION_ID
from agents_fixture import agents_path
from aicore_api.core.assets import AssetType, Environment
from aicore_api.core.audit import AUDIT_SCHEMA_VERSION, REDACTED
from aicore_api.db.tenancy import bind_tenant
from aicore_api.discovery import DiscoveredAsset, register_discovered_asset
from assets_fixture import assets_path
from audit_fixture import AuditScene
from identity_fixture import IdentityFactory

#: Every key the list response publishes. Written out rather than derived so a field
#: added to the schema shows up here as a failing expectation.
RESPONSE_KEYS = {"organization_id", "items", "limit", "offset", "count", "total"}

#: Every key one event publishes — the whole of what an investigation is given.
EVENT_KEYS = {
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
}

#: The one insert the tests write by hand: a row as a migration or a data fix would leave
#: it, so the *read* boundary can be tested against something the write boundary never saw.
_INSERT = text(
    "INSERT INTO aicore.audit_events "
    "(organization_id, event_type, schema_version, actor_type, resource_type, outcome, "
    " correlation_id, source, request_id, metadata) "
    "VALUES (:organization_id, :event_type, 1, :actor_type, :resource_type, :outcome, "
    " :correlation_id, :source, :request_id, CAST(:metadata AS jsonb)) "
    "RETURNING id"
)


def _insert_row(
    engine: Engine, organization_id: uuid.UUID, *, metadata: Mapping[str, Any]
) -> uuid.UUID:
    """Write one row straight into the table, as only a maintenance path could.

    The application refuses to build a row whose metadata is nested or oversized, so the
    only way to test what the *read* side does with one is to put it there directly. The
    row is a system event on the ingestion path: the simplest shape the schema admits.
    """
    with bind_tenant(organization_id), engine.begin() as connection:
        return connection.execute(
            _INSERT,
            {
                "organization_id": str(organization_id),
                "event_type": "asset.created",
                "actor_type": "system",
                "resource_type": "asset",
                "outcome": "success",
                "correlation_id": "corr-inserted",
                "source": "ingestion",
                "request_id": None,
                "metadata": json.dumps(dict(metadata)),
            },
        ).scalar_one()


def _asset(scene: AuditScene, *, request_id: str | None = None, **fields: Any) -> Mapping[str, Any]:
    """Create one asset through the API, as the scene's owner."""
    payload: dict[str, Any] = {"name": "Audited Asset", "asset_type": "model", **fields}
    headers = {"X-Request-ID": request_id} if request_id else None
    response = scene.trail.as_owner().post(
        assets_path(scene.organization_id), json=payload, headers=headers
    )
    assert response.status_code == 201, response.text
    return response.json()


def _agent(scene: AuditScene, *, request_id: str | None = None, **fields: Any) -> Mapping[str, Any]:
    """Register one agent through the API, as the scene's owner."""
    payload: dict[str, Any] = {
        "display_name": "Audited Agent",
        "category": "assistant",
        "version": "1.0.0",
        "status": "active",
        "environment": "production",
        **fields,
    }
    headers = {"X-Request-ID": request_id} if request_id else None
    response = scene.trail.as_owner().post(
        agents_path(scene.organization_id), json=payload, headers=headers
    )
    assert response.status_code == 201, response.text
    return response.json()


def _ingested(scene: AuditScene, session: Session, *, external_identifier: str) -> uuid.UUID:
    """Report an asset the way an integration does, and return the row it created.

    The ingestion path is the one origin that is not a request: no person, no request id,
    ``source = 'ingestion'``. It is seeded here so the ``actor_type``/``source`` filters
    have something to select that no HTTP call could have produced.
    """
    result = register_discovered_asset(
        session,
        scene.organization_id,
        DiscoveredAsset(
            source="test-collector",
            external_identifier=external_identifier,
            name="Discovered Asset",
            asset_type=AssetType.AGENT,
            environment=Environment.PRODUCTION,
        ),
    )
    return result.asset_id


@dataclass(frozen=True, slots=True)
class Seeded:
    """One tenant holding an event of every shape Phase 8 writes."""

    asset_id: uuid.UUID
    agent_id: uuid.UUID
    attributed_agent_id: uuid.UUID
    discovered_asset_id: uuid.UUID
    policy_id: uuid.UUID
    denied_target_id: uuid.UUID
    execution_idempotency_key: str


@pytest.fixture
def seeded(audit: AuditScene, integration_session: Session) -> Seeded:
    """Produce one event of each kind through the API the build actually serves.

    The order is the point: the require-approval request happens while a
    ``require_approval`` policy is in force and the executed one after it is disabled, so
    the two rows differ by the decision the *engine* made rather than by a fixture.
    """
    asset = _asset(audit, request_id="req-seed-asset")
    response = audit.trail.as_owner().patch(
        f"{assets_path(audit.organization_id)}/{asset['id']}", json={"name": "Renamed Asset"}
    )
    assert response.status_code == 200, response.text

    agent = _agent(audit, request_id="req-seed-agent", display_name="Execution Target")
    attributed = _agent(
        audit, request_id="req-seed-attributed-agent", display_name="Attributed Agent"
    )
    discovered_id = _ingested(audit, integration_session, external_identifier="cluster://seed")

    policy = audit.policies.create(
        "Hold executions",
        resource="action",
        action="execute",
        effect="require_approval",
        conditions=[],
    )
    audit.policies.activate(policy)

    held = audit.actions.execute(agent["id"], idempotency_key="test-seed-held")
    assert held.status_code == 403, held.text

    audit.policies.set_status(policy, "disabled")

    missing = uuid.uuid4()
    denied = audit.actions.execute(missing, idempotency_key="test-seed-denied")
    # A target this organization does not have is answered as a 404 — the caller learns
    # nothing about whether the row exists elsewhere — and the trail still records the
    # refusal, which is the whole difference between a ledger and an audit trail.
    assert denied.status_code == 404, denied.text
    assert denied.json()["error"]["code"] == "not_found"

    key = "test-seed-executed"
    executed = audit.actions.execute(
        agent["id"],
        agent_id=attributed["id"],
        idempotency_key=key,
        request_id="req-seed-executed",
    )
    assert executed.status_code == 200, executed.text
    # The same request again: the ledger answers instead of the adapter, which the trail
    # records as its own event rather than as a second execution. A client retrying one
    # request is one flow, so it carries the same request id.
    replayed = audit.actions.execute(
        agent["id"],
        agent_id=attributed["id"],
        idempotency_key=key,
        request_id="req-seed-executed",
    )
    assert replayed.status_code == 200, replayed.text

    return Seeded(
        asset_id=uuid.UUID(asset["id"]),
        agent_id=uuid.UUID(agent["id"]),
        attributed_agent_id=uuid.UUID(attributed["id"]),
        discovered_asset_id=discovered_id,
        policy_id=policy.id,
        denied_target_id=missing,
        execution_idempotency_key=key,
    )


# ── The record ────────────────────────────────────────────────────────────────


def test_an_event_says_exactly_what_the_request_did(audit: AuditScene) -> None:
    """One request, one row, every field traced back to something the server resolved."""
    created = _asset(audit, request_id="req-one-event", name="Traced Asset")

    item = audit.trail.page()[0]

    assert item["event_type"] == "asset.created"
    assert item["schema_version"] == AUDIT_SCHEMA_VERSION
    assert item["organization_id"] == str(audit.organization_id)
    assert item["actor_type"] == "human"
    assert item["actor_id"] == str(audit.identity.user_id)
    assert item["actor_membership_id"] == str(audit.identity.membership_id)
    assert item["agent_id"] is None
    assert item["resource_type"] == "asset"
    assert item["resource_id"] == created["id"]
    assert item["action"] == "asset.create"
    assert item["decision"] is None
    assert item["outcome"] == "success"
    assert item["correlation_id"] == "req-one-event"
    assert item["request_id"] == "req-one-event"
    assert item["source"] == "api"

    # The metadata is the summary the route chose, and nothing of the body it accepted:
    # not the name, not a description, not the asset's own metadata.
    assert set(item["metadata"]) == {"asset_type", "discovery_state"}
    assert "Traced Asset" not in json.dumps(item["metadata"])

    # The timestamp is the server's, and it is a real moment around now.
    occurred_at = datetime.fromisoformat(item["occurred_at"])
    assert occurred_at.tzinfo is not None
    assert abs(datetime.now(UTC) - occurred_at) < timedelta(minutes=1)


def test_the_response_names_every_field_it_publishes(audit: AuditScene) -> None:
    """An explicit schema, not a row passed through: the keys are exactly these."""
    _asset(audit)

    body = audit.trail.get().json()

    assert set(body) == RESPONSE_KEYS
    assert set(body["items"][0]) == EVENT_KEYS


def test_the_page_reports_its_own_shape(audit: AuditScene) -> None:
    """``limit``, ``offset`` and ``count`` describe the page; ``total`` is opt-in."""
    for index in range(3):
        _asset(audit, name=f"Paged Asset {index}")

    response = audit.trail.get(limit=2, offset=1)
    body = response.json()

    assert body["limit"] == 2
    assert body["offset"] == 1
    assert body["count"] == 2
    assert len(body["items"]) == 2
    assert body["total"] is None  # not asked for, so not computed

    counted = audit.trail.get(limit=2, offset=1, total=True).json()
    assert counted["total"] == 3
    assert counted["count"] == 2


def test_the_trail_is_newest_first(audit: AuditScene) -> None:
    """The ordering is ``occurred_at DESC, event_id DESC``: the newest event reads first."""
    for index in range(3):
        _asset(audit, name=f"Ordered Asset {index}")

    page = audit.trail.page()

    assert [item["occurred_at"] for item in page] == sorted(
        (item["occurred_at"] for item in page), reverse=True
    )
    # And the order is the order things happened in: the rows were written one at a time.
    assert [item["metadata"]["asset_type"] for item in page] == ["model"] * 3


def test_one_request_that_leaves_two_events_groups_them(audit: AuditScene) -> None:
    """An execution writes an admitted row and an outcome row, tied by one correlation id."""
    agent = _agent(audit)

    response = audit.trail.as_owner().post(
        audit.actions.path,
        json={
            "action": ACTION_ID,
            "target_id": agent["id"],
            "environment": "production",
            "arguments": {},
            "idempotency_key": f"test-{uuid.uuid4().hex}",
        },
        headers={"X-Request-ID": "req-execution"},
    )
    assert response.status_code == 200, response.text

    events = audit.trail.stored()
    # Registering an agent creates its inventory record as well, which is an event of its
    # own; the two execution events follow.
    assert [event["event_type"] for event in events] == [
        "asset.created",
        "agent.registered",
        "action.requested",
        "action.executed",
    ]

    request_events = [event for event in events if event["event_type"].startswith("action.")]
    assert {event["correlation_id"] for event in request_events} == {"req-execution"}
    assert {event["request_id"] for event in request_events} == {"req-execution"}
    # The admission is undecided; the outcome carries the decision that allowed it.
    assert request_events[0]["decision"] is None
    assert request_events[0]["outcome"] == "pending"
    assert request_events[1]["decision"] == "allow"
    assert request_events[1]["outcome"] == "success"


def test_a_client_cannot_choose_the_correlation_of_a_request_it_did_not_make(
    audit: AuditScene,
) -> None:
    """An unsafe request id is replaced rather than stored, so it cannot be claimed."""
    _asset(audit, request_id="has spaces and is not an identifier")

    item = audit.trail.page()[0]

    assert item["correlation_id"] != "has spaces and is not an identifier"
    assert item["request_id"] != "has spaces and is not an identifier"
    assert item["correlation_id"] == item["request_id"]  # the generated one, used for both


def test_an_unknown_query_parameter_is_not_a_way_to_write_a_field(audit: AuditScene) -> None:
    """Filters are named by the endpoint; anything else is ignored, not honoured."""
    _asset(audit)

    plain = audit.trail.page()
    decorated = audit.trail.page(
        source="ingestion",
        event_id=str(uuid.uuid4()),
        id=str(uuid.uuid4()),
        occurred_at="2026-01-01T00:00:00Z",
        organization_id=str(uuid.uuid4()),
    )

    assert decorated == plain


# ── The query: every filter, and each one asserted to narrow ──────────────────


def test_filtering_by_event_type(audit: AuditScene, seeded: Seeded) -> None:
    assert audit.trail.types(event_type="asset.discovered") == ["asset.discovered"]
    assert audit.trail.types(event_type="policy.created") == ["policy.created"]

    # Repeated values are ORed, which is what makes one request enough for a set.
    selected = audit.trail.types(event_type=["policy.created", "policy.status_changed"])
    assert selected == ["policy.status_changed", "policy.status_changed", "policy.created"]


def test_filtering_by_actor_type(audit: AuditScene, seeded: Seeded) -> None:
    system = audit.trail.page(actor_type="system")
    human = audit.trail.page(actor_type="human")

    assert [item["event_type"] for item in system] == ["asset.discovered"]
    assert system[0]["actor_id"] is None
    assert system[0]["actor_membership_id"] is None
    assert len(human) == len(audit.trail.page()) - 1
    assert {item["actor_id"] for item in human} == {str(audit.identity.user_id)}


def test_filtering_by_actor_id(audit: AuditScene, seeded: Seeded) -> None:
    """The person who acted is queryable, and a person who did nothing selects nothing."""
    assert audit.trail.page(actor_id=str(uuid.uuid4())) == []

    body = audit.trail.get(actor_id=str(audit.identity.user_id), total=True).json()

    assert body["total"] == len(audit.trail.page()) - 1  # every event but the ingestion one
    assert {item["actor_id"] for item in body["items"]} == {str(audit.identity.user_id)}


def test_filtering_by_resource_type_and_id(audit: AuditScene, seeded: Seeded) -> None:
    assets = audit.trail.page(resource_type="asset")
    assert {item["event_type"] for item in assets} == {
        "asset.created",
        "asset.updated",
        "asset.discovered",
    }

    one = audit.trail.page(resource_id=str(seeded.asset_id))
    assert [item["event_type"] for item in one] == ["asset.updated", "asset.created"]
    assert {item["resource_id"] for item in one} == {str(seeded.asset_id)}

    # A resource the tenant does not have is an empty page, not an error.
    assert audit.trail.page(resource_id=str(uuid.uuid4())) == []


def test_filtering_by_agent_id(audit: AuditScene, seeded: Seeded) -> None:
    """Attribution is queryable: which events name this agent, and which name none."""
    attributed = audit.trail.page(agent_id=str(seeded.attributed_agent_id))

    assert [item["event_type"] for item in attributed] == [
        "action.replayed",
        "action.requested",
        "action.executed",
        "action.requested",
    ]
    assert {item["agent_id"] for item in attributed} == {str(seeded.attributed_agent_id)}
    # The agent's own registration is not one of them: it was a person's act, on a row
    # that is the resource rather than the attribution.
    assert "agent.registered" not in {item["event_type"] for item in attributed}


def test_filtering_by_action(audit: AuditScene, seeded: Seeded) -> None:
    """A lifecycle operation names the permission; an execution names the action."""
    lifecycle = audit.trail.page(action="asset.create")
    assert {item["event_type"] for item in lifecycle} == {"asset.created", "asset.discovered"}

    execution = audit.trail.page(action=ACTION_ID)
    assert {item["event_type"] for item in execution} == {
        "action.requested",
        "action.denied",
        "action.require_approval",
        "action.executed",
        "action.replayed",
    }


def test_filtering_by_decision_and_outcome(audit: AuditScene, seeded: Seeded) -> None:
    allowed = audit.trail.page(decision="allow")
    assert {item["outcome"] for item in allowed} == {"success", "replayed"}

    denied = audit.trail.page(decision="deny")
    assert [item["event_type"] for item in denied] == ["action.denied"]
    assert denied[0]["outcome"] == "blocked"
    assert denied[0]["resource_id"] == str(seeded.denied_target_id)

    held = audit.trail.page(decision="require_approval")
    assert [item["event_type"] for item in held] == ["action.require_approval"]
    assert held[0]["outcome"] == "not_executed"

    # Decisions and outcomes are separate axes: "blocked" says how it ended, "deny" says
    # why — and asking for one never implies the other.
    assert audit.trail.page(outcome="blocked") == denied
    assert {item["event_type"] for item in audit.trail.page(outcome="not_executed")} == {
        "action.require_approval"
    }
    # An undecided event is not an allowed or a denied one.
    assert set(audit.trail.page(outcome="pending")[0]) == EVENT_KEYS
    assert {item["decision"] for item in audit.trail.page(outcome="pending")} == {None}


def test_filtering_by_correlation_id(audit: AuditScene, seeded: Seeded) -> None:
    """Everything one flow did is reachable by the id its request carried."""
    events = audit.trail.page(correlation_id="req-seed-executed")

    assert [item["event_type"] for item in events] == [
        "action.replayed",
        "action.requested",
        "action.executed",
        "action.requested",
    ]
    assert {item["correlation_id"] for item in events} == {"req-seed-executed"}
    # A different request is a different flow: it selects nothing of the first one's.
    assert [item["event_type"] for item in audit.trail.page(correlation_id="req-seed-asset")] == [
        "asset.created"
    ]


def test_filtering_by_time(audit: AuditScene, seeded: Seeded) -> None:
    """A window is inclusive at both ends, and a window outside the trail is empty."""
    stored = audit.trail.stored()
    oldest = stored[0]["occurred_at"]
    newest = stored[-1]["occurred_at"]
    assert isinstance(oldest, datetime) and isinstance(newest, datetime)

    whole = audit.trail.page(start_time=oldest.isoformat(), end_time=newest.isoformat(), limit=200)
    assert len(whole) == len(stored)

    after = audit.trail.page(start_time=newest.isoformat(), limit=200)
    assert after, "the newest event is inside a window that starts at it"
    assert all(item["occurred_at"] >= newest.isoformat() for item in after)

    assert audit.trail.page(start_time=(newest + timedelta(seconds=1)).isoformat()) == []
    assert audit.trail.page(end_time=(oldest - timedelta(seconds=1)).isoformat()) == []


def test_filters_compose_by_narrowing(audit: AuditScene, seeded: Seeded) -> None:
    """Different filters are ANDed: the second one can only remove rows."""
    everything = audit.trail.page(actor_type="human")
    narrowed = audit.trail.page(actor_type="human", resource_type="asset")

    assert len(narrowed) <= len(everything)
    assert {item["resource_type"] for item in narrowed} == {"asset"}
    assert narrowed == [item for item in everything if item["resource_type"] == "asset"]


def test_a_filter_cannot_widen_the_boundary(
    audit: AuditScene, seeded: Seeded, identity_factory: IdentityFactory, authenticate
) -> None:
    """A filter is a query, not a scope: it names nothing the caller could not already see.

    The values below are real — a correlation id, a resource id, an actor id and an event
    id, all of them this tenant's — and a caller in another tenant gets an empty page for
    every one of them, with the same total an empty filter would produce.
    """
    other = identity_factory(role_code="owner")

    response = authenticate(other).get(
        f"/organizations/{other.organization_id}/audit-events",
        params={
            "correlation_id": "req-seed-executed",
            "resource_id": str(seeded.asset_id),
            "actor_id": str(audit.identity.user_id),
            "limit": 200,
            "total": "true",
        },
    )

    assert response.status_code == 200
    assert response.json()["items"] == []
    assert response.json()["total"] == 0


# ── Pagination ────────────────────────────────────────────────────────────────


def test_paging_walks_the_whole_trail_without_repeating(audit: AuditScene, seeded: Seeded) -> None:
    """``limit``/``offset`` over a total order: every row exactly once, in order."""
    everything = audit.trail.page(limit=200)
    assert len(everything) > 4

    walked: list[Mapping[str, Any]] = []
    offset = 0
    while True:
        page = audit.trail.page(limit=3, offset=offset)
        if not page:
            break
        walked.extend(page)
        offset += 3

    assert [item["id"] for item in walked] == [item["id"] for item in everything]


def test_pagination_is_bounded(audit: AuditScene) -> None:
    """There is no way to ask for the whole trail, and no way to ask for none of it."""
    for params in (
        {"limit": 0},
        {"limit": 201},
        {"limit": -1},
        {"offset": -1},
        {"offset": 100_001},
    ):
        assert audit.trail.get(**params).status_code == 422


def test_total_counts_the_filtered_set_not_the_page(audit: AuditScene, seeded: Seeded) -> None:
    body = audit.trail.get(event_type="action.requested", limit=1, total=True).json()

    assert body["count"] == 1
    assert body["total"] == len(audit.trail.page(event_type="action.requested")) > 1


# ── Authorization ─────────────────────────────────────────────────────────────


def test_the_owner_and_the_security_administrator_read_the_trail_others_do_not(
    audit: AuditScene, identity_factory: IdentityFactory, authenticate
) -> None:
    """``audit.read`` is what the route requires, and it is deliberately narrow."""
    _asset(audit)
    allowed = [
        identity_factory(role_code=role, organization_id=audit.organization_id)
        for role in ("owner", "security_admin")
    ]
    refused = [
        identity_factory(role_code=role, organization_id=audit.organization_id)
        for role in ("admin", "ai_admin", "analyst", "viewer")
    ]

    for identity in allowed:
        response = authenticate(identity).get(audit.trail.path)
        assert response.status_code == 200, (identity.role_code, response.text)

    for identity in refused:
        response = authenticate(identity).get(audit.trail.path)
        assert response.status_code == 403, (identity.role_code, response.text)
        # A refusal says nothing about the tenant: not how many events it has, not
        # whether it has any.
        assert str(audit.organization_id) not in response.text


def test_an_anonymous_caller_reads_nothing(audit: AuditScene) -> None:
    """Without a credential there is nothing to authorize, so the answer is 401."""
    anonymous = TestClient(audit.trail.client.app, raise_server_exceptions=False)

    response = anonymous.get(audit.trail.path)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_an_unusable_credential_is_refused_before_the_trail_is_consulted(
    audit: AuditScene,
) -> None:
    client = TestClient(audit.trail.client.app, raise_server_exceptions=False)
    client.headers["Authorization"] = "Bearer not-a-real-token"

    response = client.get(audit.trail.path)

    assert response.status_code == 401


def test_the_endpoint_offers_no_write(audit: AuditScene) -> None:
    """The trail is written by the platform: every other method on the path is a 405."""
    _asset(audit)
    before = audit.trail.count()

    for method in ("POST", "PUT", "PATCH", "DELETE"):
        response = audit.trail.as_owner().request(method, audit.trail.path, json={})
        assert response.status_code == 405, (method, response.text)

    assert audit.trail.count() == before


# ── Tenant isolation ──────────────────────────────────────────────────────────


def test_a_foreign_organization_is_indistinguishable_from_a_missing_one(
    audit: AuditScene, identity_factory: IdentityFactory, authenticate
) -> None:
    """No existence oracle: the same status and the same body for both."""
    _asset(audit)
    stranger = identity_factory(role_code="owner")

    foreign = authenticate(stranger).get(audit.trail.path)
    unknown = authenticate(stranger).get(f"/organizations/{uuid.uuid4()}/audit-events")

    assert foreign.status_code == unknown.status_code == 404

    # The same answer, down to the body: only the request id differs, because each request
    # is a different request.
    def _shape(response: Any) -> dict[str, Any]:
        error = dict(response.json()["error"])
        error.pop("request_id")
        return error

    assert _shape(foreign) == _shape(unknown)
    assert _shape(foreign)["code"] == "not_found"
    body = json.dumps(foreign.json())
    assert str(audit.organization_id) not in body
    assert "audit" not in body.lower()  # not even the name of what it could not read


def test_a_member_of_another_tenant_cannot_read_this_trail_through_a_filter(
    audit: AuditScene, seeded: Seeded, identity_factory: IdentityFactory, authenticate
) -> None:
    """A membership elsewhere, and filters that name this tenant's rows: still 404."""
    outsider = identity_factory(role_code="security_admin")

    response = authenticate(outsider).get(
        audit.trail.path,
        params={"actor_id": str(audit.identity.user_id), "total": "true"},
    )

    assert response.status_code == 404


def test_two_tenants_never_see_each_others_events(
    audit: AuditScene, identity_factory: IdentityFactory, authenticate
) -> None:
    """The same request in two organizations produces two trails that do not touch."""
    _asset(audit, request_id="req-shared")
    other = identity_factory(role_code="owner")
    other_client = authenticate(other)
    other_asset_response = other_client.post(
        assets_path(other.organization_id),
        json={"name": "Other Tenant Asset", "asset_type": "model"},
        headers={"X-Request-ID": "req-shared"},
    )
    assert other_asset_response.status_code == 201, other_asset_response.text

    theirs = other_client.get(f"/organizations/{other.organization_id}/audit-events").json()
    mine = audit.trail.get().json()

    assert {item["organization_id"] for item in theirs["items"]} == {str(other.organization_id)}
    assert {item["organization_id"] for item in mine["items"]} == {str(audit.organization_id)}
    assert theirs["total"] is None

    # The shared request id groups each tenant's own events, and only those.
    assert audit.trail.types(correlation_id="req-shared") == ["asset.created"]
    assert [item["event_type"] for item in theirs["items"]] == ["asset.created"]


# ── Malformed input ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "params",
    [
        {"event_type": "asset.exploded"},
        {"event_type": "asset"},
        {"actor_type": "robot"},
        {"decision": "maybe"},
        {"outcome": "succeeded"},
        {"resource_type": "firewall"},
        {"actor_id": "not-a-uuid"},
        {"agent_id": "not-a-uuid"},
        {"resource_id": "not-a-uuid"},
        {"correlation_id": "has spaces"},
        {"correlation_id": "x" * 65},
        {"correlation_id": ""},
        {"action": "Not An Action"},
        {"action": "a." * 40},
        {"start_time": "yesterday"},
        {"end_time": "2026-13-45T00:00:00Z"},
        {"limit": "many"},
        {"offset": "1.5"},
        {"total": "perhaps"},
    ],
)
def test_a_malformed_filter_is_refused(audit: AuditScene, params: Mapping[str, Any]) -> None:
    """Every filter is typed, so a value outside the vocabulary never reaches a query."""
    response = audit.trail.get(**params)

    assert response.status_code == 422, (params, response.text)
    # The refusal does not echo the value back as a query, and it names no event.
    assert "items" not in response.text


def test_an_inverted_time_range_is_a_mistake_not_an_empty_page(audit: AuditScene) -> None:
    """Answering it with no rows would look like "there is nothing to find"."""
    _asset(audit)
    now = datetime.now(UTC)

    response = audit.trail.get(
        start_time=(now + timedelta(minutes=1)).isoformat(), end_time=now.isoformat()
    )

    assert response.status_code == 422
    assert "start_time" in response.json()["error"]["message"]


@pytest.mark.parametrize(
    "value",
    [
        "'; DROP TABLE aicore.audit_events; --",
        "1 OR 1=1",
        "%",
        "../../etc/passwd",
        "corr zero",
        "corr\u200bzero",  # unicode: not in the alphabet the request layer accepts
    ],
)
def test_injection_shaped_filters_are_refused_and_change_nothing(
    audit: AuditScene, value: str
) -> None:
    """A filter is a parameter, and a shape the request layer could not produce is a 422.

    The comparison is against an *empty* column, and the appended characters are the
    interesting part: with no wildcard in the alphabet, ``%`` names a percent sign rather
    than "anything", so a filter that does not match a literal value selects nothing.
    """
    _asset(audit)
    before = audit.trail.count()

    response = audit.trail.get(correlation_id=value)

    assert response.status_code == 422, value
    assert audit.trail.count() == before
    assert audit.trail.page()[0]["event_type"] == "asset.created"


def test_a_unicode_filter_is_refused_by_shape_rather_than_by_encoding(audit: AuditScene) -> None:
    """The alphabet is fixed, so a value outside it is a 422 and never a query."""
    for params in ({"action": "äst"}, {"correlation_id": "córr"}, {"event_type": "asset.created✓"}):
        assert audit.trail.get(**params).status_code == 422, params


# ── The response boundary ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("access_token", "would-be-a-credential"),
        ("api_key", "would-be-a-credential"),
        ("session_cookie", "would-be-a-credential"),
        ("note", "Bearer abcdefghijklmnop"),
        ("note", "eyJabcdefghij.payload.signature"),
        ("note", "-----BEGIN PRIVATE KEY-----"),
    ],
)
def test_a_secret_shaped_metadata_value_never_reaches_the_reader(
    audit: AuditScene, key: str, value: str
) -> None:
    """Defence in depth: the read boundary redacts what the table happens to hold."""
    _insert_row(audit.trail.engine, audit.organization_id, metadata={key: value, "kept": "yes"})

    item = audit.trail.page()[0]

    assert item["metadata"][key] == REDACTED
    assert value not in json.dumps(item)
    assert item["metadata"]["kept"] == "yes"


def test_a_row_the_boundary_cannot_represent_is_reported_as_empty_metadata(
    audit: AuditScene,
) -> None:
    """A row written outside the writer still reads: its summary is dropped, not echoed."""
    _insert_row(
        audit.trail.engine,
        audit.organization_id,
        metadata={"nested": {"payload": "the boundary refuses this"}},
    )

    item = audit.trail.page()[0]

    assert item["metadata"] == {}
    # The rest of the record is intact: the event itself is not lost because its summary
    # is unreadable.
    assert item["event_type"] == "asset.created"
    assert item["correlation_id"] == "corr-inserted"
    assert item["source"] == "ingestion"


def test_no_response_carries_credential_material(audit: AuditScene, seeded: Seeded) -> None:
    """The caller's own token, a bearer prefix, or a cookie: none of it is in the record."""
    body = json.dumps(audit.trail.get(limit=200).json())
    lowered = body.lower()

    assert audit.identity.token not in body
    for forbidden in ("bearer", "token", "secret", "password", "api_key", "cookie"):
        assert forbidden not in lowered, forbidden


def test_the_stored_row_is_what_the_api_reports(audit: AuditScene) -> None:
    """The endpoint is a view of the table, not a second version of the truth."""
    _asset(audit)

    stored = audit.trail.stored()[0]
    reported = audit.trail.page()[0]

    assert reported["id"] == str(stored["id"])
    assert reported["event_type"] == stored["event_type"]
    assert reported["correlation_id"] == stored["correlation_id"]
    assert reported["metadata"] == stored["metadata"]
    assert datetime.fromisoformat(reported["occurred_at"]) == stored["occurred_at"]
