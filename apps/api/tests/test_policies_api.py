"""The policy API: definition, lifecycle, versioning, evaluation — and nothing else.

Phase 6's routes are a governance record with a dry-run read on top. These tests
assert the three properties that make that a control rather than a feature:

- **The record is reproducible.** Editing a definition appends a version; the old
  version still says what it said. Nothing here rewrites history, and nothing here
  lets a client pretend a version is a later one.
- **The record never acts.** Every route either reads or writes the record. The one
  route that evaluates is a dry run: it reports what the two layers answered and
  performs no action, no approval and no enforcement.
- **The vocabulary is closed at the edge.** A resource, action, condition field,
  operator, value or lifecycle state this build does not declare is refused when it
  is written, not stored and skipped when it is evaluated.

Tenant isolation and authorization have their own files — ``test_policies.py`` for
the database, ``test_permissions.py``/``test_authorization.py`` for who may call
what — and the language is checked in ``test_policy_conditions.py``.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aicore_api.core.policy import (
    DEFAULT_PRIORITY,
    POLICY_DESCRIPTION_MAX_LENGTH,
    POLICY_NAME_MAX_LENGTH,
)
from identity_fixture import Identity, IdentityFactory
from policies_fixture import (
    DEFAULT_CONDITION,
    PolicyFactory,
    count_policies,
    count_versions,
    policy_payload,
)


def _collection(identity: Identity) -> str:
    return f"/organizations/{identity.organization_id}/policies"


def _code(response: Any) -> str:
    """The error code the envelope carries, for the tests about refusals."""
    return str(response.json()["error"]["code"])


# ── Defining a policy ────────────────────────────────────────────────────────


def test_a_policy_is_created_as_a_draft_with_its_definition(policies: PolicyFactory) -> None:
    """Creation stores the record and its first version, and it is not yet in force."""
    created = policies.create("Production agent changes", effect="deny", priority=10)

    assert created.status == "draft"
    assert created.version == 1
    assert created.effect == "deny"
    assert created.resource == "agent"
    assert created.action == "update"
    assert created.priority == 10
    assert list(created.conditions) == [DEFAULT_CONDITION]

    body = created.body
    assert body["organization_id"] == str(policies.organization_id)
    assert body["description"].startswith("Written by the test suite")
    assert body["created_at"] <= body["updated_at"]
    # A draft is a record, not a control: reading it back gives exactly what was
    # written, and nothing about the create is lost on the way through the API.
    assert policies.read(created).json() == body


def test_a_policy_is_created_with_the_default_priority_when_none_is_given(
    policies: PolicyFactory,
) -> None:
    """An omitted priority is the documented default, not an arbitrary number."""
    response = policies.post(
        {
            "name": "Defaults",
            "description": "No priority and no conditions.",
            "resource": "asset",
            "action": "delete",
            "effect": "require_approval",
        }
    )

    assert response.status_code == 201, response.text
    assert response.json()["priority"] == DEFAULT_PRIORITY
    assert response.json()["conditions"] == []
    assert response.json()["status"] == "draft"


def test_a_policy_may_be_created_active(policies: PolicyFactory) -> None:
    """``active`` is an initial state: a policy can be put in force as it is defined."""
    assert policies.create("In force from the start", status="active").status == "active"


@pytest.mark.parametrize("status", ["disabled", "retired"])
def test_a_policy_cannot_be_created_disabled_or_retired(
    policies: PolicyFactory, status: str
) -> None:
    """Those are states a policy *moves to*; being born there would be a quiet record."""
    response = policies.post(policy_payload("Born dead", status=status))

    assert response.status_code == 422
    assert _code(response) == "validation_error"
    assert "status" in response.text


def test_the_same_name_cannot_be_used_twice_in_one_organization(
    policies: PolicyFactory,
) -> None:
    """Names are how people refer to a policy; two of them would make that ambiguous."""
    policies.create("Staging guard")

    duplicate = policies.post(policy_payload("Staging guard"))

    assert duplicate.status_code == 409
    assert _code(duplicate) == "conflict"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("resource", "firewall"),
        ("resource", "incident"),
        ("action", "block"),
        # Paired with the default resource this is ``agent.approve``: still a pair no
        # phase declares. ``action.execute`` itself is declared — Phase 7's target — and
        # is exercised in ``test_action_*``.
        ("action", "approve"),
        ("side_effects", True),
    ],
)
def test_a_target_or_field_this_build_does_not_declare_is_refused(
    policies: PolicyFactory, field: str, value: Any
) -> None:
    """The vocabulary is closed at the edge: no future resource, no stray field.

    ``firewall`` and ``incident`` are resources a later phase owns, which is exactly
    why no policy may be written about them here: this build cannot enforce a
    capability it does not have, and a policy about one would be a claim rather than
    a control.
    """
    response = policies.post(policy_payload("Nope", **{field: value}))

    assert response.status_code == 422
    assert _code(response) == "validation_error"


def test_a_condition_outside_the_language_is_refused_with_the_reason(
    policies: PolicyFactory,
) -> None:
    """An unusable condition is rejected at the edge, not stored and skipped later."""
    response = policies.post(
        policy_payload(
            "Half a condition",
            conditions=[{"field": "environment", "operator": "sql_like", "value": "%prod%"}],
        )
    )

    assert response.status_code == 422
    assert _code(response) == "validation_error"
    # The refusal names the field that was wrong and the operators that exist,
    # without echoing a value the language does not accept.
    assert "conditions" in response.text
    assert "greater_than_or_equal" in response.text


def test_a_condition_of_the_wrong_type_for_its_field_is_refused(
    policies: PolicyFactory,
) -> None:
    """``environment`` is a closed set of strings: ``1`` is not one of them."""
    response = policies.post(
        policy_payload(
            "Typed wrongly",
            conditions=[{"field": "environment", "operator": "equals", "value": 1}],
        )
    )

    assert response.status_code == 422
    assert "string" in response.text


def test_an_empty_or_over_long_name_and_description_are_refused(
    policies: PolicyFactory,
) -> None:
    """Bounded text, trimmed: a policy is a rule an operator reads in one screen."""
    responses = (
        policies.post(policy_payload("x" * (POLICY_NAME_MAX_LENGTH + 1))),
        policies.post(
            policy_payload("Long", description="y" * (POLICY_DESCRIPTION_MAX_LENGTH + 1))
        ),
        policies.post(policy_payload("Blank", description="")),
    )

    for response in responses:
        assert response.status_code == 422, response.text


def test_a_name_is_stored_trimmed(policies: PolicyFactory) -> None:
    """Two spellings of one name would defeat the uniqueness the database enforces."""
    assert policies.create("  Padded name  ").name == "Padded name"


# ── Reading and listing ──────────────────────────────────────────────────────


def test_the_listing_filters_by_the_current_version(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """Filters describe what a policy *now* says, never what it said before."""
    denied = policies.create("Denied", effect="deny", resource="agent")
    allowed = policies.create("Allowed", effect="allow", resource="asset", action="delete")

    denied_page = policies.get(effect="deny")
    asset_page = policies.get(resource="asset")
    agent_deny = policies.get(effect="deny", resource="agent")

    assert [item["policy_id"] for item in denied_page.json()["items"]] == [str(denied.id)]
    assert [item["policy_id"] for item in asset_page.json()["items"]] == [str(allowed.id)]
    assert [item["policy_id"] for item in agent_deny.json()["items"]] == [str(denied.id)]
    assert agent_deny.json()["count"] == 1
    assert agent_deny.json()["total"] is None


def test_a_filter_moves_with_the_definition_it_describes(policies: PolicyFactory) -> None:
    """After an edit the policy answers the *new* filter, and no longer the old one."""
    policy = policies.create("Was a deny", effect="deny")
    policies.patch(policy, {"effect": "allow"})

    assert policies.get(effect="deny").json()["count"] == 0
    assert policies.get(effect="allow").json()["count"] == 1


def test_the_total_is_reported_only_when_it_is_asked_for(policies: PolicyFactory) -> None:
    """The filtered total costs a second query, so it is opt-in — and it agrees."""
    policies.create("One")
    policies.create("Two", effect="allow")

    without = policies.get()
    with_total = policies.get(total="true")

    assert without.json()["count"] == 2
    assert without.json()["total"] is None
    assert with_total.json()["total"] == 2


def test_a_page_is_bounded_and_paged_deterministically(policies: PolicyFactory) -> None:
    """No unbounded listing, no skipped row, no repeated row."""
    for index in range(3):
        policies.create(f"Policy {index}")

    first = policies.get(limit=2, offset=0)
    second = policies.get(limit=2, offset=2)

    ids = [item["policy_id"] for item in first.json()["items"] + second.json()["items"]]
    assert len(ids) == 3
    assert len(set(ids)) == 3
    assert policies.get(limit=201).status_code == 422


def test_an_unknown_policy_id_is_a_404(policies: PolicyFactory) -> None:
    """The route is addressable only by real identifiers of this organization."""
    response = policies.get(f"{policies.path}/{uuid.uuid4()}")

    assert response.status_code == 404
    assert _code(response) == "not_found"


# ── Lifecycle ────────────────────────────────────────────────────────────────


def test_a_policy_can_be_activated_disabled_reactivated_and_retired(
    policies: PolicyFactory,
) -> None:
    """The lifecycle is a table, and every edge in it works."""
    policy = policies.create("Lifecycle")
    assert policy.status == "draft"

    active = policies.set_status(policy, "active")
    assert active.status == "active"

    disabled = policies.set_status(active, "disabled")
    assert disabled.status == "disabled"

    reactivated = policies.set_status(disabled, "active")
    assert reactivated.status == "active"

    assert policies.set_status(reactivated, "retired").status == "retired"


def test_an_impossible_lifecycle_move_is_a_conflict(policies: PolicyFactory) -> None:
    """Retired is terminal, and the refusal names the state it could not leave."""
    policy = policies.set_status(policies.create("Terminal"), "retired")

    response = policies.patch(policy, {"status": "active"})

    assert response.status_code == 409
    assert _code(response) == "conflict"
    assert "terminal" in response.text


def test_a_draft_cannot_be_disabled_directly(policies: PolicyFactory) -> None:
    """Disabling means "take this out of force"; a draft was never in force."""
    response = policies.patch(policies.create("Never in force"), {"status": "disabled"})

    assert response.status_code == 409
    assert "draft" in response.text


def test_activating_a_policy_twice_is_not_an_error(policies: PolicyFactory) -> None:
    """A retried activation is idempotent: the state asked for is the state held."""
    policy = policies.set_status(policies.create("Idempotent"), "active")

    again = policies.patch(policy, {"status": "active"})

    assert again.status_code == 200, again.text
    assert again.json()["status"] == "active"
    assert again.json()["version"] == 1


def test_an_unknown_lifecycle_state_is_refused(policies: PolicyFactory) -> None:
    """The states are a closed set, checked before the transition table is read."""
    response = policies.patch(policies.create("States"), {"status": "suspended"})

    assert response.status_code == 422
    assert _code(response) == "validation_error"


# ── Versioning ───────────────────────────────────────────────────────────────


def test_editing_the_definition_appends_a_version_and_keeps_the_old_one(
    policies: PolicyFactory,
) -> None:
    """A published version is never rewritten; the new one is a new row."""
    policy = policies.create("Edited", priority=10)
    assert policy.version == 1

    response = policies.patch(
        policy,
        {
            "priority": 5,
            "conditions": [{"field": "risk_classification", "operator": "equals", "value": "high"}],
        },
    )

    assert response.status_code == 200, response.text
    published = response.json()
    assert published["version"] == 2
    assert published["priority"] == 5
    assert published["conditions"] == [
        {"field": "risk_classification", "operator": "equals", "value": "high"}
    ]

    history = policies.versions(policy)
    assert history.status_code == 200, history.text
    body = history.json()
    assert [entry["version"] for entry in body["items"]] == [1, 2]
    assert body["current_version"] == 2
    assert body["total"] == 2
    assert body["items"][0]["conditions"] == [DEFAULT_CONDITION]
    assert body["items"][0]["priority"] == 10
    assert body["items"][1]["priority"] == 5


def test_changing_only_the_label_does_not_publish_a_version(policies: PolicyFactory) -> None:
    """A name is what a person calls the policy; it does not change what it does."""
    renamed = policies.patch(
        policies.create("Before"), {"name": "After", "description": "Sharpened wording."}
    )

    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["name"] == "After"
    assert renamed.json()["version"] == 1


def test_a_patch_that_changes_nothing_does_not_publish_a_version(
    policies: PolicyFactory,
) -> None:
    """Sending the current values back is not an edit, and does not inflate history."""
    policy = policies.create("Unchanged", priority=7)

    response = policies.patch(policy, {"priority": 7, "effect": "deny"})

    assert response.status_code == 200, response.text
    assert response.json()["version"] == 1


def test_a_patch_partially_edits_the_definition_and_the_rest_carries_over(
    policies: PolicyFactory,
) -> None:
    """A definition is a whole; a partial edit is completed from the current version."""
    policy = policies.create("Partial", priority=42, effect="deny", conditions=[])

    response = policies.patch(policy, {"conditions": [dict(DEFAULT_CONDITION)]})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["version"] == 2
    assert body["priority"] == 42
    assert body["effect"] == "deny"
    assert body["conditions"] == [DEFAULT_CONDITION]


def test_the_version_history_is_readable_newest_last_and_bounded(
    policies: PolicyFactory,
) -> None:
    """Every version of a policy is readable, oldest first, and the read is paged."""
    policy = policies.create("Historied")
    for priority in (90, 80, 70):
        policies.patch(policy, {"priority": priority})

    body = policies.versions(policy).json()
    assert [entry["version"] for entry in body["items"]] == [1, 2, 3, 4]
    assert body["count"] == 4
    assert body["total"] == 4

    page = policies.versions(policy, limit=2, offset=0).json()
    second = policies.versions(policy, limit=2, offset=2).json()
    assert [entry["version"] for entry in page["items"]] == [1, 2]
    assert [entry["version"] for entry in second["items"]] == [3, 4]
    assert page["total"] == 4
    assert policies.versions(policy, limit=201).status_code == 422


def test_a_definition_edit_cannot_publish_a_target_that_does_not_exist(
    policies: PolicyFactory,
) -> None:
    """The same gate as creation: a PATCH cannot publish what a POST cannot create."""
    policy = policies.create("Guarded")

    response = policies.patch(policy, {"resource": "firewall", "action": "block"})

    assert response.status_code == 422
    assert policies.read(policy).json()["version"] == 1


def test_clearing_every_condition_is_an_edit_that_is_recorded(policies: PolicyFactory) -> None:
    """``conditions: []`` means "no conditions" — a blanket rule — not "unchanged"."""
    policy = policies.create("Conditional")

    response = policies.patch(policy, {"conditions": []})

    assert response.status_code == 200, response.text
    assert response.json()["conditions"] == []
    assert response.json()["version"] == 2


def test_the_definition_cannot_be_nulled_out(policies: PolicyFactory) -> None:
    """Omitted means unchanged; explicit null is refused rather than guessed at."""
    response = policies.patch(policies.create("NotNullable"), {"conditions": None})

    assert response.status_code == 422
    assert "conditions" in response.text


def test_an_empty_patch_is_refused(policies: PolicyFactory) -> None:
    """A request that asks for nothing is a client bug, not a silent success."""
    response = policies.patch(policies.create("Empty patch"), {})

    assert response.status_code == 422
    assert "at least one" in response.text


def test_an_unknown_patch_field_is_refused(policies: PolicyFactory) -> None:
    """Extra keys are refused everywhere in this API; a policy is no exception."""
    response = policies.patch(policies.create("Extra keys"), {"permissions": ["agent.delete"]})

    assert response.status_code == 422


# ── Deleting ─────────────────────────────────────────────────────────────────


def test_deleting_a_policy_removes_it_and_its_history(
    policies: PolicyFactory, integration_engine
) -> None:
    """The record and its versions go together: an orphaned version is unreachable."""
    policy = policies.create("Doomed")
    policies.patch(policy, {"priority": 3})

    deleted = policies.delete(policy.item_path)

    assert deleted.status_code == 204
    assert policies.read(policy).status_code == 404
    assert count_policies(integration_engine, policies.organization_id) == 0
    assert count_versions(integration_engine, policies.organization_id) == 0


def test_deleting_an_unknown_policy_is_a_404(policies: PolicyFactory) -> None:
    """Deleting what is not there fails the same way reading it does."""
    response = policies.delete(f"{policies.path}/{uuid.uuid4()}")

    assert response.status_code == 404
    assert _code(response) == "not_found"


# ── The dry run ──────────────────────────────────────────────────────────────


def _evaluate(
    client: TestClient,
    identity: Identity,
    *,
    resource: str = "agent",
    action: str = "update",
    facts: Mapping[str, Any] | None = None,
) -> Any:
    return client.post(
        f"{_collection(identity)}/evaluate",
        json={
            "resource": resource,
            "action": action,
            "facts": {"environment": "production"} if facts is None else dict(facts),
        },
    )


def test_the_dry_run_reports_both_layers_and_never_acts(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """The evaluation is a report: authorization, policy and the effective answer."""
    policy = policies.create("Deny production agents", effect="deny")
    policies.activate(policy)

    response = _evaluate(authenticate(owner_identity), owner_identity)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["dry_run"] is True
    assert body["authorization"]["allowed"] is True
    assert body["authorization"]["permission"] == "agent.update"
    assert body["policy"]["decision"] == "deny"
    assert body["policy"]["policy_id"] == str(policy.id)
    assert body["policy"]["policy_version"] == 1
    assert body["policy"]["policy_name"] == policy.name
    assert body["policy"]["matched_conditions"] == [
        {
            "field": "environment",
            "operator": "equals",
            "value": "production",
            "actual": "production",
        }
    ]
    assert body["effective"]["decision"] == "deny"
    assert body["effective"]["allowed"] is False
    assert body["effective"]["denied"] is True
    assert body["effective"]["reason"] == "policy_denied"
    assert body["principal_role"] == "owner"
    assert body["evaluated_at"]

    # Nothing was written: the dry run is not a decision *record* either, so the
    # policy is unchanged and no approval, action or enforcement happened anywhere.
    assert policies.read(policy).json()["version"] == 1


def test_the_dry_run_says_not_applicable_when_no_policy_addresses_the_target(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """An empty policy layer is a decision of its own, and the effective answer is
    the authorization decision rather than a policy's."""
    policies.create("About something else", resource="asset", action="delete")

    body = _evaluate(authenticate(owner_identity), owner_identity).json()

    assert body["policy"]["decision"] == "not_applicable"
    assert body["policy"]["reason"] == "no_matching_policy"
    assert body["policy"]["applicable"] is False
    assert body["policy"]["evaluated_policies"] == 0
    assert body["effective"]["allowed"] is True
    assert body["effective"]["reason"] == "authorization_grant"


def test_a_draft_policy_does_not_participate_in_evaluation(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """Only an active policy is in force, which is what the lifecycle states mean."""
    policies.create("Still a draft", effect="deny")

    body = _evaluate(authenticate(owner_identity), owner_identity).json()

    assert body["policy"]["decision"] == "not_applicable"
    assert body["policy"]["evaluated_policies"] == 0


def test_a_policy_that_does_not_match_the_context_does_not_apply(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """The context decides: production is denied, staging is untouched."""
    policies.activate(policies.create("Deny production agents", effect="deny"))
    client = authenticate(owner_identity)

    production = _evaluate(client, owner_identity).json()
    staging = _evaluate(client, owner_identity, facts={"environment": "staging"}).json()

    assert production["policy"]["decision"] == "deny"
    assert staging["policy"]["decision"] == "not_applicable"


def test_missing_context_never_satisfies_a_condition(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """Unknown context is not a match, so a deny cannot be bypassed by omission."""
    policies.activate(policies.create("Deny production agents", effect="deny"))

    body = _evaluate(authenticate(owner_identity), owner_identity, facts={}).json()

    assert body["policy"]["decision"] == "not_applicable"
    assert body["policy"]["evaluated_policies"] == 1
    assert body["policy"]["matched_policy_count"] == 0


def test_a_policy_deny_overrides_an_allowing_authorization(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """The effective answer is the *combination*: a policy can only restrict.

    The owner here holds ``agent.update`` outright, so the authorization layer
    allows it. The deny policy then decides the effective answer, because a
    permission is what a role may do and a policy is what it may do *here*.
    """
    policies.activate(policies.create("Deny production agents", effect="deny"))

    body = _evaluate(authenticate(owner_identity), owner_identity).json()

    assert body["authorization"]["allowed"] is True
    assert body["effective"]["allowed"] is False
    assert body["effective"]["denied"] is True


def test_the_dry_run_reports_require_approval_as_a_value(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """``require_approval`` is a reported outcome; nothing in this build approves."""
    policies.activate(
        policies.create("Ask first", effect="require_approval", resource="asset", action="delete")
    )

    body = _evaluate(
        authenticate(owner_identity), owner_identity, resource="asset", action="delete"
    ).json()

    assert body["policy"]["decision"] == "require_approval"
    assert body["effective"]["decision"] == "require_approval"
    assert body["effective"]["requires_approval"] is True
    assert body["effective"]["allowed"] is False
    assert body["effective"]["reason"] == "policy_requires_approval"


def test_a_deny_outranks_a_require_approval_regardless_of_priority(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """Precedence is by effect first: no priority can argue a denial away."""
    policies.activate(
        policies.create(
            "Deny at the bottom", effect="deny", priority=1000, resource="asset", action="delete"
        )
    )
    policies.activate(
        policies.create(
            "Approval at the top",
            effect="require_approval",
            priority=0,
            resource="asset",
            action="delete",
        )
    )

    body = _evaluate(
        authenticate(owner_identity), owner_identity, resource="asset", action="delete"
    ).json()

    assert body["policy"]["decision"] == "deny"
    assert body["effective"]["decision"] == "deny"
    assert body["policy"]["matched_policy_count"] == 2


def test_the_dry_run_accepts_an_empty_target_that_no_policy_uses(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """A declared target with no policy is still evaluable, and reports nothing."""
    body = _evaluate(
        authenticate(owner_identity), owner_identity, resource="role", action="read"
    ).json()

    assert body["policy"]["decision"] == "not_applicable"
    assert body["authorization"]["permission"] == "role.read"
    assert body["effective"]["allowed"] is True


def test_the_dry_run_refuses_a_fact_the_server_owns(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """``user_role`` and ``is_resource_owner`` come from the membership, not the body."""
    client = authenticate(owner_identity)

    for fact, value in (("user_role", "owner"), ("is_resource_owner", True)):
        response = client.post(
            f"{_collection(owner_identity)}/evaluate",
            json={"resource": "agent", "action": "update", "facts": {fact: value}},
        )
        assert response.status_code == 422, response.text
        assert fact in response.text


def test_the_dry_run_refuses_an_unknown_fact_or_a_wrongly_typed_one(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """The context is typed like the language: unknown fields and wrong values stop."""
    client = authenticate(owner_identity)

    unknown = client.post(
        f"{_collection(owner_identity)}/evaluate",
        json={"resource": "agent", "action": "update", "facts": {"request_source": "cli"}},
    )
    wrong_value = client.post(
        f"{_collection(owner_identity)}/evaluate",
        json={"resource": "agent", "action": "update", "facts": {"environment": "Production"}},
    )
    wrong_type = client.post(
        f"{_collection(owner_identity)}/evaluate",
        json={"resource": "agent", "action": "update", "facts": {"agent_age_days": "seven"}},
    )

    for response in (unknown, wrong_value, wrong_type):
        assert response.status_code == 422, response.text


def test_the_dry_run_refuses_a_target_this_build_does_not_declare(
    policies: PolicyFactory, authenticate, owner_identity: Identity
) -> None:
    """The evaluation target is the same closed vocabulary as a policy's."""
    response = _evaluate(
        authenticate(owner_identity), owner_identity, resource="firewall", action="block"
    )

    assert response.status_code == 422


def test_the_user_role_fact_is_the_callers_own_membership(
    policies: PolicyFactory,
    authenticate,
    owner_identity: Identity,
    identity_factory: IdentityFactory,
) -> None:
    """A policy about roles is evaluated against the membership, never the body."""
    policy = policies.create(
        "Owners only",
        conditions=[{"field": "user_role", "operator": "in", "value": ["owner"]}],
    )
    policies.activate(policy)
    admin: Identity = identity_factory(
        role_code="admin", organization_id=owner_identity.organization_id
    )

    owner_view = _evaluate(authenticate(owner_identity), owner_identity).json()
    admin_view = _evaluate(authenticate(admin), admin).json()

    assert owner_view["principal_role"] == "owner"
    assert owner_view["policy"]["decision"] == "deny"
    assert admin_view["principal_role"] == "admin"
    assert admin_view["policy"]["decision"] == "not_applicable"
