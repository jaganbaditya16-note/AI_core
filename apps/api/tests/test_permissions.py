"""The permission vocabulary: resource, action, identifier — closed and validated.

Phase 5's claim is that authorization is written in a *vocabulary* rather than in
loose strings: every requirement is a ``resource.action`` identifier whose halves
come from closed enums, and anything else is refused instead of being carried into
a check. These tests keep that true, including the negative half of it: ``approve``,
``kill``, ``block`` and their relatives are **absent** until the phase that implements
them, because a vocabulary that lists actions nothing can perform advertises
enforcement that does not exist.

Phase 7 is where ``execute`` stopped being one of those words, and the vocabulary grew
by exactly the pair that describes it: the ``action`` resource (the registered action
catalogue) and ``action.execute`` (run one of them through the firewall). Two things
follow, and both are asserted below rather than assumed: ``execute`` exists as an
*action* on that resource and on no other — there is no ``agent.execute`` and no
``policy.execute``, because this phase runs registered actions, not agents or
policies — and ``parse_permission_code`` now *recognizes* a well-formed pair this build
does not declare, which is precisely why :meth:`Permission.parse` is the stricter door
and the one every caller uses.

Two kinds of test live here:

- **the vocabulary itself** — parsing, uniqueness, coverage, and the refusals
  (no LLM, no network, no guesswork: a string either classifies or raises);
- **the vocabulary against the database** — every seeded row classifies, and the
  code catalogue and the seeded catalogue hold exactly the same codes, so a
  permission cannot exist on one side only.

Which role grants what is asserted elsewhere: ``test_authorization.py`` for the
role matrix, ``test_migrations.py`` for the catalog parity that predates Phase 5.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from aicore_api.core.permissions import (
    PERMISSION_CODE_PATTERN,
    RESOURCE_ACTIONS,
    ROLE_PERMISSIONS,
    Action,
    Permission,
    Resource,
    RoleCode,
    UnknownPermissionError,
    all_permissions,
    parse_permission_code,
    permissions_for_resource,
)
from aicore_api.db.models.rbac import CODE_PATTERN as MODEL_CODE_PATTERN
from aicore_api.db.repositories.rbac import RoleCatalog

#: Strings that are *not* permissions this build declares, and why each is refused.
#: The trailing well-formed ``resource.action`` pairs are the ones the roadmap (or a
#: later phase of it) mentions; they are here so that adding one without the phase
#: that implements it fails — and, for ``policy.execute`` and ``policy.approve``,
#: so that evaluation can never grow an execution or an approval step.
REFUSED_CODES = (
    "",
    "agent",
    "agent.",
    ".read",
    "agent.update.extra",
    "agent-read",
    "Agent.Read",
    "agent.Read",
    "agent.read ",
    " agent.read",
    "agent..read",
    "policy",
    "policy.approve",
    "policy.kill",
    "policy.evaluate",
    "incident.read",
    "firewall.block",
    "tool.invoke",
    "action.approve",
    "action.kill",
    "action.block",
    "action.execute_all",
    "agent.firewall.block",
)

#: Well-formed pairs this build does **not** declare: both halves are in the vocabulary
#: — ``execute`` became one in Phase 7 — and the pair is not a permission, so
#: :meth:`Permission.parse` refuses it. Listed separately because the *other* door
#: (:func:`parse_permission_code`) is allowed to recognize them: telling "this is not a
#: permission code" apart from "this is not a permission" is what lets a route or a
#: policy report a malformed target differently from an unsupported one. What must never
#: happen is one of them being *treated as* a capability, which is what the test asserts.
UNDECLARED_PAIRS: tuple[tuple[str, Action], ...] = (
    ("agent.execute", Action.EXECUTE),
    ("policy.execute", Action.EXECUTE),
    ("asset.execute", Action.EXECUTE),
    ("role.execute", Action.EXECUTE),
    ("action.read", Action.READ),
    ("action.create", Action.CREATE),
)


def test_the_catalog_is_a_validated_resource_action_vocabulary() -> None:
    """Every permission is exactly one resource and one action, by construction."""
    for permission in Permission:
        resource, action = parse_permission_code(permission.value)
        assert resource is permission.resource, permission
        assert action is permission.action, permission
        assert permission.resource is Resource(resource.value)
        assert permission.action is Action(action.value)
        # The identifier itself: `resource.action`, one dot, no decoration.
        assert permission.value.count(".") == 1, permission
        assert re.fullmatch(PERMISSION_CODE_PATTERN, permission.value), permission


def test_permission_identifiers_are_unique() -> None:
    """Two permissions with one code would make a grant ambiguous."""
    codes = [permission.value for permission in all_permissions()]

    assert len(codes) == len(set(codes))


def test_every_resource_and_action_is_used_by_the_catalog() -> None:
    """A vocabulary entry nothing maps to would be an intention, not a capability."""
    assert set(RESOURCE_ACTIONS) == set(Resource)
    used_actions = {action for actions in RESOURCE_ACTIONS.values() for action in actions}
    assert used_actions == set(Action)


def test_the_resource_action_map_is_derived_from_the_catalog() -> None:
    """It cannot disagree with the permissions, because it is computed from them."""
    assert dict(RESOURCE_ACTIONS) == {
        resource: frozenset(
            permission.action for permission in Permission if permission.resource is resource
        )
        for resource in Resource
    }


def test_permissions_for_resource_returns_that_resource_and_refuses_an_unknown_one() -> None:
    """Grouping capabilities by resource is a lookup, and a typo is an error."""
    assert permissions_for_resource(Resource.AGENT) == (
        Permission.AGENT_READ,
        Permission.AGENT_CREATE,
        Permission.AGENT_UPDATE,
        Permission.AGENT_DELETE,
    )
    assert all(
        permission.resource is Resource.AGENT for permission in permissions_for_resource("agent")
    )

    assert permissions_for_resource(Resource.POLICY) == (
        Permission.POLICY_READ,
        Permission.POLICY_CREATE,
        Permission.POLICY_UPDATE,
        Permission.POLICY_DELETE,
    )
    assert all(
        permission.resource is Resource.POLICY for permission in permissions_for_resource("policy")
    )

    # One permission on the action catalogue: running a registered action. Not a
    # catalogue of verbs — an identifier, an argument schema and an adapter decide what
    # may run, and one permission decides who may ask.
    assert permissions_for_resource(Resource.ACTION) == (Permission.ACTION_EXECUTE,)
    assert all(
        permission.resource is Resource.ACTION for permission in permissions_for_resource("action")
    )

    with pytest.raises(ValueError, match="unknown resource"):
        permissions_for_resource("firewall")


@pytest.mark.parametrize("code", REFUSED_CODES)
def test_an_undeclared_permission_code_is_refused(code: str) -> None:
    """Nothing arbitrary enters the vocabulary — not by typo, not by roadmap."""
    with pytest.raises(UnknownPermissionError):
        Permission.parse(code)


@pytest.mark.parametrize("code", REFUSED_CODES)
def test_an_undeclared_code_cannot_be_parsed_into_a_resource_and_action(code: str) -> None:
    """A malformed code is refused by both doors: parsing alone accepts no future action."""
    with pytest.raises(UnknownPermissionError):
        parse_permission_code(code)


@pytest.mark.parametrize(("code", "action"), UNDECLARED_PAIRS)
def test_a_well_formed_pair_this_build_does_not_declare_is_still_not_a_permission(
    code: str, action: Action
) -> None:
    """``execute`` exists on ``action``, and the vocabulary knows it — the catalogue does not.

    The halves are recognized (that is what :func:`parse_permission_code` is for), and the
    pair is not a permission, so declaring it is impossible and using it as one is
    impossible: only :class:`Permission` members ever reach an authorization decision.
    """
    with pytest.raises(UnknownPermissionError):
        Permission.parse(code)

    resource, parsed_action = parse_permission_code(code)
    assert parsed_action is action
    declared_pairs = {(permission.resource, permission.action) for permission in Permission}
    assert (resource, parsed_action) not in declared_pairs

    # And in the direction that matters: nothing that *is* a permission may share the
    # pair of an undeclared one.
    assert (resource, parsed_action) not in {
        (permission.resource, permission.action) for permission in all_permissions()
    }


def test_the_only_resource_that_may_be_executed_is_the_action_catalogue() -> None:
    """The precision Phase 7 claims, asserted: one resource, one action, no wildcard.

    ``execute`` was added as an action *and* as a permission on exactly one resource. A
    second resource growing it — ``agent.execute``, ``policy.execute`` — is the change
    this test exists to catch, because it would quietly turn "run a registered action"
    into "run an agent" or "enforce a policy", neither of which this build can do.
    """
    resources_with_execute = {
        permission.resource for permission in Permission if permission.action is Action.EXECUTE
    }
    assert resources_with_execute == {Resource.ACTION}
    assert Permission.ACTION_EXECUTE.value == "action.execute"
    assert not [
        permission
        for permission in Permission
        if "*" in permission.value or permission.value.endswith(".all")
    ]


def test_a_refusal_is_a_value_error() -> None:
    """Callers that already treat catalog mistakes as value errors keep working."""
    assert issubclass(UnknownPermissionError, ValueError)


def test_the_vocabulary_declares_no_future_phase_action() -> None:
    """Runtime control belongs to the phases that implement it, not to this one.

    ``execute`` graduated in Phase 7 — it names running a registered action through the
    firewall, and nothing else. Every other control-plane verb is still absent, and the
    permission codes are checked as well as the enum, because a permission is where such
    a verb would actually appear.
    """
    assert {action.value for action in Action} == {
        "read",
        "create",
        "update",
        "delete",
        "manage",
        "execute",
    }
    forbidden = {"approve", "kill", "block", "intercept", "control", "scan", "suspend"}
    assert not forbidden & {action.value for action in Action}
    assert not [code for code in (p.value for p in Permission) if code.split(".")[-1] in forbidden]
    # One resource may be executed, and it is the action catalogue itself.
    assert RESOURCE_ACTIONS[Resource.ACTION] == frozenset({Action.EXECUTE})


def test_the_vocabulary_declares_no_future_phase_resource() -> None:
    """A resource appears when a permission guards it, which is when it exists.

    ``action`` arrived with Phase 7 and guards the registered action catalogue — the
    list of things this build may be asked to run. A resource is a namespace of real
    capabilities, so every member below is one: the resources still absent are the ones
    whose phase has not happened.
    """
    assert {resource.value for resource in Resource} == {
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
    forbidden = {
        "incident",
        "tool",
        "model",
        "data_source",
        "mcp_server",
        "firewall",
        "session",
        "enforcement",
        "approval",
        "kill_switch",
    }
    assert not forbidden & {resource.value for resource in Resource}
    assert permissions_for_resource(Resource.ACTION) == (Permission.ACTION_EXECUTE,)


def test_the_code_pattern_is_the_same_in_the_vocabulary_and_in_the_model() -> None:
    """The database decides what a code *is*; the vocabulary must decide identically.

    The model's pattern is the one its ``CHECK`` constraint renders, so this ties
    :func:`parse_permission_code` to the constraint that rejects a malformed code
    at the other end.
    """
    assert PERMISSION_CODE_PATTERN == MODEL_CODE_PATTERN


def test_every_role_grant_is_a_declared_permission() -> None:
    """A role cannot grant a capability the vocabulary does not declare."""
    assert set(ROLE_PERMISSIONS) == set(RoleCode)
    for role_code, granted in ROLE_PERMISSIONS.items():
        assert granted <= set(Permission), f"{role_code} grants something undeclared: {granted}"
        for permission in granted:
            assert permission.resource in Resource
            assert permission.action in Action


#: The role matrix, written out literally. Deliberately a *second* copy of the
#: table in ``core.permissions``: ``test_authorization.py`` asserts that the code
#: catalog and the seeded rows agree, which would still pass if somebody widened a
#: role in both places at once. This test is the review gate for that — any change
#: to who may do what has to be made here too, in a diff a reviewer can see.
EXPECTED_ROLE_MATRIX: dict[RoleCode, set[Permission]] = {
    RoleCode.OWNER: set(Permission),
    RoleCode.ADMIN: {
        Permission.ORGANIZATION_READ,
        Permission.ORGANIZATION_UPDATE,
        Permission.USER_READ,
        Permission.USER_MANAGE,
        Permission.ROLE_READ,
        Permission.ASSET_READ,
        Permission.ASSET_CREATE,
        Permission.ASSET_UPDATE,
        Permission.ASSET_DELETE,
        Permission.AGENT_READ,
        Permission.AGENT_CREATE,
        Permission.AGENT_UPDATE,
        Permission.AGENT_DELETE,
        Permission.POLICY_READ,
        Permission.POLICY_CREATE,
        Permission.POLICY_UPDATE,
        Permission.POLICY_DELETE,
        Permission.ACTION_EXECUTE,
    },
    RoleCode.SECURITY_ADMIN: {
        Permission.ORGANIZATION_READ,
        Permission.USER_READ,
        Permission.AUDIT_READ,
        Permission.SECURITY_READ,
        # Phase 10: recording a finding is security work, so the security administrator
        # records one; an analyst reads findings and never records them.
        Permission.SECURITY_CREATE,
        Permission.ASSET_READ,
        Permission.ASSET_UPDATE,
        Permission.AGENT_READ,
        Permission.AGENT_UPDATE,
        Permission.POLICY_READ,
        Permission.POLICY_CREATE,
        Permission.POLICY_UPDATE,
        Permission.ACTION_EXECUTE,
    },
    RoleCode.AI_ADMIN: {
        Permission.ORGANIZATION_READ,
        Permission.USER_READ,
        Permission.ASSET_READ,
        Permission.ASSET_CREATE,
        Permission.ASSET_UPDATE,
        Permission.AGENT_READ,
        Permission.AGENT_CREATE,
        Permission.AGENT_UPDATE,
    },
    RoleCode.ANALYST: {
        Permission.ORGANIZATION_READ,
        Permission.SECURITY_READ,
        Permission.ASSET_READ,
        Permission.AGENT_READ,
    },
    RoleCode.VIEWER: {
        Permission.ORGANIZATION_READ,
        Permission.ASSET_READ,
        Permission.AGENT_READ,
    },
}


def test_the_role_matrix_is_exactly_the_documented_one() -> None:
    """Who may do what, spelled out: widening a role is a deliberate, visible change.

    Phase 5 reviewed the matrix against the resources that exist rather than
    re-deriving it from the roadmap, and kept it: every grant below answers a
    capability the application can actually enforce. Phase 7 added ``action.execute``
    to the owner, the administrator and the security administrator — running a
    registered action is administration and security work — and deliberately not to the
    AI administrator, whose work a policy constrains. Phase 6 added the policy
    namespace to three roles, each for a stated reason — the security administrator
    writes a policy (recording a containment decision is its job) but cannot delete
    one, administration manages policies outright, the AI administrator holds none
    because the party a policy constrains does not write the constraint, and the
    analyst and the viewer read no policy at all: governance configuration is not
    inventory and not security findings.
    """
    assert {
        role: set(granted) for role, granted in ROLE_PERMISSIONS.items()
    } == EXPECTED_ROLE_MATRIX


def test_no_role_holds_a_permission_for_a_resource_that_does_not_exist() -> None:
    """Least privilege, checked as a property: grants only name implemented resources."""
    implemented_resources = set(Resource)
    for role_code, granted in ROLE_PERMISSIONS.items():
        for permission in granted:
            assert permission.resource in implemented_resources, f"{role_code}: {permission}"
        # Reading is universal; writing is not. A role that could write everywhere
        # would be an administration role by accident.
        writes = {p for p in granted if p.action in {Action.CREATE, Action.DELETE}}
        assert writes <= {
            Permission.ASSET_CREATE,
            Permission.ASSET_DELETE,
            Permission.AGENT_CREATE,
            Permission.AGENT_DELETE,
            Permission.POLICY_CREATE,
            # Phase 10: recording a risk finding creates an append-only record, and the
            # roles that may do it are the owner and the security administrator — the
            # second of which is not in the administration set below, so the capability is
            # named here rather than implied by a role.
            Permission.SECURITY_CREATE,
        } or role_code in {
            RoleCode.OWNER,
            RoleCode.ADMIN,
            RoleCode.AI_ADMIN,
        }, f"{role_code}: unexpected write grants {writes}"

        # Writing a policy is the one governance record a non-administrative role
        # may create, and only the security administrator does. Deleting one is not
        # part of that job: removing the record stays with the owner and the
        # administrator, exactly as deleting an asset or an agent does.
        if granted & {Permission.POLICY_CREATE, Permission.POLICY_UPDATE, Permission.POLICY_DELETE}:
            assert role_code in {RoleCode.OWNER, RoleCode.ADMIN, RoleCode.SECURITY_ADMIN}
        if Permission.POLICY_DELETE in granted:
            assert role_code in {RoleCode.OWNER, RoleCode.ADMIN}
        # Updating a policy without being able to create one would be a strange
        # grant; the two travel together or not at all.
        if Permission.POLICY_UPDATE in granted:
            assert Permission.POLICY_CREATE in granted


def test_the_seeded_catalog_holds_exactly_the_declared_permissions(
    integration_session: Session,
) -> None:
    """Code and database agree in both directions: no extra row, no missing row."""
    catalog = RoleCatalog(integration_session)
    rows = catalog.list_permissions()

    declared = {permission.value for permission in Permission}
    seeded = {row.code for row in rows}

    assert seeded == declared, f"only in one place: code={declared - seeded} db={seeded - declared}"
    for row in rows:
        resource, action = parse_permission_code(row.code)
        assert resource in Resource
        assert action in Action
        # Descriptions are published, so an empty one is a hole in the contract.
        assert row.description.strip(), row.code
    assert len({row.id for row in rows}) == len(rows)


def test_the_api_publishes_the_resource_and_action_of_every_permission(
    database_client: TestClient, owner_identity, authenticate
) -> None:
    """The vocabulary is visible without parsing: `code`, `resource` and `action`.

    The published pair is compared against the vocabulary rather than against a
    literal list here — the closed set of codes is asserted above and in
    ``test_migrations.py``, so this test is about the *shape* a client receives.
    """
    client = authenticate(owner_identity)
    response = client.get(f"/organizations/{owner_identity.organization_id}/permissions")

    assert response.status_code == 200, response.text
    published = response.json()["permissions"]

    assert [entry["code"] for entry in published] == sorted(entry["code"] for entry in published)
    assert {entry["code"] for entry in published} == {p.value for p in Permission}
    for entry in published:
        resource, action = parse_permission_code(entry["code"])
        assert entry["resource"] == resource.value
        assert entry["action"] == action.value
        assert entry["description"].strip()


def test_publishing_the_catalog_still_requires_role_read(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """The vocabulary is not a public endpoint: reading it is a catalog permission."""
    viewer = identity_factory(role_code="viewer")
    client = authenticate(viewer)

    response = client.get(f"/organizations/{viewer.organization_id}/permissions")

    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "forbidden"


def test_a_route_can_only_declare_a_declared_permission() -> None:
    """The requirement helper takes the enum, so a string cannot be smuggled in."""
    from aicore_api.auth.dependencies import require_permission

    with pytest.raises(UnknownPermissionError):
        Permission.parse("agent.execute")

    # Every permission a route may declare is a member of the vocabulary, and the
    # helper stamps exactly that member onto the dependency.
    for permission in Permission:
        requirement = require_permission(permission)
        assert requirement.required_permission is permission
        assert requirement.required_permission.resource is permission.resource
