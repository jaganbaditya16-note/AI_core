"""The inventory over HTTP: contract, validation, authorization and isolation.

These are the tests that decide whether Phase 3 is trustworthy, because they are
the only ones that exercise the whole path a client takes: credential →
principal → membership → permission → tenant-scoped query → response. Everything
here goes through the API with a real token; nothing calls a repository to
establish a precondition the API could not have produced, except where the point
is that the API *cannot* produce it (a foreign owner, an unknown asset type).

The security cases the phase requires are all present, in this order:

- cross-tenant read, modification and deletion, and IDOR with another
  organization's asset id — each answered with the same 404 an unknown id gets;
- unauthorized creation, update and deletion, by role;
- invalid asset type, lifecycle state, discovery state, environment and metadata;
- pagination abuse, since an unbounded list query is a denial-of-service and a
  tenant-isolation risk in the same breath.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.testclient import TestClient

from aicore_api.core.permissions import ROLE_PERMISSIONS, Permission, RoleCode
from aicore_api.main import create_app
from assets_fixture import (
    ASSET_TYPES,
    AssetFactory,
    asset_path,
    assets_path,
    sample_metadata,
)
from identity_fixture import Identity, IdentityFactory, suspend_membership

#: Every field an asset response may contain. Asserted exactly, so a future field
#: (a credential, an internal note) cannot appear in the contract unnoticed.
ASSET_FIELDS = {
    "id",
    "organization_id",
    "name",
    "description",
    "asset_type",
    "status",
    "environment",
    "discovery_state",
    "risk_classification",
    "external_identifier",
    "discovery_source",
    "last_seen_at",
    "metadata",
    "owner",
    "created_at",
    "updated_at",
}


def _assets_path(identity: Identity) -> str:
    """The collection URL for an identity's organization."""
    return assets_path(identity.organization_id)


def _asset_path(identity: Identity, asset_id: uuid.UUID) -> str:
    """The item URL for one asset of an identity's organization."""
    return asset_path(identity.organization_id, asset_id)


# ── Creating, reading, listing ───────────────────────────────────────────────


def test_creating_an_asset_persists_it_and_returns_the_record(
    assets: AssetFactory, owner_identity: Identity, authenticate
) -> None:
    """The create path, end to end: 201, then readable, then in the listing."""
    created = assets.create(
        name="Support Copilot",
        asset_type="application",
        description="Answers tier-1 tickets.",
        environment="production",
        status="active",
        metadata=sample_metadata("application"),
    )

    assert set(created.body) == ASSET_FIELDS
    assert created.body["organization_id"] == str(owner_identity.organization_id)
    assert created.body["discovery_source"] == "manual"
    assert created.body["last_seen_at"] is None
    assert created.body["owner"] is None

    client = authenticate(owner_identity)
    fetched = client.get(_asset_path(owner_identity, created.id))
    assert fetched.status_code == 200
    assert fetched.json() == created.body

    listing = client.get(_assets_path(owner_identity)).json()
    assert [item["id"] for item in listing["items"]] == [str(created.id)]
    assert listing["count"] == 1
    assert listing["total"] is None


def test_every_supported_asset_type_can_be_registered(assets: AssetFactory) -> None:
    """All seven types are creatable through the same endpoint."""
    created = assets.create_each_type()
    assert [record.asset_type for record in created] == list(ASSET_TYPES)


@pytest.mark.parametrize("asset_type", ASSET_TYPES)
def test_metadata_round_trips_for_each_asset_type(
    assets: AssetFactory, owner_identity: Identity, authenticate, asset_type: str
) -> None:
    """Type-specific metadata survives a write, a read, an update and a re-read.

    The update half is not padding: PATCH and POST reach the database down
    different paths, and a metadata field that only works on one of them is a bug
    a client would find before a test did.
    """
    created = assets.create(
        name=f"{asset_type} asset",
        asset_type=asset_type,
        metadata=sample_metadata(asset_type),
    )
    assert created.body["metadata"] == sample_metadata(asset_type)

    client = authenticate(owner_identity)
    updated = client.patch(
        _asset_path(owner_identity, created.id),
        json={"metadata": sample_metadata(asset_type)},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["metadata"] == sample_metadata(asset_type)

    assert client.get(_asset_path(owner_identity, created.id)).json()[
        "metadata"
    ] == sample_metadata(asset_type)


def test_the_owner_is_a_member_of_this_organization(
    assets: AssetFactory,
    owner_identity: Identity,
    identity_factory: IdentityFactory,
    authenticate,
) -> None:
    """An owner can be assigned, and comes back resolved to a real member."""
    member = identity_factory(
        role_code="viewer", organization_id=owner_identity.organization_id, full_name="Ada Member"
    )
    created = assets.create(
        name="Owned App", asset_type="application", owner_user_id=str(member.user_id)
    )

    owner = created.body["owner"]
    assert owner["membership_id"] == str(member.membership_id)
    assert owner["user_id"] == str(member.user_id)
    assert owner["full_name"] == "Ada Member"
    assert "token" not in owner

    assert (
        authenticate(owner_identity).get(_assets_path(owner_identity) + "/owners").json()["owners"]
    )


def test_a_reported_owner_must_be_an_active_member_of_the_same_organization(
    assets: AssetFactory,
    owner_identity: Identity,
    identity_factory: IdentityFactory,
) -> None:
    """Ownership is resolved against this tenant's memberships, and only active ones."""
    outsider = identity_factory(role_code="owner")
    member = identity_factory(role_code="viewer", organization_id=owner_identity.organization_id)

    refused_foreign = assets.create(
        name="Foreign Owner",
        asset_type="model",
        expected_status=422,
        owner_user_id=str(outsider.user_id),
    )
    assert refused_foreign is None  # the factory returns nothing for a refusal

    suspend_membership(assets.engine, member)
    refused_suspended = assets.client.post(
        _assets_path(owner_identity),
        json={
            "name": "Suspended Owner",
            "asset_type": "model",
            "owner_user_id": str(member.user_id),
        },
    )
    assert refused_suspended.status_code == 422
    assert "active member" in refused_suspended.json()["error"]["message"]


def test_the_listing_can_be_filtered_and_counted(
    assets: AssetFactory, owner_identity: Identity, authenticate
) -> None:
    """Each documented filter works, and they combine."""
    client = authenticate(owner_identity)
    assets.create(name="Prod Model", asset_type="model", environment="production", status="active")
    assets.create(name="Staging Tool", asset_type="tool", environment="staging", status="active")
    assets.create(
        name="Shadow Agent",
        asset_type="agent",
        environment="production",
        discovery_state="shadow",
        risk_classification="high",
    )

    path = _assets_path(owner_identity)
    assert client.get(f"{path}?asset_type=model").json()["count"] == 1
    assert client.get(f"{path}?asset_type=model&asset_type=tool").json()["count"] == 2
    assert client.get(f"{path}?environment=production").json()["count"] == 2
    assert client.get(f"{path}?discovery_state=shadow").json()["count"] == 1
    assert client.get(f"{path}?risk_classification=high").json()["count"] == 1
    assert client.get(f"{path}?status=active").json()["count"] == 2
    assert client.get(f"{path}?asset_type=model&environment=staging").json()["count"] == 0

    # The owner filter counts by membership, not by name: exactly the record that
    # names this member is returned, and nothing else.
    assets.create(name="Owned Api", asset_type="api", owner_user_id=str(owner_identity.user_id))
    owned = client.get(f"{path}?owner_membership_id={owner_identity.membership_id}").json()
    assert owned["count"] == 1
    assert [item["name"] for item in owned["items"]] == ["Owned Api"]
    nobody = client.get(f"{path}?owner_membership_id={uuid.uuid4()}").json()
    assert nobody["count"] == 0

    counted = client.get(f"{path}?asset_type=model&total=true").json()
    assert counted["count"] == 1
    assert counted["total"] == 1


def test_paging_is_stable_and_bounded(
    assets: AssetFactory, owner_identity: Identity, authenticate
) -> None:
    """A client can page through the inventory, and cannot ask for all of it."""
    client = authenticate(owner_identity)
    created = [assets.create(name=f"Asset {index}", asset_type="model").id for index in range(5)]
    path = _assets_path(owner_identity)

    first = client.get(f"{path}?limit=2&offset=0").json()
    second = client.get(f"{path}?limit=2&offset=2").json()
    third = client.get(f"{path}?limit=2&offset=4").json()

    assert [len(page["items"]) for page in (first, second, third)] == [2, 2, 1]
    assert first["limit"] == 2 and first["offset"] == 0
    seen = [item["id"] for page in (first, second, third) for item in page["items"]]
    assert len(set(seen)) == 5
    assert set(seen) == {str(asset_id) for asset_id in created}
    assert seen[0] == str(created[-1])  # newest first

    assert client.get(f"{path}?total=true&limit=2").json()["total"] == 5


def test_altering_and_removing_an_asset_works_as_documented(
    assets: AssetFactory, owner_identity: Identity, authenticate
) -> None:
    """The lifecycle a record actually goes through: draft → active → retired/removed."""
    client = authenticate(owner_identity)
    created = assets.create(name="Lifecycle", asset_type="model")
    assert created.status == "draft"

    activated = client.patch(
        _asset_path(owner_identity, created.id),
        json={"status": "active", "risk_classification": "medium", "description": "In service."},
    )
    assert activated.status_code == 200
    assert activated.json()["status"] == "active"
    assert activated.json()["risk_classification"] == "medium"
    assert activated.json()["updated_at"] > created.body["updated_at"]

    retired = client.patch(_asset_path(owner_identity, created.id), json={"status": "retired"})
    assert retired.json()["status"] == "retired"

    removed = client.delete(_asset_path(owner_identity, created.id))
    assert removed.status_code == 204
    assert removed.content == b""
    assert client.get(_asset_path(owner_identity, created.id)).status_code == 404


def test_an_external_identifier_cannot_be_reused_for_the_same_type(
    assets: AssetFactory, owner_identity: Identity
) -> None:
    """The dedup rule reported to the client, not only enforced in the database."""
    assets.create(name="First", asset_type="model", external_identifier="registry://models/one")
    duplicate = assets.client.post(
        _assets_path(owner_identity),
        json={
            "name": "Second",
            "asset_type": "model",
            "external_identifier": "registry://models/one",
        },
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "conflict"


# ── Validation ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "Bad", "asset_type": "llm"},
        {"name": "Bad", "asset_type": "MODEL"},
        {"name": "Bad", "asset_type": "model", "status": "deprecated"},
        {"name": "Bad", "asset_type": "model", "discovery_state": "guessed"},
        {"name": "Bad", "asset_type": "model", "environment": "qa"},
        {"name": "Bad", "asset_type": "model", "risk_classification": "extreme"},
        {"name": "", "asset_type": "model"},
        {"name": "Bad", "asset_type": "model", "description": "x" * 2001},
        {"name": "Bad", "asset_type": "model", "discovery_source": "integration:pretend"},
        {"name": "Bad", "asset_type": "model", "organization_id": str(uuid.uuid4())},
        {"name": "Bad", "asset_type": "model", "unknown_field": "value"},
    ],
)
def test_an_invalid_create_is_refused_and_stores_nothing(
    assets: AssetFactory, owner_identity: Identity, authenticate, payload: dict[str, Any]
) -> None:
    """Every closed vocabulary, the server-set fields, and unknown keys are refused.

    ``discovery_source`` and ``organization_id`` are in the list on purpose: a
    client cannot claim its record came from an integration, and cannot choose a
    tenant either. Both are server-set, and the schema forbids them.
    """
    response = assets.client.post(_assets_path(owner_identity), json=payload)
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "validation_error"
    assert authenticate(owner_identity).get(_assets_path(owner_identity)).json()["count"] == 0


@pytest.mark.parametrize(
    "payload",
    [
        {"metadata": {"unknown_field": "value"}},
        {"metadata": {"provider": ""}},
        {"metadata": {"provider": 42}},
        {"metadata": ["not", "an", "object"]},
        {"metadata": {"provider": "p" * 600}},
        {"status": "deprecated"},
        {"status": None},
        {"asset_type": "tool"},
        {"name": None},
        {},
    ],
)
def test_an_invalid_update_is_refused_and_changes_nothing(
    assets: AssetFactory, owner_identity: Identity, authenticate, payload: dict[str, Any]
) -> None:
    """Validation failures never write: the record is byte-for-byte the same after."""
    created = assets.create(name="Immutable Until Valid", asset_type="model")

    response = authenticate(owner_identity).patch(
        _asset_path(owner_identity, created.id), json=payload
    )
    assert response.status_code == 422, response.text

    unchanged = authenticate(owner_identity).get(_asset_path(owner_identity, created.id)).json()
    assert unchanged == created.body


def test_metadata_that_is_not_an_object_is_refused_on_create(
    assets: AssetFactory, owner_identity: Identity
) -> None:
    """An array or a scalar in the metadata field is malformed, not flexible."""
    for payload in (["a"], "string", 7):
        response = assets.client.post(
            _assets_path(owner_identity),
            json={"name": "Wrong Shape", "asset_type": "model", "metadata": payload},
        )
        assert response.status_code == 422


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=100000",
        "limit=-1",
        "limit=abc",
        "offset=-1",
        "offset=10000000",
        "asset_type=llm",
        "status=deprecated",
        "discovery_state=guessed",
        "environment=qa",
        "risk_classification=extreme",
        "owner_membership_id=not-a-uuid",
    ],
)
def test_an_abusive_or_invalid_query_is_refused(
    assets: AssetFactory, owner_identity: Identity, authenticate, query: str
) -> None:
    """No unbounded list query, and no filter value outside the vocabulary.

    ``limit`` is capped at 200 and ``offset`` at 100 000, so one request cannot ask
    the database for an unbounded amount of work — the general rule is enforced as
    a property of the endpoint rather than trusted to its callers.
    """
    response = authenticate(owner_identity).get(f"{_assets_path(owner_identity)}?{query}")
    assert response.status_code == 422, (query, response.text)


def test_the_default_page_size_is_applied_when_none_is_given(
    assets: AssetFactory, owner_identity: Identity, authenticate
) -> None:
    """A listing without ``limit`` is bounded too."""
    for index in range(3):
        assets.create(name=f"Default {index}", asset_type="model")

    listing = authenticate(owner_identity).get(_assets_path(owner_identity)).json()
    assert listing["limit"] == 50
    assert listing["offset"] == 0
    assert listing["count"] == 3


# ── Isolation: the security cases ────────────────────────────────────────────


@pytest.fixture
def foreign_asset(identity_factory: IdentityFactory, authenticate) -> tuple[Identity, uuid.UUID]:
    """An asset that belongs to a different organization, owned by its own member."""
    other = identity_factory(role_code="owner")
    created = authenticate(other).post(
        _assets_path(other), json={"name": "Globex Model", "asset_type": "model"}
    )
    assert created.status_code == 201
    return other, uuid.UUID(created.json()["id"])


def test_another_organizations_asset_cannot_be_read_modified_or_deleted(
    assets: AssetFactory, owner_identity: Identity, authenticate, foreign_asset
) -> None:
    """Cross-tenant read, update and delete: all refused, and all identically.

    The caller here is an owner of their own organization — the most privileged
    member there is. Privilege is scoped to the tenant, so it buys nothing in
    another one.
    """
    other, asset_id = foreign_asset
    client = authenticate(owner_identity)

    read = client.get(_asset_path(owner_identity, asset_id))
    updated = client.patch(_asset_path(owner_identity, asset_id), json={"status": "retired"})
    deleted = client.delete(_asset_path(owner_identity, asset_id))

    for response in (read, updated, deleted):
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"

    # Nothing changed for the organization that does own it.
    still_there = authenticate(other).get(_asset_path(other, asset_id))
    assert still_there.status_code == 200
    assert still_there.json()["status"] == "draft"


def test_a_foreign_asset_is_indistinguishable_from_an_unknown_one(
    assets: AssetFactory, owner_identity: Identity, authenticate, foreign_asset
) -> None:
    """IDOR, answered the only safe way: identical responses for both cases.

    If a foreign id produced a different status or message, the endpoint would be
    an oracle for which asset ids exist in other tenants — the enumeration step of
    a cross-tenant attack.
    """
    _, foreign_id = foreign_asset
    client = authenticate(owner_identity)

    foreign = client.get(_asset_path(owner_identity, foreign_id))
    unknown = client.get(_asset_path(owner_identity, uuid.uuid4()))

    assert foreign.status_code == unknown.status_code == 404
    assert foreign.json()["error"]["code"] == unknown.json()["error"]["code"]
    assert foreign.json()["error"]["message"] == unknown.json()["error"]["message"]
    assert foreign.json()["error"]["details"] == unknown.json()["error"]["details"]


def test_an_asset_id_cannot_be_borrowed_into_another_organization(
    assets: AssetFactory, owner_identity: Identity, identity_factory: IdentityFactory, authenticate
) -> None:
    """Swapping the organization in the path does not carry the asset with it."""
    created = assets.create(name="Mine", asset_type="model")
    other = identity_factory(role_code="owner")

    # The id is real, the organization in the path is real, and the caller is a
    # member of it — but not of the organization the asset is in.
    assert authenticate(other).get(_asset_path(other, created.id)).status_code == 404
    assert authenticate(other).get(_assets_path(other)).json()["count"] == 0


def test_a_member_of_another_organization_cannot_reach_the_inventory_at_all(
    assets: AssetFactory, owner_identity: Identity, authenticate, foreign_asset
) -> None:
    """A non-member learns nothing: no listing, no creation, 404 rather than 403."""
    other, _ = foreign_asset

    assert authenticate(other).get(_assets_path(owner_identity)).status_code == 404
    assert authenticate(other).get(f"{_assets_path(owner_identity)}/owners").status_code == 404
    created = authenticate(other).post(
        _assets_path(owner_identity), json={"name": "Injected", "asset_type": "model"}
    )
    assert created.status_code == 404
    assert created.json()["error"]["code"] == "not_found"


def test_a_membership_that_is_not_active_cannot_touch_the_inventory(
    assets: AssetFactory, owner_identity: Identity, identity_factory: IdentityFactory, authenticate
) -> None:
    """A suspended member is a member — and is told so, with 403 rather than 404."""
    member = identity_factory(role_code="owner", organization_id=owner_identity.organization_id)
    created = assets.create(name="Suspension Target", asset_type="model")
    suspend_membership(assets.engine, member)

    client = authenticate(member)
    for response in (
        client.get(_assets_path(owner_identity)),
        client.post(_assets_path(owner_identity), json={"name": "x", "asset_type": "model"}),
        client.get(_asset_path(owner_identity, created.id)),
        client.delete(_asset_path(owner_identity, created.id)),
    ):
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "forbidden"


# ── Authorization by role ────────────────────────────────────────────────────


@pytest.fixture
def inventory(assets: AssetFactory) -> uuid.UUID:
    """One asset, created by an owner, for the role tests to act on."""
    return assets.create(name="Authorization Target", asset_type="model").id


@pytest.mark.parametrize(
    ("role", "can_create", "can_update", "can_delete"),
    [
        (RoleCode.OWNER, True, True, True),
        (RoleCode.ADMIN, True, True, True),
        (RoleCode.AI_ADMIN, True, True, False),
        (RoleCode.SECURITY_ADMIN, False, True, False),
        (RoleCode.ANALYST, False, False, False),
        (RoleCode.VIEWER, False, False, False),
    ],
)
def test_the_four_asset_permissions_are_enforced_by_role(
    assets: AssetFactory,
    owner_identity: Identity,
    identity_factory: IdentityFactory,
    authenticate,
    inventory: uuid.UUID,
    role: RoleCode,
    can_create: bool,
    can_update: bool,
    can_delete: bool,
) -> None:
    """The permission table, verified through the API for every seeded role.

    Every role can read — that is what makes the difference between the roles
    visible here: the split is over *writing* to the inventory, not seeing it.
    """
    actor = identity_factory(role_code=role.value, organization_id=owner_identity.organization_id)
    client = authenticate(actor)

    read = client.get(_assets_path(owner_identity))
    assert read.status_code == 200, f"{role} should be able to read the inventory"

    created = client.post(
        _assets_path(owner_identity), json={"name": f"{role} asset", "asset_type": "model"}
    )
    assert created.status_code == (201 if can_create else 403), role

    updated = client.patch(
        _asset_path(owner_identity, inventory), json={"risk_classification": "low"}
    )
    assert updated.status_code == (200 if can_update else 403), role

    deleted = client.delete(_asset_path(owner_identity, inventory))
    assert deleted.status_code == (204 if can_delete else 403), role


def test_a_refusal_names_the_permission_that_was_missing(
    assets: AssetFactory, owner_identity: Identity, identity_factory: IdentityFactory, authenticate
) -> None:
    """A 403 says what the caller lacks, and reveals nothing else."""
    viewer = identity_factory(role_code="viewer", organization_id=owner_identity.organization_id)
    response = authenticate(viewer).post(
        _assets_path(owner_identity), json={"name": "Denied", "asset_type": "model"}
    )

    assert response.status_code == 403
    body = response.json()["error"]
    assert body["code"] == "forbidden"
    assert "asset.create" in body["message"]


def test_no_role_holds_permissions_this_phase_did_not_introduce() -> None:
    """Phase 3 adds exactly four permissions, and no role gains anything else.

    Stated as an assertion because the temptation to widen a role while adding a
    feature is exactly how a least-privilege table erodes.
    """
    assert {permission for permission in Permission if permission.value.startswith("asset.")} == {
        Permission.ASSET_READ,
        Permission.ASSET_CREATE,
        Permission.ASSET_UPDATE,
        Permission.ASSET_DELETE,
    }
    assert set(ROLE_PERMISSIONS) == set(RoleCode)

    # The permission vocabulary contains nothing about executing, suspending or
    # containing an asset: those are later phases, and a permission for them now
    # would be a claim the application cannot honour.
    forbidden_prefixes = ("agent.", "policy.", "firewall.", "incident.", "action.")
    assert not [p for p in Permission if p.value.startswith(forbidden_prefixes)]


# ── Credentials ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("method", ["get", "post", "patch", "delete"])
def test_every_asset_operation_requires_credentials(
    assets: AssetFactory, owner_identity: Identity, inventory: uuid.UUID, method: str
) -> None:
    """Without a credential there is nothing to authorize, so the answer is 401."""
    anonymous = TestClient(assets.client.app, raise_server_exceptions=False)
    url = (
        _assets_path(owner_identity)
        if method in {"get", "post"}
        else _asset_path(owner_identity, inventory)
    )
    response = anonymous.request(method.upper(), url, json={} if method == "patch" else None)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_an_asset_response_never_carries_a_credential(
    assets: AssetFactory, owner_identity: Identity, authenticate
) -> None:
    """No token, hash or membership secret appears in an inventory response."""
    created = assets.create(name="Credential Free", asset_type="model")
    listing = authenticate(owner_identity).get(_assets_path(owner_identity)).json()
    serialized = listing["items"][0]

    assert set(serialized) == ASSET_FIELDS
    assert set(created.body) == ASSET_FIELDS
    assert "token" not in listing
    assert "token_hash" not in listing
    assert "aicore_" not in str(listing)
    assert "password" not in str(listing).lower()


# ── The routes' own declarations ─────────────────────────────────────────────


def _required_permissions(route: APIRoute) -> set[Permission]:
    """Permissions a route declares, read from its dependency tree."""
    found: set[Permission] = set()
    pending = list(route.dependant.dependencies)
    while pending:
        dependency = pending.pop()
        permission = getattr(dependency.call, "required_permission", None)
        if permission is not None:
            found.add(permission)
        pending.extend(dependency.dependencies)
    return found


def _asset_routes(app: FastAPI) -> dict[tuple[str, str], set[Permission]]:
    declared: dict[tuple[str, str], set[Permission]] = {}
    # `app.routes` yields lazily-included routers; iter_route_contexts is how
    # FastAPI itself walks the effective routes.
    for context in iter_route_contexts(app.routes):
        route = context.original_route
        if not isinstance(route, APIRoute) or "assets" not in route.path:
            continue
        for method in route.methods - {"HEAD", "OPTIONS"}:
            declared[(method, route.path)] = _required_permissions(route)
    return declared


def test_every_asset_route_declares_the_permission_it_enforces() -> None:
    """Authorization is a property of the route, not of the handler body.

    Read from the built application rather than from the source: a route that
    forgets its requirement — or acquires the wrong one in a refactor — fails here.
    """
    app = create_app()
    declared = _asset_routes(app)

    parent = "/organizations/{organization_id}/assets"
    assert declared == {
        ("GET", parent): {Permission.ASSET_READ},
        ("POST", parent): {Permission.ASSET_CREATE},
        ("GET", f"{parent}/owners"): {Permission.ASSET_READ},
        ("GET", f"{parent}/{{asset_id}}"): {Permission.ASSET_READ},
        ("PATCH", f"{parent}/{{asset_id}}"): {Permission.ASSET_UPDATE},
        ("DELETE", f"{parent}/{{asset_id}}"): {Permission.ASSET_DELETE},
    }


def test_the_inventory_is_not_reachable_without_an_organization_in_the_path() -> None:
    """There is no flat `/assets`: a tenant is always named explicitly."""
    paths = {path for _, path in _asset_routes(create_app())}
    assert paths
    assert all("{organization_id}" in path for path in paths)
    assert not any(path.startswith("/assets") for path in paths)
