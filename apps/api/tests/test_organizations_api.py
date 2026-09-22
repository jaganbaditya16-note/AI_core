"""The minimal organization persistence path over HTTP.

Two halves, both pinned here:

- **Reading a tenant is authorized.** Phase 2 protects ``GET /organizations/{id}``
  behind an authenticated membership, so these tests carry a real credential —
  the same one an operator would provision with the CLI.
- **Creating a tenant is not, and must not be presented as if it were.** There is
  no platform-administrator concept yet, so tenant creation cannot be authorized;
  it exists only in development and test environments and is a 404 everywhere
  else. A future phase replaces it with an authorized route rather than widening
  this one.

The database is real PostgreSQL when ``scripts/test-db.sh`` provides it (the
persistence tests), and the hermetic app from conftest covers validation.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from aicore_api.config import Settings
from aicore_api.main import create_app

PREFIX = "/organizations"


def test_create_organization_persists_it(database_client: TestClient) -> None:
    """POST /organizations writes a tenant and returns it."""
    slug = f"api-{uuid.uuid4().hex[:8]}"

    response = database_client.post(PREFIX, json={"name": "API Created", "slug": slug})

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["slug"] == slug
    assert body["name"] == "API Created"
    assert body["status"] == "active"
    assert uuid.UUID(body["id"])
    assert body["created_at"] and body["updated_at"]


def test_duplicate_slug_is_a_conflict(database_client: TestClient) -> None:
    """A taken slug is a 409, not a 500 or a silent overwrite."""
    payload = {"name": "Duplicate", "slug": f"dup-{uuid.uuid4().hex[:8]}"}

    assert database_client.post(PREFIX, json=payload).status_code == 201
    response = database_client.post(PREFIX, json=payload)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "conflict"


def test_created_organization_can_be_read_back(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """A member reads their own tenant; the credential is what makes it theirs."""
    slug = f"read-{uuid.uuid4().hex[:8]}"
    created = database_client.post(PREFIX, json={"name": "Readable", "slug": slug}).json()
    member = identity_factory(organization_id=uuid.UUID(created["id"]), role_code="viewer")

    response = authenticate(member).get(f"{PREFIX}/{created['id']}")

    assert response.status_code == 200
    assert response.json()["slug"] == slug


def test_unknown_organization_is_a_404(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """An organization nobody belongs to is a 404, not an empty 200."""
    member = identity_factory(role_code="owner")

    response = authenticate(member).get(f"{PREFIX}/{uuid.uuid4()}")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_invalid_request_body_is_rejected(client: TestClient) -> None:
    """Validation happens before the database is touched.

    Runs against the hermetic app on purpose: a request that fails validation must
    never reach PostgreSQL, so this test passing with no database at all is the
    assertion.
    """
    response = client.post(PREFIX, json={"name": "Bad Slug", "slug": "Not A Slug"})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_client_cannot_choose_its_own_status(client: TestClient) -> None:
    """Lifecycle state is an authorization decision, so the field is refused."""
    response = client.post(
        PREFIX,
        json={"name": "Sneaky", "slug": f"sneaky-{uuid.uuid4().hex[:8]}", "status": "suspended"},
    )

    assert response.status_code == 422


def test_organizations_routes_are_absent_outside_development_and_test() -> None:
    """No unauthenticated tenant creation in staging or production.

    Protected reads stay available there — what disappears with the environment
    is only the provisioning route that cannot be authorized yet.
    """
    for environment in ("staging", "production"):
        settings = Settings(  # type: ignore[call-arg]  # remaining fields come from the environment
            database_url="postgresql+psycopg://aicore:aicore@127.0.0.1:1/aicore",
            environment=environment,
            docs_enabled=False,
        )
        app = create_app(settings)
        with TestClient(app, raise_server_exceptions=False) as production_client:
            response = production_client.post(PREFIX, json={"name": "Nope", "slug": "nope"})

        assert response.status_code == 404, environment


@pytest.mark.integration
def test_persistence_survives_a_new_session(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """The write is committed, not held in a request-scoped transaction."""
    slug = f"durable-{uuid.uuid4().hex[:8]}"
    created = database_client.post(PREFIX, json={"name": "Durable", "slug": slug}).json()
    member = identity_factory(organization_id=uuid.UUID(created["id"]), role_code="owner")

    # A second request reads it back through a fresh session from the pool.
    response = authenticate(member).get(f"{PREFIX}/{created['id']}")

    assert response.status_code == 200
    assert response.json()["name"] == "Durable"
