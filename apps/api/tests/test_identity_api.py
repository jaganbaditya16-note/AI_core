"""``GET /me``: who the caller is, and what they may do.

This is the endpoint that answers the first three questions in the phase's
objective — who is this, which organizations do they belong to, and what does
their role allow — and it is the only identity endpoint that exists. Authorization
*decisions* are not made here; this reports what the server will enforce, and
``test_authorization.py`` proves that the enforcement actually happens.

The response deliberately carries no credential material and no other
organization's data: it is built from the authenticated principal's own
memberships, and nothing else.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import Engine

from aicore_api.core.permissions import ROLE_PERMISSIONS, RoleCode
from identity_fixture import (
    Identity,
    expire_token,
    revoke_token,
    suspend_membership,
    suspend_user,
)

ME = "/me"


def test_an_authenticated_user_is_identified(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """The caller's identity, their organization, their role, their permissions."""
    identity: Identity = identity_factory(role_code="owner", email="ada@example.test")

    response = authenticate(identity).get(ME)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["user"]["id"] == str(identity.user_id)
    assert body["user"]["email"] == "ada@example.test"
    assert body["user"]["status"] == "active"
    assert len(body["memberships"]) == 1

    membership = body["memberships"][0]
    assert membership["organization"]["id"] == str(identity.organization_id)
    assert membership["organization"]["slug"] == identity.organization_slug
    assert membership["role"]["code"] == "owner"
    assert membership["status"] == "active"
    assert membership["permissions"] == sorted(
        permission.value for permission in ROLE_PERMISSIONS[RoleCode.OWNER]
    )


def test_every_membership_is_reported(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """One person, two organizations, two roles — both are listed, each with its own."""
    first: Identity = identity_factory(role_code="owner")
    second: Identity = identity_factory(role_code="ai_admin")
    joined = identity_factory.join(
        first, organization_id=second.organization_id, role_code="analyst"
    )

    response = authenticate(joined).get(ME)

    assert response.status_code == 200
    memberships = response.json()["memberships"]
    assert len(memberships) == 2
    by_slug = {membership["organization"]["slug"]: membership for membership in memberships}
    assert by_slug[first.organization_slug]["role"]["code"] == "owner"
    assert by_slug[second.organization_slug]["role"]["code"] == "analyst"
    assert by_slug[second.organization_slug]["permissions"] == sorted(
        permission.value for permission in ROLE_PERMISSIONS[RoleCode.ANALYST]
    )


def test_authentication_is_required(database_client: TestClient) -> None:
    """No credential, no identity — and the client is told how to authenticate."""
    response = database_client.get(ME)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["error"]["code"] == "unauthorized"


def test_every_broken_credential_is_refused_identically(
    database_client: TestClient, identity_factory, integration_engine: Engine
) -> None:
    """Unknown, revoked and expired tokens, and a suspended account: one answer.

    A client — or an attacker probing — must not be able to tell *why* a credential
    failed, because that difference is a signal: "this token existed" and "this
    account exists" are both worth knowing.
    """
    unknown = "aicore_not-issued-to-anybody"
    revoked: Identity = identity_factory()
    revoke_token(integration_engine, revoked.token_id)
    expired: Identity = identity_factory()
    expire_token(integration_engine, expired.token_id)
    suspended: Identity = identity_factory()
    suspend_user(integration_engine, suspended.user_id)

    answers = []
    for token in (unknown, revoked.token, expired.token, suspended.token):
        response = database_client.get(ME, headers={"Authorization": f"Bearer {token}"})
        answers.append(
            (
                response.status_code,
                response.json()["error"]["code"],
                response.headers.get("www-authenticate"),
            )
        )

    assert answers == [(401, "unauthorized", "Bearer")] * 4


def test_the_credential_is_never_echoed(
    database_client: TestClient, identity_factory, authenticate
) -> None:
    """A response must not contain the credential that produced it."""
    identity: Identity = identity_factory()

    response = authenticate(identity).get(ME)

    assert identity.token not in response.text
    # The user object is exactly the four fields a client needs — nothing internal
    # (no hash, no prefix, no revocation state) is published.
    assert set(response.json()["user"]) == {"id", "email", "full_name", "status"}


def test_credentials_are_only_read_from_the_authorization_header(
    database_client: TestClient, identity_factory
) -> None:
    """A valid credential in the wrong place is not a credential.

    Query strings end up in access logs and referrers, and cookies are sent by the
    browser on a request the user did not intend; accepting either would mean a
    credential that leaks by design.
    """
    identity: Identity = identity_factory()

    in_query = database_client.get(
        ME, params={"token": identity.token, "api_token": identity.token}
    )
    in_cookie = database_client.get(ME, cookies={"token": identity.token})
    in_body = database_client.request("GET", ME, json={"token": identity.token})

    assert in_query.status_code == 401
    assert in_cookie.status_code == 401
    assert in_body.status_code == 401


def test_a_suspended_membership_grants_nothing(
    database_client: TestClient, identity_factory, authenticate, integration_engine: Engine
) -> None:
    """A suspended membership is visible, and carries no permissions at all."""
    identity: Identity = identity_factory(role_code="owner")
    suspend_membership(integration_engine, identity)

    body = authenticate(identity).get(ME).json()

    membership = body["memberships"][0]
    assert membership["status"] == "suspended"
    assert membership["permissions"] == []
    # The role is still reported: the suspension is the fact, not a lack of a role.
    assert membership["role"]["code"] == "owner"
