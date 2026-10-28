"""The provisioning CLI: how an installation gets its first identity.

Phase 2 ships no user-management API — deliberately. Creating the first
organization, the first user and the first credential is a *provisioning* action,
and provisioning belongs to whoever holds database access, not to an
unauthenticated HTTP route. That makes the CLI the documented path from an empty
database to a working credential, and the only path to one, so it is worth
testing as the operator would use it: run the command, take what it printed, and
authenticate with it.

An untested CLI here would mean the phase's front door was the least verified
part of it.
"""

from __future__ import annotations

import re
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from aicore_api.auth.tokens import hash_token
from aicore_api.cli import build_parser, main
from aicore_api.core.permissions import ROLE_PERMISSIONS, RoleCode
from identity_fixture import find_identity, purge_identity, stored_token_rows

#: The plaintext token is printed on a line of its own, so it can be piped.
_TOKEN_LINE = re.compile(r"^aicore_[A-Za-z0-9_\-]+$", re.MULTILINE)


def _printed_token(output: str) -> str:
    """The one line of CLI output that is a credential."""
    matches = _TOKEN_LINE.findall(output)
    assert len(matches) == 1, f"expected exactly one token in the output:\n{output}"
    return matches[0]


def test_bootstrap_produces_a_working_owner(
    database_client: TestClient, integration_engine: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    """Bootstrap, then use the printed token over HTTP, exactly as the docs say."""
    suffix = uuid.uuid4().hex[:8]
    slug, email = f"cli-{suffix}", f"cli-{suffix}@example.test"

    exit_code = main(
        [
            "bootstrap",
            "--email",
            email,
            "--full-name",
            "Command Line",
            "--organization-name",
            "CLI Corporation",
            "--organization-slug",
            slug,
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    token = _printed_token(output)
    assert slug in output and email in output

    identity = find_identity(integration_engine, organization_slug=slug, email=email, token=token)
    try:
        response = database_client.get("/me", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["user"]["email"] == email
        membership = body["memberships"][0]
        assert membership["organization"]["slug"] == slug
        assert membership["role"]["code"] == RoleCode.OWNER.value
        assert membership["permissions"] == sorted(
            permission.value for permission in ROLE_PERMISSIONS[RoleCode.OWNER]
        )

        # The token the operator received is the one the database hashed, and the
        # plaintext is nowhere in the row.
        stored = stored_token_rows(integration_engine, identity.token_id)
        assert stored.token_hash == hash_token(token)
        assert token not in (stored.token_prefix, stored.name)
    finally:
        purge_identity(integration_engine, identity)


def test_bootstrap_refuses_a_slug_that_is_already_taken(
    database_client: TestClient, integration_engine: Engine, capsys: pytest.CaptureFixture[str]
) -> None:
    """Running it twice is an error, not a second tenant with the same slug."""
    suffix = uuid.uuid4().hex[:8]
    slug, email = f"cli-{suffix}", f"cli-{suffix}@example.test"
    arguments = [
        "bootstrap",
        "--email",
        email,
        "--full-name",
        "Command Line",
        "--organization-name",
        "CLI Corporation",
        "--organization-slug",
        slug,
    ]
    assert main(arguments) == 0
    first = find_identity(
        integration_engine,
        organization_slug=slug,
        email=email,
        token=_printed_token(capsys.readouterr().out),
    )
    try:
        exit_code = main(arguments)

        assert exit_code == 1
        captured = capsys.readouterr()
        assert f"error: an organization with slug '{slug}' already exists" in captured.err
        assert _TOKEN_LINE.findall(captured.out) == []
    finally:
        purge_identity(integration_engine, first)


def test_an_unknown_role_is_refused_before_anything_is_written() -> None:
    """The role list comes from the catalog, and argparse rejects anything else."""
    with pytest.raises(SystemExit) as exit_info:
        main(
            [
                "add-member",
                "--organization",
                "somewhere",
                "--email",
                "nobody@example.test",
                "--role",
                "auditor_shadow",
            ]
        )

    assert exit_info.value.code == 2


def test_the_cli_offers_no_password_or_credential_argument(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """There are no passwords in AICore, and no way to hand one over.

    A credential is 256 bits of CSPRNG output that the CLI *generates*; a
    ``--password`` flag would mean the opposite, and ``--token-value`` would mean
    storing something weaker. Both are refused here as a matter of contract, not
    of current implementation.
    """
    with pytest.raises(SystemExit):
        main(["create-api-token", "--help"])
    printed = capsys.readouterr().out

    assert "--email" in printed and "--name" in printed  # who it is for, what it is for
    for forbidden in ("--password", "--secret", "--token-value"):
        assert forbidden not in printed
        assert forbidden not in build_parser().format_help()
