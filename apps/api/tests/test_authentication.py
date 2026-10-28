"""Authentication: credentials in, a principal out — or nothing.

These tests exercise the layer that decides *who is calling*, below HTTP. The
interesting failures here are quiet ones: a token that keeps working after it was
revoked, an account that still authenticates while suspended, a credential
accepted from somewhere other than the ``Authorization`` header. Each of those
would pass a happy-path API test and each is a real incident, so they are asserted
directly.

The tokens are real rows in real PostgreSQL, issued through the application's own
repository. A fake session would let these tests agree with a bug in the code they
are meant to check.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from aicore_api.auth.providers import (
    MAX_CREDENTIAL_LENGTH,
    ApiTokenAuthenticationProvider,
    Credentials,
    build_authentication_provider,
    parse_authorization_header,
)
from aicore_api.auth.tokens import generate_token, hash_token
from aicore_api.config import Settings
from aicore_api.db.models.api_token import ApiToken
from identity_fixture import (
    Identity,
    expire_token,
    revoke_token,
    stored_token_rows,
    suspend_user,
)


def _session(engine: Engine) -> Session:
    """A session of its own, because committed fixture rows are the subject."""
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return factory()


# ── The credential ────────────────────────────────────────────────────────────


def test_tokens_are_random_and_recognisable() -> None:
    """Two calls never collide, and a token in a log is identifiable as one."""
    first, first_prefix, first_hash = generate_token()
    second, _second_prefix, second_hash = generate_token()

    assert first != second
    assert first.startswith("aicore_") and first_prefix.startswith("aicore_")
    assert first_hash == hash_token(first)
    assert first_hash != first and second_hash != first_hash


def test_hashing_is_deterministic_and_one_way() -> None:
    """Lookup needs the hash to be stable; storage needs it to be irreversible."""
    plaintext, _prefix, digest = generate_token()

    assert hash_token(plaintext) == digest
    assert plaintext not in digest
    assert len(digest) == 64  # sha256, hex-encoded
    assert digest == digest.lower()


def test_only_the_hash_reaches_the_database(integration_engine: Engine, identity_factory) -> None:
    """Nothing stored may be replayable as the credential."""
    identity: Identity = identity_factory()

    row = stored_token_rows(integration_engine, identity.token_id)

    assert identity.token not in row.token_hash
    assert row.token_hash == hash_token(identity.token)
    assert row.token_hash != identity.token
    # The prefix exists so a leaked token can be recognised and revoked; it must
    # be far too short to be a credential in its own right.
    assert row.token_prefix in identity.token
    assert len(row.token_prefix) < len(identity.token) / 2


def test_the_header_is_parsed_and_parsed_strictly() -> None:
    """One scheme, one value, no guessing."""
    bearer = Credentials(scheme="bearer", value="aicore_abc")
    assert parse_authorization_header("Bearer aicore_abc") == bearer
    assert parse_authorization_header("bearer aicore_abc") == bearer
    assert parse_authorization_header("Bearer  aicore_abc") == bearer

    assert parse_authorization_header(None) is None
    assert parse_authorization_header("") is None
    assert parse_authorization_header("aicore_abc") is None  # no scheme
    assert parse_authorization_header("Bearer") is None  # no credential
    # The scheme is *parsed*, not filtered here: a provider decides which schemes
    # it accepts, so a new one does not mean editing the parser.
    assert parse_authorization_header("Basic aicore_abc") == Credentials("basic", "aicore_abc")
    assert parse_authorization_header(f"Bearer {'x' * (MAX_CREDENTIAL_LENGTH + 1)}") is None


def test_a_credential_does_not_print_its_secret() -> None:
    """A credential ends up in tracebacks and log lines; its repr must not leak it."""
    assert "aicore_secret" not in repr(Credentials(scheme="bearer", value="aicore_secret"))


# ── Establishing a principal ──────────────────────────────────────────────────


def test_a_valid_token_identifies_its_user(integration_engine: Engine, identity_factory) -> None:
    identity: Identity = identity_factory(role_code="analyst")
    session = _session(integration_engine)

    principal = ApiTokenAuthenticationProvider(session).authenticate(
        Credentials("bearer", identity.token)
    )

    assert principal is not None
    assert principal.user_id == identity.user_id
    assert principal.email == identity.email
    assert principal.status == "active"


def test_an_unknown_token_identifies_nobody(integration_session) -> None:
    provider = ApiTokenAuthenticationProvider(integration_session)

    assert provider.authenticate(Credentials("bearer", "aicore_definitely-not-issued")) is None
    assert provider.authenticate(Credentials("bearer", str(uuid.uuid4()))) is None


def test_a_revoked_token_stops_working(integration_engine: Engine, identity_factory) -> None:
    """Revocation is immediate: the row survives, the credential stops working."""
    identity: Identity = identity_factory()
    revoke_token(integration_engine, identity.token_id)
    session = _session(integration_engine)

    stored = session.execute(select(ApiToken).where(ApiToken.id == identity.token_id)).scalar_one()
    assert stored.revoked_at is not None, "revoking must record when, not delete the row"
    assert (
        ApiTokenAuthenticationProvider(session).authenticate(Credentials("bearer", identity.token))
        is None
    )


def test_an_expired_token_stops_working(integration_engine: Engine, identity_factory) -> None:
    identity: Identity = identity_factory(token_expires_in=timedelta(minutes=5))
    expire_token(integration_engine, identity.token_id)

    assert (
        ApiTokenAuthenticationProvider(_session(integration_engine)).authenticate(
            Credentials("bearer", identity.token)
        )
        is None
    )


def test_a_suspended_user_cannot_authenticate(integration_engine: Engine, identity_factory) -> None:
    """Suspension is an account decision, and it takes effect on the next request."""
    identity: Identity = identity_factory()
    suspend_user(integration_engine, identity.user_id)

    assert (
        ApiTokenAuthenticationProvider(_session(integration_engine)).authenticate(
            Credentials("bearer", identity.token)
        )
        is None
    )


def test_the_provider_is_chosen_by_configuration(settings: Settings, integration_session) -> None:
    """Routes never name a provider; the configured one is what runs."""
    assert settings.auth_provider == "api_token"

    provider = build_authentication_provider(settings, integration_session)

    assert isinstance(provider, ApiTokenAuthenticationProvider)
    # An unusable provider means unauthenticated, never authenticated.
    assert provider.authenticate(Credentials("bearer", "aicore_anything")) is None
