"""Authentication providers: the seam between credentials and an identity.

The application never does "if the header looks like X then the user is Y".
It parses a credential, hands it to a provider, and gets back either a
:class:`~aicore_api.auth.principal.Principal` or ``None``. Everything else —
memberships, roles, permissions — comes later and comes from the database.

Phase 2 ships one provider, ``api_token``: bearer tokens issued by the CLI and
stored as hashes. It is a real mechanism, not a placeholder: it is what the API
accepts in every environment, including production, and it is what the test
suite authenticates with (a test that used a *different* authentication path
than production would prove nothing about production).

An external identity provider (OIDC) is added by implementing this protocol and
registering it in :data:`PROVIDERS` — no route, dependency or authorization code
changes, because none of them know how a principal was established. There is no
half-written OIDC provider in this codebase: a stub that "validates" tokens
without verifying a signature would be worse than none.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import ClassVar, Protocol

from sqlalchemy.orm import Session

from aicore_api.auth.principal import Principal
from aicore_api.auth.tokens import hash_token
from aicore_api.config import Settings
from aicore_api.db.models.user import UserStatus
from aicore_api.db.repositories.api_tokens import ApiTokenRepository
from aicore_api.db.repositories.users import UserRepository

__all__ = [
    "BEARER_SCHEME",
    "PROVIDERS",
    "ApiTokenAuthenticationProvider",
    "AuthenticationConfigurationError",
    "AuthenticationProvider",
    "Credentials",
    "build_authentication_provider",
    "parse_authorization_header",
]

#: The HTTP authentication scheme AICore accepts.
BEARER_SCHEME = "bearer"

#: Upper bound on a presented credential. Bounds the work a hostile client can
#: ask for before the value is hashed; a real token is 50 characters.
MAX_CREDENTIAL_LENGTH = 512


class AuthenticationConfigurationError(RuntimeError):
    """The configured provider does not exist. Raised at startup, not per request."""


@dataclass(frozen=True, slots=True)
class Credentials:
    """A parsed credential. ``value`` is a secret: it is never logged or stored."""

    scheme: str
    value: str

    def __repr__(self) -> str:
        return f"<Credentials scheme={self.scheme!r} value=<redacted>>"


def parse_authorization_header(header: str | None) -> Credentials | None:
    """Parse an ``Authorization`` header into a scheme and a value.

    Returns ``None`` for anything malformed — a missing scheme, an empty value,
    an over-long value, extra whitespace-separated parts. The caller turns that
    into a 401; distinguishing *why* a credential was rejected would only help
    an attacker.

    Credentials are never parsed from a query string, a cookie or a body field:
    one accepted location is one place to get the handling right.
    """
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2:
        return None
    scheme, value = parts[0].strip().lower(), parts[1].strip()
    if not scheme or not value or len(value) > MAX_CREDENTIAL_LENGTH:
        return None
    return Credentials(scheme=scheme, value=value)


class AuthenticationProvider(Protocol):
    """Turns credentials into an identity, or into ``None``."""

    name: ClassVar[str]

    def authenticate(self, credentials: Credentials) -> Principal | None:
        """Return the authenticated principal, or ``None`` if the credentials fail."""
        ...


class ApiTokenAuthenticationProvider:
    """Bearer tokens, verified against stored SHA-256 hashes."""

    name: ClassVar[str] = "api_token"

    def __init__(self, session: Session) -> None:
        self._session = session

    def authenticate(self, credentials: Credentials) -> Principal | None:
        """Resolve a bearer token to its user.

        Every failure — unknown token, revoked, expired, suspended user — returns
        ``None``. The caller cannot tell them apart, and neither can a client.
        """
        if credentials.scheme != BEARER_SCHEME:
            return None

        token = ApiTokenRepository(self._session).find_by_hash(hash_token(credentials.value))
        if token is None or token.revoked_at is not None:
            return None
        if token.expires_at is not None and token.expires_at <= datetime.now(UTC):
            return None

        user = UserRepository(self._session).get(token.user_id)
        if user is None or user.status != UserStatus.ACTIVE.value:
            return None

        # ``status`` is the literal "active" on purpose: the check above already
        # rejected every other value, so this states the invariant instead of
        # re-reading the column and hoping it still says what it said.
        return Principal(
            user_id=user.id,
            email=user.email,
            full_name=user.full_name,
            status="active",
        )


#: Provider registry. Adding a provider is adding its class plus an entry here —
#: the settings type (``AICORE_AUTH_PROVIDER``) enumerates what may be selected.
PROVIDERS: Mapping[str, Callable[[Session], AuthenticationProvider]] = MappingProxyType(
    {"api_token": ApiTokenAuthenticationProvider}
)


def build_authentication_provider(settings: Settings, session: Session) -> AuthenticationProvider:
    """Instantiate the configured provider for one unit of work.

    Providers are per-request because they need a database session; they hold no
    cache and no state between requests.
    """
    try:
        provider = PROVIDERS[settings.auth_provider]
    except KeyError as exc:  # pragma: no cover - settings validation prevents this
        raise AuthenticationConfigurationError(
            f"unknown authentication provider {settings.auth_provider!r}"
        ) from exc
    return provider(session)
