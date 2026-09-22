"""API token format and hashing.

A token is ``aicore_`` followed by 43 URL-safe base64 characters (32 bytes of
CSPRNG output). Three properties follow from that, and all three are the point:

- **Unguessable.** 256 bits of entropy. There is no rate limit that matters and
  no lockout to implement, because online guessing is hopeless.
- **Verifiable without storing it.** The database holds ``sha256(token)``; the
  plaintext is shown once, at issue time. A slow password hash would be the
  wrong tool: there is no low-entropy secret to protect against offline
  cracking, only a 256-bit random value.
- **Identifiable in a listing.** The stored prefix (``aicore_9f2c``) lets an
  operator see *which* credential a row is without being able to reconstruct it.

The prefix is deliberately short: it must be useless for authentication, so it
is never accepted as a credential — :func:`hash_token` is only ever fed the full
value, and authentication compares the hash of what was presented.
"""

from __future__ import annotations

import hashlib
import secrets

__all__ = [
    "TOKEN_BYTES",
    "TOKEN_HASH_PREFIX",
    "TOKEN_PREFIX",
    "generate_token",
    "hash_token",
    "token_prefix",
]

#: Human-recognisable marker, so a leaked string in a log is immediately
#: identifiable as an AICore credential (and can be revoked as one). Not a
#: secret: it is the same for every token and grants nothing on its own.
TOKEN_PREFIX = "aicore_"  # noqa: S105 - a public marker, not a credential

#: Bytes of randomness per token.
TOKEN_BYTES = 32

#: Leading characters kept in the database for identification. Includes the
#: marker plus 6 characters of the random part.
TOKEN_HASH_PREFIX = 12


def generate_token() -> tuple[str, str, str]:
    """Create a credential.

    Returns ``(plaintext, prefix, hash)``. The plaintext is returned to the
    caller that is issuing it and must not be stored; the other two are what the
    database keeps.
    """
    plaintext = f"{TOKEN_PREFIX}{secrets.token_urlsafe(TOKEN_BYTES)}"
    return plaintext, token_prefix(plaintext), hash_token(plaintext)


def hash_token(value: str) -> str:
    """SHA-256 of the token, hex encoded.

    Tokens are compared by hashing and looking the digest up, so the plaintext
    never reaches a query, a query log or a database index.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def token_prefix(value: str) -> str:
    """The stored, non-secret identifier for a token."""
    return value[:TOKEN_HASH_PREFIX]
