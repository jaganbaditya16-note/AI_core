"""Authentication and authorization.

- :mod:`aicore_api.auth.tokens` — token format and hashing.
- :mod:`aicore_api.auth.principal` — the authenticated caller.
- :mod:`aicore_api.auth.providers` — credentials → principal (the swappable seam).
- :mod:`aicore_api.auth.authorization` — principal + organization → permissions.
- :mod:`aicore_api.auth.dependencies` — how routes state their requirements.

Design and rationale: ``docs/authentication.md``.

Only the dependency-free parts are re-exported here. The provider layer reads the
database, and the repositories reach back into this package for token hashing:
re-exporting everything would make ``import aicore_api.auth.tokens`` execute the
provider and ORM imports first, which is a circular import. Import the module you
need (``from aicore_api.auth.providers import ...``) rather than widening this
list.
"""

from __future__ import annotations

from aicore_api.auth.principal import Principal, UserStatus
from aicore_api.auth.tokens import generate_token, hash_token, token_prefix

__all__ = [
    "Principal",
    "UserStatus",
    "generate_token",
    "hash_token",
    "token_prefix",
]
