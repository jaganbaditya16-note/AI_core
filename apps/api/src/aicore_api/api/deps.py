"""Request dependencies.

The session dependency is the application's single source of database sessions.
It closes the session in a ``finally`` block, so a handler that raises still
returns its connection to the pool.

It deliberately does **not** bind a tenant. Tenant binding is an authorization
outcome — the request handler knows its tenant only once identity is resolved —
and baking a default here would be exactly the "hidden global state" that makes
cross-tenant leaks easy. Handlers that touch tenant-owned data bind explicitly
with :func:`aicore_api.db.tenancy.bind_tenant` (or use a scoped repository).
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy.orm import Session

from aicore_api.db.session import get_session_factory


def get_session() -> Iterator[Session]:
    """Yield a session for the duration of one request."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
