"""Request dependencies.

The session dependency is the application's single source of database sessions.
It closes the session in a ``finally`` block, so a handler that raises still
returns its connection to the pool.

It deliberately does **not** bind a tenant. Tenant binding is an authorization
outcome — the request handler knows its tenant only once identity is resolved —
and baking a default here would be exactly the "hidden global state" that makes
cross-tenant leaks easy. Handlers that touch tenant-owned data bind explicitly
with :func:`aicore_api.db.tenancy.bind_tenant` (or use a scoped repository).

Phase 7 adds the other two things a request handler should not construct for itself:
the action catalogue and the adapter registry. Both are process-wide, immutable
values built from code — never configuration, never a request field — and both are
dependencies so that a test can substitute one deliberately instead of patching a
module attribute. Nothing in a request can influence either: the identifier in a body
selects an entry from these registries or the request is refused.

Phase 8 adds the audit writer, for the same reason and with one of its own: it is the
only thing that writes a trail row, so a test that wants to prove what happens when the
*record* fails needs a way to substitute it — and an application that built its own
writer per call site would have no such seam. Like the registries it is not
configurable: it is constructed from the request's session and nothing else.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from aicore_api.audit.writer import AuditWriter
from aicore_api.core.actions import ActionRegistry, default_action_registry
from aicore_api.core.executors import ActionExecutorRegistry, default_executors
from aicore_api.db.session import get_session_factory

__all__ = [
    "ActionExecutorRegistryDep",
    "ActionRegistryDep",
    "AuditWriterDep",
    "get_action_executors",
    "get_action_registry",
    "get_audit_writer",
    "get_session",
]


def get_session() -> Iterator[Session]:
    """Yield a session for the duration of one request."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def get_action_registry() -> ActionRegistry:
    """The registered actions this build serves: the allowlist, from code."""
    return default_action_registry()


def get_action_executors() -> ActionExecutorRegistry:
    """The adapters a firewall ``ALLOW`` may reach: the allowlist, one level down."""
    return default_executors()


def get_audit_writer(session: Annotated[Session, Depends(get_session)]) -> AuditWriter:
    """The audit writer for this request, on this request's session.

    One writer per request rather than a process-wide one, because the trail row belongs
    to the unit of work that made the change: no session, no traffic.
    """
    return AuditWriter(session)


ActionRegistryDep = Annotated[ActionRegistry, Depends(get_action_registry)]
ActionExecutorRegistryDep = Annotated[ActionExecutorRegistry, Depends(get_action_executors)]
AuditWriterDep = Annotated[AuditWriter, Depends(get_audit_writer)]
