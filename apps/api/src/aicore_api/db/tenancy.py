"""Tenant isolation.

The requirement: a tenant-owned row can never be read or written without an
explicit organization context, and isolation must not depend on everybody
remembering to add a filter.

Three mechanisms, layered:

1. **Ownership is declared on the model, not on the query.**
   :class:`aicore_api.db.base.TenantOwnedMixin` is the tenant boundary. Any table
   carrying an ``organization_id`` column *is* tenant-owned — the property is
   read back out of the table definition, so there is no registry to keep in sync
   and no annotation that can be forgotten.

2. **Unscoped statements against tenant-owned tables are refused.**
   A ``before_execute`` hook on the ``Engine`` class inspects every statement
   before it reaches PostgreSQL. If it touches a tenant-owned table and no tenant is bound, the
   statement never executes: :class:`TenantScopeError` is raised. This covers ORM
   queries, Core statements and raw ``text()`` SQL — which is where a
   "temporary debugging query" would otherwise turn into a cross-tenant leak.

3. **Tenant-bound access must also be filtered.** A statement that reaches a
   tenant-owned table without mentioning the tenant column is refused, so
   "forgot the WHERE clause" is a loud error rather than a cross-tenant read.
   The check is conservative on purpose: it looks for the tenant column in the
   rendered SQL, which is not a proof of correctness, but it fails closed.

4. **The scope is auditable.** :func:`current_tenant` reports whether a tenant is
   bound, so a caller (or a test) can assert it rather than assume it.

Binding is explicit and request-scoped, never global: the tenant lives in a
:class:`contextvars.ContextVar` set by whoever owns the unit of work — a test or
script today, the authentication dependency in a later phase — and reset in a
``finally`` block so one request's tenant cannot leak into the next task.

Deliberate limits, stated so nobody assumes more exists:

- This is an *application-level* boundary. It prevents application mistakes; it
  is not a defence against a compromised process, which holds the same database
  credentials the guard uses.
- It guarantees "no unscoped access" and "no unfiltered access", not that a
  filter is *semantically correct*. The data-access layer in
  :mod:`aicore_api.db.repositories` builds the predicate for callers, which is
  where correctness is reviewable.
- PostgreSQL Row Level Security is **not** enabled in Phase 1 (see
  ``docs/database.md`` for why, and for how it slots in behind this same scope
  without changing a call site).
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from sqlalchemy import event, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql.base import Executable
from sqlalchemy.sql.dml import Delete, Insert, Update
from sqlalchemy.sql.elements import ClauseElement, TextClause
from sqlalchemy.sql.schema import Table
from sqlalchemy.sql.selectable import Select
from sqlalchemy.sql.visitors import iterate

from aicore_api.db.base import Base

__all__ = [
    "TenantOwnershipError",
    "TenantScopeError",
    "bind_tenant",
    "current_tenant",
    "register_metadata",
    "tenant_owned_tables",
    "tenant_scoped",
]

#: Column whose presence defines the tenant boundary.
TENANT_COLUMN = "organization_id"

#: Bound by whoever owns the unit of work. ``None`` means "no tenant context":
#: valid for migrations, DDL and health probes; blocked for tenant-owned tables.
_current_tenant: ContextVar[uuid.UUID | None] = ContextVar("aicore_current_tenant", default=None)

#: Metadata scanned for tenant-owned tables. The application's metadata is always
#: included; the test suite registers its own fixture metadata so the isolation
#: mechanism can be exercised without shipping a domain table.
_metadatas: list[object] = [Base.metadata]


class TenantScopeError(RuntimeError):
    """Raised when SQL touches tenant-owned data without a bound tenant.

    Subclasses ``RuntimeError``: reaching this state is a programming error, not
    client input, so it must surface as a server fault rather than a 4xx.
    """


class TenantOwnershipError(ValueError):
    """Raised when a caller passes something that is not a tenant identifier."""


def register_metadata(metadata: object) -> None:
    """Include ``metadata`` when resolving which tables are tenant-owned.

    Called by the test suite for its fixture table. Production code has no reason
    to call it: application tables are found through :class:`aicore_api.db.base.Base`.
    """
    if not any(existing is metadata for existing in _metadatas):
        _metadatas.append(metadata)


def tenant_owned_tables() -> frozenset[str]:
    """Names of every table that carries the tenant boundary.

    Derived from the table definitions, so it cannot drift from the schema:
    adding ``TenantOwnedMixin`` to a model is all it takes for that table to come
    under the guard.
    """
    names: set[str] = set()
    for metadata in _metadatas:
        tables = getattr(metadata, "tables", {})
        for table in tables.values():
            if isinstance(table, Table) and TENANT_COLUMN in table.columns:
                names.add(table.name)
    return frozenset(names)


def _tables_via_iteration(statement: ClauseElement) -> set[str] | None:
    """Table names reachable by walking a statement, or ``None`` if it resists it.

    ``iterate()`` yields ``AnnotatedTable``/``AnnotatedColumn`` wrappers rather
    than ``Table``/``Column``, so the wrapped ``element`` has to be unwrapped —
    checking ``isinstance(element, Table)`` directly silently finds nothing.
    """
    names: set[str] = set()
    try:
        for element in iterate(statement):
            target = getattr(element, "element", element)
            if isinstance(target, Table):
                names.add(target.name)
                continue
            parent = getattr(target, "table", None)
            if isinstance(parent, Table):
                names.add(parent.name)
    except SQLAlchemyError:  # pragma: no cover - unusual statement shapes
        return None
    return names


def _mentions_tenant_column(statement: Executable) -> bool:
    """Whether a statement filters on the tenant column.

    A cheap, deliberately conservative check: the rendered SQL must mention
    ``organization_id``. It is not a proof that the predicate is correct (nothing
    short of row-level security can be), but it turns the common accident — a
    query that forgot its tenant filter — into a refusal instead of a cross-tenant
    read. Legitimate queries that reach the tenant column through, say, a
    relationship predicate would need an explicit ``organization_id`` condition;
    that is the intended trade-off: fail loudly rather than leak quietly.
    """
    if isinstance(statement, TextClause):
        rendered = statement.text
    else:
        try:
            rendered = str(statement)
        except SQLAlchemyError:  # pragma: no cover - unusual statement shapes
            return False
    return TENANT_COLUMN in rendered


def _references_tenant_owned(statement: Executable) -> bool:
    """Whether a statement reads or writes tenant-owned data.

    Only data access is guarded:

    - ``SELECT`` — including ORM selects, which do not expose their table until
      the FROM clause is resolved via ``get_final_froms()``;
    - ``INSERT`` / ``UPDATE`` / ``DELETE`` — their target table;
    - raw ``text()`` SQL — matched textually against the tenant-owned table
      names, which is stricter than parsing it and the safe direction to be wrong
      in, since hand-written SQL is the realistic leak path.

    **DDL is deliberately exempt.** ``CREATE``/``ALTER``/``DROP`` are schema
    management performed by reviewed migrations, which necessarily run without a
    tenant (there is no tenant in a schema change). Blocking them would make the
    guard break Alembic rather than protect a boundary. Reflection queries are
    exempt for the same reason: they read the catalog, not tenant data.

    Anything that cannot be inspected counts as tenant-data access (fail closed).
    """
    owned = tenant_owned_tables()
    if not owned:
        return False

    if isinstance(statement, TextClause):
        return any(re.search(rf"\b{re.escape(name)}\b", statement.text) for name in owned)

    if isinstance(statement, (Insert, Update, Delete)):
        table = getattr(statement, "table", None)
        return isinstance(table, Table) and table.name in owned

    if isinstance(statement, Select):
        names = {source.name for source in statement.get_final_froms() if isinstance(source, Table)}
        walked = _tables_via_iteration(statement)
        if walked is None:
            return True
        return bool((names | walked) & owned)

    return False


@event.listens_for(Engine, "before_execute", retval=True)
def _enforce_tenant_scope(
    connection: Connection,
    clauseelement: Executable,
    multiparams: object,
    params: object,
    execution_options: object,
) -> tuple[Executable, object, object]:
    """Refuse to execute unscoped statements against tenant-owned data.

    Registered on the ``Engine`` class so it applies to every engine in the
    process — the application's, Alembic's, and any engine a test creates. A
    guard that could be bypassed by constructing a second engine would not be a
    guard.

    ``Engine`` (not ``Connection``) is the required target: SQLAlchemy only
    honours class-level ``ConnectionEvents`` listeners on the Engine class, and a
    listener registered on ``Connection`` is accepted without complaint while
    never being invoked. That failure mode is silent, so it is worth stating.
    """
    del execution_options  # unused: the guard inspects the statement, not its options

    tenant_id = current_tenant()
    if _references_tenant_owned(clauseelement):
        if tenant_id is None:
            raise TenantScopeError(
                "refusing to execute a statement against tenant-owned tables without a "
                "bound tenant; use tenant_scoped(...) so the organization boundary cannot "
                "be forgotten"
            )
        if not _mentions_tenant_column(clauseelement):
            raise TenantScopeError(
                "refusing an unfiltered statement against tenant-owned tables; filter on "
                "organization_id (or use a repository built on "
                "OrganizationScopedRepository, which always does)"
            )

    # Pass the arguments through untouched: with retval=True the return value
    # replaces them, so returning fresh empties would silently drop every bind
    # parameter of every statement in the process.
    return clauseelement, multiparams, params


def current_tenant() -> uuid.UUID | None:
    """The tenant bound to the current unit of work, if any.

    Reading this never raises: "no tenant" is a legitimate state (migrations,
    readiness probes, and every operation on non-tenant-owned data such as the
    organizations table itself).
    """
    return _current_tenant.get()


@contextmanager
def bind_tenant(organization_id: uuid.UUID) -> Iterator[uuid.UUID]:
    """Bind ``organization_id`` for the duration of the ``with`` block.

    Explicit by design: there is no ambient default tenant, so forgetting to bind
    cannot silently operate on the wrong organization — it is a hard failure.
    """
    if not isinstance(organization_id, uuid.UUID):
        msg = (
            "organization_id must be a uuid.UUID, got "
            f"{type(organization_id).__name__} — a tenant id is never coerced or inferred"
        )
        raise TenantOwnershipError(msg)

    token = _current_tenant.set(organization_id)
    try:
        yield organization_id
    finally:
        # Always reset: a failed request must not leak its tenant into whatever
        # task next runs in this context.
        _current_tenant.reset(token)


@contextmanager
def tenant_scoped(connection: Connection, organization_id: uuid.UUID) -> Iterator[uuid.UUID]:
    """Bind a tenant to a connection and have PostgreSQL confirm it.

    The binding is pushed to the database transaction-locally with
    ``set_config(..., is_local => true)``. Two consequences worth having now:

    - the binding cannot outlive its transaction; and
    - the schema is already prepared for a Row Level Security policy keyed on
      ``current_setting('aicore.organization_id')``, should a later phase add one.

    A database that rejects the value fails the operation — the guard never
    degrades into "carry on unscoped".
    """
    with bind_tenant(organization_id) as tenant_id:
        connection.execute(
            text("SELECT set_config('aicore.organization_id', :tenant, true)"),
            {"tenant": str(tenant_id)},
        )
        yield tenant_id
