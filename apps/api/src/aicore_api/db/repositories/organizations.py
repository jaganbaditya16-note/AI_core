"""Organization repositories — the tenant-scoped way to reach tenant data.

This module answers one question in code rather than in prose: *how does a query
get tenant-scoped, and what happens if it is not?* Phase 1 ships no domain
resources, so the concrete methods are deliberately small. What matters is the
shape:

- :class:`OrganizationScopedRepository` is the base every future resource
  repository inherits (agents, models, tools, policies, events, incidents). It
  resolves the tenant — from an explicit argument or from the request context —
  and **fails closed** when neither exists, so reaching PostgreSQL through it
  without a tenant is not possible.
- :class:`OrganizationRepository` is the deliberate exception: the tenant
  registry itself is not tenant-scoped (there is no outer tenant to scope it to).
  That power is confined to this class and spelled out in the names of its
  methods, so the code that can see across tenants is one grep away.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aicore_api.core.domain_errors import ConflictError, NotFoundError
from aicore_api.db.models.organization import Organization, OrganizationStatus
from aicore_api.db.tenancy import TenantScopeError, bind_tenant, current_tenant

__all__ = ["OrganizationRepository", "OrganizationScopedRepository"]


class OrganizationRepository:
    """Access to the tenant registry itself."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        *,
        name: str,
        slug: str,
        status: OrganizationStatus = OrganizationStatus.ACTIVE,
    ) -> Organization:
        """Create a tenant.

        The database is the arbiter of uniqueness: the ``uq_organizations_slug``
        constraint decides, and the resulting ``IntegrityError`` is translated
        into a :class:`ConflictError`. Checking with a SELECT first would be a
        check-then-act race.
        """
        organization = Organization(name=name, slug=slug, status=status.value)
        self._session.add(organization)
        try:
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise ConflictError(f"an organization with slug {slug!r} already exists") from exc
        self._session.commit()
        self._session.refresh(organization)
        return organization

    def get(self, organization_id: uuid.UUID) -> Organization:
        """Load one tenant by id, or raise :class:`NotFoundError`."""
        organization = self._session.get(Organization, organization_id)
        if organization is None:
            raise NotFoundError(f"organization {organization_id} was not found")
        return organization

    def find(self, organization_id: uuid.UUID) -> Organization | None:
        """Load one tenant by id; ``None`` when absent.

        Used where "there is no such organization" is a normal outcome rather
        than an error — notably by the authorization layer, which must answer a
        non-member and an unknown tenant with the same 404.
        """
        return self._session.get(Organization, organization_id)

    def find_by_slug(self, slug: str) -> Organization | None:
        """Look a tenant up by slug; ``None`` when absent."""
        return self._session.execute(
            select(Organization).where(Organization.slug == slug)
        ).scalar_one_or_none()

    def count_unscoped(self) -> int:
        """Number of tenants in this installation.

        Unscoped on purpose and named accordingly: this is installation-level
        inventory, not tenant data, so it is legitimate for an operator command
        and clearly wrong inside a tenant request handler.
        """
        return len(self._session.execute(select(Organization.id)).scalars().all())


class OrganizationScopedRepository:
    """Base class for every repository of tenant-owned resources.

    Subclasses implement the queries; this class guarantees that a tenant is
    bound before any of them can run. Two ways in, both explicit:

    - pass ``organization_id`` (the caller already knows its tenant, as a request
      handler will once authentication resolves it); or
    - omit it and rely on the tenant bound to the current context by
      :func:`aicore_api.db.tenancy.bind_tenant`.

    If neither holds, construction fails and nothing reaches the database.
    """

    def __init__(self, session: Session, organization_id: uuid.UUID | None = None) -> None:
        resolved = organization_id if organization_id is not None else current_tenant()
        if resolved is None:
            raise TenantScopeError(
                f"{type(self).__name__} requires an organization: pass organization_id or run "
                "inside tenant_scoped(...) — tenant-owned data is never queried unscoped"
            )
        self.session = session
        self.organization_id = resolved

    def execute(self, statement: Any, **parameters: Any) -> Any:
        """Run ``statement`` with this repository's tenant bound.

        Binding at execution time is what keeps the engine-level guard satisfied:
        the guard reads the tenant from the context, and the context is what this
        call sets. Reaching the session directly with a tenant-owned statement
        would be refused — which is the point, because a query that skipped this
        method also skipped the tenant boundary.
        """
        with bind_tenant(self.organization_id):
            return self.session.execute(statement, **parameters)

    @contextmanager
    def writing(self) -> Iterator[Session]:
        """Bind this repository's tenant around an ORM unit of work.

        :meth:`execute` covers statements the caller composes, but a write is not
        one: SQLAlchemy issues its ``INSERT``/``UPDATE`` at flush time, from
        inside the session, so the tenant must be bound around the whole unit of
        work rather than around a single call. Without this, the engine-level
        guard refuses the flush (correctly — it cannot see a tenant) and a
        legitimate write fails rather than being silently let through.

        Use it as ``with repository.writing(): session.add(row); session.flush()``.
        """
        with bind_tenant(self.organization_id):
            yield self.session

    def _scoped(self, model: Any) -> Any:
        """A ``SELECT`` over ``model`` already filtered to this repository's tenant.

        Subclasses must build on this rather than on a bare ``select(model)``. The
        engine-level guard in :mod:`aicore_api.db.tenancy` is the backstop for the
        case where somebody does not.
        """
        self._require_tenant_owned(model)
        return select(model).where(model.organization_id == self.organization_id)

    def _scoped_count(self, model: Any) -> Any:
        """A ``COUNT`` over ``model``, filtered to this repository's tenant.

        Its own helper because the obvious spelling is wrong in a way that only
        shows up at runtime: ``select(func.count()).select_from(Model)`` looks
        tenant-scoped and is not — the filter is the part that matters, and a count
        is the easiest query to forget it on.
        """
        self._require_tenant_owned(model)
        return (
            select(func.count())
            .select_from(model)
            .where(model.organization_id == self.organization_id)
        )

    @staticmethod
    def _require_tenant_owned(model: Any) -> None:
        """Refuse to build a tenant-scoped query over something without a tenant."""
        if not hasattr(model, "organization_id"):
            raise TenantScopeError(
                f"{getattr(model, '__name__', model)!r} is not tenant-owned, so it must not be "
                "reached through a tenant-scoped repository"
            )
