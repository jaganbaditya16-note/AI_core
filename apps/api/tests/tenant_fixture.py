"""A tenant-owned fixture table, defined by the tests.

Phase 1 deliberately ships **no** domain table: there are no agents, models,
tools, data sources, policies, events or incidents yet. That leaves nothing
tenant-owned in the application schema — and a tenant boundary that cannot be
exercised is not a boundary.

``TenantScopedSample`` therefore declares one throwaway table:

- it lives on its own :class:`SampleBase`, so it is *not* on ``Base.metadata``
  (the metadata Alembic generates migrations from) and can never appear in a
  migration or in production;
- it inherits the real :class:`~aicore_api.db.base.TenantOwnedMixin`, so it gets
  the same ``organization_id`` foreign key and constraint the future resource
  tables will have;
- its metadata is registered with the tenancy guard, so the guard treats it as
  tenant-owned exactly as it will treat a real resource table.

Everything the isolation tests prove about this table is therefore a statement
about the convention, not about the fixture.
"""

from __future__ import annotations

import uuid

from sqlalchemy import MetaData, String, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from aicore_api.db.base import (
    APP_SCHEMA,
    NAMING_CONVENTION,
    Base,
    TenantOwnedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from aicore_api.db.tenancy import bind_tenant


class SampleBase(DeclarativeBase):
    """Separate metadata — the fixture table must never reach the app schema."""

    metadata = MetaData(schema=APP_SCHEMA, naming_convention=NAMING_CONVENTION)


def _make_tenant_fk_resolvable() -> None:
    """Copy ``organizations`` into the fixture metadata.

    ``tenant_scoped_samples.organization_id`` carries a real foreign key to
    ``aicore.organizations``, exactly as every future resource table will. Because
    the fixture lives on its own metadata, SQLAlchemy needs the *referenced* table
    present there to compile that constraint — the copy is only for resolution;
    PostgreSQL enforces the constraint against the real table created by the
    migration.
    """
    organizations = Base.metadata.tables[f"{APP_SCHEMA}.organizations"]
    organizations.to_metadata(SampleBase.metadata)


class TenantScopedSample(UUIDPrimaryKeyMixin, TimestampMixin, TenantOwnedMixin, SampleBase):
    """A tenant-owned row. Mirrors how a Phase 2 resource table will be declared."""

    __tablename__ = "tenant_scoped_samples"

    label: Mapped[str] = mapped_column(String(64), nullable=False)


_make_tenant_fk_resolvable()

TABLE_NAME = TenantScopedSample.__tablename__
QUALIFIED_TABLE = f"{APP_SCHEMA}.{TABLE_NAME}"


def insert_sample(session: Session, organization_id: uuid.UUID, label: str) -> uuid.UUID:
    """Insert a row for ``organization_id`` and return its identifier.

    Raw SQL on purpose: it shows that the guard covers hand-written statements
    too, not just the ORM. The ``bind_tenant`` wrapper is not ceremony — without
    it the guard refuses the statement, which is the behaviour the isolation
    tests assert. This is how application code must reach tenant-owned data.
    """
    row_id = uuid.uuid4()
    with bind_tenant(organization_id):
        session.execute(
            text(
                f"INSERT INTO {QUALIFIED_TABLE} (id, organization_id, label) "
                "VALUES (:id, :organization_id, :label)"
            ),
            {"id": row_id, "organization_id": organization_id, "label": label},
        )
    session.flush()
    return row_id


def count_samples(session: Session, organization_id: uuid.UUID) -> int:
    """Count rows for one tenant: filtered by the tenant *and* bound to it."""
    with bind_tenant(organization_id):
        rows = (
            session.execute(
                text(f"SELECT id FROM {QUALIFIED_TABLE} WHERE organization_id = :organization_id"),
                {"organization_id": organization_id},
            )
            .scalars()
            .all()
        )
    return len(rows)
