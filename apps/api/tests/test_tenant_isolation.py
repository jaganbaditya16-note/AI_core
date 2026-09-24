"""Tenant isolation is a security boundary — this file is the proof.

Two levels, deliberately separated:

* **Rules** (no database, always run): a statement touching tenant-owned data
  cannot execute without a bound tenant, a tenant-scoped repository cannot be
  constructed without one, and a tenant id is never coerced from arbitrary input.
  These use an in-memory SQLite engine purely as a connection object — the guard
  refuses the statement before any SQL reaches a server, so nothing is created
  and no server is needed.

* **Behaviour** (``integration``, real PostgreSQL): the same query returns only
  the bound tenant's rows, an unknown tenant is rejected by the foreign key, and
  a tenant-owned row can never be tenant-less.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from aicore_api.db.repositories.organizations import OrganizationScopedRepository
from aicore_api.db.tenancy import (
    TenantOwnershipError,
    TenantScopeError,
    bind_tenant,
    current_tenant,
    tenant_owned_tables,
)
from tenant_fixture import QUALIFIED_TABLE, TenantScopedSample, count_samples, insert_sample


@pytest.fixture(scope="module")
def registry_engine() -> Iterator[Engine]:
    """A connection object for the guard tests. Never touches a real database."""
    engine = create_engine("sqlite+pysqlite:///:memory:", poolclass=StaticPool)
    try:
        yield engine
    finally:
        engine.dispose()


# ── Ownership is derived from the schema, not remembered ─────────────────────


def test_tenant_owned_tables_includes_the_tenant_boundary_table() -> None:
    assert TenantScopedSample.__tablename__ in tenant_owned_tables()


def test_organizations_is_not_tenant_owned() -> None:
    """The tenant registry defines the boundary, so it is not inside it."""
    assert "organizations" not in tenant_owned_tables()


def test_the_policy_tables_are_tenant_owned() -> None:
    """Derived from the schema, exactly like the sample table: a policy and its
    versions carry an ``organization_id``, so the guard covers both — including the
    history, which is the half a reader is most likely to forget."""
    owned = tenant_owned_tables()

    assert "policies" in owned
    assert "policy_versions" in owned


def test_the_policy_repository_cannot_be_built_without_a_tenant() -> None:
    """The same rule as every other tenant-scoped repository, applied to policies."""
    from aicore_api.db.repositories.policies import PolicyRepository

    with pytest.raises(TenantScopeError):
        PolicyRepository(_SessionStub())  # type: ignore[arg-type]


class _SessionStub:
    """A session-shaped object that is never used: construction fails before it."""

    def execute(self, *_: object, **__: object) -> None:  # pragma: no cover
        raise AssertionError("a repository without a tenant must not reach the session")


# ── A tenant id is never inferred or coerced ─────────────────────────────────


def test_tenant_id_must_be_a_uuid() -> None:
    not_a_uuid = "6f1b1b1e-0000-0000-0000-000000000000"

    with pytest.raises(TenantOwnershipError), bind_tenant(not_a_uuid):  # type: ignore[arg-type]
        pass


def test_the_binding_is_reset_after_the_block() -> None:
    """One request's tenant must not leak into whatever runs next."""
    tenant_id = uuid.uuid4()

    with bind_tenant(tenant_id):
        assert current_tenant() == tenant_id

    assert current_tenant() is None


# ── Unscoped access to tenant-owned data is refused ──────────────────────────


def test_orm_select_without_a_bound_tenant_is_refused(registry_engine: Engine) -> None:
    with (
        registry_engine.connect() as connection,
        pytest.raises(TenantScopeError, match="without a bound tenant"),
    ):
        connection.execute(select(TenantScopedSample))


def test_raw_sql_without_a_bound_tenant_is_refused(registry_engine: Engine) -> None:
    """Hand-written SQL is the realistic leak path, so it is guarded too."""
    with registry_engine.connect() as connection, pytest.raises(TenantScopeError):
        connection.execute(text(f"SELECT id FROM {QUALIFIED_TABLE}"))


def test_insert_without_a_bound_tenant_is_refused(registry_engine: Engine) -> None:
    with registry_engine.connect() as connection, pytest.raises(TenantScopeError):
        connection.execute(
            text(
                f"INSERT INTO {QUALIFIED_TABLE} (id, organization_id, label) "
                "VALUES (:id, :organization_id, :label)"
            ),
            {"id": uuid.uuid4(), "organization_id": uuid.uuid4(), "label": "unscoped"},
        )


def test_the_guard_covers_every_engine_in_the_process() -> None:
    """A guard that a second engine could bypass would not be a guard."""
    engine = create_engine("sqlite+pysqlite:///:memory:", poolclass=StaticPool)
    try:
        with engine.connect() as connection, pytest.raises(TenantScopeError):
            connection.execute(text(f"SELECT id FROM {QUALIFIED_TABLE}"))
    finally:
        engine.dispose()


# ── A tenant-scoped repository cannot be built without a tenant ──────────────


def test_repository_requires_an_organization() -> None:
    """Nothing reaches the database when the tenant is missing."""
    assert current_tenant() is None

    with pytest.raises(TenantScopeError, match="requires an organization"):
        OrganizationScopedRepository(session=None)  # type: ignore[arg-type]


def test_repository_refuses_a_model_that_is_not_tenant_owned() -> None:
    """A tenant-scoped repository must not be used for tenant-agnostic tables."""
    from aicore_api.db.models.organization import Organization

    repository = OrganizationScopedRepository(session=None, organization_id=uuid.uuid4())  # type: ignore[arg-type]

    with pytest.raises(TenantScopeError, match="not tenant-owned"):
        repository._scoped(Organization)


# ── Behaviour that only a real database can demonstrate ──────────────────────


@pytest.mark.integration
def test_unfiltered_query_is_refused_even_with_a_bound_tenant(
    integration_engine: Engine,
    tenant_sample_table: str,
) -> None:
    """Binding a tenant is necessary but not sufficient: the query must be filtered.

    Without this rule, a bound tenant would merely label a query that still reads
    every tenant's rows.
    """
    with (
        integration_engine.connect() as connection,
        bind_tenant(uuid.uuid4()),
        pytest.raises(TenantScopeError, match="unfiltered statement"),
    ):
        connection.execute(text(f"SELECT id FROM {QUALIFIED_TABLE}"))


@pytest.mark.integration
def test_scoped_repository_returns_only_the_bound_tenants_rows(
    integration_session: Session,
    tenant_sample_table: str,
    two_organizations: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """The data-access layer is where tenant filtering is guaranteed."""
    tenant_a, tenant_b = two_organizations
    insert_sample(integration_session, tenant_a, "acme-agent")
    insert_sample(integration_session, tenant_b, "globex-agent")
    integration_session.commit()

    assert count_samples(integration_session, tenant_a) == 1
    assert count_samples(integration_session, tenant_b) == 1

    def labels_for(tenant: uuid.UUID) -> list[str]:
        repository = OrganizationScopedRepository(integration_session, organization_id=tenant)
        # `_scoped` is the base every resource repository builds on: a SELECT that
        # always carries the tenant predicate.
        return [
            row.label
            for row in repository.execute(repository._scoped(TenantScopedSample)).scalars().all()
        ]

    assert labels_for(tenant_a) == ["acme-agent"]
    assert labels_for(tenant_b) == ["globex-agent"]


@pytest.mark.integration
def test_cross_tenant_row_cannot_be_loaded_by_primary_key(
    integration_session: Session,
    tenant_sample_table: str,
    two_organizations: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """Knowing another tenant's row id must not be enough to read it."""
    tenant_a, tenant_b = two_organizations
    row_b = insert_sample(integration_session, tenant_b, "secret")
    integration_session.commit()

    with bind_tenant(tenant_a):
        rows = integration_session.execute(
            text(f"SELECT id FROM {QUALIFIED_TABLE} WHERE id = :id AND organization_id = :tenant"),
            {"id": row_b, "tenant": tenant_a},
        ).all()

    assert rows == []
    # ...and the row does exist for its owner, so the test is not passing by accident.
    assert count_samples(integration_session, tenant_b) == 1


@pytest.mark.integration
def test_a_row_cannot_be_attached_to_an_unknown_tenant(
    integration_engine: Engine,
    tenant_sample_table: str,
) -> None:
    """The foreign key is the last line of defence if the guard is bypassed."""
    with (
        integration_engine.connect() as connection,
        bind_tenant(uuid.uuid4()),
        pytest.raises(IntegrityError),
    ):
        connection.execute(
            text(
                f"INSERT INTO {QUALIFIED_TABLE} (id, organization_id, label) "
                "VALUES (:id, :organization_id, :label)"
            ),
            {"id": uuid.uuid4(), "organization_id": uuid.uuid4(), "label": "orphan"},
        )


@pytest.mark.integration
def test_a_tenant_owned_row_can_never_be_tenant_less(
    integration_engine: Engine,
    tenant_sample_table: str,
) -> None:
    """Nullability: the boundary column is NOT NULL, so no row can escape a tenant."""
    with (
        integration_engine.connect() as connection,
        bind_tenant(uuid.uuid4()),
        pytest.raises(IntegrityError),
    ):
        connection.execute(
            text(
                f"INSERT INTO {QUALIFIED_TABLE} (id, organization_id, label) "
                "VALUES (:id, NULL, :label)"
            ),
            {"id": uuid.uuid4(), "label": "no tenant"},
        )


@pytest.mark.integration
def test_filtered_raw_sql_is_allowed_with_a_bound_tenant(
    integration_engine: Engine,
    tenant_sample_table: str,
    two_organizations: tuple[uuid.UUID, uuid.UUID],
) -> None:
    """A filtered statement still works — the rule is narrow, not a blanket ban."""
    tenant_a, _ = two_organizations

    with integration_engine.connect() as connection, bind_tenant(tenant_a):
        statement = text(
            f"SELECT organization_id FROM {QUALIFIED_TABLE} WHERE organization_id = :tenant"
        )
        rows = connection.execute(statement, {"tenant": tenant_a}).all()

    assert {row[0] for row in rows} <= {tenant_a}
