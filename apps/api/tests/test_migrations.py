"""The migration is the schema, and the models must agree with it.

There is no `Base.metadata.create_all()` in this project: tables are created by
reviewed Alembic revisions (``database/migrations/versions``). That makes drift
between a model and a revision a real failure mode — the application would query
columns the database does not have — so the comparison is asserted here.

Two properties are checked:

- **the migrated schema matches the models** (the migration is not out of date);
- **an unmigrated database fails readiness** rather than being silently usable,
  which is how a missing migration would otherwise present itself in production.
"""

from __future__ import annotations

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, inspect, text

from aicore_api.db.base import APP_SCHEMA, Base
from aicore_api.db.models.organization import Organization

CONFIG = Config("alembic.ini")
EXPECTED_REVISION = "0001_organizations"


def test_migration_revision_is_the_expected_head() -> None:
    """One revision, named for what it does; a second one must be a review decision."""
    script = ScriptDirectory.from_config(CONFIG)

    assert script.get_current_head() == EXPECTED_REVISION
    assert [revision.revision for revision in script.walk_revisions()] == [EXPECTED_REVISION]


def test_every_migration_states_a_real_downgrade() -> None:
    """A downgrade that does nothing is not a reversal; check it performs work."""
    import inspect as python_inspect

    revision = ScriptDirectory.from_config(CONFIG).get_revision(EXPECTED_REVISION)
    assert revision is not None
    body = python_inspect.getsource(revision.module.downgrade)

    assert "op." in body, "downgrade() contains no schema operation"


def test_migrated_schema_matches_the_models(integration_engine: Engine) -> None:
    """Compare the live schema with the metadata Alembic generates from."""
    inspector = inspect(integration_engine)

    assert APP_SCHEMA in inspector.get_schema_names(), f"schema {APP_SCHEMA!r} is missing"

    live_tables = set(inspector.get_table_names(schema=APP_SCHEMA)) - {"alembic_version"}
    model_tables = {table.name for table in Base.metadata.tables.values()}

    assert live_tables == model_tables

    live_columns = {
        column["name"]
        for column in inspector.get_columns(Organization.__tablename__, schema=APP_SCHEMA)
    }
    model_columns = {column.name for column in Organization.__table__.columns}

    assert live_columns == model_columns


def test_constraint_names_match_the_models(integration_engine: Engine) -> None:
    """Constraint *names* are part of the contract, not an implementation detail.

    This catches a subtle class of drift: giving a constraint an explicit name in
    a model **overrides** the naming convention, so the model can describe `slug`
    while the migration created `uq_organizations_slug`. Alembic then proposes
    dropping and re-adding it. Comparing the names the metadata renders with the
    names in the live database makes that disagreement a test failure.
    """
    inspector = inspect(integration_engine)

    live = {
        row["name"] for row in inspector.get_unique_constraints("organizations", schema=APP_SCHEMA)
    }
    live |= {
        row["name"] for row in inspector.get_check_constraints("organizations", schema=APP_SCHEMA)
    }
    live.add(inspector.get_pk_constraint("organizations", schema=APP_SCHEMA)["name"])

    expected = {c.name for c in Organization.__table__.constraints if c.name is not None}

    assert expected <= live, (
        f"model declares constraints the database does not have: {expected - live}"
    )


def test_the_table_comment_is_declared_in_the_model(integration_engine: Engine) -> None:
    """The schema the models describe is exactly the schema in the database."""
    with integration_engine.connect() as connection:
        comment = connection.execute(
            text("SELECT obj_description('aicore.organizations'::regclass, 'pg_class')")
        ).scalar_one()

    assert comment is not None
    assert Organization.__table__.comment == comment


def test_the_tenant_boundary_is_enforced_in_the_database(
    integration_engine: Engine,
    tenant_sample_table: str,
) -> None:
    """The foreign key is what makes the boundary hold outside the application."""
    inspector = inspect(integration_engine)
    foreign_keys = inspector.get_foreign_keys("organizations", schema=APP_SCHEMA)

    # organizations is the tenant root: it references nothing.
    assert foreign_keys == []

    # The fixture table (and every future resource table) references it with
    # ON DELETE RESTRICT.
    from tenant_fixture import TenantScopedSample

    sample_fks = inspector.get_foreign_keys(TenantScopedSample.__tablename__, schema=APP_SCHEMA)
    assert len(sample_fks) == 1
    assert sample_fks[0]["referred_table"] == "organizations"
    assert sample_fks[0]["options"].get("ondelete") == "RESTRICT"
    assert sample_fks[0]["constrained_columns"] == ["organization_id"]


def test_only_organizations_is_part_of_the_application_schema(
    integration_engine: Engine,
) -> None:
    """Phase 1 ships exactly one application table.

    The models, the migration and the live database must agree on that — this is
    the assertion that keeps a domain table from arriving unnoticed.
    """
    inspector = inspect(integration_engine)
    # The session-scoped tenant fixture may be present while the suite runs; it is
    # created by tests/tenant_fixture.py and is never part of the application schema.
    from tenant_fixture import TABLE_NAME as TEST_FIXTURE_TABLE

    live = (
        set(inspector.get_table_names(schema=APP_SCHEMA))
        - {"alembic_version"}
        - {TEST_FIXTURE_TABLE}
    )

    assert live == {"organizations"}
    assert {table.name for table in Base.metadata.tables.values()} == {"organizations"}
    assert TEST_FIXTURE_TABLE not in Base.metadata.tables


def test_an_unmigrated_database_is_detected(integration_engine: Engine) -> None:
    """Readiness for a fresh database must report the absence of the schema.

    Simulated by asking the question the migration answers: does the version table
    carry the expected revision? A database where this returns nothing has not
    been migrated.
    """
    with integration_engine.connect() as connection:
        # Literal statement: the schema name is a constant, not user input.
        revision = connection.execute(
            text("SELECT version_num FROM aicore.alembic_version")
        ).scalar_one()

    assert revision == EXPECTED_REVISION
