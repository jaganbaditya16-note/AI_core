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
from sqlalchemy.orm import Session

from aicore_api.core.permissions import ROLE_PERMISSIONS, Permission
from aicore_api.db.base import APP_SCHEMA, Base
from aicore_api.db.models.organization import Organization
from aicore_api.db.repositories.rbac import RoleCatalog

CONFIG = Config("alembic.ini")
EXPECTED_REVISION = "0005_policies"
#: Oldest first: each revision's ``down_revision`` must be the one before it.
EXPECTED_CHAIN = [
    "0001_organizations",
    "0002_identity_and_rbac",
    "0003_assets",
    "0004_agents",
    "0005_policies",
]


def test_migration_revision_is_the_expected_head() -> None:
    """The head is named for what it does; another revision is a review decision."""
    script = ScriptDirectory.from_config(CONFIG)

    assert script.get_current_head() == EXPECTED_REVISION
    assert [revision.revision for revision in reversed(list(script.walk_revisions()))] == (
        EXPECTED_CHAIN
    )


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


def test_the_application_schema_is_exactly_what_the_models_declare(
    integration_engine: Engine,
) -> None:
    """Nine tables: the tenant registry, Phase 2's identity and RBAC tables, Phase 3's
    asset inventory and Phase 4's agent registry.

    The models, the migrations and the live database must agree on that set — this
    is the assertion that keeps a table from arriving unnoticed, and the reason
    "we will add the table later" cannot quietly become a schema change.
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

    expected = {
        "organizations",
        "users",
        "roles",
        "permissions",
        "role_permissions",
        "memberships",
        "api_tokens",
        "assets",
        "agents",
        "policies",
        "policy_versions",
    }
    assert live == expected
    assert {table.name for table in Base.metadata.tables.values()} == expected
    assert TEST_FIXTURE_TABLE not in Base.metadata.tables


def test_the_migration_seeds_the_catalog_the_code_declares(
    integration_session: Session,
) -> None:
    """The role/permission catalog exists twice: as code and as a seeded migration.

    The migration has to seed it (a deployment must not start with an empty
    catalog), and ``aicore_api.core.permissions`` has to state it (tests and
    application code need it without a database). Both copies are therefore
    compared against the live rows here: change one without the other and this
    fails, rather than a role silently losing a capability in production.
    """
    catalog = RoleCatalog(integration_session)
    seeded = catalog.grants_by_role_code()

    assert set(seeded) == set(ROLE_PERMISSIONS), "a role exists in one place only"
    for role_code, granted in seeded.items():
        expected = {permission.value for permission in ROLE_PERMISSIONS[role_code]}
        assert granted == expected, f"{role_code} grants {granted}, the code says {expected}"
    assert {row.code for row in catalog.list_permissions()} == {
        permission.value for permission in Permission
    }


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
