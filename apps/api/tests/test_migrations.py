"""The migration is the schema, and the models must agree with it."""
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
EXPECTED_REVISION = "0009_incident_approvals"
EXPECTED_CHAIN = [
    "0001_organizations",
    "0002_identity_and_rbac",
    "0003_assets",
    "0004_agents",
    "0005_policies",
    "0006_action_firewall",
    "0007_audit_events",
    "0008_anomaly_detections",
    "0009_incident_approvals",
]


def test_migration_revision_is_the_expected_head() -> None:
    script = ScriptDirectory.from_config(CONFIG)
    assert script.get_current_head() == EXPECTED_REVISION
    assert [revision.revision for revision in reversed(list(script.walk_revisions()))] == EXPECTED_CHAIN


def test_every_migration_states_a_real_downgrade() -> None:
    import inspect as python_inspect

    revision = ScriptDirectory.from_config(CONFIG).get_revision(EXPECTED_REVISION)
    assert revision is not None
    assert "op." in python_inspect.getsource(revision.module.downgrade)


def test_migrated_schema_matches_the_models(integration_engine: Engine) -> None:
    inspector = inspect(integration_engine)
    assert APP_SCHEMA in inspector.get_schema_names()
    live_tables = set(inspector.get_table_names(schema=APP_SCHEMA)) - {"alembic_version"}
    model_tables = {table.name for table in Base.metadata.tables.values()}
    assert live_tables == model_tables
    live_columns = {column["name"] for column in inspector.get_columns(Organization.__tablename__, schema=APP_SCHEMA)}
    model_columns = {column.name for column in Organization.__table__.columns}
    assert live_columns == model_columns


def test_constraint_names_match_the_models(integration_engine: Engine) -> None:
    inspector = inspect(integration_engine)
    live = {row["name"] for row in inspector.get_unique_constraints("organizations", schema=APP_SCHEMA)}
    live |= {row["name"] for row in inspector.get_check_constraints("organizations", schema=APP_SCHEMA)}
    live.add(inspector.get_pk_constraint("organizations", schema=APP_SCHEMA)["name"])
    expected = {constraint.name for constraint in Organization.__table__.constraints if constraint.name is not None}
    assert expected <= live


def test_the_table_comment_is_declared_in_the_model(integration_engine: Engine) -> None:
    with integration_engine.connect() as connection:
        comment = connection.execute(text("SELECT obj_description('aicore.organizations'::regclass, 'pg_class')")).scalar_one()
    assert comment is not None
    assert Organization.__table__.comment == comment


def test_the_tenant_boundary_is_enforced_in_the_database(integration_engine: Engine, tenant_sample_table: str) -> None:
    inspector = inspect(integration_engine)
    assert inspector.get_foreign_keys("organizations", schema=APP_SCHEMA) == []
    from tenant_fixture import TenantScopedSample
    sample_fks = inspector.get_foreign_keys(TenantScopedSample.__tablename__, schema=APP_SCHEMA)
    assert len(sample_fks) == 1
    assert sample_fks[0]["referred_table"] == "organizations"
    assert sample_fks[0]["options"].get("ondelete") == "RESTRICT"
    assert sample_fks[0]["constrained_columns"] == ["organization_id"]


def test_the_application_schema_is_exactly_what_the_models_declare(integration_engine: Engine) -> None:
    inspector = inspect(integration_engine)
    from tenant_fixture import TABLE_NAME as TEST_FIXTURE_TABLE
    live = set(inspector.get_table_names(schema=APP_SCHEMA)) - {"alembic_version", TEST_FIXTURE_TABLE}
    expected = {
        "organizations", "users", "roles", "permissions", "role_permissions", "memberships", "api_tokens",
        "assets", "agents", "policies", "policy_versions", "action_executions", "audit_events",
        "anomaly_detections", "incidents", "incident_evidence", "approval_requests",
    }
    assert live == expected
    assert {table.name for table in Base.metadata.tables.values()} == expected
    assert TEST_FIXTURE_TABLE not in Base.metadata.tables


def test_the_migration_seeds_the_catalog_the_code_declares(integration_session: Session) -> None:
    catalog = RoleCatalog(integration_session)
    seeded = catalog.grants_by_role_code()
    assert set(seeded) == set(ROLE_PERMISSIONS)
    for role_code, granted in seeded.items():
        expected = {permission.value for permission in ROLE_PERMISSIONS[role_code]}
        assert granted == expected
    assert {row.code for row in catalog.list_permissions()} == {permission.value for permission in Permission}


def test_an_unmigrated_database_is_detected(integration_engine: Engine) -> None:
    with integration_engine.connect() as connection:
        revision = connection.execute(text("SELECT version_num FROM aicore.alembic_version")).scalar_one()
    assert revision == EXPECTED_REVISION
