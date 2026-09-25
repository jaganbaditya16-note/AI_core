"""Test configuration.

The environment is configured *before* the application module is imported, so
the app under test is built from a known, hermetic configuration: the database
URL points at a closed port, which makes readiness fail fast and deterministically
without requiring a running PostgreSQL.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest

# ── Environment (must run before `aicore_api` is imported) ────────────────────
#: Unreachable on purpose (port 1) — readiness must fail without a live database.
#: The credentials in it are fake: they exist so test_health_ready.py has a
#: credential-bearing URL to prove the readiness detail never leaks one. No real
#: password appears anywhere in this repository.
OFFLINE_DATABASE_URL = "postgresql+psycopg://aicore:aicore@127.0.0.1:1/aicore"

# AICORE_DATABASE_URL is *assigned*, not defaulted, so the application under test
# stays hermetic even when a developer has a live database exported. Integration
# tests reach PostgreSQL through AICORE_TEST_DATABASE_URL instead.
os.environ["AICORE_ENVIRONMENT"] = "test"
os.environ["AICORE_DATABASE_URL"] = OFFLINE_DATABASE_URL
os.environ.setdefault("AICORE_DATABASE_CONNECT_TIMEOUT_SECONDS", "1")
os.environ.setdefault("AICORE_LOG_LEVEL", "warning")
os.environ.setdefault("AICORE_DEBUG", "false")


from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import Engine, create_engine, text  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from actions_fixture import ActionFactory  # noqa: E402
from agents_fixture import AgentFactory  # noqa: E402
from aicore_api.config import Settings, get_settings  # noqa: E402
from aicore_api.db import tenancy  # noqa: E402
from aicore_api.db.base import APP_SCHEMA  # noqa: E402
from aicore_api.db.session import dispose_engine  # noqa: E402
from aicore_api.main import create_app  # noqa: E402
from assets_fixture import AssetFactory  # noqa: E402
from audit_fixture import AuditFactory, AuditScene  # noqa: E402
from identity_fixture import Identity, IdentityFactory  # noqa: E402
from monitoring_fixture import MonitoringScene  # noqa: E402
from policies_fixture import PolicyFactory  # noqa: E402
from tenant_fixture import SampleBase, TenantScopedSample  # noqa: E402

# The fixture table is registered with the isolation guard for the whole session,
# so the guard treats it as tenant-owned exactly as it will a real resource table.
tenancy.register_metadata(SampleBase.metadata)


@pytest.fixture(scope="session")
def settings() -> Settings:
    get_settings.cache_clear()
    return Settings()


@pytest.fixture(scope="session")
def client(settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def offline_settings() -> Settings:
    """Settings whose database is guaranteed unreachable."""
    return Settings(  # type: ignore[call-arg]  # env supplies the remaining fields
        database_url=OFFLINE_DATABASE_URL,
        database_connect_timeout_seconds=1,
        environment="test",
    )


# ── Phase 1: database and multi-tenancy fixtures ─────────────────────────────
#
# Integration tests run against a real PostgreSQL and are skipped unless
# scripts/test-db.sh (or CI) exports AICORE_TEST_DATABASE_URL. Real PostgreSQL is
# used deliberately: the things under test are foreign keys, check constraints,
# unique constraints, Alembic migrations and UUID server defaults — SQLite would
# verify none of them.

TEST_DATABASE_URL_ENV = "AICORE_TEST_DATABASE_URL"


@pytest.fixture(scope="session")
def integration_engine() -> Iterator[Engine]:
    """Engine for the migrated test database, or skip."""
    url = os.environ.get(TEST_DATABASE_URL_ENV, "").strip()
    if not url:
        pytest.skip(
            f"{TEST_DATABASE_URL_ENV} is not set — run `bash scripts/test-db.sh`, which starts "
            "PostgreSQL, applies the migrations and runs these tests"
        )

    engine = create_engine(url, poolclass=StaticPool)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def integration_session(integration_engine: Engine) -> Iterator[Session]:
    """A session whose work is rolled back after the test."""
    factory = sessionmaker(bind=integration_engine, autoflush=False, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture(scope="session")
def tenant_sample_table(integration_engine: Engine) -> Iterator[str]:
    """Create the tenant-owned fixture table for the duration of the session.

    Registering its metadata is what makes the isolation guard classify it as
    tenant-owned — the same mechanism that will apply to real resource tables.
    """
    tenancy.register_metadata(SampleBase.metadata)
    with integration_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{APP_SCHEMA}"'))
    TenantScopedSample.__table__.create(integration_engine, checkfirst=True)
    try:
        yield TenantScopedSample.__tablename__
    finally:
        TenantScopedSample.__table__.drop(integration_engine, checkfirst=True)


@pytest.fixture
def database_client(
    monkeypatch: pytest.MonkeyPatch, integration_engine: Engine
) -> Iterator[TestClient]:
    """An application whose database is the migrated test database.

    The session-scoped ``client`` fixture is deliberately hermetic (it points at a
    closed port), so tests that need real persistence use this one. The database
    URL is injected through the environment because that is how the application
    reads it — the DB layer resolves its settings from ``get_settings()``, not from
    the settings object passed to ``create_app``. Caches are cleared on the way in
    and on the way out so the rest of the suite stays hermetic.
    """
    monkeypatch.setenv("AICORE_DATABASE_URL", os.environ[TEST_DATABASE_URL_ENV])
    get_settings.cache_clear()
    dispose_engine()
    try:
        app = create_app()
        with TestClient(app, raise_server_exceptions=False) as test_client:
            yield test_client
    finally:
        dispose_engine()
        get_settings.cache_clear()


# ── Phase 2: identities, roles and credentials ───────────────────────────────
#
# An authenticated request needs a real user, a real membership and a real token,
# because that is what production will use. provision_identity() writes all three
# — committed — and the factory below deletes them again afterwards.


@pytest.fixture
def identity_factory(integration_engine: Engine) -> Iterator[IdentityFactory]:
    """Provision identities, then remove all of them.

    Cleanup is dependency-ordered inside ``IdentityFactory.purge`` — memberships
    and credentials before the tenants they reference — so a test may put one
    person into another identity's organization.
    """
    factory = IdentityFactory(integration_engine)
    try:
        yield factory
    finally:
        factory.purge()


@pytest.fixture
def authenticate(database_client: TestClient):
    """Send requests as a provisioned identity.

    Returns the client with an ``Authorization`` header attached, so a test reads
    like the call it is making: ``authenticate(identity).get("/me")``.
    """

    def attach(identity: Identity) -> TestClient:
        database_client.headers["Authorization"] = f"Bearer {identity.token}"
        return database_client

    return attach


@pytest.fixture
def owner_identity(identity_factory: IdentityFactory) -> Identity:
    """An owner of a fresh organization — the caller most Phase 3 tests act as."""
    return identity_factory(role_code="owner")


@pytest.fixture
def assets(
    authenticate, owner_identity: Identity, integration_engine: Engine
) -> Iterator[AssetFactory]:
    """An owner of a fresh tenant, authenticated, and a factory for their assets.

    Every Phase 3 test needs the same three things: a tenant that belongs to
    nobody else, a credential that can act in it, and assets to act on. The assets
    are created *through the API* by the factory, so a test that uses this fixture
    is already exercising the create path it is about to assert on.
    """
    factory = AssetFactory(
        client=authenticate(owner_identity),
        organization_id=owner_identity.organization_id,
        engine=integration_engine,
    )
    try:
        yield factory
    finally:
        # Before the identity purge, which happens after this fixture: a membership
        # that still owns assets cannot be deleted (the composite foreign key is
        # RESTRICT), so the inventory has to go first.
        factory.purge()


@pytest.fixture
def agents(
    authenticate, owner_identity: Identity, integration_engine: Engine
) -> Iterator[AgentFactory]:
    """An owner of a fresh tenant, authenticated, and a factory for their agents.

    The registry mirror of the ``assets`` fixture: a tenant that belongs to nobody
    else, a credential that can register in it, and agents created *through the API*
    so a test using this fixture is already exercising the registration path it is
    about to assert on.
    """
    factory = AgentFactory(
        client=authenticate(owner_identity),
        organization_id=owner_identity.organization_id,
        engine=integration_engine,
    )
    try:
        yield factory
    finally:
        # Before the identity purge, which happens after this fixture: an agent's
        # asset may be owned by a membership that cannot be deleted while it is
        # referenced (the composite foreign key is RESTRICT).
        factory.purge()


@pytest.fixture
def policies(
    authenticate, owner_identity: Identity, integration_engine: Engine
) -> Iterator[PolicyFactory]:
    """An owner of a fresh tenant, authenticated, and a factory for their policies.

    The governance mirror of the ``assets`` and ``agents`` fixtures: a tenant that
    belongs to nobody else, a credential that may manage it, and policies created
    *through the API* so a test using this fixture has already exercised the create
    path it is about to assert on.
    """
    factory = PolicyFactory(
        client=authenticate(owner_identity),
        organization_id=owner_identity.organization_id,
        engine=integration_engine,
        token=owner_identity.token,
    )
    try:
        yield factory
    finally:
        # Before the identity purge, which happens after this fixture: a policy
        # references its organization with RESTRICT, so the organization cannot be
        # deleted while one is still there.
        factory.purge()


@pytest.fixture
def actions(
    authenticate, owner_identity: Identity, integration_engine: Engine
) -> Iterator[ActionFactory]:
    """An owner of a fresh tenant, authenticated, and a factory for executions.

    Phase 7's mirror of the ``assets``/``agents``/``policies`` fixtures: a tenant that
    belongs to nobody else, a credential that may execute in it, and a way to send
    execution requests and read what they left in the idempotency ledger.
    """
    factory = ActionFactory(
        client=authenticate(owner_identity),
        organization_id=owner_identity.organization_id,
        engine=integration_engine,
        token=owner_identity.token,
    )
    try:
        yield factory
    finally:
        # Before the identity purge, which happens after this fixture: a ledger row
        # references its organization with RESTRICT.
        factory.purge()


@pytest.fixture
def audit(
    authenticate, owner_identity: Identity, integration_engine: Engine
) -> Iterator[AuditScene]:
    """An owner of a fresh tenant, and everything that acts inside it.

    Phase 8's mirror of the ``assets``/``agents``/``policies``/``actions`` fixtures,
    bundled: the trail is a record *of* those operations, so a test needs both the
    operations and the record in one tenant, under one credential, on one client. It
    writes nothing itself — the factories write their own subjects, and the tests read
    what the platform recorded about them, both through the API and from the raw table.
    """
    client = authenticate(owner_identity)
    identity = owner_identity
    trail = AuditFactory(
        client=client,
        organization_id=identity.organization_id,
        engine=integration_engine,
        token=identity.token,
    )
    scene = AuditScene(
        identity=identity,
        trail=trail,
        assets=AssetFactory(
            client=client,
            organization_id=identity.organization_id,
            engine=integration_engine,
        ),
        agents=AgentFactory(
            client=client,
            organization_id=identity.organization_id,
            engine=integration_engine,
        ),
        policies=PolicyFactory(
            client=client,
            organization_id=identity.organization_id,
            engine=integration_engine,
            token=identity.token,
        ),
        actions=ActionFactory(
            client=client,
            organization_id=identity.organization_id,
            engine=integration_engine,
            token=identity.token,
        ),
    )
    try:
        yield scene
    finally:
        # Before the identity purge, which happens after this fixture: the resources and
        # the trail reference their organization with RESTRICT, and the trail only
        # deletes under the override the fixture names.
        scene.purge()


@pytest.fixture
def monitoring(audit: AuditScene) -> Iterator[MonitoringScene]:
    """Phase 9's fixture: the audit scene, read through the monitoring endpoints.

    Monitoring measures the trail, so its tests need activity *and* the recording of it in
    one tenant, under one credential, on one client — which is exactly what the Phase 8
    scene already provides. This wraps it rather than rebuilding it, and adds the two
    things the views need that the trail's own fixture does not: reading the five views,
    and placing history at instants the server's clock cannot produce.
    """
    scene = MonitoringScene(audit=audit)
    try:
        yield scene
    finally:
        # The audit scene's own teardown removes the trail; nothing extra is created
        # except the seeded rows, which live in that trail.
        scene.purge()


@pytest.fixture
def two_organizations(integration_session: Session) -> tuple[uuid.UUID, uuid.UUID]:
    """Two tenants, so cross-tenant behaviour is testable."""
    from aicore_api.db.repositories.organizations import OrganizationRepository

    repository = OrganizationRepository(integration_session)
    suffix = uuid.uuid4().hex[:8]
    first = repository.create(name="Acme Corporation", slug=f"acme-{suffix}")
    second = repository.create(name="Globex Corporation", slug=f"globex-{suffix}")
    return first.id, second.id
