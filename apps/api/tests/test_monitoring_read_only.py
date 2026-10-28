"""Monitoring reads, and cannot do anything else — asserted, not asserted-about.

The phase makes one promise worth more than its arithmetic: *measurement is not action*.
Nothing a client sends to the five views may change an audit event, a policy, a permission,
an agent or an asset, and nothing may execute anything. Those are claims about absence, and
absence is the hardest property to test by example — so this file attacks it from four
sides.

- **Behaviour, over the API.** A fingerprint of the tenant's whole record — every row of
  the trail, the registry, the policy store and the ledger — taken before the reads, and
  compared after every view has been read in every window. A read that wrote anything,
  including an audit event about the read itself, changes a count.
- **The repository directly.** Every read it declares is called twice, and the trail's
  digest is compared: this bypasses the routes and the service, so the layer closest to SQL
  is the one being held to the claim.
- **The objects and the source.** The service holds a repository and nothing else, and an
  import-and-identifier scan over the phase's five modules checks that monitoring cannot
  reach an executor, the action firewall, the policy engine, the audit *writer*, the
  append-only override, a model provider or an outbound client — because a layer that
  *could* do those things is a layer that will eventually be asked to.
- **The statements.** What SQL the views actually send — how many statements, and that
  each is a tenant-scoped, window-bounded ``SELECT`` — is asserted in the integration file,
  which captures them.

What is deliberately not here: authorization. Whether a caller may read monitoring at all
is the authorization suite's subject, and it sweeps these five routes with the rest of the
protected surface.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from aicore_api.core.audit import AuditEventType
from aicore_api.core.monitoring import TimeInterval
from aicore_api.db.repositories.monitoring import MonitoringRepository
from aicore_api.db.tenancy import bind_tenant
from aicore_api.monitoring.service import MonitoringService
from monitoring_fixture import MonitoringScene, action_event

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PACKAGE = REPOSITORY_ROOT / "apps" / "api" / "src" / "aicore_api"

#: The phase's five modules — everything Phase 9 added to the application.
MODULES = (
    PACKAGE / "core" / "monitoring.py",
    PACKAGE / "db" / "repositories" / "monitoring.py",
    PACKAGE / "monitoring" / "service.py",
    PACKAGE / "schemas" / "monitoring.py",
    PACKAGE / "api" / "routes" / "monitoring.py",
)

#: Project modules a measurement has no business reaching: the executor and the firewall
#: (running an action), the policy engine (changing one), the audit writer and the event
#: seam (writing history), authorization, and discovery (observing the environment).
FORBIDDEN_PROJECT_MODULES = (
    "aicore_api.actions",
    "aicore_api.auth.authorization",
    "aicore_api.core.events",
    "aicore_api.core.policy",
    "aicore_api.core.permissions",
    "aicore_api.core.request_context",
    "aicore_api.db.repositories.actions",
    "aicore_api.db.repositories.agents",
    "aicore_api.db.repositories.assets",
    "aicore_api.db.repositories.audit",
    "aicore_api.db.repositories.organizations",
    "aicore_api.db.repositories.policies",
    "aicore_api.discovery",
    "aicore_api.firewall",
)

#: The only names any module may take from the audit layer: the vocabulary. Importing the
#: writer, the sanitizer or the retention override is how a measurement becomes an event.
AUDIT_VOCABULARY = frozenset({"AuditDecision", "AuditEventType"})

#: Three of the forbidden modules are exceptions, and all of them are narrow. A
#: tenant-scoped repository has to inherit the class that enforces the tenant boundary; a
#: route has to name the permission it requires; and the handler has to hold the authorized
#: context it was given. So the *names* are allowed and nothing else from those modules is:
#: the phase can require a permission and read the caller's tenant, and it can do nothing
#: with either.
ALLOWED_NAMES_FROM = {
    "aicore_api.auth.authorization": {"OrganizationContext"},
    "aicore_api.auth.dependencies": {"SessionDep", "require_permission"},
    "aicore_api.core.permissions": {"Permission"},
    "aicore_api.db.repositories.organizations": {"OrganizationScopedRepository"},
}

#: The third-party roots a monitoring module may import from, alongside the standard
#: library. Anything else — an HTTP client, a model provider, a vector store, a queue — is a
#: capability the phase does not have, and an import statement is how it would get one.
#: "Standard library" is ``sys.stdlib_module_names`` rather than a list this file maintains.
THIRD_PARTY_ROOTS = frozenset(
    {"fastapi", "pydantic", "sqlalchemy", "starlette", "typing_extensions"}
)

#: Calls no module of this phase may make: the write verbs, and the transaction-local
#: override that permits deleting the append-only trail. The clock is treated separately,
#: because the phase does read it — in exactly one place.
FORBIDDEN_CALLS = frozenset(
    {
        "add",
        "commit",
        "delete",
        "flush",
        "insert",
        "merge",
        "rollback",
        "set_config",
        "truncate",
        "update",
    }
)

#: Words that would mean the phase had grown a provider, a store or an outbound client.
#: Checked against the source rather than the imports, because "no LLM anywhere" is a claim
#: about the whole module, not only about what it imports today.
FORBIDDEN_WORDS = (
    "nemotron",
    "nebius",
    "openai",
    "anthropic",
    "langchain",
    "kafka",
    "redis",
    "elasticsearch",
    "httpx",
    "urllib",
    "aiohttp",
    "socket",
    "embedding",
    "vector",
)

#: The tables Phase 9 measures or must leave alone. Counted per tenant, because the
#: isolation guard requires the tenant filter on a tenant-owned table.
TABLES = (
    "audit_events",
    "assets",
    "agents",
    "policies",
    "policy_versions",
    "action_executions",
)

VIEWS = ("summary", "agents", "actions", "policies", "trends")

WINDOWS: tuple[dict[str, str], ...] = (
    {"window": "5m"},
    {"window": "15m"},
    {"window": "1h"},
    {"window": "24h"},
    {"window": "7d"},
)


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def _imports(path: Path) -> set[str]:
    """Every module path a file imports, as dotted names."""
    found: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return found


def _imported_from(path: Path, module: str) -> set[str]:
    """The names a file imports from one specific module."""
    names: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.ImportFrom) and node.module == module:
            names.update(alias.name for alias in node.names)
    return names


def _called_names(path: Path) -> set[str]:
    """Every function or method name a file calls, as the source spells it.

    Docstrings are not calls, so a module may *describe* committing a transaction — and
    these modules describe at length what they refuse to do — without appearing to do it.
    """
    found: set[str] = set()
    for node in ast.walk(_tree(path)):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            found.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            found.add(node.func.attr)
    return found


def _fingerprint(engine: Engine, organization_id: uuid.UUID) -> dict[str, int]:
    """How many rows the tenant has in every table the phase touches or watches."""
    with bind_tenant(organization_id), engine.begin() as connection:
        return {
            table: int(
                connection.execute(
                    text(
                        f"SELECT count(*) FROM aicore.{table} "
                        "WHERE organization_id = :organization_id"
                    ),
                    {"organization_id": str(organization_id)},
                ).scalar_one()
            )
            for table in TABLES
        }


def _trail_digest(scene: MonitoringScene) -> str:
    """Every stored row of the tenant's trail, in order, as one hash."""
    rendered = json.dumps(
        [{key: str(value) for key, value in row.items()} for row in scene.stored()],
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _read_every_view(scene: MonitoringScene) -> None:
    """Read all five views in every named window, asserting each answers."""
    for window in WINDOWS:
        for view in VIEWS:
            response = scene.get(view, **window)
            assert response.status_code == 200, (view, window, response.text)


@pytest.fixture
def populated(monitoring: MonitoringScene) -> MonitoringScene:
    """A tenant with history of every shape the views report.

    Real operations — a registration, an asset, a policy, an execution and a refusal — plus
    one row of each pipeline state, so the views have something to count in every section
    rather than being vacuously quiet.
    """
    agent = monitoring.agents.register(display_name="Measured Agent", environment="production")
    assert agent is not None
    monitoring.assets.create(name="Measured Asset", asset_type="model")
    monitoring.policies.create(name="Measured Policy")

    executed = monitoring.actions.execute(str(agent.id), agent_id=str(agent.id))
    assert executed.status_code == 200, executed.text
    denied = monitoring.actions.execute(str(agent.id), agent_id=str(agent.id))
    assert denied.status_code in {200, 404}, denied.text

    monitoring.seed(
        action_event(AuditEventType.ACTION_REQUESTED.value, 3.0, agent_id=agent.id),
        action_event(AuditEventType.ACTION_EXECUTED.value, 4.0, agent_id=agent.id),
        action_event(AuditEventType.ACTION_DENIED.value, 5.0, agent_id=agent.id),
    )
    return monitoring


# ── behaviour: reading changes nothing ───────────────────────────────────────


def test_reading_every_view_changes_no_row_of_the_tenant(populated: MonitoringScene) -> None:
    """The fingerprint of the record is identical after every view has been read, twice."""
    before = _fingerprint(populated.trail.engine, populated.organization_id)
    digest = _trail_digest(populated)
    assert before["audit_events"] > 0  # there was something to measure

    _read_every_view(populated)
    _read_every_view(populated)

    assert _trail_digest(populated) == digest
    assert _fingerprint(populated.trail.engine, populated.organization_id) == before


def test_reading_the_same_window_twice_answers_the_same_way(
    populated: MonitoringScene,
) -> None:
    """Over a window the caller pinned, a measurement is a pure function of the trail."""
    end = datetime.now(UTC)
    window = {
        "window": "custom",
        "start_time": (end - timedelta(hours=2)).isoformat(),
        "end_time": end.isoformat(),
    }
    for view in VIEWS:
        first = populated.get(view, **window)
        second = populated.get(view, **window)
        assert first.status_code == 200, view
        assert first.json() == second.json(), view


def test_no_view_writes_an_audit_event_about_being_read(populated: MonitoringScene) -> None:
    """Counting is not an event: the trail gains nothing when it is measured."""
    before = populated.trail_count()
    _read_every_view(populated)
    assert populated.trail_count() == before


def test_no_view_executes_anything(populated: MonitoringScene) -> None:
    """The ledger is untouched: monitoring cannot run an action, and does not try."""
    before = populated.actions.count_executions()
    _read_every_view(populated)
    assert populated.actions.count_executions() == before


def test_every_repository_read_is_side_effect_free(populated: MonitoringScene) -> None:
    """The layer closest to SQL, called directly: the trail comes back byte for byte."""
    digest = _trail_digest(populated)
    now = datetime.now(UTC)
    start, end = now - timedelta(hours=1), now

    with Session(bind=populated.trail.engine) as session:
        repository = MonitoringRepository(session, populated.organization_id)
        for _ in range(2):
            repository.summary(start=start, end=end)
            repository.active_identifiers(start=start, end=end)
            repository.denial_reasons(start=start, end=end)
            repository.decision_counts(start=start, end=end)
            repository.agent_activity(start=start, end=end, limit=10, offset=0)
            repository.count_agents(start=start, end=end)
            repository.action_activity(start=start, end=end)
            repository.trend(start=start, end=end, interval=TimeInterval.HOUR)

    assert _trail_digest(populated) == digest
    assert populated.trail_count() > 0


def test_every_stored_event_is_identical_after_the_views_are_read(
    populated: MonitoringScene,
) -> None:
    """The digest catches any change; this says it row by row, so a failure names the row."""
    before = [dict(row) for row in populated.stored()]
    assert before

    _read_every_view(populated)

    assert [dict(row) for row in populated.stored()] == before


def test_reading_a_tenant_that_does_not_exist_writes_nothing(
    populated: MonitoringScene,
) -> None:
    """A refused read is a refused read: no row, no counter, no side effect."""
    before = _fingerprint(populated.trail.engine, populated.organization_id)
    for view in VIEWS:
        response = populated.client.get(f"/organizations/{uuid.uuid4()}/monitoring/{view}")
        assert response.status_code == 404, view
    assert _fingerprint(populated.trail.engine, populated.organization_id) == before


# ── the objects ──────────────────────────────────────────────────────────────


def test_the_service_holds_nothing_but_a_repository() -> None:
    """No session, no engine, no executor and no policy engine: one collaborator."""
    service = MonitoringService(object())  # type: ignore[arg-type]
    assert set(vars(service)) == {"repository"}
    assert sorted(
        name
        for name in dir(MonitoringService)
        if not name.startswith("_") and callable(getattr(MonitoringService, name))
    ) == ["actions", "agents", "policies", "summary", "trends"]


def test_the_repository_declares_no_write_method() -> None:
    """Eight reads, and no verb that could change a row — on the class that owns the SQL."""
    declared = {name for name in vars(MonitoringRepository) if not name.startswith("_")}
    assert declared == {
        "summary",
        "active_identifiers",
        "denial_reasons",
        "decision_counts",
        "agent_activity",
        "count_agents",
        "action_activity",
        "trend",
    }
    for name in declared:
        assert not re.search(r"(add|create|delete|insert|update|write|save|commit|flush)", name)


# ── the source: what the phase cannot reach ──────────────────────────────────


@pytest.mark.parametrize("module", MODULES, ids=lambda path: path.relative_to(PACKAGE).as_posix())
def test_no_module_of_the_phase_imports_something_that_could_act(module: Path) -> None:
    """An import scan, over every module the phase adds.

    Two lists: the project modules a measurement has no business reaching, and the external
    roots it may use. Anything outside them is a capability this phase should not have — and
    if a later phase needs one, this test is where that decision gets written down.
    """
    imported = _imports(module)
    for forbidden in FORBIDDEN_PROJECT_MODULES:
        reached = {
            dotted
            for dotted in imported
            if dotted == forbidden or dotted.startswith(f"{forbidden}.")
        }
        if not reached:
            continue
        assert forbidden in ALLOWED_NAMES_FROM, (module.name, forbidden, reached)
        taken = _imported_from(module, forbidden)
        assert taken <= ALLOWED_NAMES_FROM[forbidden], (module.name, forbidden, taken)

    for dotted in imported:
        root = dotted.split(".")[0]
        assert (
            root == "aicore_api" or root in sys.stdlib_module_names or root in THIRD_PARTY_ROOTS
        ), (module.name, dotted)


@pytest.mark.parametrize("module", MODULES, ids=lambda path: path.relative_to(PACKAGE).as_posix())
def test_the_only_audit_names_the_phase_takes_are_the_vocabulary(module: Path) -> None:
    """Reading the record's language is not writing to the record.

    ``AuditEventType`` names what happened and ``AuditDecision`` names what was decided;
    the writer, the sanitizer and the retention override are absent from the phase
    entirely, which is what keeps a measurement from becoming an event.
    """
    taken = _imported_from(module, "aicore_api.core.audit")
    assert taken <= AUDIT_VOCABULARY, (module.name, taken - AUDIT_VOCABULARY)


def test_the_only_model_the_phase_imports_is_the_trail() -> None:
    """No agent, asset or policy model — the phase measures events, not subjects.

    Reaching a subject model would be the first step towards changing one: a suspended
    agent and a measured one are not far apart in a diff.
    """
    models = {
        dotted
        for module in MODULES
        for dotted in _imports(module)
        if dotted.startswith("aicore_api.db.models")
    }
    assert models == {
        "aicore_api.db.models.audit_event",
        "aicore_api.db.models.audit_event.AuditEvent",
    }


@pytest.mark.parametrize("module", MODULES, ids=lambda path: path.relative_to(PACKAGE).as_posix())
def test_no_module_of_the_phase_writes_anything(module: Path) -> None:
    """No write call and no retention override, anywhere in the phase."""
    called = _called_names(module)
    assert called.isdisjoint(FORBIDDEN_CALLS), (module.name, called & FORBIDDEN_CALLS)


def test_the_server_clock_is_read_in_exactly_one_place() -> None:
    """A measurement's ``now`` is decided once, in the window resolver, from the request.

    Anywhere else — the service, the repository, a schema — and two endpoints called at the
    same moment would disagree about which interval they had measured.
    """
    routes = PACKAGE / "api" / "routes" / "monitoring.py"
    assert routes.read_text().count("datetime.now(") == 1

    for module in (
        PACKAGE / "core" / "monitoring.py",
        PACKAGE / "db" / "repositories" / "monitoring.py",
        PACKAGE / "monitoring" / "service.py",
    ):
        source = module.read_text()
        for clock in ("datetime.now(", "utcnow(", "time.time(", "date.today("):
            assert clock not in source, (module.name, clock)


def test_the_routes_declare_no_write_handler() -> None:
    """Five reads, and no decorator that could accept a write."""
    routes = (PACKAGE / "api" / "routes" / "monitoring.py").read_text()
    assert re.findall(r"@router\.(get|post|put|patch|delete)\(", routes) == ["get"] * 5
    for verb in ("post", "put", "patch", "delete"):
        assert f"@router.{verb}(" not in routes


def test_no_module_of_the_phase_can_delete_the_trail() -> None:
    """The append-only override is named nowhere in the phase, and neither is a bypass."""
    for module in MODULES:
        source = module.read_text().lower()
        for forbidden in ("audit_retention", "session_replication_role", "row_security"):
            assert forbidden not in source, (module.name, forbidden)


@pytest.mark.parametrize("module", MODULES, ids=lambda path: path.relative_to(PACKAGE).as_posix())
def test_no_module_of_the_phase_reaches_a_model_a_store_or_a_network(module: Path) -> None:
    """No model provider, no embeddings, no vector store, no queue, no HTTP client.

    The phase's arithmetic is SQL and Python. There is no NVIDIA, Nebius or OpenAI anywhere
    near it, and no way for a measurement to leave the process — which is also what keeps
    "no LLM" from being a statement about the current configuration.
    """
    source = module.read_text().lower()
    for word in FORBIDDEN_WORDS:
        assert word not in source, (module.name, word)


def test_the_phase_adds_no_agent_status_and_no_policy_write() -> None:
    """Monitoring has no vocabulary for suspending an agent or changing a policy."""
    for module in MODULES:
        source = module.read_text()
        for word in (
            "AgentStatus",
            "set_status",
            "suspend",
            "PolicyVersion",
            "publish_version",
            "PolicyEngine",
        ):
            assert word not in source, (module.name, word)


def test_the_phase_carries_no_second_event_system() -> None:
    """One record, one writer: monitoring appends nothing of its own.

    The audit trail is the only place activity is recorded. A monitoring module that
    declared an event, a stream or a second writer would be the beginning of two accounts
    of the same thing — and two accounts eventually disagree.
    """
    for module in MODULES:
        source = module.read_text()
        for word in ("AuditWriter", "emit_event", "MonitorEvent", "TrackingTable", "Snapshot"):
            assert word not in source, (module.name, word)


def test_the_phase_reads_the_trail_through_one_table() -> None:
    """``MonitoringRepository`` names one table, and it is the record."""
    source = (PACKAGE / "db" / "repositories" / "monitoring.py").read_text()
    tables = set(re.findall(r"aicore\.([a-z_]+)", source)) | set(
        re.findall(r'__tablename__\s*=\s*"([a-z_]+)"', source)
    )
    assert tables <= {"audit_events"}, tables
    assert source.count("AuditEvent") > 0
