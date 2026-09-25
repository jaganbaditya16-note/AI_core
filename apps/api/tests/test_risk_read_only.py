"""Phase 10 analyses and cannot act — asserted from the source and from the database.

The phase's promise is about absence: *detection is not response*. The engine must not
authorize, execute, invoke the firewall, block, approve, suspend or contain an agent,
revoke or change a permission, change a policy, open an incident, alert or remediate — and
a risk level must never become an input to any of those decisions. Absence is tested here
from three sides:

- **The imports, both ways.** No Phase 10 module imports the firewall, the policy engine,
  the executors, the action pipeline, the audit writer, the registry or inventory models, a
  network client or a model provider; and no module *outside* Phase 10 imports the engine,
  except the router that mounts it and the model registry — so nothing that decides can
  read a risk level.
- **The write surface.** Five of the phase's modules make no write call at all. Two may
  write, and only to ``anomaly_detections``: the store (``INSERT … ON CONFLICT DO
  NOTHING``) and the operator command (one ``commit``). The routes are ``GET`` only.
- **Behaviour.** Every table the phase must leave alone — the trail, agents, assets,
  policies, policy versions, the execution ledger, memberships, roles and permissions — is
  fingerprinted before and after analysing and recording, and compared.
"""

from __future__ import annotations

import ast
import hashlib
import re
import sys
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, text

from aicore_api.db.repositories.anomaly_detections import AnomalyDetectionRepository
from aicore_api.db.repositories.risk_history import RiskHistoryRepository
from aicore_api.db.tenancy import bind_tenant
from aicore_api.risk.service import RiskAnalysisService
from monitoring_fixture import fixed_agent_id
from risk_fixture import DENIED, RiskScene, observed, steady_history

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PACKAGE = REPOSITORY_ROOT / "apps" / "api" / "src" / "aicore_api"

READ_ONLY_MODULES = (
    PACKAGE / "core" / "risk.py",
    PACKAGE / "db" / "repositories" / "risk_history.py",
    PACKAGE / "risk" / "service.py",
    PACKAGE / "schemas" / "risk.py",
    PACKAGE / "api" / "routes" / "risk.py",
)
WRITER_MODULES = (
    PACKAGE / "db" / "repositories" / "anomaly_detections.py",
    PACKAGE / "risk" / "cli.py",
)
MODEL_MODULE = PACKAGE / "db" / "models" / "anomaly_detection.py"
MODULES = (*READ_ONLY_MODULES, *WRITER_MODULES, MODEL_MODULE, PACKAGE / "risk" / "__init__.py")

#: Modules that decide or act. A Phase 10 module importing any of these could act on a
#: detection; that capability is what the phase does not have.
FORBIDDEN_PROJECT_MODULES = (
    "aicore_api.actions",
    "aicore_api.api.routes.actions",
    "aicore_api.api.routes.agents",
    "aicore_api.api.routes.assets",
    "aicore_api.api.routes.policies",
    "aicore_api.audit",
    "aicore_api.core.actions",
    "aicore_api.core.agents",
    "aicore_api.core.assets",
    "aicore_api.core.events",
    "aicore_api.core.execution",
    "aicore_api.core.executors",
    "aicore_api.core.firewall",
    "aicore_api.core.policy",
    "aicore_api.core.policy_engine",
    "aicore_api.db.models.action_execution",
    "aicore_api.db.models.agent",
    "aicore_api.db.models.api_token",
    "aicore_api.db.models.asset",
    "aicore_api.db.models.membership",
    "aicore_api.db.models.policy",
    "aicore_api.db.models.rbac",
    "aicore_api.db.repositories.action_executions",
    "aicore_api.db.repositories.agents",
    "aicore_api.db.repositories.api_tokens",
    "aicore_api.db.repositories.assets",
    "aicore_api.db.repositories.audit_events",
    "aicore_api.db.repositories.memberships",
    "aicore_api.db.repositories.policies",
    "aicore_api.db.repositories.rbac",
    "aicore_api.discovery",
    "aicore_api.firewall",
    "aicore_api.monitoring",
)

#: Narrow exceptions: a route names its permission and holds its authorized context; a
#: tenant repository inherits the tenant boundary; the audit layer lends its vocabulary.
ALLOWED_NAMES_FROM = {
    "aicore_api.auth.authorization": {"OrganizationContext"},
    "aicore_api.auth.dependencies": {"SessionDep", "require_permission"},
    "aicore_api.core.permissions": {"Permission"},
    "aicore_api.core.audit": {"AuditEventType"},
    "aicore_api.core.domain_errors": {"NotFoundError"},
    "aicore_api.db.repositories.organizations": {
        "OrganizationRepository",
        "OrganizationScopedRepository",
    },
    "aicore_api.db.models.organization": {"Organization"},
}

THIRD_PARTY_ROOTS = frozenset({"fastapi", "pydantic", "sqlalchemy", "starlette"})

FORBIDDEN_CALLS = frozenset(
    {"add", "commit", "delete", "flush", "insert", "merge", "set_config", "truncate", "update"}
)

#: Words that would mean the phase had grown a provider, an outbound client or a store.
FORBIDDEN_WORDS = (
    "nemotron",
    "nebius",
    "openai",
    "anthropic",
    "langchain",
    "httpx",
    "urllib",
    "aiohttp",
    "socket",
    "embedding",
    "vector",
    "kafka",
    "redis",
    "smtp",
    "webhook",
)

#: Identifiers (not prose) that would name a response to a detection.
FORBIDDEN_IDENTIFIERS = re.compile(
    r"(suspend|quarantine|contain|revoke|block|kill|disable|remediat|incident|alert|notify"
    r"|escalate_to|approve|authorize|set_status|publish_version|grant)",
    re.IGNORECASE,
)

TABLES_BY_TENANT = (
    "audit_events",
    "agents",
    "assets",
    "policies",
    "policy_versions",
    "action_executions",
    "memberships",
)
GLOBAL_TABLES = ("roles", "permissions", "role_permissions")


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def _imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            found.add(node.module)
    return found


def _imported_from(path: Path, module: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.ImportFrom) and node.module == module:
            names.update(alias.name for alias in node.names)
    return names


def _called_names(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                found.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                found.add(node.func.attr)
    return found


def _identifiers(path: Path) -> set[str]:
    """Every name the code defines or uses — not its docstrings or comments."""
    found: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.add(node.name)
        elif isinstance(node, ast.arg):
            found.add(node.arg)
    return found


def _ids(path: Path) -> str:
    return path.relative_to(PACKAGE).as_posix()


# ── imports ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("module", MODULES, ids=_ids)
def test_no_module_of_the_phase_imports_something_that_could_act(module: Path) -> None:
    for imported in _imports(module):
        if not imported.startswith("aicore_api"):
            root = imported.split(".")[0]
            assert root in sys.stdlib_module_names or root in THIRD_PARTY_ROOTS, (
                module.name,
                imported,
            )
            continue
        if imported in ALLOWED_NAMES_FROM:
            allowed = ALLOWED_NAMES_FROM[imported]
            assert _imported_from(module, imported) <= allowed, (module.name, imported)
            continue
        for forbidden in FORBIDDEN_PROJECT_MODULES:
            assert not (imported == forbidden or imported.startswith(forbidden + ".")), (
                module.name,
                imported,
            )


def test_nothing_that_decides_can_read_a_risk_level() -> None:
    """Risk is never an authorization input: only the router and the registry import it."""
    phase = {path.resolve() for path in MODULES}
    risk_modules = (
        "aicore_api.core.risk",
        "aicore_api.risk",
        "aicore_api.db.repositories.risk_history",
        "aicore_api.db.repositories.anomaly_detections",
        "aicore_api.db.models.anomaly_detection",
        "aicore_api.api.routes.risk",
        "aicore_api.schemas.risk",
    )
    allowed_importers = {
        (PACKAGE / "api" / "router.py").resolve(),
        (PACKAGE / "db" / "models" / "__init__.py").resolve(),
    }
    offenders = []
    for path in PACKAGE.rglob("*.py"):
        if path.resolve() in phase or path.resolve() in allowed_importers:
            continue
        source = path.read_text()
        for node in ast.walk(ast.parse(source)):
            names: list[str] = []
            if isinstance(node, ast.ImportFrom) and node.module is not None:
                names = [node.module] + [f"{node.module}.{alias.name}" for alias in node.names]
            elif isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            if any(name.startswith(prefix) for name in names for prefix in risk_modules):
                offenders.append(_ids(path))
        if "anomaly_detections" in source or "RiskLevel" in source:
            offenders.append(_ids(path))
    assert offenders == []


def test_the_decision_layers_do_not_mention_the_engine() -> None:
    for name in ("firewall.py", "policy_engine.py", "execution.py", "executors.py", "policy.py"):
        source = (PACKAGE / "core" / name).read_text()
        for word in ("core.risk", "RiskLevel", "anomaly", "AnomalyDetection"):
            assert word not in source, (name, word)
    for path in (PACKAGE / "auth").rglob("*.py"):
        assert "risk" not in path.read_text().lower().replace("risk_classification", ""), path


# ── the write surface ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("module", READ_ONLY_MODULES, ids=_ids)
def test_the_analytical_modules_write_nothing(module: Path) -> None:
    called = _called_names(module)
    assert called.isdisjoint(FORBIDDEN_CALLS), (module.name, called & FORBIDDEN_CALLS)


def test_the_store_only_inserts_and_only_into_its_own_table() -> None:
    module = PACKAGE / "db" / "repositories" / "anomaly_detections.py"
    called = _called_names(module) & FORBIDDEN_CALLS
    assert called == {"insert"}
    source = module.read_text()
    assert "insert(AnomalyDetection)" in source
    assert "on_conflict_do_nothing" in source
    assert "on_conflict_do_update" not in source


def test_the_operator_command_only_commits_what_the_store_inserted() -> None:
    module = PACKAGE / "risk" / "cli.py"
    assert _called_names(module) & FORBIDDEN_CALLS == {"commit"}


def test_the_repositories_declare_no_update_or_delete() -> None:
    for repository, allowed_writes in (
        (RiskHistoryRepository, set()),
        (AnomalyDetectionRepository, {"record"}),
    ):
        own = {name for name in vars(repository) if not name.startswith("__")}
        writes = {
            name
            for name in own
            if re.match(r"_?(append|insert|update|delete|remove|purge|save|set|record|write)", name)
        }
        assert writes == allowed_writes, (repository.__name__, writes)


def test_the_service_holds_nothing_but_a_history_repository() -> None:
    assert RiskAnalysisService.__init__.__code__.co_varnames[:2] == ("self", "history")


def test_the_routes_are_reads() -> None:
    routes = (PACKAGE / "api" / "routes" / "risk.py").read_text()
    assert re.findall(r"@router\.(get|post|put|patch|delete)\(", routes) == ["get"] * 3


def test_the_server_clock_is_read_once_per_entry_point() -> None:
    assert (PACKAGE / "api" / "routes" / "risk.py").read_text().count("datetime.now(") == 1
    assert (PACKAGE / "risk" / "cli.py").read_text().count("datetime.now(") == 1
    for module in (
        PACKAGE / "core" / "risk.py",
        PACKAGE / "db" / "repositories" / "risk_history.py",
        PACKAGE / "db" / "repositories" / "anomaly_detections.py",
        PACKAGE / "risk" / "service.py",
    ):
        source = module.read_text()
        for clock in ("datetime.now(", "utcnow(", "time.time(", "date.today("):
            assert clock not in source, (module.name, clock)


@pytest.mark.parametrize("module", MODULES, ids=_ids)
def test_no_module_names_a_response_to_a_detection(module: Path) -> None:
    named = {name for name in _identifiers(module) if FORBIDDEN_IDENTIFIERS.search(name)}
    assert named == set(), (module.name, named)


@pytest.mark.parametrize("module", MODULES, ids=_ids)
def test_no_module_reaches_a_model_provider_or_a_network(module: Path) -> None:
    source = module.read_text().lower()
    for word in FORBIDDEN_WORDS:
        assert word not in source, (module.name, word)
    assert "http://" not in source and "https://" not in source


def test_the_history_repository_reads_one_table_and_never_its_metadata() -> None:
    source = (PACKAGE / "db" / "repositories" / "risk_history.py").read_text()
    assert set(re.findall(r"aicore\.([a-z_]+)", source)) <= {"audit_events"}
    assert "event_metadata" not in source
    assert "AuditEvent.metadata" not in source
    assert "correlation_id" not in source
    assert "actor_" not in source


def test_the_trail_schema_is_untouched_by_the_migration() -> None:
    migration = (
        REPOSITORY_ROOT / "database" / "migrations" / "versions" / "0008_anomaly_detections.py"
    ).read_text()
    code = migration.split('"""', 2)[2]  # after the module docstring
    code = "\n".join(line for line in code.splitlines() if not line.startswith("down_revision"))
    assert "audit_events" not in code
    for statement in ("op.alter_column", "op.drop_column", "op.add_column", "op.drop_constraint"):
        assert statement not in code


# ── behaviour ─────────────────────────────────────────────────────────────────


def _fingerprint(engine: Engine, organization_id: uuid.UUID) -> dict[str, str]:
    """A digest of every row the phase must leave alone, per table."""
    digests: dict[str, str] = {}
    with bind_tenant(organization_id), engine.begin() as connection:
        for table in TABLES_BY_TENANT:
            rows: Iterable[str] = connection.execute(
                text(
                    f"SELECT t::text FROM aicore.{table} t "
                    "WHERE t.organization_id = :organization_id ORDER BY t::text"
                ),
                {"organization_id": str(organization_id)},
            ).scalars()
            digests[table] = hashlib.sha256("\n".join(rows).encode()).hexdigest()
        for table in GLOBAL_TABLES:
            rows = connection.execute(
                text(f"SELECT t::text FROM aicore.{table} t ORDER BY t::text")
            ).scalars()
            digests[table] = hashlib.sha256("\n".join(rows).encode()).hexdigest()
    return digests


@pytest.fixture
def populated(risk: RiskScene) -> RiskScene:
    """A tenant with a real registry, inventory, policy and executed actions — and an anomaly."""
    agent = risk.monitoring.agents.register(display_name="Risk Subject", environment="production")
    assert agent is not None
    risk.monitoring.policies.create()
    for _ in range(2):
        risk.monitoring.actions.executed(agent.id, agent_id=str(agent.id))
    windows = risk.windows()
    subject = fixed_agent_id(501)
    risk.seed(
        steady_history(subject, windows, per_slot=3)
        + observed(subject, windows, count=30, outcome=DENIED, action="agent.rotate_keys")
    )
    return risk


def test_analysing_and_recording_change_no_other_row(
    populated: RiskScene, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _fingerprint(populated.engine, populated.organization_id)

    for baseline in ("7d", "14d", "30d"):
        for observation in ("1h", "6h", "24h"):
            populated.analysis(baseline=baseline, observation=observation, total="true")
    populated.detections(total="true")
    assert populated.record() == 0
    assert populated.record() == 0
    capsys.readouterr()

    assert populated.stored()  # the anomaly was found and recorded ...
    assert _fingerprint(populated.engine, populated.organization_id) == before  # ... and only that


def test_no_analysis_is_audited_or_executes_anything(populated: RiskScene) -> None:
    events = populated.monitoring.trail_count()
    executions = populated.monitoring.actions.count_executions()
    populated.analysis()
    populated.detections()
    assert populated.monitoring.trail_count() == events
    assert populated.monitoring.actions.count_executions() == executions


def test_the_same_analysis_twice_answers_the_same_way(populated: RiskScene) -> None:
    assert populated.analysis(total="true") == populated.analysis(total="true")


def test_an_anomalous_agent_can_still_act(populated: RiskScene) -> None:
    """Risk is not authorization: a CRITICAL agent's requests are decided exactly as before."""
    agent: Any = populated.monitoring.agents.register(
        display_name="Also Watched", environment="production"
    )
    assert agent is not None
    windows = populated.windows()
    populated.seed(
        steady_history(agent.id, windows, per_slot=3)
        + observed(agent.id, windows, count=30, outcome=DENIED, action="agent.rotate_keys")
    )
    assert populated.agent(agent.id)["risk_level"] in {"high", "critical"}

    body = populated.monitoring.actions.executed(agent.id, agent_id=str(agent.id))
    assert body["executed"] is True
