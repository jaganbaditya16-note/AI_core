"""The analysis cannot act — asserted, not asserted-about.

Phase 10's most important promise is a negative one: *detection is not response*. A finding
may say that an agent's rate deviated from its own history; it may not suspend the agent,
change a policy, deny an action, execute anything, append to the trail, or alert anybody.
Those are claims about absence, and absence is the hardest property to test by example — so
this file attacks it from four sides, the same four sides Phase 9's read-only suite uses,
with one difference: this phase *does* write, once, and the tests below say exactly where.

- **Behaviour, over the API.** A fingerprint of the tenant's whole record — the trail, the
  registry, the policy store, the ledger, the authorization tables and the detections — is
  taken before and after every risk route has been exercised, including the recording POST.
  Only one row moves, and it is the detection that was asked for.
- **The firewall.** The strongest claim available through HTTP: an agent is assessed, found
  to be deviating, and then *executes* an action — and the execution is allowed exactly as it
  was before. A finding that could refuse an action would be an authorization engine; this
  phase is not one, and the test is what keeps the two apart.
- **The objects and the source.** The repository that owns the phase's SQL declares one read
  and one writer; the service holds repositories and a clock, nothing else; and an
  import-and-identifier scan over the phase's eight modules checks that the risk layer cannot
  reach an executor, the firewall, the policy engine, the authorization decision, the audit
  writer, the retention override, a model provider or an outbound client.
- **Immutability.** A repeated analysis is a no-op: the stored row comes back byte for byte,
  and the database's triggers refuse an edit or a delete of it.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DatabaseError

from aicore_api.core.risk import RiskLevel
from aicore_api.db.repositories.risk import DetectionRepository, RiskRepository
from aicore_api.db.tenancy import bind_tenant
from aicore_api.risk.service import RiskService
from risk_fixture import BASELINE_HOURS, RiskScene, declared_names

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PACKAGE = REPOSITORY_ROOT / "apps" / "api" / "src" / "aicore_api"

#: The phase's eight modules — everything Phase 10 added to the application.
MODULES = (
    PACKAGE / "core" / "risk.py",
    PACKAGE / "db" / "models" / "anomaly_detection.py",
    PACKAGE / "db" / "repositories" / "risk.py",
    PACKAGE / "risk" / "__init__.py",
    PACKAGE / "risk" / "engine.py",
    PACKAGE / "risk" / "service.py",
    PACKAGE / "schemas" / "risk.py",
    PACKAGE / "api" / "routes" / "risk.py",
)

#: Project modules an analysis has no business reaching: the executor and the firewall
#: (running an action), the policy engine and its repository (changing one), the
#: authorization decision (deciding one), the audit writer and the event seam (writing
#: history), discovery, and the write-side repositories of other phases.
FORBIDDEN_PROJECT_MODULES = (
    "aicore_api.actions",
    "aicore_api.auth.authorization",
    "aicore_api.core.events",
    "aicore_api.core.policy",
    "aicore_api.core.request_context",
    "aicore_api.db.repositories.actions",
    "aicore_api.db.repositories.assets",
    "aicore_api.db.repositories.audit",
    "aicore_api.db.repositories.policies",
    "aicore_api.discovery",
    "aicore_api.firewall",
)

#: Names the phase is allowed to take from those modules, and every one of them is a read
#: or a boundary: the caller's tenant, the permission a route requires, the base class that
#: enforces the tenant scope, the not-found error an unknown agent raises, and the registry
#: reader that answers "is this agent this organization's?".
ALLOWED_NAMES_FROM = {
    "aicore_api.auth.authorization": {"OrganizationContext"},
    "aicore_api.auth.dependencies": {"SessionDep", "require_permission"},
    "aicore_api.core.domain_errors": {"NotFoundError"},
    "aicore_api.db.repositories.agents": {"AgentRepository"},
    "aicore_api.db.repositories.organizations": {"OrganizationScopedRepository"},
}

#: The audit layer this phase may use is the vocabulary and nothing else: an event *type*
#: names what happened, and the writer, the sanitizer and the retention override are the
#: ways to make something happen. None of the three appears here.
AUDIT_VOCABULARY = frozenset({"AuditEventType"})

#: The models the phase may import. Two it reads — the trail it measures and the registry
#: it assesses — and one it writes.
ALLOWED_MODELS = frozenset(
    {
        "aicore_api.db.models.agent",
        "aicore_api.db.models.agent.Agent",
        "aicore_api.db.models.anomaly_detection",
        "aicore_api.db.models.anomaly_detection.AnomalyDetection",
        "aicore_api.db.models.anomaly_detection.AnomalyDetection.__table__",
        "aicore_api.db.models.audit_event",
        "aicore_api.db.models.audit_event.AuditEvent",
    }
)

#: Third-party roots the phase may import from, alongside the standard library.
THIRD_PARTY_ROOTS = frozenset({"fastapi", "pydantic", "sqlalchemy", "starlette"})

#: Write verbs no module of this phase may call. ``insert`` and ``commit`` are absent from
#: this list on purpose: the phase has exactly one write, in exactly one method, and the
#: tests below pin where — a list that forbade them here would only force the write into a
#: helper that hid it.
FORBIDDEN_CALLS = frozenset(
    {"add", "delete", "flush", "merge", "rollback", "set_config", "truncate", "update"}
)

#: Words that would mean the phase had grown a provider, a store or an outbound client.
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
    "celery",
)

#: The vocabulary of response. A finding is a measurement: no suspension, no revocation,
#: no kill switch, no remediation, no approval, no incident, no alert.
FORBIDDEN_CAPABILITIES = (
    "suspend",
    "revoke",
    "kill_switch",
    "remediat",
    "quarantine",
    "incident",
    "alerting",
    "notify",
    "escalat",
    "approve",
    "workflow",
)

#: Every tenant-owned table this organization can have rows in, counted per tenant. The
#: detection table is listed last because it is the one that may change, and by exactly one
#: row. The role and permission catalogues are global — one row per role for the whole
#: installation — so a finding cannot move them per tenant, and they are asserted separately
#: by the authorization suite.
TABLES = (
    "audit_events",
    "assets",
    "agents",
    "policies",
    "policy_versions",
    "action_executions",
    "memberships",
    "anomaly_detections",
)

VIEWS = ("agents", "detections")


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
    """Every function or method name a file calls, as the source spells it."""
    found: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                found.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                found.add(node.func.attr)
    return found


def _fingerprint(engine: Engine, organization_id: uuid.UUID) -> dict[str, str]:
    """A digest of every tenant-owned row this organization has, table by table.

    A read that wrote *anything* — a row, a counter, an event about being read — changes one
    of these digests. Counted with the tenant bound, because the isolation guard requires it.
    """
    digest: dict[str, str] = {}
    with bind_tenant(organization_id), engine.connect() as connection:
        for table in TABLES:
            rows = connection.execute(
                text(
                    f"SELECT * FROM aicore.{table} WHERE organization_id = :organization_id"
                    " ORDER BY 1"
                ),
                {"organization_id": str(organization_id)},
            ).mappings()
            rendered = json.dumps([dict(row) for row in rows], default=str, sort_keys=True)
            digest[table] = hashlib.sha256(rendered.encode()).hexdigest()
    return digest


def _seed_and_agent(scene: RiskScene) -> uuid.UUID:
    """An agent with a steady week behind it, and an observation that deviates from it."""
    # ``environment`` is the one fact the firewall reads before an executor runs, and only
    # a production registration can be executed against — so the boundary test registers
    # exactly that.
    record = scene.agents.register(display_name="Boundary Agent", environment="production")
    assert record is not None
    scene.seed_baseline(record.id, hours=BASELINE_HOURS, per_hour=1)
    scene.seed_observation(record.id, requests=40)
    return record.id


def _read_every_view(scene: RiskScene, agent_id: uuid.UUID) -> None:
    """Every read route the phase serves, once each."""
    for view in VIEWS:
        assert scene.get(view).status_code == 200, view
    assert scene.get("agents", str(agent_id)).status_code == 200
    assert scene.assessment(agent_id)


# ── behaviour: the record moves exactly once, and only in one table ──────────


def test_recording_a_finding_changes_nothing_but_the_detection_table(risk: RiskScene) -> None:
    """A finding is a row in one table. Nothing else in the tenant moves.

    The fingerprint covers the trail, the registry, the policy store, the ledger and the
    authorization tables; only ``anomaly_detections`` may differ, which is what "recording
    is not acting" means once it is checked rather than intended.
    """
    agent_id = _seed_and_agent(risk)
    before = _fingerprint(risk.engine, risk.organization_id)

    body = risk.record(agent_id)
    assert body["recorded"] is True

    after = _fingerprint(risk.engine, risk.organization_id)
    changed = {table for table in TABLES if before[table] != after[table]}
    assert changed == {"anomaly_detections"}
    assert risk.stored_count() == 1


def test_reading_the_risk_surface_changes_nothing_at_all(risk: RiskScene) -> None:
    """The four reads are reads: not one digest moves, including the detection table."""
    agent_id = _seed_and_agent(risk)
    risk.record(agent_id)
    before = _fingerprint(risk.engine, risk.organization_id)

    _read_every_view(risk, agent_id)
    assert risk.detected()["count"] == 1

    assert _fingerprint(risk.engine, risk.organization_id) == before


def test_a_refused_request_writes_nothing(risk: RiskScene) -> None:
    """A 422, a 403 and a 404 are all refusals, and a refusal has no side effect."""
    agent_id = _seed_and_agent(risk)
    before = _fingerprint(risk.engine, risk.organization_id)

    assert risk.analyze(uuid.uuid4()).status_code == 404
    assert risk.analyze(agent_id, window="1h").status_code == 422
    assert risk.get("detections", str(uuid.uuid4())).status_code == 404

    assert _fingerprint(risk.engine, risk.organization_id) == before


def test_a_finding_does_not_gate_execution(risk: RiskScene) -> None:
    """The firewall is not consulted, and the firewall does not consult this.

    An agent whose behaviour is recorded as deviating — level ``medium`` at least, and a
    real recorded finding — executes a registered action immediately afterwards, on the same
    client, in the same tenant. It is allowed: the analysis has no vote on whether an action
    runs. Anything else would be an authorization engine wearing an analysis engine's name.
    """
    agent_id = _seed_and_agent(risk)
    recorded = risk.record(agent_id)
    assert recorded["assessment"]["anomaly"] is True
    assert RiskLevel(recorded["assessment"]["risk_level"]) is not RiskLevel.NONE

    before = risk.actions.count_executions()
    executed = risk.actions.execute(agent_id, agent_id=str(agent_id))
    assert executed.status_code == 200, executed.text
    body = executed.json()
    assert body["executed"] is True
    assert body["firewall"]["outcome"] == "allow"
    # The firewall's outcome and the ledger row: the action ran, and it ran because the
    # ordinary path permitted it — not because a finding did, and not despite one.
    assert body["execution_id"]
    assert risk.actions.find_execution(body["idempotency_key"]) is not None
    assert risk.actions.count_executions() == before + 1


def test_the_trail_gains_no_event_about_being_assessed(risk: RiskScene) -> None:
    """Analysing is not an operation of the platform, so it is not an event on its record."""
    agent_id = _seed_and_agent(risk)
    before = risk.monitoring.trail_count()

    _read_every_view(risk, agent_id)
    risk.record(agent_id)

    assert risk.monitoring.trail_count() == before


# ── the objects ──────────────────────────────────────────────────────────────


def test_the_trail_repository_declares_one_read_and_no_writer() -> None:
    """The class that owns the phase's read SQL has no verb that could change a row."""
    declared = {name for name in vars(RiskRepository) if not name.startswith("_")}
    assert declared == {"activity"}
    for name in declared:
        assert not re.search(r"(add|create|delete|insert|update|write|save|commit|flush)", name)


def test_the_detection_repository_declares_exactly_one_write() -> None:
    """Recording, reading one, listing and counting — and the write is the first of them."""
    declared = {name for name in vars(DetectionRepository) if not name.startswith("_")}
    assert declared == {"record", "find", "page", "count"}
    # One name in that set records; the other three read. There is no update and no delete,
    # because the table's triggers would refuse both and offering them would be a lie.
    assert declared & {"record"} == {"record"}
    for name in declared - {"record"}:
        assert not re.search(r"(add|create|delete|insert|update|save|record)", name), name


def test_the_service_holds_repositories_and_nothing_that_could_act() -> None:
    """No session-owning executor, no policy engine, no audit writer, no adapter."""
    service = RiskService(
        risk=object(),  # type: ignore[arg-type]
        detections=object(),  # type: ignore[arg-type]
        agents=object(),  # type: ignore[arg-type]
    )
    held = set(vars(service))
    assert held == {"_risk", "_detections", "_agents", "_parameters"}
    for forbidden in ("executor", "registry", "policy", "audit", "writer", "session", "engine"):
        assert not any(forbidden in name for name in held), (forbidden, held)
    assert sorted(
        name
        for name in dir(RiskService)
        if not name.startswith("_") and callable(getattr(RiskService, name))
    ) == [
        "assess_agent",
        "assess_page",
        "detection",
        "detection_count",
        "detections",
        "record",
    ]


# ── the source: what the phase cannot reach ──────────────────────────────────


@pytest.mark.parametrize("module", MODULES, ids=lambda path: path.relative_to(PACKAGE).as_posix())
def test_no_module_of_the_phase_imports_something_that_could_act(module: Path) -> None:
    """An import scan, over every module the phase adds.

    Two lists: the project modules an analysis has no business reaching, and the external
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


def test_the_only_audit_name_the_phase_takes_is_the_vocabulary() -> None:
    """Reading the record's language is not writing to the record."""
    for module in MODULES:
        taken = _imported_from(module, "aicore_api.core.audit")
        assert taken <= AUDIT_VOCABULARY, (module.name, taken - AUDIT_VOCABULARY)


def test_the_only_models_the_phase_touches_are_the_trail_the_registry_and_its_own_table() -> None:
    """No asset, policy or execution model: a finding's subject is an agent, and nothing else.

    Reaching a policy model would be the first step towards changing one, and reaching an
    execution model towards deciding whether one runs.
    """
    models = {
        dotted
        for module in MODULES
        for dotted in _imports(module)
        if dotted.startswith("aicore_api.db.models")
    }
    assert models <= ALLOWED_MODELS, models - ALLOWED_MODELS
    assert "aicore_api.db.models.audit_event" in models
    assert "aicore_api.db.models.anomaly_detection" in models


@pytest.mark.parametrize("module", MODULES, ids=lambda path: path.relative_to(PACKAGE).as_posix())
def test_no_module_of_the_phase_calls_a_write_it_should_not(module: Path) -> None:
    """No delete, no update, no flush, no rollback and no retention override, anywhere."""
    called = _called_names(module)
    assert called.isdisjoint(FORBIDDEN_CALLS), (module.name, called & FORBIDDEN_CALLS)


def test_the_only_statements_that_write_live_in_one_method() -> None:
    """The phase's write is one statement in one method, and it is not hidden in a helper.

    ``pg_insert`` and ``commit`` appear in the repository and nowhere else — not in the
    service, not in a route, not in the schemas — so "this phase writes one table" is a
    fact about the source rather than a claim about the call graph.
    """
    repository = PACKAGE / "db" / "repositories" / "risk.py"
    holders = {module.name for module in MODULES if "pg_insert(" in module.read_text()}
    assert holders == {repository.name}

    source = repository.read_text()
    assert source.count("pg_insert(") == 1
    assert source.count("self.session.commit()") == 1
    # The one insert names the detection table, and the class it lives in is the one that
    # may write it.
    body = _tree(repository)
    classes = {node.name: node for node in ast.walk(body) if isinstance(node, ast.ClassDef)}
    record = next(
        node
        for node in classes["DetectionRepository"].body
        if isinstance(node, ast.FunctionDef) and node.name == "record"
    )
    called = {
        node.func.attr
        for node in ast.walk(record)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    named = {
        node.func.id
        for node in ast.walk(record)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "pg_insert" in named | called
    assert "commit" in called


def test_no_module_of_the_phase_reaches_a_model_a_store_or_a_network() -> None:
    """No model provider, no embeddings, no vector store, no queue, no HTTP client.

    The phase's arithmetic is SQL and Python. There is no NVIDIA, Nebius or OpenAI anywhere
    near it, and no way for a measurement to leave the process — which is also what keeps
    "no LLM" from being a statement about the current configuration.
    """
    for module_path in MODULES:
        source = module_path.read_text().lower()
        for word in FORBIDDEN_WORDS:
            assert word not in source, (module_path.name, word)


def test_the_phase_has_no_vocabulary_for_suspending_or_alerting() -> None:
    """No agent status, no revocation, no kill switch, no approval and no incident room.

    Checked against the phase's *names* — classes, fields, arguments and literals — rather
    than its prose, because the prose is where it says it is none of those things. A name is
    what a client renders and what a later phase extends, and none of these appear.
    """
    for module in MODULES:
        names = declared_names(module)
        assert names, module.name
        for name in sorted(names):
            lowered = name.lower()
            for word in FORBIDDEN_CAPABILITIES:
                assert word not in lowered, (module.name, name, word)


def test_the_routes_declare_four_reads_and_one_recording_write() -> None:
    """Five handlers: four reads, and one POST that writes one row and returns it."""
    routes = (PACKAGE / "api" / "routes" / "risk.py").read_text()
    verbs = re.findall(r"@router\.(get|post|put|patch|delete)\(", routes)
    assert sorted(verbs) == ["get", "get", "get", "get", "post"]
    for verb in ("put", "patch", "delete"):
        assert f"@router.{verb}(" not in routes


def test_the_server_clock_is_read_in_exactly_one_place() -> None:
    """One ``now`` per request, decided by the window resolver.

    Every number in a response describes one moment. A second clock read — in the service,
    the engine or a repository — would let two parts of one answer disagree about when they
    were computed, and would make a recorded window depend on how long the request took.
    """
    routes = PACKAGE / "api" / "routes" / "risk.py"
    assert routes.read_text().count("datetime.now(") == 1
    for module in (
        PACKAGE / "core" / "risk.py",
        PACKAGE / "risk" / "engine.py",
        PACKAGE / "risk" / "service.py",
        PACKAGE / "db" / "repositories" / "risk.py",
    ):
        source = module.read_text()
        for clock in ("datetime.now(", "utcnow(", "time.time(", "date.today("):
            assert clock not in source, (module.name, clock)


def test_no_module_of_the_phase_can_delete_or_edit_a_detection() -> None:
    """The append-only override is named nowhere in the phase, and neither is a bypass."""
    for module in MODULES:
        source = module.read_text().lower()
        for forbidden in ("risk_retention", "audit_retention", "session_replication_role"):
            assert forbidden not in source, (module.name, forbidden)


# ── immutability ─────────────────────────────────────────────────────────────


def test_repeating_an_analysis_leaves_the_stored_row_untouched(risk: RiskScene) -> None:
    """Deduplication is a no-op, not a rewrite: the first record of a window is its record."""
    agent_id = _seed_and_agent(risk)
    first = risk.record(agent_id)
    (before,) = risk.stored()

    second = risk.record(agent_id)
    (after,) = risk.stored()

    assert second["recorded"] is False
    assert after == before
    assert second["detection"]["detected_at"] == first["detection"]["detected_at"]
    assert json.dumps(after["evidence"], sort_keys=True) == json.dumps(
        before["evidence"], sort_keys=True
    )


def test_a_stored_detection_is_append_only(risk: RiskScene, integration_engine: Engine) -> None:
    """The database refuses an edit and an ordinary delete; only a named retention lets go."""
    agent_id = _seed_and_agent(risk)
    risk.record(agent_id)
    (row,) = risk.stored()

    for statement in (
        "UPDATE aicore.anomaly_detections SET risk_level = 'none'"
        " WHERE organization_id = :organization_id AND id = :id",
        "DELETE FROM aicore.anomaly_detections"
        " WHERE organization_id = :organization_id AND id = :id",
    ):
        with (
            pytest.raises(DatabaseError, match="append-only"),
            bind_tenant(risk.organization_id),
            integration_engine.begin() as connection,
        ):
            connection.execute(
                text(statement),
                {"organization_id": str(risk.organization_id), "id": str(row["id"])},
            )
    assert risk.stored_count() == 1


def test_the_analysis_is_reproducible_after_the_record_exists(risk: RiskScene) -> None:
    """Nothing is cached and nothing is remembered: the same window computes the same answer."""
    agent_id = _seed_and_agent(risk)
    fresh = risk.assessment(agent_id)
    risk.record(agent_id)
    again = risk.assessment(agent_id)

    for key in ("status", "anomaly", "risk_level", "detection_type", "dimensions", "factors"):
        assert again[key] == fresh[key], key


def test_an_assessment_of_one_agent_is_the_same_in_a_page(risk: RiskScene) -> None:
    """Two code paths, one arithmetic: the page's row and the single route agree."""
    agent_id = _seed_and_agent(risk)
    alone = risk.assessment(agent_id)
    page = risk.assessments()
    (item,) = [entry for entry in page["items"] if entry["entity_id"] == str(agent_id)]

    for key in ("status", "anomaly", "risk_level", "dimensions", "factors"):
        assert item[key] == alone[key], key
