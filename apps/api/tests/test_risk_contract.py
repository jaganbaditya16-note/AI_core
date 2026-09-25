"""Phase 10's published surface, its mirrors and its documentation, checked without a database.

The other Phase 10 files check behaviour. This one checks the things a later change could
widen without any of those going red.

**What a client can ask.** Three routes, all ``GET``, no request body, and the whole query
surface of each, read from the OpenAPI document a client codes against. A parameter that
let a client *state* a risk level, an anomaly state, a baseline value or evidence would
have to be added here first.

**What a response may hold.** Every field of every risk response is walked: a count, a
float statistic, a stated time, an identifier, a closed vocabulary, one of the phase's own
shapes — or, in exactly one field, the evidence document the engine builds and checks. The
closed vocabularies are pinned in the Python enums, the OpenAPI document, the migration's
CHECK lists and the TypeScript mirror, so the four cannot drift apart.

**What the document promises.** ``docs/risk.md`` is part of the deliverable: its constants
table must agree with the code, and each capability the phase withholds must be named as
withheld — in a sentence that says so.
"""

from __future__ import annotations

import enum
import importlib.util
import inspect
import re
import types
import typing
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from aicore_api.core import risk as engine
from aicore_api.core.permissions import ROLE_PERMISSIONS, Permission, RoleCode
from aicore_api.schemas import risk as risk_schemas

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]  # apps/api/tests/<file> → repo
DOCUMENT = REPOSITORY_ROOT / "docs" / "risk.md"
SHARED_TYPES = REPOSITORY_ROOT / "packages" / "types" / "src" / "index.ts"
MIGRATION = REPOSITORY_ROOT / "database" / "migrations" / "versions" / "0008_anomaly_detections.py"
SOURCE_ROOT = REPOSITORY_ROOT / "apps" / "api" / "src" / "aicore_api"

ANALYSIS = "/organizations/{organization_id}/risk/analysis"
DETECTIONS = "/organizations/{organization_id}/risk/detections"
DETECTION = "/organizations/{organization_id}/risk/detections/{detection_id}"
RISK_PATHS = (ANALYSIS, DETECTIONS, DETECTION)

#: Every module the phase ships. All but ``risk/__init__.py`` are named in the document.
RISK_MODULES = (
    "core/risk.py",
    "db/models/anomaly_detection.py",
    "db/repositories/risk_history.py",
    "db/repositories/anomaly_detections.py",
    "risk/__init__.py",
    "risk/service.py",
    "risk/cli.py",
    "schemas/risk.py",
    "api/routes/risk.py",
)
DOCUMENTED_MODULES = (
    "core/risk.py",
    "db/repositories/risk_history.py",
    "db/repositories/anomaly_detections.py",
    "risk/service.py",
    "risk/cli.py",
    "api/routes/risk.py",
    "schemas/risk.py",
    "0008_anomaly_detections",
    "packages/types/src/index.ts",
)

#: The whole query surface, per route. ``organization_id`` (and ``detection_id``) are path.
EXPECTED_QUERY_PARAMETERS = {
    ANALYSIS: {"baseline", "observation", "as_of", "agent_id", "limit", "offset", "total"},
    DETECTIONS: {"agent_id", "detection_type", "risk_level", "limit", "offset", "total"},
    DETECTION: set(),
}

#: Words naming something only the server may produce. None may be the name of a
#: parameter on the analysis route — an input there would be a way to state a result.
SERVER_OWNED_WORDS = (
    "anomal",
    "risk",
    "evidence",
    "factor",
    "score",
    "mean",
    "stddev",
    "threshold",
    "state",
    "status",
    "detected",
    "fingerprint",
    "severity",
)

#: Published schema fields, per shape. Additions are a deliberate act.
EXPECTED_RISK_SCHEMAS = {
    "RiskWindowsRead": {
        "baseline",
        "baseline_start",
        "baseline_end",
        "observation",
        "observation_start",
        "observation_end",
        "slot_seconds",
        "slots",
    },
    "RiskFactorRead": {"code", "effect", "level", "steps", "detection_type", "count"},
    "RiskCheckRead": {"detection_type", "status", "reason"},
    "RiskBaselineStatisticsRead": {"history_slots", "events", "mean", "stddev", "zero_variance"},
    "RiskObservationRead": {"requests", "denials", "executions", "failures"},
    "RiskAgentBehaviourRead": {
        "baseline_requests",
        "baseline_active_slots",
        "baseline_distinct_actions",
        "observed_distinct_actions",
        "novel_action_count",
        "baseline_distinct_resources",
        "observed_distinct_resources",
        "novel_resource_count",
        "baseline_active_hours_utc",
        "observed_active_hours_utc",
        "baseline_peak_requests",
        "observed_peak_requests",
    },
    "RiskDetectionRead": {
        "detection_type",
        "risk_level",
        "risk_factors",
        "evidence",
        "fingerprint",
    },
    "RiskAgentAnalysisRead": {
        "entity_type",
        "agent_id",
        "status",
        "anomaly_state",
        "risk_level",
        "risk_factors",
        "insufficient_reasons",
        "baseline_statistics",
        "observation",
        "behaviour",
        "checks",
        "detections",
    },
    "RiskAnalysisResponse": {
        "organization_id",
        "engine_version",
        "windows",
        "items",
        "limit",
        "offset",
        "count",
        "total",
    },
    "AnomalyDetectionRead": {
        "id",
        "organization_id",
        "schema_version",
        "engine_version",
        "detected_at",
        "entity_type",
        "entity_id",
        "detection_type",
        "analysis_status",
        "anomaly_state",
        "risk_level",
        "windows",
        "evidence",
        "risk_factors",
        "fingerprint",
    },
    "AnomalyDetectionListResponse": {
        "organization_id",
        "items",
        "limit",
        "offset",
        "count",
        "total",
    },
}

#: The closed vocabularies, published by name. Values are pinned against the enums.
PUBLISHED_VOCABULARIES: dict[str, type[enum.Enum]] = {
    "BaselineWindow": engine.BaselineWindow,
    "ObservationWindow": engine.ObservationWindow,
    "EntityType": engine.EntityType,
    "DetectionType": engine.DetectionType,
    "AnalysisStatus": engine.AnalysisStatus,
    "AnomalyState": engine.AnomalyState,
    "InsufficientReason": engine.InsufficientReason,
    "CheckStatus": engine.CheckStatus,
    "CheckReason": engine.CheckReason,
    "RiskLevel": engine.RiskLevel,
    "RiskFactorCode": engine.RiskFactorCode,
    "FactorEffect": engine.FactorEffect,
}

#: The TypeScript alias for each vocabulary (two are prefixed: the bare names are generic).
TYPESCRIPT_VOCABULARIES = {
    "RiskBaselineWindow": engine.BaselineWindow,
    "RiskObservationWindow": engine.ObservationWindow,
    "RiskEntityType": engine.EntityType,
    "DetectionType": engine.DetectionType,
    "AnalysisStatus": engine.AnalysisStatus,
    "AnomalyState": engine.AnomalyState,
    "InsufficientReason": engine.InsufficientReason,
    "CheckStatus": engine.CheckStatus,
    "CheckReason": engine.CheckReason,
    "RiskLevel": engine.RiskLevel,
    "RiskFactorCode": engine.RiskFactorCode,
    "FactorEffect": engine.FactorEffect,
}


def _openapi(client: TestClient) -> dict[str, Any]:
    document: dict[str, Any] = client.get("/openapi.json").json()
    return document


def _parameters(document: dict[str, Any], path: str) -> dict[str, dict[str, Any]]:
    return {
        parameter["name"]: parameter
        for parameter in document["paths"][path]["get"].get("parameters", [])
    }


def _resolved(schemas_block: dict[str, Any], schema: dict[str, Any]) -> list[dict[str, Any]]:
    """A schema with ``$ref`` and ``anyOf`` resolved to the real constraints."""
    if "$ref" in schema:
        return [schemas_block[schema["$ref"].rsplit("/", 1)[-1]]]
    if "anyOf" in schema:
        return [
            member
            for entry in schema["anyOf"]
            if entry.get("type") != "null"
            for member in _resolved(schemas_block, entry)
        ]
    return [schema]


def _risk_models() -> dict[str, type[BaseModel]]:
    return {
        name: value
        for name, value in vars(risk_schemas).items()
        if inspect.isclass(value)
        and issubclass(value, BaseModel)
        and value.__module__ == risk_schemas.__name__
    }


def _declared_types(annotation: object) -> list[object]:
    """The annotation with ``| None`` flattened and ``list[…]`` unwrapped one level."""
    if typing.get_origin(annotation) in (typing.Union, types.UnionType):
        return [
            member
            for argument in typing.get_args(annotation)
            if argument is not type(None)
            for member in _declared_types(argument)
        ]
    if typing.get_origin(annotation) is list:
        return list(typing.get_args(annotation))
    return [annotation]


def _prose() -> str:
    """The document as one line, without markdown's wrapping, emphasis or quote markers."""
    text = DOCUMENT.read_text(encoding="utf-8").replace(">", " ").replace("*", "")
    return " ".join(text.split())


def _migration_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("risk_migration_0008", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _typescript_union(source: str, name: str) -> set[str]:
    match = re.search(rf"export type {name} =([^;]+);", source)
    assert match, f"packages/types has no union '{name}'"
    return set(re.findall(r'"([^"]+)"', match.group(1)))


def _typescript_interface(source: str, name: str) -> set[str]:
    match = re.search(rf"export interface {name} \{{(.*?)\n\}}", source, re.DOTALL)
    assert match, f"packages/types has no interface '{name}'"
    # Top-level members only: two-space indentation, ``name:`` or ``name?:``.
    return set(re.findall(r"^  (\w+)\??:", match.group(1), re.MULTILINE))


# ── The modules and the surface ───────────────────────────────────────────────


def test_the_phase_is_the_modules_and_the_document_it_says_it_is() -> None:
    for relative in RISK_MODULES:
        assert (SOURCE_ROOT / relative).is_file(), relative
    assert MIGRATION.is_file()
    assert DOCUMENT.is_file()

    text = DOCUMENT.read_text(encoding="utf-8")
    for relative in DOCUMENTED_MODULES:
        assert relative in text, relative


def test_the_client_surface_is_three_get_routes_without_a_body(client: TestClient) -> None:
    """Three reads, no fourth, no verb but GET, and no request body anywhere.

    A body would be a way to hand the server an anomaly, a level or a baseline; a write
    verb would be a way to store one. Neither exists, so neither can be spoofed.
    """
    document = _openapi(client)
    published = {path for path in document["paths"] if "/risk" in path}
    assert published == set(RISK_PATHS)

    for path in RISK_PATHS:
        methods = document["paths"][path]
        assert set(methods) == {"get"}, (path, set(methods))
        operation = methods["get"]
        assert "requestBody" not in operation, path
        assert operation["tags"] == ["risk"], path
        assert {"200", "401", "403", "404", "422"} <= set(operation["responses"]), path

    # No component anywhere is a request for this subject.
    for name in document["components"]["schemas"]:
        subject = name.startswith(("Risk", "Anomaly", "Detection"))
        assert not (subject and name.endswith(("Request", "Create", "Update", "Patch"))), name


def test_the_query_surface_is_exactly_the_documented_one(client: TestClient) -> None:
    document = _openapi(client)
    for path, expected in EXPECTED_QUERY_PARAMETERS.items():
        parameters = _parameters(document, path)
        path_parameters = {name for name, value in parameters.items() if value["in"] == "path"}
        query = {name for name, value in parameters.items() if value["in"] == "query"}
        assert query == expected, (path, query)
        assert path_parameters == set(re.findall(r"\{(\w+)\}", path)), path

    analysis = _parameters(document, ANALYSIS)
    schemas_block = document["components"]["schemas"]
    assert analysis["baseline"]["schema"]["default"] == engine.DEFAULT_BASELINE_WINDOW.value
    assert analysis["observation"]["schema"]["default"] == engine.DEFAULT_OBSERVATION_WINDOW.value
    limit = _resolved(schemas_block, analysis["limit"]["schema"])[0]
    assert (limit["minimum"], limit["maximum"]) == (1, 100)
    listing_limit = _resolved(schemas_block, _parameters(document, DETECTIONS)["limit"]["schema"])
    assert (listing_limit[0]["minimum"], listing_limit[0]["maximum"]) == (1, 200)


@pytest.mark.parametrize("word", SERVER_OWNED_WORDS)
def test_the_analysis_accepts_no_parameter_naming_a_server_owned_value(
    client: TestClient, word: str
) -> None:
    for name in _parameters(_openapi(client), ANALYSIS):
        assert word not in name.lower(), name


def test_the_listing_filters_are_closed_vocabularies(client: TestClient) -> None:
    """The listing may *filter* by type and level, and only by values the server emits."""
    document = _openapi(client)
    schemas_block = document["components"]["schemas"]
    parameters = _parameters(document, DETECTIONS)
    for name, vocabulary in (
        ("detection_type", engine.DetectionType),
        ("risk_level", engine.RiskLevel),
    ):
        (schema,) = _resolved(schemas_block, parameters[name]["schema"])
        assert set(schema["enum"]) == {member.value for member in vocabulary}, name


def test_every_parameter_is_bounded(client: TestClient) -> None:
    document = _openapi(client)
    schemas_block = document["components"]["schemas"]
    for path in RISK_PATHS:
        for name, parameter in _parameters(document, path).items():
            for schema in _resolved(schemas_block, parameter["schema"]):
                bounded = (
                    "enum" in schema
                    or schema.get("format") in {"uuid", "date-time"}
                    or schema.get("type") == "boolean"
                    or (schema.get("type") == "integer" and "maximum" in schema)
                )
                assert bounded, (path, name, schema)


# ── The response shapes ───────────────────────────────────────────────────────


def test_the_published_shapes_are_exactly_the_pinned_ones(client: TestClient) -> None:
    schemas_block = _openapi(client)["components"]["schemas"]
    for name, fields in EXPECTED_RISK_SCHEMAS.items():
        assert name in schemas_block, name
        assert set(schemas_block[name]["properties"]) == fields, name
    assert set(_risk_models()) == set(EXPECTED_RISK_SCHEMAS)


def test_the_published_vocabularies_match_the_engine(client: TestClient) -> None:
    schemas_block = _openapi(client)["components"]["schemas"]
    for name, vocabulary in PUBLISHED_VOCABULARIES.items():
        assert schemas_block[name]["enum"] == [member.value for member in vocabulary], name

    # The vocabularies the brief fixed, stated literally rather than derived.
    assert [member.value for member in engine.DetectionType] == [
        "action_rate_spike",
        "action_rate_drop",
        "failure_rate_spike",
        "denial_rate_spike",
        "novel_action",
        "novel_resource",
        "unusual_time",
        "unusual_frequency",
    ]
    assert [member.value for member in engine.RiskLevel] == [
        "none",
        "low",
        "medium",
        "high",
        "critical",
    ]
    assert [member.value for member in engine.BaselineWindow] == ["7d", "14d", "30d"]


def test_a_risk_response_field_holds_a_value_the_server_can_account_for() -> None:
    """Counts, statistics, times, identifiers, vocabularies, own shapes — and one document.

    ``evidence`` is the only free-form field, and it is built and checked by the engine
    (``ensure_safe_evidence``) before it is published. Nothing else may be a mapping, and
    nothing may be ``Any``.
    """
    scalars = (int, float, str, bool, uuid.UUID, datetime)
    own_shapes = set(_risk_models().values())
    mappings: set[tuple[str, str]] = set()

    for name, model in _risk_models().items():
        for field, info in model.model_fields.items():
            for annotation in _declared_types(info.annotation):
                if annotation in scalars or annotation in own_shapes:
                    continue
                if inspect.isclass(annotation) and issubclass(annotation, enum.Enum):
                    assert annotation in PUBLISHED_VOCABULARIES.values(), (name, field)
                    continue
                assert annotation == dict[str, Any], (name, field, annotation)
                mappings.add((name, field))

    assert mappings == {("RiskDetectionRead", "evidence"), ("AnomalyDetectionRead", "evidence")}


def test_no_published_field_is_a_numeric_risk_score() -> None:
    """Risk is a word. The only floats are the two baseline statistics."""
    floats = {
        (name, field)
        for name, model in _risk_models().items()
        for field, info in model.model_fields.items()
        if float in _declared_types(info.annotation)
    }
    assert floats == {
        ("RiskBaselineStatisticsRead", "mean"),
        ("RiskBaselineStatisticsRead", "stddev"),
    }
    for name, model in _risk_models().items():
        for field in model.model_fields:
            assert "score" not in field, (name, field)
            assert "weight" not in field, (name, field)
        risk_level = model.model_fields.get("risk_level")
        if risk_level is not None:
            assert risk_level.annotation is engine.RiskLevel, name


# ── The permission ────────────────────────────────────────────────────────────


def test_the_phase_declares_no_permission_and_changes_no_role() -> None:
    """Every route's guard is ``audit.read``; the matrix is Phase 2's.

    ``security.read`` would be the wrong single guard: the analyst holds it without
    ``audit.read``, and an analysis is the trail in derived form.
    """
    codes = {permission.value for permission in Permission}
    assert not [code for code in codes if "risk" in code or "anomal" in code]

    routes = (SOURCE_ROOT / "api/routes/risk.py").read_text(encoding="utf-8")
    assert routes.count("require_permission(Permission.AUDIT_READ)") == 1
    assert routes.count("require_permission(") == 1

    # The two roles the document names are exactly the roles holding audit.read.
    holders = {
        role for role, granted in ROLE_PERMISSIONS.items() if Permission.AUDIT_READ in granted
    }
    assert holders == {RoleCode.OWNER, RoleCode.SECURITY_ADMIN}
    reads_findings_only = {
        role
        for role, granted in ROLE_PERMISSIONS.items()
        if Permission.SECURITY_READ in granted and Permission.AUDIT_READ not in granted
    }
    assert RoleCode.ANALYST in reads_findings_only


# ── The migration and the TypeScript mirror ──────────────────────────────────


def test_the_migration_vocabularies_match_the_engine() -> None:
    """The table's CHECK lists are literals (a migration is frozen) — pinned here."""
    migration = _migration_module()
    assert migration.revision == "0008_anomaly_detections"
    assert migration.down_revision == "0007_audit_events"
    assert tuple(migration.DETECTION_TYPES) == tuple(m.value for m in engine.DetectionType)
    assert tuple(migration.ENTITY_TYPES) == tuple(m.value for m in engine.EntityType)
    assert tuple(migration.BASELINE_WINDOWS) == tuple(m.value for m in engine.BaselineWindow)
    assert tuple(migration.OBSERVATION_WINDOWS) == tuple(m.value for m in engine.ObservationWindow)
    # A stored detection is never "none": the table holds anomalies only.
    assert tuple(migration.STORED_RISK_LEVELS) == tuple(
        m.value for m in engine.RiskLevel if m is not engine.RiskLevel.NONE
    )


def test_the_typescript_mirror_matches_the_published_shapes() -> None:
    source = SHARED_TYPES.read_text(encoding="utf-8")
    assert "/* ── Anomaly & risk (Phase 10)" in source

    for name, fields in EXPECTED_RISK_SCHEMAS.items():
        assert _typescript_interface(source, name) == fields, name
    for name, vocabulary in TYPESCRIPT_VOCABULARIES.items():
        assert _typescript_union(source, name) == {m.value for m in vocabulary}, name

    evidence = _typescript_interface(source, "RiskEvidence")
    assert evidence == {
        "engine_version",
        "detection_type",
        "entity",
        "baseline",
        "observation",
        "measurement",
        "comparison",
        "risk_factors",
    }


# ── The document ──────────────────────────────────────────────────────────────


#: Every constant the document's tables state, with the value the code holds.
DOCUMENTED_CONSTANTS = (
    "MIN_BASELINE_EVENTS",
    "MIN_HISTORY_SLOTS",
    "MIN_ACTIVE_SLOTS",
    "RATE_SIGMA",
    "RATE_MIN_DELTA",
    "SHARE_DELTA",
    "SHARE_EXTREME_DELTA",
    "SHARE_MIN_OBSERVED_EVENTS",
    "SHARE_MIN_OBSERVED_SAMPLE",
    "SHARE_MIN_BASELINE_SAMPLE",
    "RESOURCE_REUSE_MIN_RATIO",
    "UNUSUAL_TIME_MIN_EVENTS",
    "UNUSUAL_TIME_MAX_ACTIVE_HOURS",
    "BURST_RATIO",
    "BURST_MIN_DELTA",
    "MAX_EVIDENCE_ITEMS",
    "MAX_EVIDENCE_BYTES",
)


@pytest.mark.parametrize("name", DOCUMENTED_CONSTANTS)
def test_the_documented_constants_are_the_code(name: str) -> None:
    value = getattr(engine, name)
    text = DOCUMENT.read_text(encoding="utf-8")
    match = re.search(rf"\| `{name}` \| `([^`]+)` \|", text)
    assert match, f"docs/risk.md does not state {name}"
    assert match.group(1) == str(value), (name, match.group(1), value)


def test_the_documented_history_span_and_base_levels_are_the_code() -> None:
    text = DOCUMENT.read_text(encoding="utf-8")
    assert engine.MIN_HISTORY_SPAN.total_seconds() == 86400
    assert "| `MIN_HISTORY_SPAN` | `1 day` |" in text
    for detection, level in engine.BASE_RISK.items():
        factor = engine.DETECTION_FACTORS[detection]
        row = f"| `{detection.value}` | `{level.value}` | `{factor.value}` |"
        assert row in text, row


def test_the_document_names_the_whole_vocabulary() -> None:
    text = DOCUMENT.read_text(encoding="utf-8")
    for vocabulary in (
        engine.DetectionType,
        engine.RiskLevel,
        engine.InsufficientReason,
        engine.CheckReason,
        engine.RiskFactorCode,
        engine.BaselineWindow,
        engine.ObservationWindow,
    ):
        for member in vocabulary:
            assert f"`{member.value}`" in text, member


#: Subjects the brief requires the document to cover, as the words a reader looks for.
REQUIRED_SUBJECTS = (
    "detection vocabulary",
    "baseline",
    "observation",
    "cold start",
    "minimum-data rules",
    "statistical methods",
    "zero variance",
    "risk levels and factors",
    "evidence",
    "limitations",
    "detection ≠ incident",
    "tenant isolation",
    "performance",
    "deduplication",
)


@pytest.mark.parametrize("subject", REQUIRED_SUBJECTS)
def test_the_document_covers_each_required_subject(subject: str) -> None:
    assert subject in DOCUMENT.read_text(encoding="utf-8").lower(), subject


#: What the phase withholds, and must say it withholds.
WITHHELD_CAPABILITIES = (
    "authorize",
    "execute",
    "firewall",
    "suspend",
    "revoke",
    "modify a policy",
    "create an incident",
    "send an alert",
    "remediate",
    "automatic response",
    "language model",
    "numeric risk score",
    "opaque scoring",
    "fabricated",
    "anomalous for lack of history",
)

DENIALS = ("no", "not", "never", "cannot", "nothing", "neither", "without")


@pytest.mark.parametrize("capability", WITHHELD_CAPABILITIES)
def test_the_document_names_every_capability_the_phase_withholds(capability: str) -> None:
    pattern = re.compile(
        rf"\b({'|'.join(DENIALS)})\b[^.;]{{0,160}}?{re.escape(capability)}", re.IGNORECASE
    )
    assert pattern.search(_prose()), capability


def test_the_document_states_the_boundary_sentence() -> None:
    boundary = "DETECTION ≠ INCIDENT. RISK ≠ AUTHORIZATION. THERE IS NO AUTOMATIC RESPONSE."
    assert boundary in _prose()
    for path in RISK_PATHS:
        assert path in DOCUMENT.read_text(encoding="utf-8"), path
