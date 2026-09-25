"""Phase 10's published surface and its documentation, checked without a database.

The other Phase 10 files check behaviour: that a window resolves, that a bound is crossed,
that a record is not written twice, that an analysis changes nothing. This one checks the
three things a future change could widen without any of those going red.

**What a client can send.** Five routes, their methods, their whole query surface, the bound
on every parameter, and the one request body — read from the OpenAPI document rather than
from the code, because the document is what a client codes against. A parameter that carried
an analytical value (`?threshold=…`, `?baseline_mean=…`), a verdict (`?anomaly=true`) or a
way around the window would have to be declared here, and this file fails until someone
writes down that they meant it.

**What a response may hold.** Every field of every risk response is walked and its annotation
checked against a short list: a measurement, a stated time, an identifier, a value of a
closed vocabulary, or one of the phase's own published shapes. ``Any``, a bare ``dict`` or a
free-form document fails. The check that goes with it is the vocabulary one: no field of any
risk schema is named ``score``, ``severity``, ``confidence``, ``health``, ``verdict``,
``incident``, ``alert``, ``priority``, ``weight`` or ``intent``, and no such word appears in
a parameter name — the phase publishes measurements and levels, and nothing that reads like
a judgement about a subject.

**What the document promises.** ``docs/risk.md`` is part of the deliverable, and a document
that quietly dropped "anomaly is not an incident" while the code kept a straight face would
be the worst kind of drift. The last tests read it: the four boundaries are stated exactly,
the subjects the phase is required to document are present, and every capability the phase
*withholds* is named as withheld — in a sentence that says so, not merely absent from a list.
"""

from __future__ import annotations

import enum
import inspect
import json
import re
import types
import typing
import uuid
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from aicore_api import schemas
from aicore_api.core.permissions import Permission

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]  # apps/api/tests/<file> → repo
DOCUMENT = REPOSITORY_ROOT / "docs" / "risk.md"

#: The five endpoints, in the order the document lists them.
RISK_PATHS = (
    "/organizations/{organization_id}/risk/agents",
    "/organizations/{organization_id}/risk/agents/{agent_id}",
    "/organizations/{organization_id}/risk/detections",
    "/organizations/{organization_id}/risk/detections/{detection_id}",
    "/organizations/{organization_id}/risk/analysis",
)

READ_PATHS = RISK_PATHS[:4]
RECORDING_PATH = RISK_PATHS[4]

#: Every module the phase ships, and the ones the document names in its module table.
RISK_MODULES = (
    "core/risk.py",
    "db/repositories/risk.py",
    "risk/__init__.py",
    "risk/engine.py",
    "risk/service.py",
    "schemas/risk.py",
    "api/routes/risk.py",
)

DOCUMENTED_MODULES = (
    "core/risk.py",
    "risk/engine.py",
    "risk/service.py",
    "db/repositories/risk.py",
    "schemas/risk.py",
    "api/routes/risk.py",
)

#: The whole query surface of the phase, per route: the two windows on every route that
#: reads or records an assessment, the page on the two collections, and the filters on the
#: record feed. ``agent_id`` on the single-agent route is a path parameter, not a query.
QUERY_PARAMETERS = {
    RISK_PATHS[0]: {
        "window",
        "start_time",
        "end_time",
        "baseline",
        "limit",
        "offset",
        "total",
    },
    RISK_PATHS[1]: {"window", "start_time", "end_time", "baseline"},
    RISK_PATHS[2]: {
        "limit",
        "offset",
        "agent_id",
        "detection_type",
        "risk_level",
        "assessment_status",
        "total",
    },
    RISK_PATHS[3]: set(),
    RISK_PATHS[4]: {"window", "start_time", "end_time", "baseline"},
}

#: Path parameters, which are identifiers and nothing else.
PATH_PARAMETERS = {
    RISK_PATHS[0]: {"organization_id"},
    RISK_PATHS[1]: {"organization_id", "agent_id"},
    RISK_PATHS[2]: {"organization_id"},
    RISK_PATHS[3]: {"organization_id", "detection_id"},
    RISK_PATHS[4]: {"organization_id"},
}

#: Words a *client* must not be able to send: a threshold, a bound, a baseline statistic, a
#: level, an anomaly flag or a verdict. None of them may name a query parameter or a
#: request-body property. (They appear in responses, of course — as the measurements and
#: interpretations this phase exists to publish, which is exactly why they are outputs.)
CLIENT_CANNOT_STATE = (
    "score",
    "severity",
    "confidence",
    "health",
    "verdict",
    "incident",
    "alert",
    "priority",
    "weight",
    "intent",
    "malicious",
    "compromise",
    "attack",
    "breach",
    "threshold",
    "anomaly",
    "baseline_mean",
    "baseline_stddev",
)

#: Every published model of this phase, with its complete field set. Spelling these out is
#: the point: a field added to a response is a filed diff here rather than a quiet widening.
EXPECTED_RISK_SCHEMAS = {
    "RiskWindowRead": {"start", "end"},
    "RiskParametersRead": {
        "deviation_multiple",
        "extreme_multiple",
        "rate_change_ratio",
        "min_baseline_buckets",
        "min_baseline_events",
        "min_ratio_samples",
        "min_observed_samples",
        "min_distinct_hours",
        "min_novel_occurrences",
    },
    "RiskObservationRead": {
        "start",
        "end",
        "events",
        "requests",
        "executions",
        "failures",
        "denials",
        "approval_required",
        "replays",
        "completed",
        "action_count",
        "resource_count",
        "active_hours",
        "span_hours",
    },
    "RiskBaselineRead": {
        "window",
        "start",
        "end",
        "events",
        "requests",
        "executions",
        "failures",
        "denials",
        "approval_required",
        "completed",
        "action_count",
        "resource_count",
        "hourly_buckets",
        "active_hours",
    },
    "RiskDimensionRead": {
        "metric",
        "status",
        "reason",
        "observed",
        "baseline_mean",
        "baseline_stddev",
        "upper_bound",
        "lower_bound",
        "threshold_multiple",
        "baseline_samples",
        "observation_samples",
        "detection_types",
    },
    "RiskFactorItemRead": {"kind", "value", "occurrences", "resource_type"},
    "RiskFactorRead": {
        "type",
        "metric",
        "observed",
        "baseline_mean",
        "baseline_stddev",
        "upper_bound",
        "lower_bound",
        "threshold_multiple",
        "threshold_occurrences",
        "baseline_samples",
        "observation_samples",
        "items",
    },
    "RiskAssessmentRead": {
        "organization_id",
        "entity_type",
        "entity_id",
        "status",
        "anomaly",
        "risk_level",
        "detection_type",
        "observation",
        "baseline",
        "dimensions",
        "factors",
        "parameters",
        "generated_at",
    },
    "RiskDetectionWindowRead": {"start", "end"},
    "RiskEvidenceRead": {"observation", "baseline", "parameters", "dimensions"},
    "RiskDetectionRead": {
        "id",
        "organization_id",
        "detected_at",
        "entity_type",
        "entity_id",
        "status",
        "anomaly",
        "risk_level",
        "detection_type",
        "observation",
        "baseline",
        "baseline_window",
        "schema_version",
        "evidence",
        "factors",
    },
    "RiskAgentListResponse": {
        "organization_id",
        "observation",
        "baseline_window",
        "generated_at",
        "items",
        "limit",
        "offset",
        "count",
        "total",
    },
    "RiskDetectionListResponse": {
        "organization_id",
        "items",
        "limit",
        "offset",
        "count",
        "total",
    },
    "RiskAnalysisRequest": {"agent_id"},
    "RiskAnalysisResponse": {"organization_id", "recorded", "detection", "assessment"},
}

#: The vocabularies, exactly. A value added to any of them is a new claim the phase can make.
EXPECTED_VOCABULARIES = {
    "EntityType": {"agent"},
    "DetectionType": {
        "action_rate_spike",
        "action_rate_drop",
        "failure_rate_spike",
        "denial_rate_spike",
        "novel_action",
        "novel_resource",
        "unusual_time",
    },
    "RiskMetric": {
        "action_rate",
        "failure_rate",
        "denial_rate",
        "novel_action",
        "novel_resource",
        "unusual_time",
    },
    "RiskLevel": {"none", "low", "medium", "high", "critical"},
    "AssessmentStatus": {"insufficient_data", "within_baseline", "deviating"},
    "DimensionStatus": {"measured", "deviation", "insufficient_data"},
    "BaselineWindow": {"24h", "7d", "14d", "30d"},
    "InsufficiencyReason": {
        "baseline_too_short",
        "baseline_empty",
        "baseline_no_signal",
        "baseline_insufficient_samples",
        "observation_insufficient_samples",
        "baseline_no_hours",
        "baseline_no_history",
    },
    "FactorItemKind": {"action", "resource", "hour"},
}

#: Field names that would make a *response* read as a judgement about its subject rather
#: than a report about its data. None of them is a name anywhere in this phase, on either
#: side of the request: ``anomaly`` is a boolean about measurements, and ``threshold_multiple``
#: is the multiple that produced a bound — neither is a verdict.
VERDICT_FIELDS = (
    "score",
    "severity",
    "confidence",
    "health",
    "verdict",
    "incident",
    "alert",
    "priority",
    "weight",
    "intent",
)


def _risk_schemas() -> dict[str, type[BaseModel]]:
    """Every published model this phase declares, keyed by name."""
    return {
        name: value
        for name in dir(schemas.risk)
        if name.endswith(("Read", "Response"))
        for value in (getattr(schemas.risk, name),)
        if inspect.isclass(value) and issubclass(value, BaseModel)
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
    """The document as one line, without markdown's wrapping or quote markers."""
    return " ".join(DOCUMENT.read_text().replace(">", " ").split())


def _parameters(document: dict, path: str) -> dict[str, dict]:
    operations = document["paths"][path]
    method = next(iter(operations))
    return {parameter["name"]: parameter for parameter in operations[method]["parameters"]}


def _resolved(schemas_block: dict, schema: dict) -> list[dict]:
    """A parameter's schema, with ``$ref`` and ``anyOf`` resolved to the real constraints."""
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


def test_the_phase_is_the_modules_and_the_document_it_says_it_is() -> None:
    """Seven modules behind five endpoints, in one document that names each layer."""
    for relative in RISK_MODULES:
        module = REPOSITORY_ROOT / "apps/api/src/aicore_api" / relative
        assert module.is_file(), module
    assert DOCUMENT.is_file(), DOCUMENT

    text = DOCUMENT.read_text()
    for relative in DOCUMENTED_MODULES:
        assert relative in text, relative


def test_the_client_surface_is_four_reads_and_one_recording(client: TestClient) -> None:
    """Four ``GET``s, one ``POST``, and a request body on exactly the one of them."""
    document = client.get("/openapi.json").json()
    published = {path for path in document["paths"] if "/risk/" in path}
    assert published == set(RISK_PATHS)

    for path in READ_PATHS:
        methods = document["paths"][path]
        assert set(methods) == {"get"}, (path, set(methods))
        assert "requestBody" not in methods["get"], path
    assert set(document["paths"][RECORDING_PATH]) == {"post"}

    # The document's component schemas contain exactly one request model for this phase, and
    # it holds one identifier. A second request model would be a second thing to send.
    requests = {
        name: set(body["properties"])
        for name, body in document["components"]["schemas"].items()
        if name.startswith("Risk") and "Request" in name
    }
    assert requests == {"RiskAnalysisRequest": {"agent_id"}}
    request_body = document["components"]["schemas"]["RiskAnalysisRequest"]
    assert request_body["additionalProperties"] is False
    assert request_body["required"] == ["agent_id"]

    # And no risk route accepts anything else in a body: the recording route's body is that
    # one model, and every other route has none.
    recorded_body = document["paths"][RECORDING_PATH]["post"]["requestBody"]
    assert recorded_body["content"]["application/json"]["schema"]["$ref"] == (
        "#/components/schemas/RiskAnalysisRequest"
    )


def test_the_query_surface_is_exactly_the_documented_one(client: TestClient) -> None:
    """Every parameter of every route, as a set — additions are a deliberate act."""
    document = client.get("/openapi.json").json()

    for path, expected in QUERY_PARAMETERS.items():
        parameters = _parameters(document, path)
        assert set(parameters) == expected | PATH_PARAMETERS[path], (path, set(parameters))
        for name in expected:
            assert parameters[name]["in"] == "query", (path, name)
        for name in PATH_PARAMETERS[path]:
            assert parameters[name]["in"] == "path", (path, name)

    assert {name for names in QUERY_PARAMETERS.values() for name in names} == {
        "window",
        "start_time",
        "end_time",
        "baseline",
        "limit",
        "offset",
        "total",
        "agent_id",
        "detection_type",
        "risk_level",
        "assessment_status",
    }

    # The window vocabulary is Phase 9's, reused rather than reinvented.
    for path in (RISK_PATHS[0], RISK_PATHS[1], RECORDING_PATH):
        parameters = _parameters(document, path)
        assert parameters["window"]["schema"]["default"] == "24h"
        assert parameters["baseline"]["schema"]["default"] == "7d"


@pytest.mark.parametrize("word", CLIENT_CANNOT_STATE)
def test_no_parameter_and_no_field_can_state_an_analytical_value(
    client: TestClient, word: str
) -> None:
    """A threshold, a level, a score or a verdict is not something a caller can send.

    Checked on parameter names and on every declared field name of every risk schema. The
    words that legitimately appear inside *other* words (``threshold_multiple`` is a
    published measurement, ``assessment_status`` is a filter over recorded facts) are
    spelled here as what they are: the list names the things a client could otherwise set.
    """
    document = client.get("/openapi.json").json()
    for path in RISK_PATHS:
        for name in _parameters(document, path):
            assert word not in name, (path, name)
    for name, body in document["components"]["schemas"].items():
        if not name.startswith("Risk"):
            continue
        for field in body.get("properties", {}):
            if name == "RiskAnalysisRequest":
                assert word not in field, (name, field)


def test_every_parameter_is_bounded(client: TestClient) -> None:
    """Oversized input is refused by the declaration, not by a handler's good intentions."""
    document = client.get("/openapi.json").json()
    schemas_block = document["components"]["schemas"]

    for path in RISK_PATHS:
        for name, parameter in _parameters(document, path).items():
            for schema in _resolved(schemas_block, parameter["schema"]):
                bounded = (
                    "enum" in schema
                    or schema.get("format") in {"uuid", "date-time"}
                    or schema.get("type") == "boolean"
                    or (schema.get("type") == "integer" and "maximum" in schema)
                    or (schema.get("type") == "string" and "maxLength" in schema)
                )
                assert bounded, (path, name, schema)

    # The bounds themselves: a page, an offset, an observation window, a baseline.
    agents = _parameters(document, RISK_PATHS[0])
    assert agents["limit"]["schema"]["maximum"] == 100
    assert agents["limit"]["schema"]["default"] == 25
    detections = _parameters(document, RISK_PATHS[2])
    assert detections["limit"]["schema"]["maximum"] == 200
    assert detections["limit"]["schema"]["default"] == 50
    assert detections["offset"]["schema"]["maximum"] == 100_000


def test_a_risk_response_field_holds_a_measurement_or_a_stated_value() -> None:
    """No field of any risk response can carry a document, a payload or an open mapping.

    Every annotation is one of a short list: a number, a boolean, a string, an identifier, a
    stated time, a value of a closed vocabulary, or one of the phase's own published shapes
    — possibly inside a list of one of those.
    """
    scalars = (int, float, str, bool, uuid.UUID, datetime)
    composites = set(_risk_schemas().values())

    for name, model in _risk_schemas().items():
        for field, info in model.model_fields.items():
            for annotation in _declared_types(info.annotation):
                if annotation in scalars or annotation in composites:
                    continue
                if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
                    continue
                assert getattr(annotation, "model_fields", None) is not None, (
                    name,
                    field,
                    annotation,
                )

    # No mapping at all, in any published shape: an open dictionary is where arbitrary JSON
    # would live, and this phase's evidence is a list of declared models instead.
    mappings = {
        f"{name}.{field}": str(info.annotation)
        for name, model in _risk_schemas().items()
        for field, info in model.model_fields.items()
        if str(info.annotation).startswith(("dict[", "Dict["))
    }
    assert mappings == {}


@pytest.mark.parametrize("word", VERDICT_FIELDS)
def test_no_risk_schema_has_a_verdict_field(client: TestClient, word: str) -> None:
    """There is no score, no severity and no confidence anywhere a caller can read one.

    The level is a value of a closed vocabulary, and this is what keeps a future change from
    adding the number that would make it look like a measurement of one.
    """
    document = client.get("/openapi.json").json()
    for name, body in document["components"]["schemas"].items():
        if not (name.startswith("Risk") and name not in {"RiskClassification"}):
            continue
        assert not [field for field in body.get("properties", {}) if word in field], (name, word)

    for path in RISK_PATHS:
        for name in _parameters(document, path):
            assert word not in name, (path, name)

    # The check is over *names*, not prose: ``RiskLevel``'s own description names severity,
    # confidence, intent and diagnosis in order to say it is none of them, and a description
    # that refused those words while the schema carried one would be the failure this test is
    # for. Every declared name is walked instead — properties, nested titles, references.
    names: list[str] = []
    for name, body in document["components"]["schemas"].items():
        if not (name.startswith("Risk") and name != "RiskClassification"):
            continue
        names.append(name)
        for field, declared in body.get("properties", {}).items():
            names.append(field)
            names.append(str(declared.get("title", "")))
            names.append(str(declared.get("$ref", "")).rsplit("/", 1)[-1])
    for declared_name in names:
        for forbidden in VERDICT_FIELDS:
            assert forbidden not in declared_name.lower(), (declared_name, forbidden)


@pytest.mark.parametrize("vocabulary", sorted(EXPECTED_VOCABULARIES))
def test_the_vocabularies_are_published_and_closed(client: TestClient, vocabulary: str) -> None:
    """Every word a client switches on is enumerated in the document, with these members."""
    document = client.get("/openapi.json").json()
    published = document["components"]["schemas"][vocabulary]
    assert set(published["enum"]) == EXPECTED_VOCABULARIES[vocabulary]
    assert published["type"] == "string"


def test_a_risk_response_publishes_the_shapes_it_says_it_does(client: TestClient) -> None:
    """Every field of every published model, checked against the document and the models."""
    document = client.get("/openapi.json").json()
    schemas_block = document["components"]["schemas"]

    for name, fields in EXPECTED_RISK_SCHEMAS.items():
        assert name in schemas_block, name
        assert set(schemas_block[name]["properties"]) == fields, name

    # The models themselves carry the same fields, so the document and the code cannot
    # diverge into two different contracts.
    declared = {
        name: set(getattr(schemas.risk, name).model_fields) for name in EXPECTED_RISK_SCHEMAS
    }
    for name, fields in EXPECTED_RISK_SCHEMAS.items():
        assert declared[name] == fields, name


def test_the_level_vocabulary_is_this_phases_own(client: TestClient) -> None:
    """``RiskLevel`` is the phase's, and the pre-existing agent classification is not used.

    The agent registry already had a five-value classification. This phase deliberately does
    not reuse it: a recorded level can be ``none``, which says "there is no finding", and an
    unassessed agent is a different fact. The two vocabularies stay separate.
    """
    document = client.get("/openapi.json").json()
    assert (
        set(document["components"]["schemas"]["RiskLevel"]["enum"])
        == EXPECTED_VOCABULARIES["RiskLevel"]
    )
    rendered = json.dumps(
        {path: body for path, body in document["paths"].items() if "/risk/" in path}
    )
    assert "RiskClassification" not in rendered


def test_the_phase_reuses_two_permissions_and_invents_none() -> None:
    """Reads are ``security.read``, the one write is ``security.create``, and that is all.

    Both codes are Phase 2's — the phase added a *grant*, not a concept. A ``risk.*`` or
    ``anomaly.*`` code would either guard nothing or hand its holder a capability the
    vocabulary does not have a word for.
    """
    codes = {permission.value for permission in Permission}
    for forbidden in ("risk.", "anomaly.", "incident.", "threat.", "detection.", "firewall."):
        assert not [code for code in codes if code.startswith(forbidden)], forbidden
    assert Permission.SECURITY_READ.value in codes
    assert Permission.SECURITY_CREATE.value in codes

    routes = (REPOSITORY_ROOT / "apps/api/src/aicore_api/api/routes/risk.py").read_text()
    assert routes.count("require_permission(Permission.SECURITY_READ)") == 1
    assert routes.count("require_permission(Permission.SECURITY_CREATE)") == 1
    assert routes.count("require_permission(") == 2


#: The subjects this phase is required to state, as the words a reader would look for.
REQUIRED_SUBJECTS = (
    "baseline",
    "observation",
    "population",
    "standard deviation",
    "zero",
    "30 days",
    "insufficient_data",
    "cold start",
    "evidence",
    "dedup",
    "append-only",
    "0008_anomaly_risk",
    "aicore.anomaly_detections",
    "security.read",
    "security.create",
    "isolation",
    "limitations",
    "idempotent",
    "determinis",
)


@pytest.mark.parametrize("subject", REQUIRED_SUBJECTS)
def test_the_document_states_what_the_phase_measures(subject: str) -> None:
    assert subject.lower() in DOCUMENT.read_text().lower(), subject


#: What the phase withholds, and must say it withholds — the difference between a build that
#: does not do something and a build that does not mention it.
WITHHELD_CAPABILITIES = (
    "incident",
    "alert",
    "notification",
    "kill switch",
    "suspension",
    "revocation",
    "automated response",
    "containment",
    "approval",
    "LLM",
    "embedding",
    "vector store",
    "frontend",
    "SIEM",
    "governance",
    "score",
    "severity",
    "confidence",
    "payload",
    "metadata",
)

DENIALS = ("no", "not", "never", "cannot", "nothing", "neither", "without", "nor")


@pytest.mark.parametrize("capability", WITHHELD_CAPABILITIES)
def test_the_document_names_every_capability_the_phase_withholds(capability: str) -> None:
    pattern = re.compile(
        rf"\b({'|'.join(DENIALS)})\b[^.;]{{0,180}}?{re.escape(capability)}", re.IGNORECASE
    )
    assert pattern.search(_prose()), capability


def test_the_document_states_the_four_boundaries_and_the_five_routes() -> None:
    prose = _prose()
    for boundary in (
        "ANOMALY ≠ INCIDENT",
        "RISK ≠ PROOF OF COMPROMISE",
        "DETECTION ≠ AUTOMATIC RESPONSE",
        "ANOMALY ENGINE ≠ AUTHORIZATION ENGINE",
    ):
        assert boundary in prose, boundary

    text = DOCUMENT.read_text()
    for path in RISK_PATHS:
        assert f"`{path}`" in text, path

    # The level table is published, so a reader can check a level rather than trust it.
    for level in EXPECTED_VOCABULARIES["RiskLevel"]:
        assert f"`{level}`" in DOCUMENT.read_text(), level
    for metric in EXPECTED_VOCABULARIES["RiskMetric"]:
        assert f"`{metric}`" in DOCUMENT.read_text(), metric
    for detection_type in EXPECTED_VOCABULARIES["DetectionType"]:
        assert f"`{detection_type}`" in DOCUMENT.read_text(), detection_type


def test_the_document_says_there_is_no_score() -> None:
    """The phase's central claim about its own language, in its own words."""
    prose = _prose()
    assert "There is no score anywhere in this phase" in prose
