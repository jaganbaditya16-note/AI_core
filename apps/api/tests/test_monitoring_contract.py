"""Phase 9's published surface and its documentation, checked without a database.

The other Phase 9 files check behaviour: that a window resolves, that a count is right,
that a refusal is a 404, that reading changes nothing. This one checks the two things a
future change could widen without any of those going red.

**What a client can ask.** The five routes, their methods, their whole query surface and
the bound on every parameter, read from the OpenAPI document rather than from the code —
because the document is what a client codes against. A parameter that carried a comparison
(``?compare=previous``), a judgement (``?threshold=…``) or a way around the window would
have to be declared here, and this file fails until someone writes down that they meant it.

**What a response may hold.** Every field of every monitoring response is walked and its
annotation checked against a short list: a count, a rate, a stated time, an identifier, a
value of a closed vocabulary, or one of the phase's own published shapes. ``Any``, a bare
``dict`` or a nested document fails — the trail has a metadata column and the Phase 8
listing publishes it; this lock is what keeps it out of the measurements.

**What the document promises.** ``docs/monitoring.md`` is part of the deliverable, and a
document that quietly dropped "no anomaly detection" while the code kept a straight face
would be the worst kind of drift. The last tests read it: the subjects the phase is
required to state are present, and each capability the phase *withholds* is named as
withheld — in a sentence that says so, not merely absent from a list.
"""

from __future__ import annotations

import enum
import inspect
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
from aicore_api.schemas.monitoring import (
    DenialSummaryRead,
    ExecutionHealthRead,
    MonitoringSummaryResponse,
    MonitoringWindowRead,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]  # apps/api/tests/<file> → repo
DOCUMENT = REPOSITORY_ROOT / "docs" / "monitoring.md"

#: The five endpoints, and the module each layer of the phase lives in. Five of the six are
#: named in the document's module table (``__init__.py`` re-exports and is not a subject).
MONITORING_PATHS = (
    "/organizations/{organization_id}/monitoring/summary",
    "/organizations/{organization_id}/monitoring/agents",
    "/organizations/{organization_id}/monitoring/actions",
    "/organizations/{organization_id}/monitoring/policies",
    "/organizations/{organization_id}/monitoring/trends",
)

DOCUMENTED_MODULES = (
    "core/monitoring.py",
    "db/repositories/monitoring.py",
    "monitoring/service.py",
    "schemas/monitoring.py",
    "api/routes/monitoring.py",
)

#: Every module the phase ships, including the package's own re-export.
MONITORING_MODULES = (
    "core/monitoring.py",
    "db/repositories/monitoring.py",
    "monitoring/__init__.py",
    "monitoring/service.py",
    "schemas/monitoring.py",
    "api/routes/monitoring.py",
)

#: The whole query surface of the phase, per route. ``window``/``start_time``/``end_time``
#: come from the shared window dependency and are on all five — a client chooses *which*
#: interval to measure and never what time it is.
EXPECTED_QUERY_PARAMETERS = {
    MONITORING_PATHS[0]: {"window", "start_time", "end_time"},
    MONITORING_PATHS[1]: {
        "window",
        "start_time",
        "end_time",
        "agent_id",
        "limit",
        "offset",
        "total",
    },
    MONITORING_PATHS[2]: {"window", "start_time", "end_time", "action"},
    MONITORING_PATHS[3]: {"window", "start_time", "end_time"},
    MONITORING_PATHS[4]: {"window", "start_time", "end_time", "interval"},
}

#: Words that would turn a measurement into a question about judgement or comparison. None
#: of them may name a parameter, and none may appear in a parameter's description.
UNMEASURABLE_WORDS = (
    "anomal",
    "alert",
    "baseline",
    "compare",
    "deviation",
    "expected",
    "health",
    "incident",
    "normal",
    "previous",
    "rank",
    "risk",
    "score",
    "severity",
    "threshold",
    "unusual",
)


def _monitoring_schemas() -> dict[str, type]:
    """Every published model this phase declares, keyed by name."""
    return {
        name: value
        for name in dir(schemas.monitoring)
        if name.endswith("Read") or name.endswith("Response")
        for value in (getattr(schemas.monitoring, name),)
        if inspect.isclass(value)
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
    """The document as one line, without markdown's wrapping or quote markers.

    A sentence in a 100-column markdown file is wrapped, bolded and indented; the claim it
    makes is still one claim, so a check about what the document *says* must read it that
    way instead of line by line.
    """
    return " ".join(DOCUMENT.read_text().replace(">", " ").split())


def _parameters(document: dict, path: str) -> dict[str, dict]:
    return {
        parameter["name"]: parameter for parameter in document["paths"][path]["get"]["parameters"]
    }


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
    """Six modules behind five endpoints, in one document that names each layer.

    The document is checked against the tree rather than trusted: a doc that described a
    different module split would be describing a different phase.
    """
    for relative in MONITORING_MODULES:
        module = REPOSITORY_ROOT / "apps/api/src/aicore_api" / relative
        assert module.is_file(), module
    assert DOCUMENT.is_file(), DOCUMENT

    text = DOCUMENT.read_text()
    for relative in DOCUMENTED_MODULES:
        assert relative in text, relative


def test_the_client_surface_is_five_get_routes_and_nothing_else(client: TestClient) -> None:
    """Five reads, no sixth, no verb other than GET, and no request body anywhere.

    A monitoring endpoint with a body would accept a measurement, and this phase measures;
    a ``POST`` would be a write, and this phase has none. The published document is where
    that is asserted, rather than the handler source a client never sees.
    """
    document = client.get("/openapi.json").json()
    published = {path for path in document["paths"] if "monitoring" in path}
    assert published == set(MONITORING_PATHS)

    for path in MONITORING_PATHS:
        methods = document["paths"][path]
        assert set(methods) == {"get"}, (path, set(methods))
        assert "requestBody" not in methods["get"], path

    # The document's own inventory of components must not have grown a monitoring request.
    for name in document["components"]["schemas"]:
        assert not (
            "Monitoring" in name and name.endswith(("Request", "Create", "Update", "Patch"))
        ), name


def test_the_query_surface_is_exactly_the_documented_one(client: TestClient) -> None:
    """Every parameter of every route, as a set — additions are a deliberate act.

    This is what makes "keep it small" enforceable: an endpoint that grew a comparison, a
    threshold or a second window would have to be added here first.
    """
    document = client.get("/openapi.json").json()

    for path, expected in EXPECTED_QUERY_PARAMETERS.items():
        parameters = _parameters(document, path)
        assert set(parameters) == expected | {"organization_id"}, (path, set(parameters))
        assert parameters["organization_id"]["in"] == "path"
        assert parameters["window"]["schema"]["default"] == "24h"
        for name in expected:
            assert parameters[name]["in"] == "query"

    assert {name for path, names in EXPECTED_QUERY_PARAMETERS.items() for name in names} == {
        "window",
        "start_time",
        "end_time",
        "agent_id",
        "limit",
        "offset",
        "total",
        "action",
        "interval",
    }


@pytest.mark.parametrize("word", UNMEASURABLE_WORDS)
def test_no_parameter_asks_for_a_judgement_or_a_comparison(client: TestClient, word: str) -> None:
    document = client.get("/openapi.json").json()
    for path in MONITORING_PATHS:
        for name, parameter in _parameters(document, path).items():
            assert word not in name, (path, name)
            assert word not in (parameter.get("description") or "").lower(), (path, name)


def test_every_parameter_is_bounded(client: TestClient) -> None:
    """Oversized input is refused by the declaration, not by a handler's good intentions.

    Each parameter resolves to an enumerated value, a typed identifier or timestamp, a
    boolean, or a number or string with an explicit ceiling — there is no free-form string
    and no unbounded integer in this phase's surface.
    """
    document = client.get("/openapi.json").json()
    schemas_block = document["components"]["schemas"]

    for path in MONITORING_PATHS:
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


def test_a_monitoring_response_field_holds_a_count_a_time_or_an_identifier() -> None:
    """No field of any monitoring response can carry an event, a row or a metadata document.

    Every annotation is one of a short list: a number, a rate, a stated time, a string, an
    identifier, a value of a closed vocabulary, or one of the phase's own published shapes.
    The only mappings allowed are the two counter breakdowns — ``dict[str, int]``, keyed by
    a closed vocabulary rather than by anything a caller could put in a document.
    """
    scalars = (int, float, str, bool, uuid.UUID, datetime)
    composites = {MonitoringWindowRead, ExecutionHealthRead, DenialSummaryRead}

    for name, model in _monitoring_schemas().items():
        for field, info in model.model_fields.items():
            for annotation in _declared_types(info.annotation):
                if annotation in scalars or annotation in composites:
                    continue
                if annotation is type(None):
                    continue
                if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
                    continue
                if str(annotation).startswith("dict["):
                    assert str(annotation) == "dict[str, int]", (name, field, annotation)
                    continue
                assert getattr(annotation, "model_fields", None) is not None, (
                    name,
                    field,
                    annotation,
                )

    # Exactly the two counter breakdowns are mappings, and both count integers.
    # One mapping, counting integers, keyed by a closed vocabulary. The decisions half of
    # the policy view is a published model instead — three named counts, not a dictionary
    # whose keys a writer could choose.
    mappings = {
        field: info.annotation
        for model in _monitoring_schemas().values()
        for field, info in model.model_fields.items()
        if str(info.annotation).startswith("dict[")
    }
    assert mappings == {"by_reason": dict[str, int]}


def test_the_published_ratios_are_the_only_floats_and_the_only_nullable_numbers() -> None:
    """A count is an integer and a rate is a nullable float — checked over every field.

    ``0.0`` from a missing denominator would read as "everything failed", so the nullable
    floats are exactly the two rates and nothing else is allowed to become one.
    """
    nullable_floats = {
        field
        for model in _monitoring_schemas().values()
        for field, info in model.model_fields.items()
        if info.annotation == float | None
    }
    assert nullable_floats == {"success_rate", "failure_rate"}

    # Every other field is a count, a string, an identifier, a stated time, a published
    # mapping or a published shape (inside a list, if it is a page) — so no field can hold
    # an arbitrary value, and none can hold a float that is not one of the two rates.
    for name, model in _monitoring_schemas().items():
        for field, info in model.model_fields.items():
            if field.endswith("_rate"):
                assert info.annotation == float | None, (name, field)
                continue
            for member in _declared_types(info.annotation):
                declared = inspect.isclass(member) and issubclass(member, BaseModel | enum.Enum)
                assert declared or member in (
                    int,
                    str,
                    uuid.UUID,
                    datetime,
                    dict[str, int],
                ), (name, field, member)


def test_the_summary_publishes_what_the_service_measures() -> None:
    """The headline shape, field for field.

    A metric that existed in the counter table and not in the response — or the reverse —
    would be a metric nobody can read, so the published set is stated in full.
    """
    assert set(MonitoringSummaryResponse.model_fields) == {
        "organization_id",
        "window",
        "total_events",
        "action_requests",
        "action_executions",
        "action_failures",
        "action_denials",
        "action_replays",
        "approval_required",
        "asset_creations",
        "asset_updates",
        "asset_deletions",
        "asset_discoveries",
        "agent_registrations",
        "agent_updates",
        "agent_deletions",
        "policy_creations",
        "policy_updates",
        "policy_version_publications",
        "policy_status_changes",
        "policy_deletions",
        "policy_changes",
        "active_agents",
        "active_assets",
        "execution_health",
        "denials",
    }


def test_monitoring_declares_no_permission_of_its_own() -> None:
    """The phase reuses ``audit.read`` and adds nothing to the vocabulary.

    A measurement is a sum over rows that permission already guards, so a new permission
    would either guard nothing or hand its holder the trail in aggregate — and a role that
    held it without holding ``audit.read`` would be reading history it may not read.
    """
    codes = {permission.value for permission in Permission}
    assert not [code for code in codes if "monitor" in code]
    assert Permission.AUDIT_READ.value in codes

    routes = (REPOSITORY_ROOT / "apps/api/src/aicore_api/api/routes/monitoring.py").read_text()
    assert routes.count("require_permission(Permission.AUDIT_READ)") == 1
    assert routes.count("require_permission(") == 1


#: The subjects this phase is required to state, as the words a reader would look for.
REQUIRED_SUBJECTS = (
    "window",
    "custom",
    "30 days",
    "aggregat",
    "consistency model",
    "isolation",
    "RBAC",
    "performance",
    "limitations",
    "endpoint",
)


@pytest.mark.parametrize("subject", REQUIRED_SUBJECTS)
def test_the_document_states_what_the_phase_measures(subject: str) -> None:
    assert subject.lower() in DOCUMENT.read_text().lower(), subject


#: What the phase withholds, and must say it withholds — the difference between a build
#: that does not do something and a build that does not mention it.
WITHHELD_CAPABILITIES = (
    "anomaly",
    "baseline",
    "alert",
    "incident",
    "kill switch",
    "dashboard",
    "LLM",
    "recommendation",
    "threshold",
    "score",
    "profiling",
    "containment",
    "metadata",
)

DENIALS = ("no", "not", "never", "cannot", "nothing", "neither", "without")


@pytest.mark.parametrize("capability", WITHHELD_CAPABILITIES)
def test_the_document_names_every_capability_the_phase_withholds(capability: str) -> None:
    pattern = re.compile(
        rf"\b({'|'.join(DENIALS)})\b[^.;]{{0,140}}?{re.escape(capability)}", re.IGNORECASE
    )
    assert pattern.search(_prose()), capability


def test_the_document_names_the_five_views_and_the_boundary_sentence() -> None:
    text = DOCUMENT.read_text()
    for path in MONITORING_PATHS:
        assert f"/monitoring/{path.rsplit('/', 1)[-1]}" in text, path

    boundary = (
        "MONITORING ≠ ANOMALY DETECTION ≠ INCIDENT RESPONSE ≠ AI INTELLIGENCE "
        "≠ AUTOMATED REMEDIATION"
    )
    assert boundary in _prose(), "the boundary sentence must be stated, exactly"
