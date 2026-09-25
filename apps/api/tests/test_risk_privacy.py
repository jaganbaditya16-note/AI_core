"""An assessment carries measurements, not secrets — asserted against a canary.

Phase 10 reads the trail in aggregate, so the interesting privacy question is not "can a
client read somebody else's data" (that is the isolation suite) but "does an analytical
answer quietly carry the raw material it was computed from". A count is a count; the events
behind it may hold a payload, an argument, a metadata blob or a person's address, and none of
those may appear in a finding.

The canary makes that concrete rather than aspirational: something recognisable is written
into the agent's own recorded metadata and into a context the analysis reads, and the whole
response — live assessment, stored evidence, stored factors, the detection feed — is searched
for it. A second canary is placed in the *columns* the aggregate never selects, so a future
edit that widened a `SELECT` would fail here rather than in production.

The structural half of the file checks the shape of what is returned: the evidence document's
leaf values are scalars from a declared set of keys, and the phase's vocabulary contains none
of the words that would turn a measurement into an accusation.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator, Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from aicore_api.core.risk import RiskLevel
from risk_fixture import BASELINE_HOURS, RiskScene, declared_names

pytestmark = pytest.mark.integration

#: A string that cannot occur by accident, written into the agent's own record.
CANARY = "canary-4f1c9a2e-secret"

#: Field names that are not measurements: a payload, a credential, a document or a
#: person. Anything with one of these names in an assessment is the wrong kind of data.
FORBIDDEN_FIELDS = frozenset(
    {
        "arguments",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "document",
        "email",
        "metadata",
        "password",
        "payload",
        "secret",
        "token",
    }
)

#: Words the phase may not use about an entity. A detection is an observation, and the
#: vocabulary it is reported in must not harden into a claim about intent or compromise.
VERDICT_WORDS = (
    "compromised",
    "malicious",
    "attacker",
    "breach",
    "intrusion",
    "hacked",
    "exfiltrat",
    "incident",
    "severity",
    "alert",
)


def _walk(value: Any, *, path: str = "") -> Iterator[tuple[str, Any]]:
    """Every leaf of a JSON document, with the path it was reached by."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _walk(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk(item, path=f"{path}[{index}]")
    else:
        yield path, value


def _leaf_names(value: Any) -> set[str]:
    """The field names at the leaves of a document, without their paths or indices."""
    names = set()
    for path, _ in _walk(value):
        name = path.rsplit(".", 1)[-1]
        names.add(name.split("[", 1)[0])
    return names


def _agent_with_history(
    scene: RiskScene, *, metadata: Mapping[str, Any] | None = None
) -> uuid.UUID:
    """One agent with a week of history and, optionally, a canary in its own record."""
    record = scene.agents.register(
        display_name=f"Private Agent {uuid.uuid4().hex[:6]}",
        identity_metadata=dict(metadata or {}),
    )
    assert record is not None
    scene.seed_baseline(record.id, hours=BASELINE_HOURS, per_hour=1)
    scene.seed_observation(record.id, requests=40)
    return record.id


# ── nothing raw travels with an answer ───────────────────────────────────────


def test_an_assessment_does_not_carry_the_agents_own_metadata(risk: RiskScene) -> None:
    """The subject's recorded facts stay where they are recorded: only counts come back.

    An agent's ``identity_metadata`` is a free-form blob the organization wrote about it.
    The engine reads the trail's *aggregate* — counts, identifiers, hours — so the blob has
    no path into a finding, and this test is what keeps that true.
    """
    agent_id = _agent_with_history(risk, metadata={"instance": CANARY, "region": "private-region"})
    body = risk.assessment(agent_id)
    rendered = json.dumps(body)

    assert CANARY not in rendered
    assert "private-region" not in rendered
    assert not (FORBIDDEN_FIELDS & {name.lower() for name in _leaf_names(body)})


def test_a_recorded_detection_does_not_carry_the_agents_own_metadata(risk: RiskScene) -> None:
    """Nor through the record: the stored evidence and factors hold measurements only."""
    agent_id = _agent_with_history(risk, metadata={"instance": CANARY})
    recorded = risk.record(agent_id)
    (row,) = risk.stored()

    assert CANARY not in json.dumps(recorded, default=str)
    assert CANARY not in json.dumps(row["evidence"], default=str)
    assert CANARY not in json.dumps(row["factors"], default=str)
    assert CANARY not in json.dumps(risk.detected(), default=str)
    assert CANARY not in json.dumps(risk.assessment(agent_id), default=str)


def test_the_evidence_document_is_a_bounded_table_of_scalars(risk: RiskScene) -> None:
    """Every leaf is a number, a boolean, a string identifier or null — nothing else.

    The evidence is what a reader checks the arithmetic against, so its shape is declared:
    a fixed set of scalar keys, one level of lists, and no nested document that could be
    used as scratch space for raw events.
    """
    agent_id = _agent_with_history(risk, metadata={"instance": CANARY})
    risk.record(agent_id)
    (row,) = risk.stored()

    for name, value in _walk(row["evidence"]):
        assert value is None or isinstance(value, (bool, int, float, str)), (name, value)
        if isinstance(value, str):
            assert len(value) <= 256, (name, len(value))
    assert set(row["evidence"]) == {"observation", "baseline", "parameters", "dimensions"}
    # The declared evidence shape: the two windows, the parameters in force, and one row
    # per measured dimension. Every name here is a measurement, a threshold, a closed
    # vocabulary member or a bound — and nothing else may appear without this list moving.
    assert set(_leaf_names(row["evidence"])) <= {
        # the observation and the baseline
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
        "window",
        "hourly_buckets",
        # the parameters in force
        "deviation_multiple",
        "extreme_multiple",
        "rate_change_ratio",
        "min_baseline_buckets",
        "min_baseline_events",
        "min_ratio_samples",
        "min_observed_samples",
        "min_distinct_hours",
        "min_novel_occurrences",
        # the dimensions
        "metric",
        "status",
        "insufficiency",
        # Why a dimension could not be measured, from the closed reason vocabulary.
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
    }, "an unexpected field in the evidence is a new kind of data in a record"


def test_the_risk_tables_hold_no_column_for_raw_material() -> None:
    """The schema is the last line of defence: there is nowhere to put a payload.

    A column added later for convenience — ``raw_events``, ``arguments``, ``details`` —
    would make every claim above temporary, so the columns are asserted here, not assumed.
    """
    from sqlalchemy import inspect

    from aicore_api.db.models.anomaly_detection import AnomalyDetection

    columns = {column.name for column in inspect(AnomalyDetection).columns}
    assert columns == {
        "id",
        "organization_id",
        "detected_at",
        "entity_type",
        "entity_id",
        "status",
        "anomaly",
        "risk_level",
        "detection_type",
        "observation_start",
        "observation_end",
        "baseline_start",
        "baseline_end",
        "baseline_window",
        "schema_version",
        "evidence",
        "factors",
    }
    assert not (FORBIDDEN_FIELDS & columns)


def test_the_aggregate_never_selects_a_column_that_holds_raw_material(risk: RiskScene) -> None:
    """What the SQL *does not* read: the trail's metadata, its correlation and the reason.

    Read from the statements the repository sends rather than from the response, because
    \"the answer did not include it\" and \"the query did not fetch it\" are different
    claims — and the second is the one that keeps a future field from leaking by default.
    """
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    from aicore_api.db.repositories.risk import RiskRepository
    from aicore_api.db.session import get_engine

    agent_id = _agent_with_history(risk)
    start, end = risk.observation_window()
    statements: list[str] = []

    def _record(connection: Any, cursor: Any, statement: str, *rest: Any) -> None:
        if "audit_events" in statement:
            statements.append(" ".join(statement.split()).lower())

    engine = get_engine()
    event.listen(engine, "before_cursor_execute", _record)
    try:
        with Session(bind=engine) as session:
            # The same shape the service asks for: the baseline window, then the
            # observation window, both bounded and both tenant-scoped.
            repository = RiskRepository(session, risk.organization_id)
            repository.activity(start=start - timedelta(days=7), end=start, agent_ids=[agent_id])
            repository.activity(start=start, end=end, agent_ids=[agent_id])
    finally:
        event.remove(engine, "before_cursor_execute", _record)

    assert statements, "the aggregate read nothing, so this test proves nothing"
    for statement in statements:
        assert statement.startswith("select")
        assert "aicore.audit_events" in statement
        assert "organization_id" in statement
        assert "occurred_at" in statement
        for column in ("metadata", "correlation_id", "request_id", "reason", "actor_id"):
            assert column not in statement, (column, statement)


# ── the vocabulary stays a vocabulary of measurements ────────────────────────


def test_no_level_or_field_claims_intent(risk: RiskScene) -> None:
    """A finding says what was measured. It never says who meant it."""
    agent_id = _agent_with_history(risk)
    rendered = json.dumps(risk.record(agent_id)).lower()
    for word in VERDICT_WORDS:
        assert word not in rendered, word

    # And the levels themselves are the declared five, not an escalating verdict list.
    assert {level.value for level in RiskLevel} == {"none", "low", "medium", "high", "critical"}


def test_the_phase_source_uses_no_verdict_vocabulary() -> None:
    """The same check over the code, excluding prose.

    Docstrings are where the boundaries are *stated* — "a detection is not an incident",
    "nothing here is a claim about intent" — so the words are allowed there and nowhere
    else. What is asserted is that no identifier, enum member, field name or literal in
    the phase reaches for verdict vocabulary, because those are the names a client
    renders, a log carries and a later phase extends.
    """
    package = Path(__file__).resolve().parents[1] / "src" / "aicore_api"
    modules = (
        package / "core" / "risk.py",
        package / "risk" / "engine.py",
        package / "risk" / "service.py",
        package / "schemas" / "risk.py",
        package / "api" / "routes" / "risk.py",
        package / "db" / "repositories" / "risk.py",
        package / "db" / "models" / "anomaly_detection.py",
    )
    for module in modules:
        names = declared_names(module)
        assert names, module.name
        for name in sorted(names):
            lowered = name.lower()
            for word in VERDICT_WORDS:
                assert word not in lowered, (module.name, name, word)
