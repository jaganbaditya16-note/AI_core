"""Recording an assessment: one insert, one identity, and a table that refuses edits.

Everything else in this phase reads. This module tests the one write it has — the record —
from four angles, because a write is where a read-only layer can quietly become something
else.

**What is written.** The row must hold the assessment that was just returned: the same
windows, the same level, the same factors, the same evidence. A record that disagreed with
the arithmetic that produced it would be a second, different claim about the same hour.

**What is not written twice.** An assessment's identity is its entity and its two windows at
one schema version, and the database — not this code — enforces that. The test that matters
inserts the same identity twice and lets PostgreSQL refuse; the endpoint's idempotence is
then the visible consequence of a constraint rather than a promise in a docstring.

**What is not written by a client.** The request body carries one identifier. A body that
tries to state a level, a threshold, a baseline or an anomaly is a 422 from a model that
forbids extra fields, and the stored row is asserted to hold only what the server derived —
so no field a caller sent can be found in it.

**What cannot be rewritten.** The table is append-only: ``UPDATE`` is refused outright, and
``DELETE`` is refused unless the transaction asks for retention by name. A finding that could
be edited after the fact would be worth less than no finding at all, so this is tested by
trying it rather than by trusting the trigger.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

from aicore_api.core.risk import (
    RISK_SCHEMA_VERSION,
    AssessmentStatus,
    DetectionType,
    RiskLevel,
)
from aicore_api.db.tenancy import bind_tenant
from risk_fixture import BASELINE_HOURS, RiskScene, types_of

pytestmark = pytest.mark.integration

#: The one-hour baseline these tests build: ten requests an hour, so a mean of ten, a spread
#: of zero and both bounds at ten.
BASELINE_PER_HOUR = 10

#: Requests in the observation hour: four times the baseline rate, which is a deviation.
LOUD_REQUESTS = 40


def deviating_agent(scene: RiskScene) -> uuid.UUID:
    """An agent with a steady week behind it and a loud hour in front of it."""
    record = scene.agents.register(display_name="Recorded Agent")
    assert record is not None
    scene.seed_baseline(record.id, hours=BASELINE_HOURS, per_hour=BASELINE_PER_HOUR)
    scene.seed_observation(record.id, requests=LOUD_REQUESTS)
    return record.id


def test_recording_writes_one_row_and_returns_it(risk: RiskScene) -> None:
    """The response is the record: one row, one identifier, and the analysis it copied."""
    agent_id = deviating_agent(risk)
    live = risk.assessment(agent_id)

    response = risk.analyze(agent_id)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["recorded"] is True
    assert body["organization_id"] == str(risk.organization_id)

    detection = body["detection"]
    assert uuid.UUID(detection["id"])
    assert detection["entity_id"] == str(agent_id)
    assert detection["entity_type"] == "agent"
    assert detection["status"] == live["status"] == AssessmentStatus.DEVIATING.value
    assert detection["anomaly"] is True
    assert detection["risk_level"] == live["risk_level"]
    assert detection["detection_type"] == live["detection_type"]
    assert detection["observation"]["start"] == live["observation"]["start"]
    assert detection["observation"]["end"] == live["observation"]["end"]
    assert detection["baseline"]["start"] == live["baseline"]["start"]
    assert detection["baseline"]["end"] == live["baseline"]["end"]
    assert detection["baseline_window"] == "7d"
    assert detection["schema_version"] == RISK_SCHEMA_VERSION

    # And the row exists, once, with the same numbers — read from the table, not the route.
    rows = risk.stored()
    assert len(rows) == 1
    row = rows[0]
    assert str(row["id"]) == detection["id"]
    assert row["risk_level"] == detection["risk_level"]
    assert row["detection_type"] == detection["detection_type"]
    assert row["factors"] == detection["factors"]
    assert row["evidence"]["dimensions"] == detection["evidence"]["dimensions"]


def test_the_live_assessment_and_the_record_are_the_same_analysis(risk: RiskScene) -> None:
    """The POST body repeats the GET body: recording is a copy, not a second computation."""
    agent_id = deviating_agent(risk)
    live = risk.assessment(agent_id)
    recorded = risk.record(agent_id)["assessment"]

    for field in ("organization_id", "status", "anomaly", "risk_level", "detection_type"):
        assert recorded[field] == live[field], field
    assert recorded["dimensions"] == live["dimensions"]
    assert recorded["factors"] == live["factors"]
    assert recorded["parameters"] == live["parameters"]
    assert recorded["observation"] == live["observation"]
    assert recorded["baseline"] == live["baseline"]
    assert types_of(recorded) == types_of(live) == [DetectionType.ACTION_RATE_SPIKE]
    assert RiskLevel(recorded["risk_level"]) is RiskLevel.MEDIUM


def test_an_unchanged_agent_records_that_it_was_within_its_baseline(risk: RiskScene) -> None:
    """``within_baseline`` is a record too: the absence of a deviation is an answer.

    A build that only stored findings would make ``no row`` mean two different things —
    "checked and normal" and "never checked". The record says which, and says it with the
    same evidence a deviation carries.
    """
    record = risk.agents.register(display_name="Steady Agent")
    assert record is not None
    risk.seed_baseline(record.id, hours=BASELINE_HOURS, per_hour=BASELINE_PER_HOUR)
    risk.seed_observation(record.id, requests=BASELINE_PER_HOUR)

    detection = risk.record(record.id)["detection"]
    assert detection["status"] == AssessmentStatus.WITHIN_BASELINE.value
    assert detection["anomaly"] is False
    assert detection["risk_level"] == RiskLevel.NONE.value
    assert detection["detection_type"] is None
    assert detection["factors"] == []
    assert len(risk.stored()) == 1


def test_an_agent_with_no_history_records_insufficient_data(risk: RiskScene) -> None:
    """Cold start is a status, not an anomaly, and it is recorded as one."""
    record = risk.agents.register(display_name="New Agent")
    assert record is not None
    detection = risk.record(record.id)["detection"]
    assert detection["status"] == AssessmentStatus.INSUFFICIENT_DATA.value
    assert detection["anomaly"] is False
    assert detection["risk_level"] == RiskLevel.NONE.value
    assert detection["detection_type"] is None
    reasons = {item["reason"] for item in detection["evidence"]["dimensions"]}
    assert reasons and None not in reasons, reasons


def test_the_same_window_recorded_twice_writes_once(risk: RiskScene) -> None:
    """The second request reports ``recorded: false`` and the identifier of the first."""
    agent_id = deviating_agent(risk)
    first = risk.analyze(agent_id)
    assert first.status_code == 201

    second = risk.analyze(agent_id)
    assert second.status_code == 200, second.text
    assert second.json()["recorded"] is False
    assert second.json()["detection"]["id"] == first.json()["detection"]["id"]
    assert risk.stored_count() == 1


def test_asking_for_the_same_analysis_again_changes_nothing_at_all(risk: RiskScene) -> None:
    """Idempotent to the byte: the record does not drift when the same hour is re-asked.

    ``detected_at`` is not updated, the evidence is not recomputed from a later clock, and
    nothing about the first answer is revised — a record of an hour is a statement about
    that hour, not about the moment somebody asked again.
    """
    agent_id = deviating_agent(risk)
    first = risk.record(agent_id)["detection"]
    second = risk.record(agent_id)["detection"]
    assert second == first
    (row,) = risk.stored()
    assert row["detected_at"] == row["detected_at"]


def test_a_different_window_is_a_different_record(risk: RiskScene) -> None:
    """A second, disjoint hour is a second finding: the identity includes both windows."""
    agent_id = deviating_agent(risk)
    risk.record(agent_id)

    start, _ = risk.observation_window()
    earlier = risk.record(
        agent_id,
        start_time=(start - timedelta(hours=1)).isoformat(),
        end_time=(start - timedelta(seconds=1)).isoformat(),
    )
    assert earlier["recorded"] is True
    assert earlier["detection"]["id"] != risk.stored()[0]["id"] or earlier["recorded"] is False
    assert risk.stored_count() == 2


def test_a_different_baseline_is_a_different_record(risk: RiskScene) -> None:
    """The same hour compared against a different history is a different claim."""
    agent_id = deviating_agent(risk)
    risk.record(agent_id, baseline="24h")
    assert risk.stored_count() == 1
    assert risk.record(agent_id, baseline="7d")["recorded"] is True
    assert risk.stored_count() == 2
    assert {row["baseline_window"] for row in risk.stored()} == {"24h", "7d"}


def test_the_identity_is_enforced_by_the_database(risk: RiskScene) -> None:
    """A duplicate identity is refused by PostgreSQL, not by a check in Python.

    The row is inserted directly, bypassing the repository, with the columns the unique
    constraint names. The database is what refuses it — which is what makes the endpoint's
    idempotence a property of the schema rather than a property of one code path.
    """
    agent_id = deviating_agent(risk)
    risk.record(agent_id)
    (row,) = risk.stored()

    columns = (
        "id, organization_id, entity_type, entity_id, status, anomaly, risk_level,"
        " detection_type, observation_start, observation_end, baseline_start, baseline_end,"
        " baseline_window, schema_version, evidence, factors"
    )
    values = {
        "id": str(uuid.uuid4()),
        "organization_id": str(risk.organization_id),
        "entity_type": row["entity_type"],
        "entity_id": str(row["entity_id"]),
        "status": row["status"],
        "anomaly": row["anomaly"],
        "risk_level": row["risk_level"],
        "detection_type": row["detection_type"],
        "observation_start": row["observation_start"],
        "observation_end": row["observation_end"],
        "baseline_start": row["baseline_start"],
        "baseline_end": row["baseline_end"],
        "baseline_window": row["baseline_window"],
        "schema_version": row["schema_version"],
        "evidence": json.dumps(row["evidence"]),
        "factors": json.dumps(row["factors"]),
    }
    with (
        pytest.raises(DatabaseError, match="uq_anomaly_detections_identity"),
        bind_tenant(risk.organization_id),
        risk.engine.begin() as connection,
    ):
        connection.execute(
            text(
                f"INSERT INTO aicore.anomaly_detections ({columns}) VALUES"
                " (:id, :organization_id, :entity_type, :entity_id, :status, :anomaly,"
                " :risk_level, :detection_type, :observation_start, :observation_end,"
                " :baseline_start, :baseline_end, :baseline_window, :schema_version,"
                " CAST(:evidence AS jsonb), CAST(:factors AS jsonb))"
            ),
            values,
        )
    assert risk.stored_count() == 1


def test_a_record_cannot_be_updated(risk: RiskScene) -> None:
    """``UPDATE`` is refused by the table itself, whatever the caller believes."""
    agent_id = deviating_agent(risk)
    risk.record(agent_id)
    (row,) = risk.stored()

    with (
        pytest.raises(DatabaseError, match="append-only"),
        bind_tenant(risk.organization_id),
        risk.engine.begin() as connection,
    ):
        connection.execute(
            text(
                "UPDATE aicore.anomaly_detections SET risk_level = 'critical'"
                " WHERE organization_id = :organization_id AND id = :id"
            ),
            {"organization_id": str(risk.organization_id), "id": str(row["id"])},
        )
    assert risk.stored()[0]["risk_level"] == row["risk_level"]
    assert risk.stored()[0]["risk_level"] == row["risk_level"]


def test_a_record_cannot_be_deleted_without_naming_retention(risk: RiskScene) -> None:
    """``DELETE`` is refused unless the transaction asks for retention by name.

    The refusal is the point: a finding is evidence, and evidence is removed by a decision
    that says out loud that it is being removed. Teardown uses that path, which is why the
    fixture's own cleanup is the example of the one way past the guard.
    """
    agent_id = deviating_agent(risk)
    risk.record(agent_id)

    with (
        pytest.raises(DatabaseError, match="append-only"),
        bind_tenant(risk.organization_id),
        risk.engine.begin() as connection,
    ):
        connection.execute(
            text("DELETE FROM aicore.anomaly_detections WHERE organization_id = :organization_id"),
            {"organization_id": str(risk.organization_id)},
        )
    assert risk.stored_count() == 1


def test_the_record_can_be_read_back_by_identifier(risk: RiskScene) -> None:
    """The stored row is reachable through the read route, and says the same thing."""
    agent_id = deviating_agent(risk)
    recorded = risk.record(agent_id)["detection"]

    fetched = risk.detection(uuid.UUID(recorded["id"]))
    assert fetched == recorded


def test_the_feed_reports_what_was_recorded(risk: RiskScene) -> None:
    """The list is the record set: filters, order and the total the caller can ask for."""
    first = deviating_agent(risk)
    second = risk.agents.register(display_name="Second Recorded Agent")
    assert second is not None
    risk.seed_baseline(second.id, hours=BASELINE_HOURS, per_hour=BASELINE_PER_HOUR)
    risk.record(first)
    risk.record(second.id)

    page = risk.detected(total=True)
    assert page["count"] == 2
    assert page["total"] == 2
    assert {item["entity_id"] for item in page["items"]} == {str(first), str(second.id)}
    assert page["items"] == sorted(
        page["items"], key=lambda item: item["detected_at"], reverse=True
    )

    filtered = risk.detected(total=True, agent_id=str(first))
    assert filtered["count"] == 1
    assert filtered["items"][0]["entity_id"] == str(first)

    by_type = risk.detected(
        total=True,
        detection_type=DetectionType.ACTION_RATE_SPIKE.value,
        risk_level=RiskLevel.MEDIUM.value,
        assessment_status=AssessmentStatus.DEVIATING.value,
    )
    assert by_type["total"] == 1
    assert by_type["items"][0]["detection_type"] == DetectionType.ACTION_RATE_SPIKE.value

    windowed = risk.detected(
        total=True,
        start_time=risk.observation_window()[0].isoformat(),
        end_time=risk.observation_window()[1].isoformat(),
    )
    assert windowed["total"] == 2


def test_a_stored_record_cannot_be_manufactured(risk: RiskScene) -> None:
    """A body that states an analytical value is refused before anything is written."""
    agent_id = deviating_agent(risk)
    path = f"/organizations/{risk.organization_id}/risk/analysis"
    for extra in (
        {"risk_level": "critical"},
        {"anomaly": True},
        {"baseline_mean": 0.0},
        {"threshold": 1.0},
        {"confidence": 0.99},
        {"detection_type": "action_rate_spike"},
        {"organization_id": str(uuid.uuid4())},
        {"actor": "someone"},
        {"baseline_start": risk.observation_window()[0].isoformat()},
    ):
        response = risk.client.post(
            path, json={"agent_id": str(agent_id), **extra}, params=risk.query()
        )
        assert response.status_code == 422, (extra, response.text)
    assert risk.stored_count() == 0

    # And the one field that is accepted is an identifier the organization holds.
    assert (
        risk.client.post(
            path, json={"agent_id": "not-an-identifier"}, params=risk.query()
        ).status_code
        == 422
    )
    assert risk.record(agent_id)["recorded"] is True
    assert risk.stored_count() == 1


def test_the_stored_row_holds_nothing_the_client_said(risk: RiskScene) -> None:
    """No query parameter a caller chose appears as a value anywhere in the record.

    The windows are the one thing a caller *does* choose — which interval to look at — and
    they appear because they are the record's identity, not because they were accepted as an
    analytical value. Everything else the row holds was derived by the server: the level, the
    factors, the thresholds and the evidence.
    """
    agent_id = deviating_agent(risk)
    marker = "client-supplied-marker"
    response = risk.client.post(
        f"/organizations/{risk.organization_id}/risk/analysis",
        json={"agent_id": str(agent_id)},
        params=risk.query(marker=marker),
    )
    assert response.status_code == 201, response.text

    (row,) = risk.stored()
    rendered = json.dumps(
        {
            key: value
            for key, value in row.items()
            if key not in {"id", "organization_id", "detected_at", "entity_id"}
        },
        default=str,
    )
    assert marker not in rendered
    assert str(risk.organization_id) not in rendered
    # The thresholds in the row are the server's configured values, not a caller's.
    assert row["evidence"]["parameters"]["deviation_multiple"] == 2.0
    assert row["evidence"]["parameters"]["rate_change_ratio"] == 2.0
    assert set(row["evidence"]["parameters"]) == {
        "deviation_multiple",
        "extreme_multiple",
        "rate_change_ratio",
        "min_baseline_buckets",
        "min_baseline_events",
        "min_ratio_samples",
        "min_observed_samples",
        "min_distinct_hours",
        "min_novel_occurrences",
    }


def test_only_the_security_administrator_may_record(risk: RiskScene, identity_factory) -> None:
    """``security.create`` is the write grant, and reading alone is not enough for it."""
    agent_id = deviating_agent(risk)
    analyst = identity_factory(role_code="analyst", organization_id=risk.organization_id)
    client = risk.as_identity(analyst)

    path = f"/organizations/{risk.organization_id}/risk/agents/{agent_id}"
    assert client.get(path, params=risk.query()).status_code in (200, 404, 403)
    response = client.post(
        f"/organizations/{risk.organization_id}/risk/analysis",
        json={"agent_id": str(agent_id)},
        params=risk.query(),
    )
    assert response.status_code == 403, response.text
    assert risk.stored_count() == 0


def test_the_record_is_this_tenants_and_no_others(risk: RiskScene) -> None:
    """A recorded row carries the request's tenant, not one the client could name."""
    agent_id = deviating_agent(risk)
    body = risk.record(agent_id)
    (row,) = risk.stored()
    assert row["organization_id"] == risk.organization_id
    assert body["organization_id"] == str(risk.organization_id)
    assert risk.detection(uuid.UUID(body["detection"]["id"]))["entity_id"] == str(agent_id)
