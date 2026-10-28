"""Phase 10 persistence: recorded once, deduplicated, immutable, and only ever anomalies.

``anomaly_detections`` is written by one operator command and read by two endpoints. These
tests run the command against the test database, then check what it stored, that storing
again stores nothing, that the database refuses to rewrite a finding, and that its
constraints refuse every row the engine would never produce.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

import psycopg
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aicore_api.core.risk import DetectionType, EntityType, detection_fingerprint
from aicore_api.db.tenancy import bind_tenant
from monitoring_fixture import fixed_agent_id
from risk_fixture import (
    CANARY_SECRET,
    DENIED,
    RiskScene,
    count_detections,
    delete_detections,
    observed,
    steady_history,
)

AGENT = fixed_agent_id(301)
QUIET = fixed_agent_id(302)
NEW = fixed_agent_id(303)


def _seed_anomalous(risk: RiskScene) -> None:
    """AGENT: a denial spike on a novel action. QUIET: steady. NEW: no history."""
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3)
        + observed(AGENT, windows, count=6, outcome=DENIED, action="agent.rotate_keys")
        + steady_history(QUIET, windows, per_slot=3)
        + observed(QUIET, windows, count=3)
        + observed(NEW, windows, count=50, spacing=timedelta(seconds=10))
    )


def _factors(factors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Factors without absent fields: the API states them as null, storage omits them."""
    return [
        {key: value for key, value in factor.items() if value is not None} for factor in factors
    ]


def _summary(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    printed = capsys.readouterr().out.strip().splitlines()
    summary: dict[str, Any] = json.loads(printed[-1])
    return summary


# ── recording ─────────────────────────────────────────────────────────────────


def test_recording_stores_each_detection_of_each_anomalous_agent(
    risk: RiskScene, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed_anomalous(risk)
    analysis = risk.agent(AGENT)

    assert risk.record() == 0
    summary = _summary(capsys)

    assert summary["agents_analyzed"] == 3
    assert summary["insufficient_history"] == 1
    assert summary["anomalous"] == 1
    assert (
        summary["detections_found"] == summary["detections_recorded"] == len(analysis["detections"])
    )
    assert summary["truncated"] is False
    assert summary["organization_id"] == str(risk.organization_id)

    stored = risk.stored()
    assert {row["entity_id"] for row in stored} == {AGENT}
    by_type = {row["detection_type"]: row for row in stored}
    for detection in analysis["detections"]:
        row = by_type[detection["detection_type"]]
        assert row["risk_level"] == detection["risk_level"]
        assert row["evidence"] == detection["evidence"]
        assert row["risk_factors"] == _factors(detection["risk_factors"])
        assert row["fingerprint"] == detection["fingerprint"]
        assert row["analysis_status"] == "analyzed"
        assert row["anomaly_state"] == "anomalous"
        assert row["entity_type"] == "agent"
        assert row["schema_version"] == 1 and row["engine_version"] == 1
        assert row["baseline_window"] == "14d" and row["observation_window"] == "24h"
        assert row["baseline_end"] == row["observation_start"]
        assert row["observation_end"] == risk.as_of
        assert row["organization_id"] == risk.organization_id


def test_recording_twice_records_nothing_new(
    risk: RiskScene, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed_anomalous(risk)
    assert risk.record() == 0
    first = _summary(capsys)
    stored = risk.stored()

    assert risk.record() == 0
    second = _summary(capsys)

    assert first["detections_recorded"] > 0
    assert second["detections_found"] == first["detections_found"]
    assert second["detections_recorded"] == 0
    assert risk.stored() == stored  # same rows, same ids, same detected_at


def test_a_different_window_is_a_different_assessment(
    risk: RiskScene, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed_anomalous(risk)
    assert risk.record() == 0
    first = {row["fingerprint"] for row in risk.stored()}
    assert risk.record(baseline="30d") == 0
    everything = {row["fingerprint"] for row in risk.stored()}
    assert first < everything
    capsys.readouterr()


def test_fingerprints_are_the_engines(risk: RiskScene) -> None:
    _seed_anomalous(risk)
    assert risk.record() == 0
    windows = risk.windows()
    for row in risk.stored():
        assert row["fingerprint"] == detection_fingerprint(
            entity_type=EntityType.AGENT,
            entity_id=row["entity_id"],
            detection_type=DetectionType(row["detection_type"]),
            windows=windows,
        )


def test_an_empty_tenant_records_nothing(
    risk: RiskScene, capsys: pytest.CaptureFixture[str]
) -> None:
    assert risk.record() == 0
    summary = _summary(capsys)
    assert summary["agents_analyzed"] == 0 and summary["detections_recorded"] == 0
    assert risk.stored() == []


def test_the_organization_can_be_named_by_slug(
    risk: RiskScene, capsys: pytest.CaptureFixture[str]
) -> None:
    with bind_tenant(risk.organization_id), risk.engine.connect() as connection:
        slug: str = connection.execute(
            text("SELECT slug FROM aicore.organizations WHERE id = :id"),
            {"id": str(risk.organization_id)},
        ).scalar_one()
    assert risk.record(organization=slug) == 0
    assert _summary(capsys)["organization_id"] == str(risk.organization_id)


@pytest.mark.parametrize(
    ("argument", "code"),
    [
        ({"organization": "no-such-organization"}, 1),
        ({"organization": str(uuid.uuid4())}, 1),
    ],
)
def test_an_unknown_organization_is_exit_1(
    risk: RiskScene, capsys: pytest.CaptureFixture[str], argument: dict[str, Any], code: int
) -> None:
    assert risk.record(**argument) == code
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize(
    "as_of",
    [timedelta(minutes=30), timedelta(hours=5)],
    ids=["misaligned", "future"],
)
def test_an_unusable_as_of_is_exit_2(
    risk: RiskScene, capsys: pytest.CaptureFixture[str], as_of: timedelta
) -> None:
    moment = risk.as_of + as_of
    assert risk.record(as_of=moment) == 2
    assert "as_of" in capsys.readouterr().err
    assert risk.stored() == []


def test_recording_does_not_touch_the_audit_trail(
    risk: RiskScene, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed_anomalous(risk)
    before = risk.monitoring.trail_signature()
    count = risk.monitoring.trail_count()
    assert risk.record() == 0
    assert risk.monitoring.trail_signature() == before
    assert risk.monitoring.trail_count() == count
    capsys.readouterr()


def test_stored_rows_carry_no_payload(risk: RiskScene, capsys: pytest.CaptureFixture[str]) -> None:
    _seed_anomalous(risk)
    assert risk.record() == 0
    rendered = json.dumps(risk.stored(), default=str)
    assert CANARY_SECRET not in rendered
    assert "metadata" not in rendered
    capsys.readouterr()


# ── reading what was recorded ─────────────────────────────────────────────────


def test_detections_are_listed_newest_first_and_filterable(
    risk: RiskScene, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed_anomalous(risk)
    assert risk.record() == 0
    capsys.readouterr()
    stored = risk.stored()

    body = risk.detections(total="true")
    assert body["total"] == body["count"] == len(stored)
    assert {item["id"] for item in body["items"]} == {str(row["id"]) for row in stored}
    keys = [(item["detected_at"], item["id"]) for item in body["items"]]
    assert keys == sorted(keys, reverse=True)

    denial = risk.detections(detection_type="denial_rate_spike")
    assert [item["detection_type"] for item in denial["items"]] == ["denial_rate_spike"]
    high = risk.detections(risk_level="high")
    assert all(item["risk_level"] == "high" for item in high["items"])
    assert risk.detections(agent_id=str(QUIET))["items"] == []
    assert len(risk.detections(agent_id=str(AGENT))["items"]) == len(stored)
    assert risk.detections(limit=1)["count"] == 1


def test_one_detection_reads_back_whole(
    risk: RiskScene, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed_anomalous(risk)
    assert risk.record() == 0
    capsys.readouterr()
    row = risk.stored()[0]

    response = risk.get(f"detections/{row['id']}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == str(row["id"])
    assert body["evidence"] == row["evidence"]
    assert _factors(body["risk_factors"]) == row["risk_factors"]
    assert body["windows"]["baseline"] == "14d"
    assert body["windows"]["slots"] == 14
    assert body["windows"]["slot_seconds"] == 86400
    assert body["anomaly_state"] == "anomalous"


def test_an_unknown_detection_is_404(risk: RiskScene) -> None:
    response = risk.get(f"detections/{uuid.uuid4()}")
    assert response.status_code == 404


# ── the database's own guarantees ─────────────────────────────────────────────


def _valid_row(risk: RiskScene) -> dict[str, Any]:
    windows = risk.windows()
    return {
        "organization_id": str(risk.organization_id),
        "engine_version": 1,
        "entity_type": "agent",
        "entity_id": str(AGENT),
        "detection_type": "novel_action",
        "analysis_status": "analyzed",
        "anomaly_state": "anomalous",
        "risk_level": "medium",
        "baseline_window": "14d",
        "observation_window": "24h",
        "baseline_start": windows.baseline_start,
        "baseline_end": windows.baseline_end,
        "observation_start": windows.observation_start,
        "observation_end": windows.observation_end,
        "evidence": json.dumps({"engine_version": 1}),
        "risk_factors": json.dumps([{"code": "novel_action_used", "effect": "base"}]),
        "fingerprint": uuid.uuid4().hex + uuid.uuid4().hex,
    }


def _insert(risk: RiskScene, row: dict[str, Any]) -> None:
    columns = ", ".join(row)
    values = ", ".join(
        f"CAST(:{key} AS jsonb)" if key in {"evidence", "risk_factors"} else f":{key}"
        for key in row
    )
    with bind_tenant(risk.organization_id), risk.engine.begin() as connection:
        connection.execute(
            text(f"INSERT INTO aicore.anomaly_detections ({columns}) VALUES ({values})"), row
        )


def test_a_valid_row_is_accepted(risk: RiskScene) -> None:
    _insert(risk, _valid_row(risk))
    assert count_detections(risk.engine, risk.organization_id) == 1


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("risk_level", "none"),
        ("risk_level", "severe"),
        ("anomaly_state", "not_anomalous"),
        ("anomaly_state", "undetermined"),
        ("analysis_status", "insufficient_history"),
        ("detection_type", "suspicious_vibes"),
        ("entity_type", "user"),
        ("baseline_window", "90d"),
        ("observation_window", "5m"),
        ("engine_version", 99),
        ("fingerprint", "not-a-digest"),
        ("evidence", json.dumps(["not", "an", "object"])),
        ("evidence", json.dumps({"blob": "x" * 20000})),
        ("risk_factors", json.dumps([])),
        ("risk_factors", json.dumps({"code": "x"})),
    ],
)
def test_rows_the_engine_would_never_write_are_refused(
    risk: RiskScene, column: str, value: object
) -> None:
    row = _valid_row(risk)
    row[column] = value
    with pytest.raises(DBAPIError):
        _insert(risk, row)
    assert count_detections(risk.engine, risk.organization_id) == 0


def test_overlapping_windows_are_refused(risk: RiskScene) -> None:
    row = _valid_row(risk)
    row["baseline_end"] = row["observation_start"] + timedelta(hours=1)
    with pytest.raises(DBAPIError):
        _insert(risk, row)


def test_the_same_fingerprint_twice_is_refused(risk: RiskScene) -> None:
    row = _valid_row(risk)
    _insert(risk, row)
    with pytest.raises(DBAPIError):
        _insert(risk, row)
    assert count_detections(risk.engine, risk.organization_id) == 1


def test_a_recorded_detection_cannot_be_updated(
    risk: RiskScene, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed_anomalous(risk)
    assert risk.record() == 0
    capsys.readouterr()
    before = risk.stored()
    for statement in (
        "UPDATE aicore.anomaly_detections SET risk_level = 'low' WHERE organization_id = :org",
        "UPDATE aicore.anomaly_detections SET evidence = '{}'::jsonb WHERE organization_id = :org",
    ):
        with (
            pytest.raises(DBAPIError, match="immutable"),
            bind_tenant(risk.organization_id),
            risk.engine.begin() as connection,
        ):
            connection.execute(text(statement), {"org": str(risk.organization_id)})
    assert risk.stored() == before


def test_the_table_cannot_be_truncated(risk: RiskScene) -> None:
    """Straight to the database, below the application's guard: the trigger itself refuses."""
    _insert(risk, _valid_row(risk))
    raw = risk.engine.raw_connection()
    try:
        cursor = raw.cursor()
        with pytest.raises(psycopg.Error, match="immutable"):
            cursor.execute("TRUNCATE aicore.anomaly_detections")
        raw.rollback()
    finally:
        raw.close()
    assert count_detections(risk.engine, risk.organization_id) == 1


def test_a_scoped_delete_is_allowed(risk: RiskScene) -> None:
    _insert(risk, _valid_row(risk))
    assert delete_detections(risk.engine, risk.organization_id) == 1
