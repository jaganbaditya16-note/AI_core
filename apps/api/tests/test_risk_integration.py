"""Phase 10 against a real trail: the aggregates PostgreSQL computes, and what they mean.

Every test seeds history at exact instants (``risk_fixture``), analyses it through the
HTTP endpoint as the tenant's owner, and asserts on the explained result. The pure rules
are tested exhaustively in ``test_risk_detection.py``; these tests prove the SQL feeds them
the right numbers — windows, slots, outcomes, novelty, hours and peaks.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from actions_fixture import ACTION_ID
from monitoring_fixture import fixed_agent_id
from risk_fixture import (
    CANARY_SECRET,
    DENIED,
    FAILED,
    RiskEvent,
    RiskScene,
    observed,
    pipeline,
    steady_history,
)

AGENT = fixed_agent_id(101)
OTHER = fixed_agent_id(102)


def _types(analysis: Any) -> set[str]:
    return {detection["detection_type"] for detection in analysis["detections"]}


def _check(analysis: Any, detection_type: str) -> Any:
    return next(check for check in analysis["checks"] if check["detection_type"] == detection_type)


# ── windows and the baseline ──────────────────────────────────────────────────


def test_a_steady_agent_is_analyzed_and_not_anomalous(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(steady_history(AGENT, windows, per_slot=3) + observed(AGENT, windows, count=3))

    analysis = risk.agent(AGENT)

    assert analysis["status"] == "analyzed"
    assert analysis["anomaly_state"] == "not_anomalous"
    assert analysis["risk_level"] == "none"
    assert analysis["risk_factors"] == []
    assert analysis["detections"] == []
    stats = analysis["baseline_statistics"]
    assert stats == {
        "history_slots": 14,
        "events": 42,
        "mean": 3.0,
        "stddev": 0.0,
        "zero_variance": True,
    }
    assert analysis["observation"] == {
        "requests": 3,
        "denials": 0,
        "executions": 3,
        "failures": 0,
    }


def test_a_rate_spike_is_detected_with_evidence(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3)
        + observed(AGENT, windows, count=20, spacing=timedelta(minutes=2))
    )

    analysis = risk.agent(AGENT)

    assert analysis["status"] == "analyzed"
    assert analysis["anomaly_state"] == "anomalous"
    assert "action_rate_spike" in _types(analysis)
    spike = next(
        item for item in analysis["detections"] if item["detection_type"] == "action_rate_spike"
    )
    evidence = spike["evidence"]
    assert evidence["entity"] == {"type": "agent", "id": str(AGENT)}
    assert evidence["measurement"]["observed_requests"] == 20
    assert evidence["measurement"]["baseline_mean"] == 3.0
    assert evidence["comparison"]["threshold"] == 8.0
    assert evidence["baseline"]["end"] == evidence["observation"]["start"]
    assert CANARY_SECRET not in str(analysis)


def test_the_baseline_excludes_the_observation_and_both_ends_are_half_open(
    risk: RiskScene,
) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3)
        # exactly at observation_start: observation, never baseline
        + pipeline(AGENT, windows.observation_start)
        # exactly at as_of: the next analysis's observation, not this one's
        + pipeline(AGENT, windows.observation_end)
        # one second before the baseline starts: outside the analysis entirely
        + pipeline(AGENT, windows.baseline_start - timedelta(seconds=1))
    )

    analysis = risk.agent(AGENT)

    assert analysis["baseline_statistics"]["events"] == 42
    assert analysis["baseline_statistics"]["history_slots"] == 14
    assert analysis["observation"]["requests"] == 1
    assert analysis["behaviour"]["baseline_requests"] == 42


def test_the_response_states_the_windows_it_compared(risk: RiskScene) -> None:
    windows = risk.windows("7d", "6h")
    body = risk.analysis(baseline="7d", observation="6h")
    stated = body["windows"]
    assert stated["baseline"] == "7d" and stated["observation"] == "6h"
    assert stated["slot_seconds"] == 6 * 3600
    for key in ("baseline_start", "baseline_end", "observation_start", "observation_end"):
        assert datetime.fromisoformat(stated[key]) == getattr(windows, key)
    assert body["windows"]["baseline_end"] == body["windows"]["observation_start"]
    assert body["windows"]["slots"] == 28
    assert body["engine_version"] == 1


def test_hourly_slots_over_seven_days(risk: RiskScene) -> None:
    windows = risk.windows("7d", "1h")
    risk.seed(
        steady_history(AGENT, windows, per_slot=1, offset=timedelta(minutes=30))
        + observed(AGENT, windows, count=1, offset=timedelta(minutes=30))
    )
    analysis = risk.agent(AGENT, baseline="7d", observation="1h")
    assert analysis["status"] == "analyzed"
    assert analysis["baseline_statistics"]["history_slots"] == 168
    assert analysis["baseline_statistics"]["mean"] == 1.0
    assert analysis["behaviour"]["baseline_active_hours_utc"] == 24
    assert analysis["anomaly_state"] == "not_anomalous"


# ── cold start ────────────────────────────────────────────────────────────────


def test_an_agent_seen_only_in_the_observation_is_insufficient_history(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(observed(AGENT, windows, count=40, spacing=timedelta(seconds=30)))

    analysis = risk.agent(AGENT)

    assert analysis["status"] == "insufficient_history"
    assert analysis["anomaly_state"] == "undetermined"
    assert analysis["risk_level"] == "none"
    assert analysis["risk_factors"] == []
    assert analysis["detections"] == []
    assert analysis["baseline_statistics"] is None
    assert analysis["insufficient_reasons"] == ["no_baseline_activity"]
    assert {check["status"] for check in analysis["checks"]} == {"not_evaluated"}
    assert analysis["observation"]["requests"] == 40


def test_an_agent_with_two_days_of_history_is_insufficient(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=15, first_slot=12, spacing=timedelta(minutes=3))
        + observed(AGENT, windows, count=40, spacing=timedelta(seconds=30))
    )
    analysis = risk.agent(AGENT)
    assert analysis["status"] == "insufficient_history"
    assert analysis["insufficient_reasons"] == [
        "history_span_below_minimum",
        "active_slots_below_minimum",
    ]


def test_history_is_measured_from_first_activity(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3, first_slot=4) + observed(AGENT, windows, count=3)
    )
    analysis = risk.agent(AGENT)
    assert analysis["status"] == "analyzed"
    assert analysis["baseline_statistics"]["history_slots"] == 10
    assert analysis["baseline_statistics"]["zero_variance"] is True
    assert analysis["anomaly_state"] == "not_anomalous"


def test_sparse_history_counts_empty_slots_as_zero(risk: RiskScene) -> None:
    windows = risk.windows()
    events = []
    for slot in (0, 5, 10):
        start = windows.baseline_start + slot * windows.slot
        events += [
            event
            for index in range(8)
            for event in pipeline(AGENT, start + timedelta(minutes=10 + 6 * index))
        ]
    risk.seed(events)

    analysis = risk.agent(AGENT)

    stats = analysis["baseline_statistics"]
    assert analysis["status"] == "analyzed"
    assert stats["history_slots"] == 14 and stats["events"] == 24
    assert stats["mean"] == round(24 / 14, 6)
    assert stats["zero_variance"] is False
    drop = _check(analysis, "action_rate_drop")
    assert drop == {
        "detection_type": "action_rate_drop",
        "status": "insufficient_data",
        "reason": "baseline_mean_below_drop_margin",
    }
    assert analysis["anomaly_state"] == "not_anomalous"


# ── each detection type, from real rows ───────────────────────────────────────


def test_a_rate_drop(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=10, spacing=timedelta(minutes=5))
        + observed(AGENT, windows, count=2)
    )
    analysis = risk.agent(AGENT)
    assert _types(analysis) == {"action_rate_drop"}
    assert analysis["risk_level"] == "low"


def test_a_failure_rate_spike(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3)
        + observed(AGENT, windows, count=6, outcome=FAILED)
    )
    analysis = risk.agent(AGENT)
    assert _types(analysis) == {"failure_rate_spike"}
    detection = analysis["detections"][0]
    assert detection["risk_level"] == "medium"  # a rise of 1.0: extreme
    assert detection["evidence"]["measurement"]["observed_failures"] == 6
    assert detection["evidence"]["measurement"]["baseline_completions"] == 42
    assert analysis["observation"]["failures"] == 6


def test_a_denial_rate_spike(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3)
        + observed(AGENT, windows, count=6, outcome=DENIED)
    )
    analysis = risk.agent(AGENT)
    assert _types(analysis) == {"denial_rate_spike"}
    assert analysis["risk_level"] == "high"
    assert analysis["observation"]["denials"] == 6
    assert _check(analysis, "failure_rate_spike")["reason"] == "observed_sample_below_minimum"


def test_a_novel_action(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3)
        + observed(AGENT, windows, count=3, action="agent.rotate_keys")
    )
    analysis = risk.agent(AGENT)
    assert _types(analysis) == {"novel_action"}
    measurement = analysis["detections"][0]["evidence"]["measurement"]
    assert measurement["novel_actions"] == ["agent.rotate_keys"]
    assert measurement["baseline_distinct_actions"] == 1
    assert measurement["observed_distinct_actions"] == 1
    assert analysis["behaviour"]["novel_action_count"] == 1


def test_a_novel_resource(risk: RiskScene) -> None:
    windows = risk.windows()
    usual, fresh = uuid.uuid4(), uuid.uuid4()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3, resource_id=usual)
        + observed(AGENT, windows, count=3, resource_id=fresh)
    )
    analysis = risk.agent(AGENT)
    assert _types(analysis) == {"novel_resource"}
    measurement = analysis["detections"][0]["evidence"]["measurement"]
    assert measurement["novel_resources"] == [f"agent:{fresh}"]
    assert analysis["behaviour"]["baseline_distinct_resources"] == 1


def test_many_novel_targets_are_counted_and_sampled_in_order(risk: RiskScene) -> None:
    windows = risk.windows()
    usual = uuid.uuid4()
    fresh = sorted((uuid.uuid4() for _ in range(20)), key=str)
    events = steady_history(AGENT, windows, per_slot=3, resource_id=usual)
    for index, target in enumerate(fresh):
        events += pipeline(
            AGENT, windows.observation_start + timedelta(minutes=10 + index), resource_id=target
        )
    risk.seed(events)
    analysis = risk.agent(AGENT)
    novel = next(d for d in analysis["detections"] if d["detection_type"] == "novel_resource")
    assert novel["evidence"]["measurement"]["novel_count"] == 20
    assert novel["evidence"]["measurement"]["novel_resources"] == [
        f"agent:{target}" for target in fresh[:16]
    ]


def test_unusual_time(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3)
        + observed(AGENT, windows, count=3, offset=timedelta(hours=10))
    )
    analysis = risk.agent(AGENT)
    assert _types(analysis) == {"unusual_time"}
    measurement = analysis["detections"][0]["evidence"]["measurement"]
    expected_hour = (windows.observation_start + timedelta(hours=10)).hour
    assert measurement["unusual_hours_utc"] == [expected_hour]
    assert measurement["baseline_active_hours_utc"] == [windows.observation_start.hour]


def test_unusual_frequency(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3)
        + observed(AGENT, windows, count=8, spacing=timedelta(seconds=20))
    )
    analysis = risk.agent(AGENT)
    assert _types(analysis) == {"unusual_frequency"}
    measurement = analysis["detections"][0]["evidence"]["measurement"]
    assert measurement == {
        "observed_peak_requests": 8,
        "baseline_peak_requests": 1,
        "bucket_seconds": 300,
    }


def test_several_types_escalate_the_agent_with_stated_factors(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3)
        + observed(
            AGENT,
            windows,
            count=30,
            outcome=DENIED,
            action="agent.rotate_keys",
            spacing=timedelta(seconds=20),
        )
    )
    analysis = risk.agent(AGENT)
    assert {
        "action_rate_spike",
        "denial_rate_spike",
        "novel_action",
        "unusual_frequency",
    } <= _types(analysis)
    assert analysis["risk_level"] == "critical"
    codes = [factor["code"] for factor in analysis["risk_factors"]]
    assert "multiple_detection_types" in codes and "broad_behaviour_change" in codes


# ── what the engine counts, and what it does not ─────────────────────────────


def test_replays_and_approval_holds_are_neither_denials_nor_failures(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3)
        + observed(AGENT, windows, count=3, outcome="action.replayed")
        + observed(
            AGENT, windows, count=3, outcome="action.require_approval", offset=timedelta(minutes=40)
        )
    )
    analysis = risk.agent(AGENT)
    assert analysis["observation"] == {"requests": 6, "denials": 0, "executions": 0, "failures": 0}


def test_unattributed_requests_and_lifecycle_events_are_not_agent_behaviour(
    risk: RiskScene,
) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3)
        + observed(AGENT, windows, count=3)
        + [
            RiskEvent("action.requested", windows.observation_start + timedelta(minutes=n), None)
            for n in range(20)
        ]
    )
    body = risk.analysis(total="true")
    assert body["total"] == 1
    assert body["items"][0]["observation"]["requests"] == 3


def test_agents_are_paged_by_identifier_with_a_total(risk: RiskScene) -> None:
    windows = risk.windows()
    agents = sorted((fixed_agent_id(200 + index) for index in range(3)), key=str)
    events = []
    for agent in agents:
        events += steady_history(agent, windows, per_slot=3) + observed(agent, windows, count=3)
    risk.seed(events)

    first = risk.analysis(limit=2, total="true")
    second = risk.analysis(limit=2, offset=2, total="true")

    assert [item["agent_id"] for item in first["items"]] == [str(agent) for agent in agents[:2]]
    assert [item["agent_id"] for item in second["items"]] == [str(agents[2])]
    assert first["total"] == second["total"] == 3
    assert first["count"] == 2 and second["count"] == 1


def test_behaviour_summarises_actions_targets_hours_and_peaks(risk: RiskScene) -> None:
    windows = risk.windows()
    target = uuid.uuid4()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3, resource_id=target)
        + steady_history(
            AGENT, windows, per_slot=1, action="agent.inventory", offset=timedelta(hours=2)
        )
        + observed(AGENT, windows, count=3, resource_id=target)
    )
    behaviour = risk.agent(AGENT)["behaviour"]
    assert behaviour["baseline_distinct_actions"] == 2
    assert behaviour["observed_distinct_actions"] == 1
    assert behaviour["baseline_distinct_resources"] == 1
    assert behaviour["baseline_active_hours_utc"] == 2
    assert behaviour["observed_active_hours_utc"] == 1
    assert behaviour["baseline_peak_requests"] == 1
    assert behaviour["baseline_active_slots"] == 14


def test_an_empty_tenant_analyses_to_an_empty_page(risk: RiskScene) -> None:
    body = risk.analysis(total="true")
    assert body["items"] == [] and body["count"] == 0 and body["total"] == 0


def test_the_canary_in_metadata_never_surfaces(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(
        steady_history(AGENT, windows, per_slot=3)
        + observed(AGENT, windows, count=30, outcome=DENIED, action="agent.rotate_keys")
    )
    body = risk.analysis()
    rendered = str(body)
    assert body["items"][0]["detections"]
    assert CANARY_SECRET not in rendered
    assert "seeded" not in rendered  # the metadata's other value
    assert "metadata" not in rendered
    assert ACTION_ID in rendered or "agent.rotate_keys" in rendered
