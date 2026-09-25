"""Phase 10 detection and risk: each rule, each level, and the evidence behind it.

Pure tests of :func:`aicore_api.core.risk.analyze_agent` over hand-built
:class:`~aicore_api.core.risk.AgentProfile` values — exactly the aggregates the repository
produces — so every threshold can be tested at, just above and just below its boundary.
No database.
"""

from __future__ import annotations

import json
import math
import re
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from aicore_api.core.risk import (
    BASE_RISK,
    DETECTION_FACTORS,
    MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_ITEMS,
    RISK_ENGINE_VERSION,
    AgentAnalysis,
    AgentProfile,
    AnalysisStatus,
    AnomalyState,
    CheckReason,
    CheckStatus,
    Detection,
    DetectionType,
    EntityType,
    FactorEffect,
    RiskError,
    RiskEvidenceError,
    RiskFactor,
    RiskFactorCode,
    RiskLevel,
    analyze_agent,
    detection_fingerprint,
    ensure_safe_evidence,
    raise_level,
    resolve_analysis_windows,
)

AGENT = uuid.UUID("00000000-0000-4000-8000-00000000000a")
OTHER = uuid.UUID("00000000-0000-4000-8000-00000000000b")
TARGET = uuid.UUID("00000000-0000-4000-8000-0000000000c1")
NOW = datetime(2026, 9, 25, 10, tzinfo=UTC)
WINDOWS = resolve_analysis_windows(baseline="14d", observation="24h", now=NOW)  # 14 slots
BASE_HOUR = 9


def _hours(**by_hour: int) -> tuple[int, ...]:
    hours = [0] * 24
    for key, count in by_hour.items():
        hours[int(key.removeprefix("h"))] = count
    return tuple(hours)


def profile(**overrides: Any) -> AgentProfile:
    """A healthy agent: 10 requests in each of 14 daily slots, one action, one target.

    Zero variance (mean 10, stddev 0), so the rate band is 10 +- 5 (the fixed floor).
    Everything executes; nothing is refused; all activity is in one UTC hour.
    """
    fields: dict[str, Any] = {
        "agent_id": AGENT,
        "baseline_requests": 140,
        "baseline_sum_squares": 100 * 14,
        "first_active_slot": 0,
        "active_slots": 14,
        "baseline_executions": 140,
        "observed_requests": 10,
        "observed_executions": 10,
        "baseline_distinct_actions": 1,
        "observed_distinct_actions": 1,
        "baseline_distinct_resources": 1,
        "observed_distinct_resources": 1,
        "baseline_hours": _hours(**{f"h{BASE_HOUR}": 140}),
        "observed_hours": _hours(**{f"h{BASE_HOUR}": 10}),
        "baseline_peak": 2,
        "observed_peak": 2,
    }
    fields.update(overrides)
    return AgentProfile(**fields)


def varied(**overrides: Any) -> AgentProfile:
    """Per-slot counts alternating 95 and 105: mean 100, stddev 5, band 100 +- 15."""
    counts = [95, 105] * 7
    fields: dict[str, Any] = {
        "baseline_requests": sum(counts),
        "baseline_sum_squares": sum(count * count for count in counts),
        "baseline_executions": sum(counts),
        "observed_requests": 100,
        "observed_executions": 100,
        "baseline_hours": _hours(**{f"h{BASE_HOUR}": sum(counts)}),
        "observed_hours": _hours(**{f"h{BASE_HOUR}": 100}),
        "baseline_peak": 30,
        "observed_peak": 30,
    }
    fields.update(overrides)
    return profile(**fields)


def detections(analysis: AgentAnalysis) -> dict[DetectionType, Detection]:
    return {detection.detection_type: detection for detection in analysis.detections}


def check(analysis: AgentAnalysis, detection_type: DetectionType) -> Any:
    return next(item for item in analysis.checks if item.detection_type is detection_type)


# ── vocabulary ────────────────────────────────────────────────────────────────


def test_the_detection_vocabulary_is_exactly_the_eight_declared_types() -> None:
    assert [item.value for item in DetectionType] == [
        "action_rate_spike",
        "action_rate_drop",
        "failure_rate_spike",
        "denial_rate_spike",
        "novel_action",
        "novel_resource",
        "unusual_time",
        "unusual_frequency",
    ]
    assert set(BASE_RISK) == set(DetectionType) == set(DETECTION_FACTORS)


def test_risk_levels_are_five_words_and_no_number() -> None:
    assert [level.value for level in RiskLevel] == ["none", "low", "medium", "high", "critical"]
    assert all(not isinstance(level.value, int) for level in RiskLevel)
    assert RiskLevel.HIGH not in BASE_RISK.values()
    assert RiskLevel.CRITICAL not in BASE_RISK.values()


def test_raise_level_caps_at_critical_and_never_raises_none() -> None:
    assert raise_level(RiskLevel.LOW, 1) is RiskLevel.MEDIUM
    assert raise_level(RiskLevel.MEDIUM, 2) is RiskLevel.CRITICAL
    assert raise_level(RiskLevel.HIGH, 5) is RiskLevel.CRITICAL
    assert raise_level(RiskLevel.NONE, 3) is RiskLevel.NONE
    with pytest.raises(ValueError):
        raise_level(RiskLevel.LOW, -1)


def test_a_healthy_agent_is_analyzed_with_every_check_reported() -> None:
    analysis = analyze_agent(profile(), WINDOWS)
    assert analysis.status is AnalysisStatus.ANALYZED
    assert analysis.anomaly_state is AnomalyState.NOT_ANOMALOUS
    assert analysis.risk_level is RiskLevel.NONE
    assert [item.detection_type for item in analysis.checks] == list(DetectionType)
    assert {item.status for item in analysis.checks} == {CheckStatus.NOT_DETECTED}


# ── ACTION_RATE_SPIKE / ACTION_RATE_DROP ──────────────────────────────────────


def test_a_spike_is_strictly_above_mean_plus_the_margin() -> None:
    assert (
        check(
            analyze_agent(profile(observed_requests=15), WINDOWS), DetectionType.ACTION_RATE_SPIKE
        ).status
        is CheckStatus.NOT_DETECTED
    )
    analysis = analyze_agent(profile(observed_requests=16), WINDOWS)
    spike = detections(analysis)[DetectionType.ACTION_RATE_SPIKE]
    assert spike.risk_level is RiskLevel.MEDIUM
    assert spike.evidence["comparison"]["method"] == "mean_stddev_fixed_floor"
    assert spike.evidence["comparison"]["threshold"] == 15.0
    assert spike.evidence["comparison"]["zero_variance"] is True
    assert spike.evidence["measurement"]["z_score"] is None  # undefined when stddev is 0


def test_zero_variance_does_not_make_a_single_extra_request_a_spike() -> None:
    """The fixed floor: a perfectly regular agent doing one more thing is not anomalous."""
    analysis = analyze_agent(profile(observed_requests=11), WINDOWS)
    assert analysis.anomaly_state is AnomalyState.NOT_ANOMALOUS


def test_an_extreme_spike_is_escalated_one_level_with_a_stated_factor() -> None:
    analysis = analyze_agent(profile(observed_requests=21), WINDOWS)
    spike = detections(analysis)[DetectionType.ACTION_RATE_SPIKE]
    assert spike.risk_level is RiskLevel.HIGH
    assert [factor.code for factor in spike.risk_factors] == [
        RiskFactorCode.ACTIVITY_SPIKE,
        RiskFactorCode.EXTREME_DEVIATION,
    ]
    assert spike.risk_factors[0].effect is FactorEffect.BASE
    assert spike.risk_factors[0].level is RiskLevel.MEDIUM
    assert spike.risk_factors[1].effect is FactorEffect.ESCALATION
    assert spike.risk_factors[1].steps == 1


def test_a_spike_against_a_varied_baseline_uses_three_sigma_and_reports_z() -> None:
    assert not analyze_agent(
        varied(observed_requests=115, observed_executions=115), WINDOWS
    ).detections
    analysis = analyze_agent(varied(observed_requests=116, observed_executions=116), WINDOWS)
    spike = detections(analysis)[DetectionType.ACTION_RATE_SPIKE]
    assert spike.evidence["comparison"]["method"] == "mean_stddev"
    assert spike.evidence["measurement"]["baseline_mean"] == 100.0
    assert spike.evidence["measurement"]["baseline_stddev"] == 5.0
    assert spike.evidence["measurement"]["z_score"] == pytest.approx(3.2)
    assert spike.risk_level is RiskLevel.MEDIUM


def test_a_drop_is_strictly_below_mean_minus_the_margin() -> None:
    assert not analyze_agent(
        varied(observed_requests=85, observed_executions=85), WINDOWS
    ).detections
    analysis = analyze_agent(varied(observed_requests=84, observed_executions=84), WINDOWS)
    drop = detections(analysis)[DetectionType.ACTION_RATE_DROP]
    assert drop.risk_level is RiskLevel.LOW
    assert drop.evidence["comparison"]["operator"] == "less_than"
    assert drop.evidence["comparison"]["threshold"] == 85.0


def test_an_extreme_drop_is_escalated() -> None:
    analysis = analyze_agent(varied(observed_requests=60, observed_executions=60), WINDOWS)
    assert detections(analysis)[DetectionType.ACTION_RATE_DROP].risk_level is RiskLevel.MEDIUM


def test_a_silent_agent_with_a_real_baseline_is_a_drop() -> None:
    analysis = analyze_agent(
        profile(
            observed_requests=0, observed_executions=0, observed_hours=(0,) * 24, observed_peak=0
        ),
        WINDOWS,
    )
    assert set(detections(analysis)) == {DetectionType.ACTION_RATE_DROP}


def test_a_drop_cannot_be_claimed_when_the_baseline_mean_is_too_small() -> None:
    """Mean 3 with a floor of 5: zero requests is an ordinary quiet slot, not a drop."""
    quiet = profile(
        baseline_requests=42,
        baseline_sum_squares=9 * 14,
        baseline_executions=42,
        observed_requests=0,
        observed_executions=0,
        observed_hours=(0,) * 24,
        observed_peak=0,
        baseline_hours=_hours(**{f"h{BASE_HOUR}": 42}),
    )
    analysis = analyze_agent(quiet, WINDOWS)
    assert analysis.anomaly_state is AnomalyState.NOT_ANOMALOUS
    drop = check(analysis, DetectionType.ACTION_RATE_DROP)
    assert drop.status is CheckStatus.INSUFFICIENT_DATA
    assert drop.reason is CheckReason.BASELINE_MEAN_BELOW_DROP_MARGIN


# ── FAILURE_RATE_SPIKE / DENIAL_RATE_SPIKE ────────────────────────────────────


def test_a_failure_share_rise_of_a_quarter_is_detected() -> None:
    analysis = analyze_agent(profile(observed_executions=7, observed_failures=3), WINDOWS)
    failure = detections(analysis)[DetectionType.FAILURE_RATE_SPIKE]
    assert failure.risk_level is RiskLevel.LOW
    measurement = failure.evidence["measurement"]
    assert measurement["baseline_share"] == 0.0
    assert measurement["observed_share"] == 0.3
    assert measurement["observed_completions"] == 10
    assert failure.evidence["comparison"]["method"] == "share_difference"


def test_a_failure_share_rise_of_half_is_extreme() -> None:
    analysis = analyze_agent(profile(observed_executions=5, observed_failures=5), WINDOWS)
    assert detections(analysis)[DetectionType.FAILURE_RATE_SPIKE].risk_level is RiskLevel.MEDIUM


def test_a_small_rise_or_too_few_failures_is_not_a_failure_spike() -> None:
    small = analyze_agent(profile(observed_executions=8, observed_failures=2), WINDOWS)
    assert DetectionType.FAILURE_RATE_SPIKE not in detections(small)
    few = analyze_agent(profile(observed_executions=3, observed_failures=2), WINDOWS)
    assert check(few, DetectionType.FAILURE_RATE_SPIKE).status is CheckStatus.NOT_DETECTED


def test_a_failure_share_needs_enough_observed_completions() -> None:
    analysis = analyze_agent(profile(observed_executions=0, observed_failures=4), WINDOWS)
    result = check(analysis, DetectionType.FAILURE_RATE_SPIKE)
    assert result.status is CheckStatus.INSUFFICIENT_DATA
    assert result.reason is CheckReason.OBSERVED_SAMPLE_BELOW_MINIMUM


def test_a_failure_share_needs_enough_baseline_completions() -> None:
    analysis = analyze_agent(
        profile(baseline_executions=9, observed_executions=0, observed_failures=10), WINDOWS
    )
    result = check(analysis, DetectionType.FAILURE_RATE_SPIKE)
    assert result.status is CheckStatus.INSUFFICIENT_DATA
    assert result.reason is CheckReason.BASELINE_SAMPLE_BELOW_MINIMUM


def test_a_denial_share_rise_is_detected_at_medium_and_extreme_at_high() -> None:
    moderate = analyze_agent(profile(observed_denials=3, observed_executions=7), WINDOWS)
    assert detections(moderate)[DetectionType.DENIAL_RATE_SPIKE].risk_level is RiskLevel.MEDIUM
    extreme = analyze_agent(profile(observed_denials=6, observed_executions=4), WINDOWS)
    denial = detections(extreme)[DetectionType.DENIAL_RATE_SPIKE]
    assert denial.risk_level is RiskLevel.HIGH
    assert denial.evidence["measurement"]["observed_share"] == 0.6
    assert denial.evidence["measurement"]["observed_requests"] == 10


def test_an_agent_that_is_always_refused_is_not_a_denial_spike() -> None:
    """A high share that is also the baseline's share is normal for this agent."""
    analysis = analyze_agent(
        profile(
            baseline_denials=140, baseline_executions=0, observed_denials=10, observed_executions=0
        ),
        WINDOWS,
    )
    assert DetectionType.DENIAL_RATE_SPIKE not in detections(analysis)


# ── NOVEL_ACTION / NOVEL_RESOURCE ─────────────────────────────────────────────


def test_an_action_the_baseline_never_requested_is_novel() -> None:
    analysis = analyze_agent(
        profile(
            observed_distinct_actions=2,
            novel_action_count=1,
            novel_actions=("agent.rotate_credentials",),
        ),
        WINDOWS,
    )
    novel = detections(analysis)[DetectionType.NOVEL_ACTION]
    assert novel.risk_level is RiskLevel.MEDIUM
    assert novel.evidence["measurement"]["novel_actions"] == ["agent.rotate_credentials"]
    assert novel.evidence["measurement"]["novel_count"] == 1
    assert novel.evidence["comparison"] == {
        "method": "set_difference",
        "operator": "not_in_baseline",
    }


def test_novelty_samples_are_sorted_and_the_count_is_not_capped() -> None:
    sample = tuple(sorted(f"agent.action_{index:02d}" for index in range(MAX_EVIDENCE_ITEMS)))
    analysis = analyze_agent(
        profile(
            observed_distinct_actions=41,
            novel_action_count=40,
            novel_actions=tuple(reversed(sample)),
        ),
        WINDOWS,
    )
    measurement = detections(analysis)[DetectionType.NOVEL_ACTION].evidence["measurement"]
    assert measurement["novel_actions"] == list(sample)
    assert measurement["novel_count"] == 40


def test_a_target_the_baseline_never_addressed_is_novel() -> None:
    reference = f"agent:{TARGET}"
    analysis = analyze_agent(
        profile(
            baseline_distinct_resources=3,
            observed_distinct_resources=2,
            novel_resource_count=1,
            novel_resources=(reference,),
        ),
        WINDOWS,
    )
    novel = detections(analysis)[DetectionType.NOVEL_RESOURCE]
    assert novel.risk_level is RiskLevel.LOW
    assert novel.evidence["measurement"]["novel_resources"] == [reference]


def test_novel_targets_are_not_claimed_for_an_agent_that_never_repeats_one() -> None:
    """If the baseline mostly touched fresh targets, a fresh target is the normal case."""
    analysis = analyze_agent(
        profile(
            baseline_distinct_resources=100,
            novel_resource_count=1,
            novel_resources=(f"agent:{TARGET}",),
            observed_distinct_resources=1,
        ),
        WINDOWS,
    )
    result = check(analysis, DetectionType.NOVEL_RESOURCE)
    assert result.status is CheckStatus.INSUFFICIENT_DATA
    assert result.reason is CheckReason.BASELINE_RESOURCE_SET_UNSTABLE
    assert DetectionType.NOVEL_RESOURCE not in detections(analysis)


# ── UNUSUAL_TIME / UNUSUAL_FREQUENCY ──────────────────────────────────────────


def test_requests_in_hours_the_baseline_never_used_are_unusual_time() -> None:
    analysis = analyze_agent(
        profile(observed_hours=_hours(**{f"h{BASE_HOUR}": 7, "h3": 3})), WINDOWS
    )
    unusual = detections(analysis)[DetectionType.UNUSUAL_TIME]
    assert unusual.risk_level is RiskLevel.LOW
    assert unusual.evidence["measurement"]["unusual_hours_utc"] == [3]
    assert unusual.evidence["measurement"]["unusual_requests"] == 3
    assert unusual.evidence["measurement"]["baseline_active_hours_utc"] == [BASE_HOUR]
    assert unusual.evidence["comparison"]["timezone"] == "utc"


def test_fewer_than_three_off_hours_requests_are_not_unusual_time() -> None:
    analysis = analyze_agent(
        profile(observed_hours=_hours(**{f"h{BASE_HOUR}": 8, "h3": 2})), WINDOWS
    )
    assert DetectionType.UNUSUAL_TIME not in detections(analysis)


def test_an_agent_active_around_the_clock_has_no_unusual_hours() -> None:
    busy_hours = tuple(10 if hour < 21 else 0 for hour in range(24))
    analysis = analyze_agent(
        profile(baseline_hours=busy_hours, observed_hours=_hours(h22=5, h23=5)), WINDOWS
    )
    result = check(analysis, DetectionType.UNUSUAL_TIME)
    assert result.status is CheckStatus.INSUFFICIENT_DATA
    assert result.reason is CheckReason.BASELINE_HOURS_SATURATED


def test_unusual_hour_lists_are_capped_but_counted() -> None:
    analysis = analyze_agent(
        profile(
            baseline_hours=_hours(h0=140),
            observed_hours=tuple(0 if hour == 0 else 1 for hour in range(24)),
            observed_requests=23,
            observed_executions=23,
        ),
        WINDOWS,
    )
    measurement = detections(analysis)[DetectionType.UNUSUAL_TIME].evidence["measurement"]
    assert len(measurement["unusual_hours_utc"]) == MAX_EVIDENCE_ITEMS
    assert measurement["unusual_hour_count"] == 23


def test_a_burst_is_double_the_baseline_peak_and_at_least_five_more() -> None:
    # baseline peak 2: threshold max(2 * 2, 2 + 5) = 7
    assert DetectionType.UNUSUAL_FREQUENCY not in detections(
        analyze_agent(profile(observed_peak=6), WINDOWS)
    )
    analysis = analyze_agent(profile(observed_peak=7), WINDOWS)
    burst = detections(analysis)[DetectionType.UNUSUAL_FREQUENCY]
    assert burst.risk_level is RiskLevel.MEDIUM
    assert burst.evidence["comparison"]["threshold"] == 7
    assert burst.evidence["measurement"]["bucket_seconds"] == 300


def test_an_extreme_burst_is_escalated() -> None:
    analysis = analyze_agent(profile(observed_peak=14), WINDOWS)
    assert detections(analysis)[DetectionType.UNUSUAL_FREQUENCY].risk_level is RiskLevel.HIGH


def test_a_busy_baseline_raises_the_burst_threshold() -> None:
    analysis = analyze_agent(varied(observed_peak=59), WINDOWS)  # threshold 60
    assert DetectionType.UNUSUAL_FREQUENCY not in detections(analysis)


# ── agent-level risk ──────────────────────────────────────────────────────────


def test_one_detection_sets_the_agent_level_to_its_own() -> None:
    analysis = analyze_agent(profile(observed_peak=7), WINDOWS)
    assert analysis.anomaly_state is AnomalyState.ANOMALOUS
    assert analysis.risk_level is RiskLevel.MEDIUM
    assert [factor.code for factor in analysis.risk_factors] == [RiskFactorCode.BURST_ACTIVITY]


def test_two_detection_types_escalate_the_agent_one_level() -> None:
    analysis = analyze_agent(
        profile(observed_peak=7, observed_hours=_hours(**{f"h{BASE_HOUR}": 7, "h3": 3})), WINDOWS
    )
    assert set(detections(analysis)) == {
        DetectionType.UNUSUAL_TIME,
        DetectionType.UNUSUAL_FREQUENCY,
    }
    assert analysis.risk_level is RiskLevel.HIGH
    breadth = analysis.risk_factors[-1]
    assert breadth.code is RiskFactorCode.MULTIPLE_DETECTION_TYPES
    assert breadth.count == 2 and breadth.steps == 1


def test_four_detection_types_escalate_twice_and_the_level_caps_at_critical() -> None:
    analysis = analyze_agent(
        profile(
            observed_requests=30,
            observed_executions=12,
            observed_denials=18,
            observed_peak=7,
            observed_hours=_hours(**{f"h{BASE_HOUR}": 27, "h3": 3}),
            novel_action_count=1,
            novel_actions=("agent.exfiltrate",),
            observed_distinct_actions=2,
        ),
        WINDOWS,
    )
    assert len(detections(analysis)) >= 4
    assert analysis.risk_level is RiskLevel.CRITICAL
    codes = [factor.code for factor in analysis.risk_factors]
    assert RiskFactorCode.MULTIPLE_DETECTION_TYPES in codes
    assert RiskFactorCode.BROAD_BEHAVIOUR_CHANGE in codes


def test_every_level_above_none_carries_factors_and_every_detection_its_own() -> None:
    analysis = analyze_agent(profile(observed_requests=21, observed_peak=14), WINDOWS)
    assert analysis.risk_level is not RiskLevel.NONE
    assert analysis.risk_factors
    for detection in analysis.detections:
        assert detection.risk_level is not RiskLevel.NONE
        assert detection.risk_factors
        assert detection.risk_factors[0].effect is FactorEffect.BASE
        assert detection.risk_factors[0].detection_type is detection.detection_type


def test_invariants_are_enforced_by_the_types() -> None:
    factor = RiskFactor(
        code=RiskFactorCode.BURST_ACTIVITY, effect=FactorEffect.BASE, level=RiskLevel.LOW
    )
    with pytest.raises(RiskError):
        Detection(DetectionType.UNUSUAL_FREQUENCY, RiskLevel.NONE, (factor,), {})
    with pytest.raises(RiskError):
        Detection(DetectionType.UNUSUAL_FREQUENCY, RiskLevel.LOW, (), {})


def test_the_analysis_is_deterministic() -> None:
    subject = profile(
        observed_requests=21, observed_peak=14, observed_denials=5, observed_executions=16
    )
    first, second = analyze_agent(subject, WINDOWS), analyze_agent(subject, WINDOWS)
    assert first == second
    rendered = [json.dumps(dict(item.evidence), sort_keys=True) for item in first.detections]
    assert rendered == [
        json.dumps(dict(item.evidence), sort_keys=True) for item in second.detections
    ]


# ── evidence ──────────────────────────────────────────────────────────────────

_INSTANT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$")


def test_evidence_has_one_shape_for_every_detection_type() -> None:
    analysis = analyze_agent(
        profile(
            observed_requests=30,
            observed_executions=12,
            observed_denials=10,
            observed_failures=8,
            observed_peak=14,
            observed_hours=_hours(**{f"h{BASE_HOUR}": 27, "h3": 3}),
            novel_action_count=1,
            novel_actions=("agent.exfiltrate",),
            observed_distinct_actions=2,
            novel_resource_count=1,
            novel_resources=(f"agent:{TARGET}",),
            observed_distinct_resources=2,
        ),
        WINDOWS,
    )
    assert len(analysis.detections) >= 6
    for detection in analysis.detections:
        evidence = detection.evidence
        assert set(evidence) == {
            "engine_version",
            "detection_type",
            "entity",
            "baseline",
            "observation",
            "measurement",
            "comparison",
            "risk_factors",
        }
        assert evidence["engine_version"] == RISK_ENGINE_VERSION
        assert evidence["detection_type"] == detection.detection_type.value
        assert evidence["entity"] == {"type": "agent", "id": str(AGENT)}
        assert set(evidence["baseline"]) == {
            "window",
            "start",
            "end",
            "slot_seconds",
            "slots",
            "history_slots",
            "active_slots",
            "requests",
        }
        assert set(evidence["observation"]) == {"window", "start", "end", "requests"}
        assert evidence["baseline"]["end"] == evidence["observation"]["start"]
        for instant in (
            evidence["baseline"]["start"],
            evidence["baseline"]["end"],
            evidence["observation"]["end"],
        ):
            assert _INSTANT.match(instant)
        assert evidence["measurement"]
        assert evidence["comparison"]["method"]
        assert evidence["risk_factors"] == [factor.as_dict() for factor in detection.risk_factors]
        assert len(json.dumps(dict(evidence)).encode()) <= MAX_EVIDENCE_BYTES


def test_evidence_is_read_only() -> None:
    evidence = detections(analyze_agent(profile(observed_peak=7), WINDOWS))[
        DetectionType.UNUSUAL_FREQUENCY
    ].evidence
    with pytest.raises(TypeError):
        evidence["measurement"] = {}  # type: ignore[index]


@pytest.mark.parametrize(
    "unsafe",
    [
        {"token": "Bearer abc.def"},
        {"arguments": '{"password": "hunter2"}'},
        {"jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"},
        {"url": "https://example.test/secret"},
        {"path": "/etc/passwd"},
        {"long": "a" * 65},
        {"Upper": 1},
        {"key with space": 1},
        {"nested": {"deep": ["ok", "NOT OK"]}},
        {"number": math.inf},
        {"number": math.nan},
        {"bytes": b"raw"},
        {"items": list(range(MAX_EVIDENCE_ITEMS + 1))},
        {f"k{index}": index * 10**12 for index in range(700)},
    ],
)
def test_unsafe_evidence_is_refused_rather_than_trimmed(unsafe: dict[str, Any]) -> None:
    with pytest.raises(RiskEvidenceError):
        ensure_safe_evidence(unsafe)


def test_safe_evidence_values_pass() -> None:
    ensure_safe_evidence(
        {
            "action": "agent.posture_check",
            "entity": str(AGENT),
            "target": f"agent:{TARGET}",
            "at": "2026-09-25T10:00:00+00:00",
            "window": "14d",
            "share": 0.25,
            "count": 3,
            "flag": True,
            "nothing": None,
            "hours": [1, 2, 3],
        }
    )


# ── fingerprints ──────────────────────────────────────────────────────────────


def _fingerprint(**overrides: Any) -> str:
    fields: dict[str, Any] = {
        "entity_type": EntityType.AGENT,
        "entity_id": AGENT,
        "detection_type": DetectionType.ACTION_RATE_SPIKE,
        "windows": WINDOWS,
    }
    fields.update(overrides)
    return detection_fingerprint(**fields)


def test_a_fingerprint_is_a_stable_sha256() -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", _fingerprint())
    assert _fingerprint() == _fingerprint()


def test_a_fingerprint_depends_on_what_was_assessed() -> None:
    later = resolve_analysis_windows(
        baseline="14d", observation="24h", as_of=datetime(2026, 9, 25, 9, tzinfo=UTC), now=NOW
    )
    variants = {
        _fingerprint(),
        _fingerprint(entity_id=OTHER),
        _fingerprint(detection_type=DetectionType.ACTION_RATE_DROP),
        _fingerprint(windows=later),
        _fingerprint(windows=resolve_analysis_windows(baseline="7d", observation="24h", now=NOW)),
        _fingerprint(windows=resolve_analysis_windows(baseline="14d", observation="6h", now=NOW)),
        _fingerprint(engine_version=RISK_ENGINE_VERSION + 1),
    }
    assert len(variants) == 7


def test_a_fingerprint_does_not_depend_on_the_measured_values() -> None:
    small = detections(analyze_agent(profile(observed_requests=16), WINDOWS))
    large = detections(analyze_agent(profile(observed_requests=500), WINDOWS))
    assert (
        small[DetectionType.ACTION_RATE_SPIKE].evidence
        != large[DetectionType.ACTION_RATE_SPIKE].evidence
    )
    assert _fingerprint() == _fingerprint()  # same entity, type and windows: same identity
