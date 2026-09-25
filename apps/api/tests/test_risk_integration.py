"""The risk engine over a real trail: known history in, stated arithmetic out.

The rest of the suite asks whether the phase behaves; this file asks whether it *adds up*.
A week of hourly buckets is seeded with counts a test can multiply in its head — ten
requests an hour, seven executions, one failure, two denials, one approval — and then one
hour is seeded differently. Every dimension the engine reports is asserted against that
arithmetic: the mean, the population spread, both bounds, the rate, the two sample counts,
and which of the six dimensions fired and which did not. Nothing in the response is taken on
trust, and nothing is random: the dataset is stated in the test, so a change in the engine
shows up as a changed number rather than as a passing suite.

The second half is about the *shape* of the queries: how many statements a view sends, that
each is a tenant-scoped, window-bounded ``SELECT`` over the trail, that the count does not
grow with the number of agents assessed, and that the one write is a single insert into one
table. Those are the claims behind "bounded PostgreSQL aggregation" — asserted where they
happen, in the SQL, rather than inferred from a response time.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, event

from aicore_api.core.risk import (
    AssessmentStatus,
    DetectionType,
    RiskLevel,
    RiskMetric,
)
from aicore_api.db.session import get_engine
from monitoring_fixture import SeededEvent
from risk_fixture import BASELINE_HOURS, RiskScene, level_of, types_of

pytestmark = pytest.mark.integration

#: The known week: one identical hour, repeated 168 times. The mean of a rate is therefore
#: the count itself and the population spread is zero, so both bounds are the mean — which
#: makes every assertion below a statement about two numbers rather than about a distribution.
BASELINE_REQUESTS = 10
BASELINE_EXECUTIONS = 7
BASELINE_FAILURES = 1
BASELINE_DENIALS = 2
BASELINE_APPROVALS = 1

#: The hour that differs: four times the request rate, three failures and five denials.
OBSERVATION_REQUESTS = 40
OBSERVATION_EXECUTIONS = 25
OBSERVATION_FAILURES = 3
OBSERVATION_DENIALS = 5
OBSERVATION_APPROVALS = 2


def known_agent(scene: RiskScene) -> Any:
    """One agent with the known week behind it and the known hour in front of it."""
    record = scene.agents.register(display_name="Known Agent")
    assert record is not None
    scene.seed_baseline(
        record.id,
        hours=BASELINE_HOURS,
        per_hour=BASELINE_REQUESTS,
        executions_per_hour=BASELINE_EXECUTIONS,
        failures_per_hour=BASELINE_FAILURES,
        denials_per_hour=BASELINE_DENIALS,
        approvals_per_hour=BASELINE_APPROVALS,
    )
    scene.seed_observation(
        record.id,
        requests=OBSERVATION_REQUESTS,
        executions=OBSERVATION_EXECUTIONS,
        failures=OBSERVATION_FAILURES,
        denials=OBSERVATION_DENIALS,
        approvals=OBSERVATION_APPROVALS,
    )
    return record


def dimension(body: dict[str, Any], metric: RiskMetric) -> dict[str, Any]:
    """One dimension of an assessment, by metric."""
    return next(item for item in body["dimensions"] if item["metric"] == metric.value)


# ── the arithmetic, stated by the test ────────────────────────────────────────


def test_the_observation_counts_are_the_events_the_test_seeded(risk: RiskScene) -> None:
    """Every counter in the observation block is the number that was written."""
    record = known_agent(risk)
    observation = risk.assessment(record.id)["observation"]

    assert observation["requests"] == OBSERVATION_REQUESTS
    assert observation["executions"] == OBSERVATION_EXECUTIONS
    assert observation["failures"] == OBSERVATION_FAILURES
    assert observation["denials"] == OBSERVATION_DENIALS
    assert observation["approval_required"] == OBSERVATION_APPROVALS
    assert observation["completed"] == OBSERVATION_EXECUTIONS + OBSERVATION_FAILURES
    assert observation["events"] == (
        OBSERVATION_REQUESTS
        + OBSERVATION_EXECUTIONS
        + OBSERVATION_FAILURES
        + OBSERVATION_DENIALS
        + OBSERVATION_APPROVALS
    )
    assert observation["span_hours"] == 1.0
    assert observation["action_count"] == 1
    assert observation["resource_count"] == 1


def test_the_baseline_statistics_are_recomputed_by_the_test(risk: RiskScene) -> None:
    """A steady week has a mean of ten and a spread of zero, so both bounds are ten."""
    record = known_agent(risk)
    body = risk.assessment(record.id)
    baseline = body["baseline"]

    assert baseline["hourly_buckets"] == BASELINE_HOURS
    assert baseline["requests"] == BASELINE_REQUESTS * BASELINE_HOURS
    assert baseline["executions"] == BASELINE_EXECUTIONS * BASELINE_HOURS
    assert baseline["failures"] == BASELINE_FAILURES * BASELINE_HOURS
    assert baseline["denials"] == BASELINE_DENIALS * BASELINE_HOURS
    assert baseline["active_hours"] == list(range(24))

    rate = dimension(body, RiskMetric.ACTION_RATE)
    assert rate["observed"] == pytest.approx(40.0)
    assert rate["baseline_mean"] == pytest.approx(10.0)
    assert rate["baseline_stddev"] == pytest.approx(0.0)
    assert rate["upper_bound"] == pytest.approx(10.0)
    assert rate["lower_bound"] == pytest.approx(10.0)
    assert rate["baseline_samples"] == BASELINE_HOURS
    assert rate["observation_samples"] == OBSERVATION_REQUESTS


def test_the_rate_that_fired_is_the_one_the_test_can_prove(risk: RiskScene) -> None:
    """One strong factor: the request rate is four times the week and twice the mean."""
    record = known_agent(risk)
    body = risk.assessment(record.id)

    assert body["status"] == AssessmentStatus.DEVIATING.value
    assert body["anomaly"] is True
    assert types_of(body) == [DetectionType.ACTION_RATE_SPIKE]
    assert level_of(body) is RiskLevel.MEDIUM

    factor = body["factors"][0]
    assert factor["metric"] == RiskMetric.ACTION_RATE.value
    assert factor["observed"] == pytest.approx(OBSERVATION_REQUESTS / 1.0)
    assert factor["baseline_mean"] == pytest.approx(float(BASELINE_REQUESTS))
    assert factor["upper_bound"] == pytest.approx(float(BASELINE_REQUESTS))
    assert factor["threshold_multiple"] == 2.0
    assert factor["items"] == []


def test_the_ratios_that_did_not_fire_are_the_ones_the_test_can_prove(risk: RiskScene) -> None:
    """The failure and denial ratios are inside their bounds, and the response says so.

    Both are measured rather than refused — the baseline has a denominator in every bucket,
    so both have a distribution — and both are reported with their numbers even though
    neither fired, because "this was checked and was within its baseline" is an answer.
    """
    record = known_agent(risk)
    body = risk.assessment(record.id)

    baseline_failure_ratio = BASELINE_FAILURES / (BASELINE_EXECUTIONS + BASELINE_FAILURES)
    failure = dimension(body, RiskMetric.FAILURE_RATE)
    assert failure["status"] == "measured"
    assert failure["observed"] == pytest.approx(
        OBSERVATION_FAILURES / (OBSERVATION_EXECUTIONS + OBSERVATION_FAILURES)
    )
    assert failure["baseline_mean"] == pytest.approx(baseline_failure_ratio)
    assert failure["baseline_stddev"] == pytest.approx(0.0)
    assert failure["upper_bound"] == pytest.approx(baseline_failure_ratio)
    assert failure["observation_samples"] == OBSERVATION_EXECUTIONS + OBSERVATION_FAILURES
    assert DetectionType.FAILURE_RATE_SPIKE not in types_of(body)

    baseline_denial_ratio = BASELINE_DENIALS / BASELINE_REQUESTS
    denial = dimension(body, RiskMetric.DENIAL_RATE)
    assert denial["status"] == "measured"
    assert denial["observed"] == pytest.approx(OBSERVATION_DENIALS / OBSERVATION_REQUESTS)
    assert denial["baseline_mean"] == pytest.approx(baseline_denial_ratio)
    assert denial["upper_bound"] == pytest.approx(baseline_denial_ratio)
    assert DetectionType.DENIAL_RATE_SPIKE not in types_of(body)


def test_the_first_use_dimensions_are_measured_and_silent(risk: RiskScene) -> None:
    """Same action, same resource, an hour the week already covers: nothing is new."""
    record = known_agent(risk)
    body = risk.assessment(record.id)

    for metric in (RiskMetric.NOVEL_ACTION, RiskMetric.NOVEL_RESOURCE, RiskMetric.UNUSUAL_TIME):
        item = dimension(body, metric)
        assert item["status"] == "measured", metric
        assert item["observed"] == pytest.approx(0.0), metric
        assert item["reason"] is None, metric
    assert len(body["dimensions"]) == 6


def test_an_hour_of_silence_after_a_loud_week_is_a_drop(risk: RiskScene) -> None:
    """The other direction, with the same arithmetic: ten an hour, then nothing at all.

    This is the case a population built from *activity* would miss entirely — an agent that
    did nothing has no rows in the observation window — which is why the population is the
    registry and why the engine reports an empty hour as a measurement rather than as
    missing data. The rate is zero, the baseline is ten an hour, and the deviation is a drop.
    """
    record = risk.agents.register(display_name="Silent Agent")
    assert record is not None
    risk.seed_baseline(record.id, hours=BASELINE_HOURS, per_hour=BASELINE_REQUESTS)

    body = risk.assessment(record.id)
    rate = dimension(body, RiskMetric.ACTION_RATE)
    assert rate["observed"] == pytest.approx(0.0)
    assert rate["baseline_mean"] == pytest.approx(float(BASELINE_REQUESTS))
    assert types_of(body) == [DetectionType.ACTION_RATE_DROP]
    assert level_of(body) is RiskLevel.MEDIUM
    assert body["factors"][0]["observed"] == pytest.approx(0.0)


def test_a_second_agent_is_assessed_against_its_own_history(risk: RiskScene) -> None:
    """History is per entity: a neighbour's loud week does not become this agent's baseline."""
    loud = risk.agents.register(display_name="Loud Agent")
    quiet = risk.agents.register(display_name="Quiet Agent")
    assert loud is not None and quiet is not None
    risk.seed_baseline(loud.id, hours=BASELINE_HOURS, per_hour=BASELINE_REQUESTS)
    risk.seed_baseline(quiet.id, hours=BASELINE_HOURS, per_hour=1)
    risk.seed_observation(quiet.id, requests=1)

    body = risk.assessment(quiet.id)
    rate = dimension(body, RiskMetric.ACTION_RATE)
    assert rate["baseline_mean"] == pytest.approx(1.0)
    assert rate["observed"] == pytest.approx(1.0)
    assert body["status"] == AssessmentStatus.WITHIN_BASELINE.value
    assert body["anomaly"] is False


def test_an_assessment_ignores_the_hour_before_its_window(risk: RiskScene) -> None:
    """The window is the window: activity outside it is not counted, however recent.

    An hour as loud as the observation is placed immediately *before* the window opens. The
    response's counts are unchanged by it — which is the difference between measuring a
    period and measuring "recently".
    """
    record = known_agent(risk)
    before = risk.observation_window()[0]
    risk.seed(
        *[
            SeededEvent(
                event_type="action.requested",
                minutes_ago=risk.minutes_ago(before - timedelta(minutes=30, seconds=index)),
                agent_id=record.id,
                action="agent.posture_check",
            )
            for index in range(60)
        ]
    )

    observation = risk.assessment(record.id)["observation"]
    assert observation["requests"] == OBSERVATION_REQUESTS
    assert observation["events"] == (
        OBSERVATION_REQUESTS
        + OBSERVATION_EXECUTIONS
        + OBSERVATION_FAILURES
        + OBSERVATION_DENIALS
        + OBSERVATION_APPROVALS
    )


def test_a_recorded_assessment_is_the_numbers_that_were_just_read(risk: RiskScene) -> None:
    """Recording is a copy of the answer, not a second computation with a different result."""
    record = known_agent(risk)
    live = risk.assessment(record.id)
    recorded = risk.record(record.id)

    assert recorded["assessment"]["dimensions"] == live["dimensions"]
    assert recorded["assessment"]["factors"] == live["factors"]

    (row,) = risk.stored()
    assert row["evidence"]["dimensions"] == live["dimensions"]
    assert row["factors"] == live["factors"]
    assert row["risk_level"] == live["risk_level"]
    assert row["detection_type"] == live["detection_type"]


# ── the statements behind the numbers ────────────────────────────────────────


class _TrailStatements:
    """Every statement one request sent to the trail, in order."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self.statements: list[str] = []

    def __enter__(self) -> _TrailStatements:
        event.listen(self._engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *_: object) -> None:
        event.remove(self._engine, "before_cursor_execute", self._record)

    def _record(self, connection: Any, cursor: Any, statement: str, *rest: Any) -> None:
        if "audit_events" in statement:
            self.statements.append(" ".join(statement.split()))

    def reset(self) -> None:
        self.statements.clear()


def _statements() -> _TrailStatements:
    """Capture what the *application's* engine sends, for the rest of the test."""
    return _TrailStatements(get_engine())


#: How many trail statements each route sends, and why that number. The engine asks three
#: questions of each of two windows — the hourly counts, the actions used and the resources
#: addressed — and a page adds nothing: the same six statements answer for every agent on it.
STATEMENTS_PER_WINDOW = 3
STATEMENTS_PER_ASSESSMENT = STATEMENTS_PER_WINDOW * 2


def test_the_single_agent_route_reads_the_two_windows_in_six_statements(risk: RiskScene) -> None:
    """Six statements, published here so a change in the engine is a changed number."""
    record = known_agent(risk)
    with _statements() as captured:
        assert risk.assessment(record.id)
    assert len(captured.statements) == STATEMENTS_PER_ASSESSMENT


def test_assessing_a_page_of_agents_costs_the_same_six_statements(risk: RiskScene) -> None:
    """The aggregate is per window, not per agent: five agents are not five times the work."""
    for index in range(5):
        registered = risk.agents.register(display_name=f"Page Agent {index}")
        assert registered is not None
    with _statements() as captured:
        assert risk.assessments()["count"] == 5
    assert len(captured.statements) == STATEMENTS_PER_ASSESSMENT


def test_every_trail_statement_is_a_bounded_tenant_scoped_select(risk: RiskScene) -> None:
    """No route can ask an unbounded question, because none of them writes one.

    Each statement must name the organization, name the trail, bound ``occurred_at`` on both
    sides, and be a ``SELECT``. The columns a window is *not* read from — the trail's
    metadata, its request correlation and its actor — are asserted absent, which is what keeps
    an aggregate from carrying the raw material it was computed from.
    """
    record = known_agent(risk)
    with _statements() as captured:
        assert risk.assessment(record.id)
        assert risk.assessments()["count"] >= 1
        assert risk.detected()["count"] == 0

    assert captured.statements
    for statement in captured.statements:
        lowered = statement.lower()
        assert lowered.startswith("select"), statement
        assert "aicore.audit_events" in lowered, statement
        assert "organization_id" in lowered, statement
        assert "occurred_at >=" in lowered and "occurred_at <=" in lowered, statement
        for verb in ("insert into", "update ", "delete from", "truncate", "for update"):
            assert verb not in lowered, statement
        for column in ("metadata", "correlation_id", "actor_id", "reason"):
            assert column not in lowered, (column, statement)


def test_the_one_write_is_a_single_insert_into_the_detection_table(risk: RiskScene) -> None:
    """Recording sends one write statement, and it names one table.

    Asserted over *every* statement the request sends, not only the trail's: the analysis may
    insert a detection and may not touch anything else — no audit event, no policy, no agent,
    no permission — which is the phase's whole write surface in one assertion.
    """
    record = known_agent(risk)
    engine = get_engine()
    statements: list[str] = []

    def _record(connection: Any, cursor: Any, statement: str, *rest: Any) -> None:
        statements.append(" ".join(statement.split()))

    event.listen(engine, "before_cursor_execute", _record)
    try:
        assert risk.record(record.id)["recorded"] is True
    finally:
        event.remove(engine, "before_cursor_execute", _record)

    writes = [
        statement
        for statement in statements
        if statement.lower().startswith(("insert", "update", "delete", "truncate"))
    ]
    assert len(writes) == 1, writes
    assert writes[0].lower().startswith("insert into aicore.anomaly_detections"), writes[0]
    for table in ("audit_events", "policies", "agents", "role_permissions", "assets"):
        assert not any(
            statement.lower().startswith(("insert", "update", "delete", "truncate"))
            and table in statement.lower()
            for statement in statements
        ), table

    # The statements that read are the six of the assessment, plus the registry lookup that
    # answers "does this organization hold this agent?" — and nothing else.
    reads = [statement for statement in statements if statement.lower().startswith("select")]
    assert len([s for s in reads if "aicore.agents" in s.lower()]) == 1
    assert (
        len([s for s in reads if "aicore.audit_events" in s.lower()]) == STATEMENTS_PER_ASSESSMENT
    )


def test_the_analysis_reads_a_window_and_not_a_table(risk: RiskScene) -> None:
    """Bounded by construction: the same request against a century of history is one query.

    The statements are the same six whether the trail holds a hundred rows or a hundred
    thousand, because the bounds are in the ``WHERE`` clause rather than in a limit applied
    after the fact. Asserted as the statement count and as the presence of both bounds — the
    measurable form of "no unbounded scan".
    """
    record = known_agent(risk)
    with _statements() as captured:
        assert risk.assessment(record.id)
    baseline_window = len(captured.statements)

    # A second week of history, placed before the baseline: the window is unchanged, so the
    # work is unchanged.
    before_baseline = risk.observation_window()[0] - timedelta(days=7)
    risk.seed(
        *[
            SeededEvent(
                event_type="action.requested",
                minutes_ago=risk.minutes_ago(before_baseline - timedelta(hours=index)),
                agent_id=record.id,
                action="agent.posture_check",
            )
            for index in range(24)
        ]
    )
    with _statements() as captured:
        assert risk.assessment(record.id)
    assert len(captured.statements) == baseline_window


def test_the_engine_holds_no_clock_of_its_own(risk: RiskScene) -> None:
    """One request, one instant: every window in a response is resolved once, from the route.

    Two reads a moment apart may disagree about which hour is "now" — that is the clock
    moving, not the engine remembering — but within one response the observation's end, the
    baseline's end and ``generated_at`` describe one moment, and the stored row records that
    moment rather than the moment of the next request.
    """
    record = known_agent(risk)
    first = risk.assessment(record.id, window="1h", start_time=None, end_time=None)
    start = first["observation"]["start"]
    recorded = risk.record(
        record.id,
        start_time=start,
        end_time=first["observation"]["end"],
    )
    (row,) = risk.stored()
    assert row["observation_start"].isoformat() == datetime.fromisoformat(start).isoformat()
    assert recorded["detection"]["detected_at"]
    assert datetime.fromisoformat(row["detected_at"].isoformat()) <= datetime.now(UTC)
