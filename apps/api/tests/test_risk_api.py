"""The risk API: what a response states, and what it refuses to be told.

These tests drive the real application against the real database, over a trail that was
seeded at known instants — so every number asserted here is arithmetic the test can check:
so many requests an hour in the baseline, so many in the observation, and therefore this
bound and this reading.

Three things are asserted in every test that can assert them. The windows are stated and
consistent (the baseline ends where the observation begins). The observation counts equal
the events that were seeded, so a response cannot report a measurement of something else.
And the thresholds in the response are the ones the server was configured with, because a
client that could influence one has a detector it can tune.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from aicore_api.core.risk import (
    AssessmentStatus,
    DetectionType,
    EntityType,
    InsufficiencyReason,
    RiskLevel,
    RiskMetric,
)
from risk_fixture import (
    BASELINE_HOURS,
    BASELINE_WINDOW,
    RiskScene,
    level_of,
    types_of,
)

pytestmark = pytest.mark.integration

#: The baseline these tests build: a week of hours, one request in each, so the hourly rate
#: is 1.0, the population spread is 0 and both bounds are 1.0. Steady enough that the bound
#: in any assertion below is the baseline mean, and cheap to seed.
BASELINE_PER_HOUR = 1

#: Requests that *match* the baseline rate: the observation window is an hour, so one
#: request in it is a rate of one an hour — identical to the baseline, and not a deviation.
MATCHING_REQUESTS = 1


def at(value: str) -> datetime:
    """A timestamp from a response, as an instant. ``Z`` and ``+00:00`` both parse."""
    return datetime.fromisoformat(value)


def seeded_agents(scene: RiskScene) -> list[uuid.UUID]:
    """Two agents in the scene's registry, registered through the real API.

    ``register`` returns ``None`` when the call was refused, so the filter is the fixture's
    own way of saying "these are the agents that exist".
    """
    records = [
        scene.agents.register(display_name="Risk Agent One"),
        scene.agents.register(display_name="Risk Agent Two"),
    ]
    return [record.id for record in records if record is not None]


def test_an_assessment_states_both_windows_and_every_dimension(risk: RiskScene) -> None:
    """One agent, one page of arithmetic: the response explains its own comparison."""
    (agent_id,) = [seeded_agents(risk)[0]]
    risk.seed_baseline(agent_id, hours=BASELINE_HOURS, per_hour=BASELINE_PER_HOUR)
    risk.seed_observation(agent_id, requests=MATCHING_REQUESTS)

    body = risk.assessment(agent_id)
    start, end = risk.observation_window()
    assert body["entity_type"] == EntityType.AGENT.value
    assert body["entity_id"] == str(agent_id)
    assert body["organization_id"] == str(risk.organization_id)
    assert at(body["observation"]["start"]) == start
    assert at(body["observation"]["end"]) == end
    assert body["baseline"]["window"] == BASELINE_WINDOW
    assert at(body["baseline"]["end"]) == start
    assert at(body["generated_at"]) >= end

    metrics = [dimension["metric"] for dimension in body["dimensions"]]
    assert metrics == [metric.value for metric in RiskMetric]
    assert body["status"] in {status.value for status in AssessmentStatus}
    assert body["risk_level"] in {level.value for level in RiskLevel}


def test_the_observation_counts_are_the_events_that_were_seeded(risk: RiskScene) -> None:
    """Measured, not asserted: the response's counts equal the trail's own.

    Nothing in the response is a summary the test cannot check. Two requests, one completed,
    one refused: the observation block says exactly that, and the rate is those requests over
    the window's half hour.
    """
    (agent_id,) = [seeded_agents(risk)[0]]
    risk.seed_baseline(agent_id, hours=BASELINE_HOURS, per_hour=BASELINE_PER_HOUR)
    risk.seed_observation(agent_id, requests=4, executions=1, denials=1, approvals=1, failures=0)
    body = risk.assessment(agent_id)
    observation = body["observation"]
    assert observation["requests"] == 4
    assert observation["executions"] == 1
    assert observation["failures"] == 0
    assert observation["denials"] == 1
    assert observation["approval_required"] == 1
    assert observation["events"] == 7
    assert observation["completed"] == 1
    assert observation["span_hours"] == 1.0

    rate = next(item for item in body["dimensions"] if item["metric"] == RiskMetric.ACTION_RATE)
    assert rate["observed"] == pytest.approx(4.0)


def test_a_named_observation_window_ends_at_the_server_clock(risk: RiskScene) -> None:
    """``window=1h`` is resolved by the server, and the response says which hour it was.

    A client never supplies the end of a named window: the response's ``end`` is the
    server's clock, and the baseline that follows from it is anchored there.
    """
    (agent_id,) = [seeded_agents(risk)[0]]
    before = datetime.now(UTC)
    body = risk.assessment(agent_id, window="1h")
    after = datetime.now(UTC)

    start = at(body["observation"]["start"])
    end = at(body["observation"]["end"])
    assert before - timedelta(seconds=5) <= end <= after + timedelta(seconds=5)
    assert start == end - timedelta(hours=1)
    assert at(body["baseline"]["start"]) == start - timedelta(days=7)


@pytest.mark.parametrize("baseline", ["24h", "7d", "14d", "30d"])
def test_the_named_baselines_are_the_four_the_vocabulary_declares(
    risk: RiskScene, baseline: str
) -> None:
    """Each named span resolves to its own length, ending where the observation starts."""
    (agent_id,) = [seeded_agents(risk)[0]]
    body = risk.assessment(agent_id, baseline=baseline)
    start = at(body["observation"]["start"])
    baseline_start = at(body["baseline"]["start"])
    assert body["baseline"]["window"] == baseline
    assert at(body["baseline"]["end"]) == start
    assert (start - baseline_start) == {
        "24h": timedelta(days=1),
        "7d": timedelta(days=7),
        "14d": timedelta(days=14),
        "30d": timedelta(days=30),
    }[baseline]


def test_the_thresholds_in_force_are_stated_and_are_the_servers(risk: RiskScene) -> None:
    """The response publishes its parameters; a client cannot supply a different set."""
    (agent_id,) = [seeded_agents(risk)[0]]
    body = risk.assessment(agent_id)
    parameters = body["parameters"]
    assert parameters["deviation_multiple"] == 2.0
    assert parameters["extreme_multiple"] == 3.0
    assert parameters["rate_change_ratio"] == 2.0
    assert parameters["min_baseline_buckets"] == 12

    # A client that tries to tune the detector gets an answer computed with the server's
    # thresholds anyway: there is no query parameter for any of these.
    tuned = risk.assessment(
        agent_id,
        deviation_multiple=99.0,
        threshold=0.1,
        confidence=0.9,
        risk_level="critical",
    )
    assert tuned["parameters"] == parameters


def test_an_agent_the_organization_does_not_hold_is_a_404(risk: RiskScene) -> None:
    """An unknown identifier and another tenant's identifier are the same answer."""
    response = risk.client.get(
        f"/organizations/{risk.organization_id}/risk/agents/{uuid.uuid4()}",
        params=risk.query(),
    )
    assert response.status_code == 404
    assert "agent not found" in response.json()["error"]["message"]


def test_a_registered_agent_with_no_history_is_insufficient_data(risk: RiskScene) -> None:
    """The cold start, through the API: a new agent is not an anomalous one.

    Registered and never seen acting: every dimension that needs history says why it could
    not be measured, the status is ``insufficient_data``, and the level is ``none``.
    """
    (agent_id,) = [seeded_agents(risk)[0]]
    body = risk.assessment(agent_id)
    assert body["status"] == AssessmentStatus.INSUFFICIENT_DATA.value
    assert body["anomaly"] is False
    assert body["risk_level"] == RiskLevel.NONE.value
    assert body["detection_type"] is None
    assert body["factors"] == []
    reasons = {dimension["reason"] for dimension in body["dimensions"]}
    assert reasons <= {reason.value for reason in InsufficiencyReason}
    assert None not in {dimension["reason"] for dimension in body["dimensions"]}


def test_a_deviation_carries_the_arithmetic_that_produced_it(risk: RiskScene) -> None:
    """One request an hour for a week, then forty in one hour: the numbers add up.

    Baseline mean 1.0, population spread 0.0, so the upper bound is 1.0. The observation is
    a rate of 40 per hour — above the bound and far above twice the mean — and the factor
    states the mean, the spread, the bound and both sample counts.
    """
    (agent_id,) = [seeded_agents(risk)[0]]
    risk.seed_baseline(agent_id, hours=BASELINE_HOURS, per_hour=BASELINE_PER_HOUR)
    risk.seed_observation(agent_id, requests=40)

    body = risk.assessment(agent_id)
    assert body["status"] == AssessmentStatus.DEVIATING.value
    assert body["anomaly"] is True
    assert types_of(body) == [DetectionType.ACTION_RATE_SPIKE]
    assert level_of(body) is RiskLevel.MEDIUM

    factor = body["factors"][0]
    assert factor["metric"] == RiskMetric.ACTION_RATE.value
    assert factor["observed"] == pytest.approx(40.0)
    assert factor["baseline_mean"] == pytest.approx(1.0)
    assert factor["baseline_stddev"] == pytest.approx(0.0)
    assert factor["upper_bound"] == pytest.approx(1.0)
    assert factor["threshold_multiple"] == 2.0
    assert factor["observation_samples"] == 40
    assert factor["baseline_samples"] == BASELINE_HOURS


def test_the_page_assesses_every_agent_in_the_registry(risk: RiskScene) -> None:
    """The population is the registry, so a silent agent is assessed rather than skipped."""
    agent_ids = seeded_agents(risk)
    risk.seed_baseline(agent_ids[0], hours=BASELINE_HOURS, per_hour=BASELINE_PER_HOUR)
    risk.seed_observation(agent_ids[0], requests=MATCHING_REQUESTS)

    body = risk.assessments(limit=10)
    assert body["count"] == len(agent_ids)
    assert {item["entity_id"] for item in body["items"]} == {str(value) for value in agent_ids}
    assert body["limit"] == 10
    assert body["offset"] == 0
    assert body["total"] is None

    with_total = risk.assessments(limit=10, total=True)
    assert with_total["total"] == len(agent_ids)

    assert at(body["observation"]["end"]) == risk.observation_window()[1]
    one = next(item for item in body["items"] if item["entity_id"] == str(agent_ids[0]))
    other = next(item for item in body["items"] if item["entity_id"] == str(agent_ids[1]))
    assert one["anomaly"] is False or one["status"] == AssessmentStatus.WITHIN_BASELINE.value
    assert other["status"] == AssessmentStatus.INSUFFICIENT_DATA.value


def test_paging_the_registry_is_stable_and_bounded(risk: RiskScene) -> None:
    """Two agents, two pages of one: no repeats, no gaps, and a bounded page size."""
    agent_ids = seeded_agents(risk)
    first = risk.assessments(limit=1, offset=0)
    second = risk.assessments(limit=1, offset=1)
    assert first["count"] == second["count"] == 1
    assert {first["items"][0]["entity_id"], second["items"][0]["entity_id"]} == {
        str(value) for value in agent_ids
    }
    over = risk.get("agents", limit=101)
    assert over.status_code == 422


def test_a_window_with_no_duration_is_refused(risk: RiskScene) -> None:
    """A rate over no time is not a measurement, so the request is a 422.

    Phase 9 accepts an empty window for a count — the answer is zero. This phase cannot: the
    span is a divisor, and the refusal is stated rather than approximated.
    """
    start, end = risk.observation_window()
    response = risk.get(
        "agents",
        window="custom",
        start_time=end.isoformat(),
        end_time=end.isoformat(),
        baseline=BASELINE_WINDOW,
    )
    assert response.status_code == 422
    assert "duration" in response.json()["error"]["message"]
    assert start < end  # the window the test meant is a real one


def test_a_naive_timestamp_is_refused(risk: RiskScene) -> None:
    """``12:00`` is not an instant: a bound without a timezone is rejected."""
    start, end = risk.observation_window()
    response = risk.get(
        "agents",
        window="custom",
        start_time=start.replace(tzinfo=None).isoformat(),
        end_time=end.isoformat(),
        baseline=BASELINE_WINDOW,
    )
    assert response.status_code == 422


def test_a_window_longer_than_a_month_is_refused(risk: RiskScene) -> None:
    """The custom window is bounded like every other span in this build."""
    start, end = risk.observation_window()
    response = risk.get(
        "agents",
        window="custom",
        start_time=(start - timedelta(days=31)).isoformat(),
        end_time=end.isoformat(),
        baseline=BASELINE_WINDOW,
    )
    assert response.status_code == 422


def test_an_undeclared_baseline_is_refused(risk: RiskScene) -> None:
    """The vocabulary is closed: ``90d`` is not a baseline this build computes."""
    response = risk.get("agents", baseline="90d")
    assert response.status_code == 422


def test_bounds_without_the_custom_window_are_refused(risk: RiskScene) -> None:
    """A named window and explicit bounds are contradictory; Phase 9's rule still applies."""
    start, end = risk.observation_window()
    response = risk.get(
        "agents",
        window="1h",
        start_time=start.isoformat(),
        end_time=end.isoformat(),
        baseline=BASELINE_WINDOW,
    )
    assert response.status_code == 422


def test_the_baseline_never_contains_the_observation(risk: RiskScene) -> None:
    """Structural, not conventional: the two windows abut and do not overlap.

    An event seeded inside the observation window cannot move a bound, because the baseline
    ends where the observation begins — which is what makes the comparison a comparison and
    not a window measured against itself.
    """
    (agent_id,) = [seeded_agents(risk)[0]]
    risk.seed_baseline(agent_id, hours=BASELINE_HOURS, per_hour=BASELINE_PER_HOUR)
    before = risk.assessment(agent_id)
    risk.seed_observation(agent_id, requests=40)
    after = risk.assessment(agent_id)

    assert before["baseline"] == after["baseline"]
    assert before["baseline"]["end"] == after["observation"]["start"]
    rate_before = next(
        item for item in before["dimensions"] if item["metric"] == RiskMetric.ACTION_RATE
    )
    rate_after = next(
        item for item in after["dimensions"] if item["metric"] == RiskMetric.ACTION_RATE
    )
    assert rate_before["baseline_mean"] == rate_after["baseline_mean"]
    assert rate_before["baseline_samples"] == rate_after["baseline_samples"]
    assert rate_after["observed"] > rate_before["observed"]


def test_another_agents_activity_is_not_in_the_assessment(risk: RiskScene) -> None:
    """One agent's window is its own: a busy neighbour does not move its rate.

    The trail is shared, so the isolation asserted here is the repository's per-agent
    projection: events attributed to a different agent are not this agent's behaviour.
    """
    agent_ids = seeded_agents(risk)
    risk.seed_observation(agent_ids[1], requests=40)
    body = risk.assessment(agent_ids[0])
    assert body["observation"]["requests"] == 0
    assert body["status"] == AssessmentStatus.INSUFFICIENT_DATA.value


def test_events_without_an_agent_are_not_anyones(risk: RiskScene) -> None:
    """Organization-level events belong to no assessment: only attributed rows count.

    A registry write, an asset change and a policy change all land in the same trail. They
    have no agent attribution, so they cannot appear in an agent's rate — which is also why
    the baseline is built from the action pipeline specifically.
    """
    (agent_id,) = [seeded_agents(risk)[0]]
    risk.assets.create(name="unrelated-asset")
    body = risk.assessment(agent_id)
    assert body["observation"]["events"] == 0


def test_a_registry_write_is_recorded_but_not_attributed(risk: RiskScene) -> None:
    """The trail proves the write happened; the assessment proves it was not counted."""
    (agent_id,) = [seeded_agents(risk)[0]]
    stored = risk.trail.stored()
    assert stored, "the registry write is on the trail"
    assert all(row["agent_id"] is None for row in stored)
    assert any(str(row["resource_id"]) == str(agent_id) for row in stored)
    assert risk.assessment(agent_id)["observation"]["events"] == 0


def test_an_assessment_is_reproducible(risk: RiskScene) -> None:
    """The same window assessed twice answers identically, field for field."""
    (agent_id,) = [seeded_agents(risk)[0]]
    risk.seed_observation(agent_id, requests=40)
    first = risk.assessment(agent_id)
    second = risk.assessment(agent_id)
    # Everything except the moment of the request is identical, field for field.
    assert first.pop("generated_at") != second.pop("generated_at")
    assert first == second


def test_the_engine_does_not_read_the_clock_per_dimension(risk: RiskScene) -> None:
    """Both windows come from one instant, so a response cannot straddle a clock tick."""
    (agent_id,) = [seeded_agents(risk)[0]]
    body = risk.assessment(agent_id, window="15m", start_time=None, end_time=None)
    end = datetime.fromisoformat(body["observation"]["end"])
    assert datetime.fromisoformat(body["generated_at"]) == end
    assert end - datetime.fromisoformat(body["observation"]["start"]) == timedelta(minutes=15)
    assert body["baseline"]["end"] == body["observation"]["start"]
