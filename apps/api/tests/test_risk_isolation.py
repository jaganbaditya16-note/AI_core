"""Phase 10 across the tenant boundary: one organization's findings are its own.

Every analysis in this phase reads *two* things at once — a trail and a registry — and both
are tenant-owned. So there are two ways for it to leak: by counting another organization's
events into this organization's baseline or observation, and by answering a request about an
identifier another organization holds. This module tests both directions, against a second
tenant that really exists, really has an agent and really has a record.

The rule the phase inherits from every phase before it: a foreign identifier is answered
exactly like one that does not exist — the same status, the same body, no hint that
something is on the other side of the wall. An isolation test that only asserts a 404 is
testing the status code, so each one here also asserts the *positive* case: the same
request against the foreign tenant's own API succeeds and returns the record, which is what
makes the 404 a boundary rather than a broken route.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from aicore_api.core.risk import AssessmentStatus, DetectionType, RiskLevel
from monitoring_fixture import SeededEvent
from risk_fixture import (
    BASELINE_HOURS,
    ForeignRiskTenant,
    RiskScene,
    fixed_agent_id,
)

pytestmark = pytest.mark.integration


def mine(scene: RiskScene) -> uuid.UUID:
    """One agent in the first tenant, with a week of known history and one loud hour."""
    record = scene.agents.register(display_name="Isolation Agent")
    assert record is not None
    scene.seed_baseline(record.id, hours=BASELINE_HOURS, per_hour=1)
    scene.seed_observation(record.id, requests=12)
    return record.id


def test_the_two_tenants_are_distinct_organizations(
    risk: RiskScene, foreign_risk: ForeignRiskTenant, foreign_agent: uuid.UUID
) -> None:
    """The premise of every assertion below: two real tenants, not one tenant twice."""
    assert foreign_risk.organization_id != risk.organization_id
    assert foreign_risk.identity.organization_id == foreign_risk.organization_id
    assert risk.as_owner().get("/me").json()["memberships"][0]["organization"]["id"] == str(
        risk.organization_id
    )
    assert foreign_risk.as_owner().get("/me").json()["memberships"][0]["organization"]["id"] == str(
        foreign_risk.organization_id
    )


def test_another_tenants_agent_is_not_found_by_this_one(
    risk: RiskScene, foreign_risk: ForeignRiskTenant, foreign_agent: uuid.UUID
) -> None:
    """A real agent, in a real registry, one organization over: a 404 with no explanation."""
    response = risk.as_owner().get(
        f"/organizations/{risk.organization_id}/risk/agents/{foreign_agent}",
        params=risk.query(),
    )
    assert response.status_code == 404, response.text
    assert response.json()["error"]["code"] == "not_found"

    # The same identifier, asked by the tenant that holds it, is an assessment.
    own = foreign_risk.as_owner().get(
        f"/organizations/{foreign_risk.organization_id}/risk/agents/{foreign_agent}",
        params=foreign_risk.query(),
    )
    assert own.status_code == 200, own.text
    assert own.json()["entity_id"] == str(foreign_agent)


def test_an_unknown_agent_and_a_foreign_agent_are_indistinguishable(
    risk: RiskScene, foreign_risk: ForeignRiskTenant, foreign_agent: uuid.UUID
) -> None:
    """Two identifiers — one that exists elsewhere, one that exists nowhere — one answer.

    This is the difference between a boundary and a source of information: a boundary that
    answered "exists, but not yours" would turn the risk route into a membership oracle.
    """
    path = f"/organizations/{risk.organization_id}/risk/agents"
    params = risk.query()
    foreign = risk.as_owner().get(f"{path}/{foreign_agent}", params=params)
    invented = risk.as_owner().get(f"{path}/{uuid.uuid4()}", params=params)

    assert foreign.status_code == invented.status_code == 404
    assert foreign.json()["error"]["code"] == invented.json()["error"]["code"] == "not_found"
    assert foreign.json()["error"]["message"] == invented.json()["error"]["message"]
    # The column names a request is about are the same in the two answers, so the answer
    # carries no hint about which identifier exists somewhere else.
    assert [item["loc"] for item in foreign.json()["error"].get("details") or []] == []


def test_recording_another_tenants_agent_writes_nothing_anywhere(
    risk: RiskScene, foreign_risk: ForeignRiskTenant, foreign_agent: uuid.UUID
) -> None:
    """The write route is scoped too: a foreign identifier cannot be recorded, by anyone."""
    assert risk.stored_count() == 0
    response = risk.as_owner().post(
        f"/organizations/{risk.organization_id}/risk/analysis",
        json={"agent_id": str(foreign_agent)},
        params=risk.query(),
    )
    assert response.status_code == 404, response.text
    assert risk.stored_count() == 0
    assert foreign_risk.detections()["count"] == 0


def test_results_are_listed_per_tenant(
    risk: RiskScene, foreign_risk: ForeignRiskTenant, foreign_agent: uuid.UUID
) -> None:
    """Each tenant's feed holds its own record, and neither feed holds the other's."""
    agent_id = mine(risk)
    recorded = risk.record(agent_id)
    foreign_risk.seed_observation(foreign_agent, requests=1)
    theirs = foreign_risk.analyze(foreign_agent)
    assert theirs.status_code in (200, 201), theirs.text

    here = risk.detected(total=True)
    there = foreign_risk.detections(total=True)
    assert [item["id"] for item in here["items"]] == [recorded["detection"]["id"]]
    assert [item["id"] for item in there["items"]] == [theirs.json()["detection"]["id"]]
    assert here["total"] == 1
    assert there["total"] == 1

    # And the foreign record is not readable by identifier from the first tenant either.
    response = risk.as_owner().get(
        f"/organizations/{risk.organization_id}/risk/detections/{theirs.json()['detection']['id']}",
        params=risk.query(),
    )
    assert response.status_code == 404, response.text


def test_another_tenants_history_is_not_counted_into_this_tenants_baseline(
    risk: RiskScene, foreign_risk: ForeignRiskTenant
) -> None:
    """The loudest possible neighbour changes nothing: the trail read is tenant-scoped.

    A foreign tenant is given a week of hours with a hundred requests an hour *in the same
    instants* this tenant's agent has its own history. If the aggregate were not scoped, the
    baseline mean would move by two orders of magnitude — so the arithmetic in the response
    is itself the isolation assertion.
    """
    agent_id = mine(risk)
    loud = foreign_risk.register_agent("Neighbour Agent")
    foreign: list[SeededEvent] = []
    for offset in range(BASELINE_HOURS):
        bucket = foreign_risk.observation_window()[0] - timedelta(hours=offset + 1)
        for index in range(100):
            foreign.append(
                SeededEvent(
                    event_type="action.requested",
                    minutes_ago=foreign_risk.minutes_ago(bucket + timedelta(seconds=index)),
                    agent_id=loud,
                    action="agent.posture_check",
                )
            )
    assert foreign_risk.seed(*foreign) == 100 * BASELINE_HOURS

    body = risk.assessment(agent_id)
    rate = next(item for item in body["dimensions"] if item["metric"] == "action_rate")
    assert rate["baseline_mean"] == pytest.approx(1.0), rate
    assert body["baseline"]["requests"] == BASELINE_HOURS
    assert body["observation"]["requests"] == 12


def test_the_page_is_this_registry_and_the_single_route_is_the_only_way_to_name_an_agent(
    risk: RiskScene, foreign_risk: ForeignRiskTenant, foreign_agent: uuid.UUID
) -> None:
    """The population is this organization's registry; naming a foreign agent is a 404.

    There is no filter on the page — a caller reads *its* registry, one page at a time — so a
    foreign agent cannot be smuggled into an assessment through a query parameter. The only
    route that names an agent answers about an identifier this organization holds, and the
    foreign identifier is answered exactly like an invented one.
    """
    agent_id = mine(risk)
    page = risk.assessments()
    assert page["count"] == 1
    assert [item["entity_id"] for item in page["items"]] == [str(agent_id)]

    # A page of the foreign registry is the foreign caller's own page, and never this one's.
    foreign_risk.seed_observation(foreign_agent, requests=1)
    assert (
        foreign_risk.as_owner()
        .get(
            f"/organizations/{foreign_risk.organization_id}/risk/agents",
            params=foreign_risk.query(),
        )
        .json()["count"]
        == 1
    )
    assert risk.assessments()["count"] == 1

    named = risk.get("agents", str(foreign_agent))
    assert named.status_code == 404, named.text
    assert named.json()["error"]["code"] == "not_found"


def test_the_detection_filters_stay_inside_the_tenant(
    risk: RiskScene, foreign_risk: ForeignRiskTenant, foreign_agent: uuid.UUID
) -> None:
    """A filter that only matches the other tenant's record returns nothing here.

    Every filter value is checked against the vocabulary first, so this is a well-formed
    request: the answer is empty because the rows are not this tenant's, not because the
    request was malformed.
    """
    agent_id = mine(risk)
    risk.record(agent_id)
    foreign_risk.seed_observation(foreign_agent, requests=1)
    assert foreign_risk.analyze(foreign_agent).status_code in (200, 201)

    ours = risk.stored()[0]
    level = ours["risk_level"]
    kind = ours["detection_type"]

    matches = risk.detected(risk_level=level, detection_type=kind)
    assert matches["count"] == 1
    assert matches["items"][0]["entity_id"] == str(agent_id)

    other_level = next(
        candidate
        for candidate in (RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH)
        if candidate.value != level
    )
    assert risk.detected(risk_level=other_level.value)["count"] == 0
    other_type = next(candidate for candidate in DetectionType if candidate.value != kind)
    assert risk.detected(detection_type=other_type.value)["count"] == 0
    assert risk.detected(assessment_status=AssessmentStatus.WITHIN_BASELINE.value)["count"] == 0


def test_paging_past_the_end_returns_nothing_rather_than_another_tenants_row(
    risk: RiskScene, foreign_risk: ForeignRiskTenant, foreign_agent: uuid.UUID
) -> None:
    """An offset is an offset into *this* tenant's feed, and the ceiling is bounded."""
    agent_id = mine(risk)
    risk.record(agent_id)
    foreign_risk.seed_observation(foreign_agent, requests=1)
    assert foreign_risk.analyze(foreign_agent).status_code in (200, 201)

    beyond = risk.detected(offset=50, total=True)
    assert beyond["items"] == []
    assert beyond["count"] == 0
    assert beyond["total"] == 1

    refused = risk.get("detections", limit=500)
    assert refused.status_code == 422, refused.text


def test_the_response_never_names_the_other_tenant(
    risk: RiskScene, foreign_risk: ForeignRiskTenant, foreign_agent: uuid.UUID
) -> None:
    """No identifier from the other organization appears anywhere in this one's answers."""
    agent_id = mine(risk)
    risk.record(agent_id)
    foreign_risk.seed_observation(foreign_agent, requests=1)
    assert foreign_risk.analyze(foreign_agent).status_code in (200, 201)

    bodies = [
        risk.assessment(agent_id),
        risk.assessments(),
        risk.detected(),
        risk.detection(risk.stored()[0]["id"]),
    ]
    forbidden = {
        str(foreign_risk.organization_id),
        str(foreign_agent),
        foreign_risk.identity.token,
        *[str(identifier) for identifier in foreign_risk.detection_ids()],
    }
    for body in bodies:
        rendered = str(body)
        for value in forbidden:
            assert value not in rendered, value


def test_the_membership_page_is_the_only_population_assessed(
    risk: RiskScene, foreign_risk: ForeignRiskTenant
) -> None:
    """An agent whose history is this tenant's but whose row is not is not assessed.

    ``fixed_agent_id`` is a stable identifier for seeded history that was never registered —
    the shape a trail can hold for an agent the registry no longer lists. It is not in this
    organization's registry, so it is not in the page: the phase assesses registered agents,
    which is why an unregistered identifier in the trail is inert rather than a finding.
    """
    risk.seed_observation(fixed_agent_id(99), requests=50)
    page = risk.assessments()
    assert page["count"] == 0
    assert page["items"] == []

    response = risk.get("agents", str(fixed_agent_id(99)))
    assert response.status_code == 404, response.text
    assert response.json()["error"]["code"] == "not_found"
    assert foreign_risk.detections()["count"] == 0
