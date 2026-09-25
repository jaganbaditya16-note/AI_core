"""Phase 10 security: who may read risk, whose data they see, and what they cannot send.

- **RBAC.** ``audit.read``: the owner and the security administrator; nobody else —
  including the analyst, whose ``security.read`` does not grant the trail.
- **Tenant isolation.** Every path is scoped by the organization in the URL, resolved
  through the caller's membership. A foreign organization is a 404; a foreign agent id
  selects nothing; a foreign detection id is a 404; recording in one tenant never writes to
  another; a repository without a tenant cannot be built.
- **No spoofing.** The surface is ``GET`` only, with no request body. Parameters that name
  engine outputs (a risk level, an anomaly state, evidence, a baseline value) are not
  inputs: sending them changes nothing. Out-of-vocabulary values are refused with 422.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from aicore_api.db.repositories.anomaly_detections import AnomalyDetectionRepository
from aicore_api.db.repositories.risk_history import RiskHistoryRepository
from aicore_api.db.tenancy import TenantScopeError
from audit_fixture import delete_events
from identity_fixture import IdentityFactory
from monitoring_fixture import fixed_agent_id
from risk_fixture import (
    CANARY_SECRET,
    DENIED,
    RiskScene,
    count_detections,
    delete_detections,
    observed,
    risk_path,
    seed_risk_events,
    steady_history,
    windows_for,
)

AGENT = fixed_agent_id(401)
VIEWS = ("analysis", "detections", f"detections/{uuid.uuid4()}")


def _anomalous(agent: uuid.UUID, risk: RiskScene) -> list[Any]:
    windows = risk.windows()
    return steady_history(agent, windows, per_slot=3) + observed(
        agent, windows, count=6, outcome=DENIED, action="agent.rotate_keys"
    )


class Foreign:
    """A second, committed tenant with its own owner and its own anomalous agent."""

    def __init__(self, identity: Any, authenticate: Any, engine: Engine) -> None:
        self.identity = identity
        self.organization_id: uuid.UUID = identity.organization_id
        self._authenticate = authenticate
        self.engine = engine

    def as_owner(self) -> TestClient:
        client: TestClient = self._authenticate(self.identity)
        return client


@pytest.fixture
def foreign(
    identity_factory: IdentityFactory, authenticate: Any, integration_engine: Engine
) -> Any:
    identity = identity_factory(role_code="owner")
    tenant = Foreign(identity, authenticate, integration_engine)
    try:
        yield tenant
    finally:
        delete_detections(integration_engine, tenant.organization_id)
        delete_events(integration_engine, tenant.organization_id, "phase 10 risk teardown")


def _seed_foreign(foreign: Foreign, risk: RiskScene) -> None:
    seed_risk_events(foreign.engine, foreign.organization_id, _anomalous(AGENT, risk))


def _record_foreign(foreign: Foreign, risk: RiskScene) -> None:
    assert risk.record(organization=str(foreign.organization_id)) == 0


# ── RBAC ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("view", VIEWS[:2])
def test_the_owner_reads_risk(risk: RiskScene, view: str) -> None:
    params = {"as_of": risk.as_of.isoformat()} if view == "analysis" else {}
    assert risk.get(view, **params).status_code == 200


@pytest.mark.parametrize("view", VIEWS[:2])
def test_the_security_administrator_reads_risk(
    risk: RiskScene, identity_factory: IdentityFactory, authenticate: Any, view: str
) -> None:
    member = identity_factory(role_code="viewer")
    member = identity_factory.join(
        member, organization_id=risk.organization_id, role_code="security_admin"
    )
    response = authenticate(member).get(risk_path(risk.organization_id, view))
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("role", ["analyst", "admin", "ai_admin", "viewer"])
@pytest.mark.parametrize("view", VIEWS)
def test_every_other_role_is_refused(
    risk: RiskScene,
    identity_factory: IdentityFactory,
    authenticate: Any,
    role: str,
    view: str,
) -> None:
    member = identity_factory(role_code="viewer")
    member = identity_factory.join(member, organization_id=risk.organization_id, role_code=role)
    response = authenticate(member).get(risk_path(risk.organization_id, view))
    assert response.status_code == 403, response.text


@pytest.mark.parametrize("view", VIEWS)
def test_an_anonymous_caller_is_401(risk: RiskScene, view: str) -> None:
    client = risk.monitoring.trail.client
    client.headers.pop("Authorization", None)
    try:
        response = client.get(risk_path(risk.organization_id, view))
        assert response.status_code == 401
    finally:
        risk.monitoring.trail.as_owner()


@pytest.mark.parametrize("view", VIEWS)
def test_a_bad_token_is_401(risk: RiskScene, view: str) -> None:
    response = risk.client.get(
        risk_path(risk.organization_id, view), headers={"Authorization": "Bearer aicore_bogus"}
    )
    assert response.status_code == 401


# ── tenant isolation ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("view", VIEWS)
def test_another_organization_is_not_found(risk: RiskScene, foreign: Foreign, view: str) -> None:
    response = risk.client.get(risk_path(foreign.organization_id, view))
    assert response.status_code == 404


@pytest.mark.parametrize("view", VIEWS)
def test_an_unknown_organization_is_not_found(risk: RiskScene, view: str) -> None:
    response = risk.client.get(risk_path(uuid.uuid4(), view))
    assert response.status_code == 404


def test_a_foreign_agents_history_is_invisible(risk: RiskScene, foreign: Foreign) -> None:
    _seed_foreign(foreign, risk)

    theirs = foreign.as_owner().get(
        risk_path(foreign.organization_id, "analysis"),
        params={"as_of": risk.as_of.isoformat(), "agent_id": str(AGENT)},
    )
    assert theirs.status_code == 200
    assert theirs.json()["items"][0]["anomaly_state"] == "anomalous"

    ours = risk.analysis(agent_id=str(AGENT), total="true")
    assert ours["items"] == [] and ours["total"] == 0
    assert risk.analysis(total="true")["total"] == 0


def test_the_same_agent_id_in_two_tenants_is_two_histories(
    risk: RiskScene, foreign: Foreign
) -> None:
    """History is never pooled across tenants, even for an identical agent id."""
    _seed_foreign(foreign, risk)
    windows = risk.windows()
    risk.seed(steady_history(AGENT, windows, per_slot=3) + observed(AGENT, windows, count=3))

    ours = risk.agent(AGENT)

    assert ours["anomaly_state"] == "not_anomalous"
    assert ours["observation"]["denials"] == 0
    assert ours["baseline_statistics"]["events"] == 42


def test_foreign_detections_are_neither_listed_nor_readable(
    risk: RiskScene, foreign: Foreign, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed_foreign(foreign, risk)
    _record_foreign(foreign, risk)
    capsys.readouterr()
    theirs = foreign.as_owner().get(risk_path(foreign.organization_id, "detections")).json()
    assert theirs["items"]
    foreign_id = theirs["items"][0]["id"]

    assert risk.detections(total="true")["total"] == 0
    assert risk.detections(agent_id=str(AGENT))["items"] == []
    response = risk.get(f"detections/{foreign_id}")
    assert response.status_code == 404
    assert foreign_id not in response.text


def test_recording_one_tenant_never_writes_another(
    risk: RiskScene, foreign: Foreign, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed_foreign(foreign, risk)
    risk.seed(_anomalous(AGENT, risk))

    assert risk.record() == 0
    capsys.readouterr()

    assert count_detections(foreign.engine, foreign.organization_id) == 0
    assert {row["organization_id"] for row in risk.stored()} == {risk.organization_id}


def test_repositories_cannot_be_built_without_a_tenant(integration_session: Session) -> None:
    with pytest.raises(TenantScopeError):
        RiskHistoryRepository(integration_session)
    with pytest.raises(TenantScopeError):
        AnomalyDetectionRepository(integration_session)


def test_a_repository_scoped_to_one_tenant_sees_only_that_tenant(
    risk: RiskScene,
    foreign: Foreign,
    integration_engine: Engine,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _seed_foreign(foreign, risk)
    _record_foreign(foreign, risk)
    capsys.readouterr()
    windows = windows_for(risk.as_of)

    with Session(integration_engine) as session:
        history = RiskHistoryRepository(session, risk.organization_id)
        store = AnomalyDetectionRepository(session, risk.organization_id)
        assert history.agent_page(windows, limit=100, offset=0) == []
        assert history.count_agents(windows) == 0
        profiles = history.profiles(windows, [AGENT])
        assert profiles[0].baseline_requests == 0 and profiles[0].observed_requests == 0
        assert store.list(limit=100, offset=0) == []
        assert store.count() == 0

        foreign_store = AnomalyDetectionRepository(session, foreign.organization_id)
        foreign_rows = foreign_store.list(limit=100, offset=0)
        assert foreign_rows
        assert store.get(foreign_rows[0].id) is None


# ── spoofing ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
@pytest.mark.parametrize("view", VIEWS)
def test_nothing_can_be_written_through_the_api(risk: RiskScene, method: str, view: str) -> None:
    body = {
        "risk_level": "none",
        "anomaly_state": "not_anomalous",
        "detection_type": "novel_action",
        "evidence": {"forged": True},
        "risk_factors": [],
    }
    kwargs: dict[str, Any] = {} if method == "delete" else {"json": body}
    response = getattr(risk.client, method)(risk_path(risk.organization_id, view), **kwargs)
    assert response.status_code == 405
    assert count_detections(risk.engine, risk.organization_id) == 0


def test_engine_outputs_sent_as_parameters_change_nothing(risk: RiskScene) -> None:
    risk.seed(_anomalous(AGENT, risk))
    honest = risk.analysis()

    forged = risk.analysis(
        risk_level="none",
        anomaly_state="not_anomalous",
        status="insufficient_history",
        evidence=json.dumps({"forged": True}),
        risk_factors="[]",
        baseline_mean="1000",
        baseline_stddev="1000",
        threshold="1000000",
        detection_type="novel_action",
        organization_id=str(uuid.uuid4()),
    )

    assert forged == honest
    assert honest["items"][0]["anomaly_state"] == "anomalous"


def test_a_body_on_a_read_is_ignored(risk: RiskScene) -> None:
    risk.seed(_anomalous(AGENT, risk))
    honest = risk.analysis()
    response = risk.client.request(
        "GET",
        risk_path(risk.organization_id, "analysis"),
        params={"as_of": risk.as_of.isoformat()},
        json={"items": [], "risk_level": "none"},
    )
    assert response.status_code == 200
    assert response.json() == honest


@pytest.mark.parametrize(
    ("view", "params"),
    [
        ("analysis", {"baseline": "90d"}),
        ("analysis", {"observation": "5m"}),
        ("analysis", {"as_of": "2026-01-01T10:30:00+00:00"}),
        ("analysis", {"as_of": "2026-01-01T10:00:00"}),
        ("analysis", {"as_of": "2999-01-01T00:00:00+00:00"}),
        ("analysis", {"as_of": "yesterday"}),
        ("analysis", {"limit": "101"}),
        ("analysis", {"limit": "0"}),
        ("analysis", {"offset": "-1"}),
        ("analysis", {"agent_id": "not-a-uuid"}),
        ("detections", {"risk_level": "severe"}),
        ("detections", {"detection_type": "suspicious_vibes"}),
        ("detections", {"limit": "201"}),
        ("detections", {"agent_id": "1; DROP TABLE aicore.audit_events"}),
    ],
)
def test_out_of_vocabulary_parameters_are_422(
    risk: RiskScene, view: str, params: dict[str, str]
) -> None:
    response = risk.get(view, **params)
    assert response.status_code == 422, response.text


def test_a_malformed_detection_id_is_422(risk: RiskScene) -> None:
    assert risk.get("detections/not-a-uuid").status_code == 422


# ── privacy ───────────────────────────────────────────────────────────────────


def test_no_response_carries_metadata_or_the_canary(
    risk: RiskScene, capsys: pytest.CaptureFixture[str]
) -> None:
    risk.seed(_anomalous(AGENT, risk))
    assert risk.record() == 0
    capsys.readouterr()
    detection_id = risk.stored()[0]["id"]

    for response in (
        risk.get("analysis", as_of=risk.as_of.isoformat()),
        risk.get("detections"),
        risk.get(f"detections/{detection_id}"),
    ):
        assert response.status_code == 200
        assert CANARY_SECRET not in response.text
        assert "metadata" not in response.text
        assert "correlation_id" not in response.text
        assert "actor_type" not in response.text and "actor_user_id" not in response.text


def test_evidence_names_no_person_and_no_credential(risk: RiskScene) -> None:
    risk.seed(_anomalous(AGENT, risk))
    items = risk.analysis()["items"]
    for detection in items[0]["detections"]:
        rendered = json.dumps(detection["evidence"])
        for forbidden in ("user_id", "membership_id", "token", "password", "secret", "arguments"):
            assert forbidden not in rendered


def test_the_cold_start_response_invents_no_baseline(risk: RiskScene) -> None:
    windows = risk.windows()
    risk.seed(observed(AGENT, windows, count=50, spacing=timedelta(seconds=5)))
    analysis = risk.agent(AGENT)
    assert analysis["baseline_statistics"] is None
    assert analysis["risk_level"] == "none"
    assert analysis["anomaly_state"] == "undetermined"
