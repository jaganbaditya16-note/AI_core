"""Readiness endpoint behaviour."""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from aicore_api.config import Settings
from aicore_api.db.session import dispose_engine
from aicore_api.main import create_app


def test_readiness_reports_503_when_database_is_unreachable(client: TestClient) -> None:
    """conftest points PostgreSQL at a closed port, so readiness must fail closed."""
    response = client.get("/health/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "error"
    assert len(body["checks"]) == 1

    check = body["checks"][0]
    assert check["name"] == "database"
    assert check["status"] == "error"
    assert check["detail"]


def test_readiness_detail_never_leaks_credentials(client: TestClient) -> None:
    """Driver messages are redacted before they are returned."""
    detail = client.get("/health/ready").json()["checks"][0]["detail"]

    assert isinstance(detail, str)
    # No user:password fragment may survive, in any URL the driver mentions.
    assert "aicore:aicore@" not in detail
    assert re.search(r"://(?!\*\*\*@)[^/\s@]+@", detail) is None
    assert len(detail) <= 301


def test_readiness_uses_injected_settings(offline_settings: Settings) -> None:
    """The probe reads the configured URL rather than a hardcoded one."""
    dispose_engine()
    app = create_app(offline_settings)
    with TestClient(app, raise_server_exceptions=False) as local_client:
        response = local_client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["checks"][0]["name"] == "database"
