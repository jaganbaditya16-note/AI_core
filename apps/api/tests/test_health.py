"""Health endpoint contract."""

from __future__ import annotations

from fastapi.testclient import TestClient

from aicore_api.config import Settings


def test_liveness_returns_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body == {
        "status": "ok",
        "service": "aicore-api",
        "version": Settings().app_version,
        "environment": "test",
    }


def test_liveness_ignores_the_database(client: TestClient) -> None:
    """Liveness must not depend on PostgreSQL (that is what readiness is for)."""
    # conftest points the database at a closed port; liveness still answers 200.
    assert client.get("/health").status_code == 200


def test_request_id_header_is_returned(client: TestClient) -> None:
    response = client.get("/health")
    assert response.headers.get("X-Request-ID")


def test_request_id_header_is_echoed_when_safe(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Request-ID": "trace-1234567890"})
    assert response.headers["X-Request-ID"] == "trace-1234567890"


def test_unsafe_request_id_header_is_replaced(client: TestClient) -> None:
    """Ids flow into logs and headers, so they are validated, not trusted."""
    response = client.get("/health", headers={"X-Request-ID": "bad id with spaces"})
    assert response.headers["X-Request-ID"] != "bad id with spaces"
    assert len(response.headers["X-Request-ID"]) == 32
