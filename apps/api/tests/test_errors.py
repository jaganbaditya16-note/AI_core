"""Error envelope behaviour."""

from __future__ import annotations

from fastapi import FastAPI, Query
from fastapi.testclient import TestClient

from aicore_api.core.errors import register_exception_handlers


def test_unknown_route_uses_the_error_envelope(client: TestClient) -> None:
    response = client.get("/does-not-exist")

    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "not_found"
    assert isinstance(error["message"], str)
    assert error["request_id"]


def test_wrong_method_uses_the_error_envelope(client: TestClient) -> None:
    response = client.post("/health")

    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"


def test_validation_errors_use_the_error_envelope() -> None:
    """Exercised through a throwaway app so Phase 0 adds no domain endpoints."""
    probe_app = FastAPI()
    register_exception_handlers(probe_app)

    @probe_app.get("/echo")
    async def echo(value: int = Query(description="An integer")) -> dict[str, int]:
        return {"value": value}

    with TestClient(probe_app, raise_server_exceptions=False) as probe_client:
        response = probe_client.get("/echo", params={"value": "not-an-int"})

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert isinstance(error["details"], list)
    assert error["details"][0]["location"] == ["query", "value"]


def test_unhandled_exception_returns_generic_500() -> None:
    """Internal details must never reach the client."""
    probe_app = FastAPI()
    register_exception_handlers(probe_app)

    @probe_app.get("/boom")
    async def boom() -> None:
        msg = "database password is hunter2"
        raise RuntimeError(msg)

    with TestClient(probe_app, raise_server_exceptions=False) as probe_client:
        response = probe_client.get("/boom")

    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "internal_error"
    assert body["error"]["message"] == "Internal server error"
    assert "hunter2" not in response.text
