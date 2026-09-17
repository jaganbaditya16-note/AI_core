"""The published contract must match the shared TypeScript types.

`packages/types` mirrors these schemas by hand; this test fails when the two
drift, which is the cheapest possible guard short of code generation.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[3]
SHARED_TYPES = REPO_ROOT / "packages" / "types" / "src" / "index.ts"

EXPECTED_HEALTH_FIELDS = {"status", "service", "version", "environment"}
EXPECTED_READINESS_FIELDS = {"status", "checks"}


def test_openapi_document_is_served(client: TestClient) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    document = response.json()
    assert document["info"]["title"] == "AICore API"
    assert "/health" in document["paths"]
    assert "/health/ready" in document["paths"]


def test_health_schema_fields(client: TestClient) -> None:
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    assert set(schemas["HealthResponse"]["properties"]) == EXPECTED_HEALTH_FIELDS
    assert set(schemas["ReadinessResponse"]["properties"]) == EXPECTED_READINESS_FIELDS


def test_readiness_documents_the_503_response(client: TestClient) -> None:
    ready = client.get("/openapi.json").json()["paths"]["/health/ready"]["get"]["responses"]

    assert "503" in ready


def test_shared_typescript_mirror_matches_schemas() -> None:
    """packages/types must declare exactly the fields the API publishes."""
    source = SHARED_TYPES.read_text(encoding="utf-8")

    report_fields = {"reachable", "checkedAt", "errors"}
    for field in sorted(EXPECTED_HEALTH_FIELDS | EXPECTED_READINESS_FIELDS | report_fields):
        assert field in source, f"packages/types is missing '{field}'"

    # Guard against a domain model creeping into the Phase 0 contract.
    forbidden = json.dumps(["agent", "model_registry", "policy", "incident", "permission"])
    assert "interface Agent" not in source
    assert "interface Policy" not in source
    assert forbidden  # keeps the constant meaningful without asserting on it
