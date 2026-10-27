"""Security and failure-path tests for the intelligence API route."""

import asyncio

import pytest
from fastapi import HTTPException
from pydantic import SecretStr

from aicore_api.api.routes import intelligence as route_module
from aicore_api.intelligence import IntelligenceUnavailable
from aicore_api.schemas.intelligence import (
    IntelligenceAdvisoryRequest,
    IntelligenceAdvisoryResponse,
)

SERVICE_TOKEN = "unit-test-service-token"


def make_request() -> IntelligenceAdvisoryRequest:
    return IntelligenceAdvisoryRequest(
        incident_type="suspicious-agent-activity",
        risk_level="high",
        affected_agent="agent-17",
        signals=[],
        requested_focus="Explain likely causes and safe next steps.",
    )


def make_response() -> IntelligenceAdvisoryResponse:
    return IntelligenceAdvisoryResponse(
        provider="nebius-token-factory",
        model="unit-test-model",
        generated_at="2026-01-01T00:00:00+00:00",
        advisory="Review the unusual activity.",
        likely_causes=["Unexpected retries"],
        safe_next_steps=["Inspect the audit log"],
        questions_for_reviewer=["Was this expected?"],
        safety_note="AI output is advisory only.",
    )


def configured_settings(settings, *, token=SERVICE_TOKEN):
    value = SecretStr(token) if token is not None else None
    return settings.model_copy(
        update={"intelligence_service_token": value}
    )


def install_fake_service(monkeypatch, result=None, error=None):
    class FakeService:
        def __init__(self, received_settings) -> None:
            pass

        async def advise(self, request):
            if error is not None:
                raise error
            return result

    monkeypatch.setattr(
        route_module, "NebiusAdvisoryService", FakeService
    )


def install_settings(monkeypatch, test_settings) -> None:
    monkeypatch.setattr(
        route_module, "get_settings", lambda: test_settings
    )


def test_valid_service_token_returns_advisory(monkeypatch, settings) -> None:
    test_settings = configured_settings(settings)
    expected = make_response()
    install_settings(monkeypatch, test_settings)
    install_fake_service(monkeypatch, result=expected)

    actual = asyncio.run(
        route_module.create_advisory(
            make_request(),
            x_aicore_intelligence_token=SERVICE_TOKEN,
        )
    )

    assert actual == expected


def test_missing_service_configuration_returns_503(
    monkeypatch, settings
) -> None:
    test_settings = configured_settings(settings, token=None)
    install_settings(monkeypatch, test_settings)

    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            route_module.create_advisory(
                make_request(),
                x_aicore_intelligence_token=SERVICE_TOKEN,
            )
        )

    assert raised.value.status_code == 503
    assert raised.value.detail == "AI advisory is not enabled"


def test_missing_request_token_returns_503(monkeypatch, settings) -> None:
    test_settings = configured_settings(settings)
    install_settings(monkeypatch, test_settings)

    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            route_module.create_advisory(
                make_request(),
                x_aicore_intelligence_token=None,
            )
        )

    assert raised.value.status_code == 503


def test_incorrect_service_token_returns_401(
    monkeypatch, settings
) -> None:
    test_settings = configured_settings(settings)
    install_settings(monkeypatch, test_settings)

    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            route_module.create_advisory(
                make_request(),
                x_aicore_intelligence_token="incorrect-test-token",
            )
        )

    assert raised.value.status_code == 401
    assert raised.value.detail == "Invalid service credential"


def test_unavailable_ai_service_returns_503(
    monkeypatch, settings
) -> None:
    test_settings = configured_settings(settings)
    install_settings(monkeypatch, test_settings)
    install_fake_service(
        monkeypatch,
        error=IntelligenceUnavailable("test-only unavailable condition"),
    )

    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            route_module.create_advisory(
                make_request(),
                x_aicore_intelligence_token=SERVICE_TOKEN,
            )
        )

    assert raised.value.status_code == 503
    assert raised.value.detail == "AI advisory is not configured"


def test_provider_failure_is_sanitized_as_502(
    monkeypatch, settings
) -> None:
    test_settings = configured_settings(settings)
    install_settings(monkeypatch, test_settings)
    install_fake_service(
        monkeypatch,
        error=RuntimeError("private provider response must not leak"),
    )

    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            route_module.create_advisory(
                make_request(),
                x_aicore_intelligence_token=SERVICE_TOKEN,
            )
        )

    assert raised.value.status_code == 502
    assert raised.value.detail == "AI advisory provider request failed"
    assert "private provider response" not in raised.value.detail
