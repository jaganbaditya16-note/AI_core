"""Mocked unit tests for the Nebius advisory adapter."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from pydantic import SecretStr

from aicore_api.intelligence import IntelligenceUnavailable, NebiusAdvisoryService
from aicore_api.intelligence import nebius as nebius_module
from aicore_api.schemas.intelligence import (
    IntelligenceAdvisoryRequest,
    IntelligenceSignal,
)


def make_request() -> IntelligenceAdvisoryRequest:
    return IntelligenceAdvisoryRequest(
        incident_type="suspicious-agent-activity",
        risk_level="high",
        affected_agent="agent-17",
        signals=[
            IntelligenceSignal(
                name="action attempts",
                value="42 in 5 minutes",
            )
        ],
        requested_focus="Explain likely causes and safe next steps.",
    )


def make_service(monkeypatch, settings, content):
    completion = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
    )
    create = AsyncMock(return_value=completion)
    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(create=create),
        )
    )
    constructor = Mock(return_value=client)
    monkeypatch.setattr(nebius_module, "AsyncOpenAI", constructor)

    configured_settings = settings.model_copy(
        update={
            "nebius_api_key": SecretStr("unit-test-key"),
            "intelligence_service_token": SecretStr("unit-test-service-token"),
            "nebius_model": "unit-test-model",
        }
    )
    service = NebiusAdvisoryService(configured_settings)
    return service, constructor, create, configured_settings


def test_successful_advisory_uses_bounded_provider_request(
    monkeypatch, settings
) -> None:
    content = json.dumps(
        {
            "advisory": "  Investigate the unusual activity.  ",
            "likely_causes": ["Unexpected retries", "A misconfigured client"],
            "safe_next_steps": ["Review the audit log"],
            "questions_for_reviewer": ["Was this activity expected?"],
        }
    )
    service, constructor, create, configured = make_service(
        monkeypatch, settings, content
    )

    result = asyncio.run(service.advise(make_request()))

    constructor.assert_called_once_with(
        api_key="unit-test-key",
        base_url=configured.nebius_base_url,
        timeout=20.0,
        max_retries=0,
    )
    call = create.await_args.kwargs
    assert call["model"] == "unit-test-model"
    assert call["temperature"] == 0.1
    assert call["max_tokens"] == 700
    assert call["response_format"] == {"type": "json_object"}

    user_payload = json.loads(call["messages"][1]["content"])
    assert user_payload["incident_type"] == "suspicious-agent-activity"
    assert user_payload["risk_level"] == "high"
    assert user_payload["affected_agent"] == "agent-17"
    assert user_payload["signals"] == [
        {"name": "action attempts", "value": "42 in 5 minutes"}
    ]

    assert result.provider == "nebius-token-factory"
    assert result.model == "unit-test-model"
    assert result.advisory == "Investigate the unusual activity."
    assert result.likely_causes == ["Unexpected retries", "A misconfigured client"]
    assert result.safe_next_steps == ["Review the audit log"]
    assert result.questions_for_reviewer == ["Was this activity expected?"]
    assert "advisory only" in result.safety_note


def test_response_text_and_list_entries_are_bounded(monkeypatch, settings) -> None:
    content = json.dumps(
        {
            "advisory": "A" * 4500,
            "likely_causes": ["B" * 600] + [f"Cause {n}" for n in range(2, 9)],
            "safe_next_steps": ["", 42, "  Review the event  "],
            "questions_for_reviewer": [],
        }
    )
    service, _, _, _ = make_service(monkeypatch, settings, content)

    result = asyncio.run(service.advise(make_request()))

    assert len(result.advisory) == 4000
    assert result.advisory == "A" * 4000
    assert len(result.likely_causes) == 6
    assert result.likely_causes[0] == "B" * 500
    assert result.safe_next_steps == ["Review the event"]
    assert result.questions_for_reviewer == []


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (None, "empty advisory"),
        ("", "empty advisory"),
        ("not JSON", "invalid advisory JSON"),
        ("[]", "invalid advisory JSON object"),
        ("{}", "omitted its summary"),
    ],
)
def test_invalid_provider_responses_fail_safely(
    monkeypatch, settings, content, message
) -> None:
    service, _, _, _ = make_service(monkeypatch, settings, content)

    with pytest.raises(RuntimeError, match=message):
        asyncio.run(service.advise(make_request()))


def test_service_refuses_missing_key_or_disabled_feature(settings) -> None:
    missing_key = settings.model_copy(
        update={
            "nebius_api_key": None,
            "intelligence_service_token": SecretStr("unit-test-service-token"),
        }
    )
    disabled = settings.model_copy(
        update={
            "nebius_api_key": SecretStr("unit-test-key"),
            "intelligence_service_token": None,
        }
    )

    with pytest.raises(IntelligenceUnavailable):
        NebiusAdvisoryService(missing_key)

    with pytest.raises(IntelligenceUnavailable):
        NebiusAdvisoryService(disabled)
