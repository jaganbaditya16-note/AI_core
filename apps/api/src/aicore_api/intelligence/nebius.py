"""Nebius Token Factory adapter for advisory-only Nemotron reasoning."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from openai import AsyncOpenAI

from aicore_api.config import Settings
from aicore_api.schemas.intelligence import (
    IntelligenceAdvisoryRequest,
    IntelligenceAdvisoryResponse,
)

_SYSTEM_PROMPT = """You are the advisory reasoning layer inside AICore, an enterprise AI control plane.
You are NOT an authorization engine and you never approve, deny, execute, contain, suspend, or
change a security control. AICore's deterministic services already made the security decision.
Your job is to help a human reviewer understand structured signals and choose safe next steps.
Never invent telemetry. Never request secrets, credentials, tokens, raw payloads, or private data.
Return JSON with exactly these keys: advisory, likely_causes, safe_next_steps, questions_for_reviewer.
Each list must contain short strings. Recommendations must be reversible, human-reviewed actions.
"""


class IntelligenceUnavailable(RuntimeError):
    """Raised when the advisory provider is deliberately not configured."""


class NebiusAdvisoryService:
    """Small, stateless adapter. No conversation history or prompts are persisted."""

    def __init__(self, settings: Settings) -> None:
        if not settings.nebius_api_key or not settings.intelligence_enabled:
            raise IntelligenceUnavailable("Nebius advisory is not configured")
        self._model = settings.nebius_model
        self._client = AsyncOpenAI(
            api_key=settings.nebius_api_key.get_secret_value(),
            base_url=settings.nebius_base_url,
            timeout=20.0,
            max_retries=1,
        )

    async def advise(self, request: IntelligenceAdvisoryRequest) -> IntelligenceAdvisoryResponse:
        signals = [signal.model_dump() for signal in request.signals]
        user_payload = {
            "incident_type": request.incident_type,
            "risk_level": request.risk_level,
            "affected_agent": request.affected_agent,
            "signals": signals,
            "requested_focus": request.requested_focus,
        }
        completion = await self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(user_payload, separators=(",", ":"))},
            ],
            temperature=0.1,
            max_tokens=700,
            response_format={"type": "json_object"},
        )
        content = completion.choices[0].message.content
        if not content:
            raise RuntimeError("Nebius returned an empty advisory")
        try:
            data: dict[str, Any] = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Nebius returned invalid advisory JSON") from exc

        def strings(name: str) -> list[str]:
            value = data.get(name, [])
            if not isinstance(value, list):
                return []
            return [item for item in value if isinstance(item, str)][:6]

        advisory = data.get("advisory")
        if not isinstance(advisory, str) or not advisory.strip():
            raise RuntimeError("Nebius advisory omitted its summary")

        return IntelligenceAdvisoryResponse(
            provider="nebius-token-factory",
            model=self._model,
            generated_at=datetime.now(UTC).isoformat(),
            advisory=advisory[:4000],
            likely_causes=strings("likely_causes"),
            safe_next_steps=strings("safe_next_steps"),
            questions_for_reviewer=strings("questions_for_reviewer"),
            safety_note="AI output is advisory only; AICore policy and firewall decisions remain deterministic.",
        )
