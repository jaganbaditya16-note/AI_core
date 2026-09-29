"""Bounded advisory investigation through Nebius Token Factory.

This module deliberately keeps the model outside authorization and execution. It receives
only a bounded, server-generated anomaly record and returns a structured investigation
brief. A model failure never changes the recorded detection and never executes an action.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

from pydantic import BaseModel, Field, ValidationError

from aicore_api.config import Settings


class InvestigatorError(RuntimeError):
    """Base error for advisory investigation failures."""


class InvestigatorUnavailableError(InvestigatorError):
    """Nebius credentials/configuration are unavailable."""


class InvestigatorUpstreamError(InvestigatorError):
    """Nebius Token Factory returned an unusable response."""


class InvestigationBrief(BaseModel):
    """Structured, non-executable investigation output."""

    summary: str = Field(min_length=1, max_length=1200)
    why_it_matters: list[str] = Field(min_length=1, max_length=6)
    hypotheses: list[str] = Field(min_length=1, max_length=6)
    checks: list[str] = Field(min_length=1, max_length=8)
    recommended_containment: list[str] = Field(min_length=1, max_length=8)
    confidence: str = Field(min_length=1, max_length=32)
    uncertainties: list[str] = Field(default_factory=list, max_length=8)
    do_not_do: list[str] = Field(min_length=1, max_length=6)


@dataclass(frozen=True, slots=True)
class InvestigationResult:
    brief: InvestigationBrief
    model: str
    correlation_id: str | None
    input_truncated: bool


_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)

_SYSTEM_PROMPT = """You are AICore's security investigation assistant.

You are advisory only. You do not authorize, approve, execute, block, delete, or change
anything. You must reason only from the supplied structured detection evidence.

Return JSON with exactly these keys:
summary, why_it_matters, hypotheses, checks, recommended_containment, confidence,
uncertainties, do_not_do.

Rules:
- Never invent evidence, users, assets, commands, credentials, IPs, or events.
- Never copy secrets or payloads into the answer.
- Every hypothesis must be explicitly framed as a hypothesis, not a fact.
- Checks must be safe verification questions a human operator can perform.
- recommended_containment must be non-executable control-plane guidance, not shell commands.
- do_not_do must state unsafe or unjustified actions to avoid.
- If evidence is insufficient, say so and lower confidence.
"""


def _bounded(value: Any, *, budget: list[int]) -> tuple[Any, bool]:
    """Bound nested JSON so model input cannot grow without limit."""
    if budget[0] <= 0:
        return "[truncated]", True
    budget[0] -= 1
    if isinstance(value, str):
        if len(value) > 600:
            return value[:600] + "…", True
        return value, False
    if isinstance(value, (int, float, bool)) or value is None:
        return value, False
    if isinstance(value, list):
        result: list[Any] = []
        truncated = len(value) > 12
        for item in value[:12]:
            bounded, cut = _bounded(item, budget=budget)
            result.append(bounded)
            truncated = truncated or cut
        return result, truncated
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        truncated = len(value) > 32
        for key, item in list(value.items())[:32]:
            bounded, cut = _bounded(item, budget=budget)
            result[str(key)[:120]] = bounded
            truncated = truncated or cut
        return result, truncated
    return str(value)[:600], True


def _extract_json(text: str) -> dict[str, Any]:
    candidate = text.strip()
    match = _JSON_FENCE.search(candidate)
    if match:
        candidate = match.group(1).strip()
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start < 0 or end <= start:
            raise InvestigatorUpstreamError(
                "Nebius returned non-JSON investigation output"
            ) from None
        try:
            parsed = json.loads(candidate[start : end + 1])
        except json.JSONDecodeError as exc:
            raise InvestigatorUpstreamError(
                "Nebius returned invalid investigation JSON"
            ) from exc
    if not isinstance(parsed, dict):
        raise InvestigatorUpstreamError("Nebius investigation JSON must be an object")
    return parsed


def _payload(detection: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    budget = [180]
    bounded, truncated = _bounded(detection, budget=budget)
    if not isinstance(bounded, dict):
        raise InvestigatorUpstreamError("internal detection payload is not an object")
    return bounded, truncated


def investigate(
    settings: Settings,
    detection: dict[str, Any],
    *,
    correlation_id: str | None = None,
) -> InvestigationResult:
    """Ask Nemotron for an advisory brief; never perform an action."""
    if settings.nebius_api_key is None or not settings.nebius_api_key.get_secret_value():
        raise InvestigatorUnavailableError("Nebius Token Factory is not configured")

    bounded_detection, truncated = _payload(detection)
    body = {
        "model": settings.nebius_model,
        "temperature": 0.1,
        "max_tokens": settings.nebius_max_output_tokens,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Investigate this anomaly record and return the required JSON only:\n"
                    + json.dumps(bounded_detection, separators=(",", ":"), ensure_ascii=True)
                ),
            },
        ],
    }
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
    req = urllib_request.Request(
        settings.nebius_base_url.rstrip("/") + "/chat/completions",
        data=encoded,
        method="POST",
        headers={
            "Authorization": f"Bearer {settings.nebius_api_key.get_secret_value()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib_request.urlopen(  # noqa: S310 - URL is validated as HTTPS configuration
            req, timeout=settings.nebius_timeout_seconds
        ) as response:
            raw = response.read(1_000_000)
    except (urllib_error.HTTPError, urllib_error.URLError, TimeoutError) as exc:
        raise InvestigatorUpstreamError("Nebius Token Factory inference failed") from exc

    try:
        envelope = json.loads(raw.decode("utf-8"))
        content = envelope["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise InvestigatorUpstreamError(
            "Nebius returned an unexpected inference envelope"
        ) from exc

    try:
        brief = InvestigationBrief.model_validate(_extract_json(str(content)))
    except ValidationError as exc:
        raise InvestigatorUpstreamError(
            "Nebius output failed the investigation contract"
        ) from exc

    return InvestigationResult(
        brief=brief,
        model=settings.nebius_model,
        correlation_id=correlation_id,
        input_truncated=truncated,
    )
