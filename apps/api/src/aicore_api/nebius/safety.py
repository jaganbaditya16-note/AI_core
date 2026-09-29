"""Security boundaries for data crossing the Nebius/Nemotron trust boundary.

The model is an untrusted reasoning component. This module keeps the boundary small:
only server-selected fields cross it, high-risk keys are redacted recursively, payload
size is capped, and model output is rejected when it appears to contain credentials.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

MAX_INPUT_BYTES = 32_768
MAX_OUTPUT_CHARS = 12_000

_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|set-cookie|"
    r"private[_-]?key|client[_-]?secret|access[_-]?key|refresh[_-]?token|credential)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?:Bearer\s+[A-Za-z0-9._~+/=-]{16,}|"
    r"(?:sk|pk|api|key|token)[_-]?[A-Za-z0-9]{20,}|"
    r"(?:ghp_|github_pat_|xoxb-|AIza|AKIA)[A-Za-z0-9_-]{16,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
    re.IGNORECASE,
)


def _redact(value: Any, *, depth: int = 0) -> tuple[Any, bool]:
    if depth > 8:
        return "[redacted:depth]", True
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        changed = False
        for raw_key, raw_value in list(value.items())[:64]:
            key = str(raw_key)[:120]
            if _SENSITIVE_KEY.search(key):
                result[key] = "[redacted:sensitive-field]"
                changed = True
                continue
            clean, was_changed = _redact(raw_value, depth=depth + 1)
            result[key] = clean
            changed = changed or was_changed
        return result, changed
    if isinstance(value, list):
        result = []
        changed = len(value) > 64
        for item in value[:64]:
            clean, was_changed = _redact(item, depth=depth + 1)
            result.append(clean)
            changed = changed or was_changed
        if len(value) > 64:
            result.append("[redacted:list-tail]")
        return result, changed
    if isinstance(value, str):
        clean = _SECRET_VALUE.sub("[redacted:secret]", value)
        return clean, clean != value
    return value, False


def sanitize_for_model(value: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Redact credential-shaped material before serialization to the model."""
    clean, changed = _redact(value)
    if not isinstance(clean, dict):
        raise ValueError("model input must remain an object")
    return clean, changed


def serialize_bounded(value: dict[str, Any]) -> tuple[bytes, bool]:
    """Serialize and enforce a hard byte ceiling for outbound model input."""
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(encoded) <= MAX_INPUT_BYTES:
        return encoded, False

    # Deterministic second-stage truncation: preserve structure, not arbitrary bytes.
    reduced = {
        "safety_note": "Input exceeded the model boundary and was reduced.",
        "data": {},
    }
    data = value.get("data", value)
    if isinstance(data, dict):
        for key, item in data.items():
            reduced["data"][key] = item
            candidate = json.dumps(
                reduced,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
            if len(candidate) > MAX_INPUT_BYTES:
                reduced["data"].pop(key)
                reduced["truncated"] = True
                break
    encoded = json.dumps(reduced, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(encoded) > MAX_INPUT_BYTES:
        encoded = (
            b'{"safety_note":"Evidence was too large to send safely.",'
            b'"truncated":true}'
        )
    return encoded, True


def evidence_digest(encoded: bytes) -> str:
    """Stable non-secret identifier for the exact bounded evidence sent to the model."""
    return hashlib.sha256(encoded).hexdigest()


def reject_secret_like_output(text: str) -> str:
    """Return safe model text or raise when it contains credential-shaped material."""
    if len(text) > MAX_OUTPUT_CHARS:
        raise ValueError("model output exceeded the safety boundary")
    if _SECRET_VALUE.search(text):
        raise ValueError("model output contained credential-shaped material")
    return text
