"""Contract tests for the bounded Nebius/Nemotron investigator."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from aicore_api.nebius.investigator import (
    InvestigatorUpstreamError,
    _extract_json,
    _payload,
)


def test_extract_json_accepts_fenced_output() -> None:
    brief = _extract_json('```json\n{"summary":"ok"}\n```')
    assert brief == {"summary": "ok"}


def test_extract_json_rejects_non_json() -> None:
    with pytest.raises(InvestigatorUpstreamError):
        _extract_json("I cannot answer safely")


def test_payload_is_bounded() -> None:
    value, truncated = _payload(
        {
            "evidence": {"large": "x" * 5000},
            "risk_factors": [{"reason": "y" * 5000} for _ in range(30)],
        }
    )
    assert truncated is True
    assert len(value["evidence"]["large"]) < 1000
    assert len(value["risk_factors"]) <= 12


def test_investigation_contract_never_adds_execution_fields() -> None:
    # This is intentionally a structural test rather than an inference-quality claim.
    from aicore_api.nebius.investigator import InvestigationBrief

    brief = InvestigationBrief(
        summary="Observed anomaly requires review.",
        why_it_matters=["The detection crossed a recorded threshold."],
        hypotheses=["A workload pattern may have changed."],
        checks=["Compare the observation window with the approved change record."],
        recommended_containment=["Have a human reviewer assess the affected agent."],
        confidence="medium",
        uncertainties=["The detection does not establish root cause."],
        do_not_do=["Do not execute remediation solely from this model output."],
    )
    assert "execute" not in brief.model_dump()
    assert "command" not in json.dumps(brief.model_dump()).lower()
