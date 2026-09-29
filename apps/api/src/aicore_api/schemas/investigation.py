"""Public contract for the advisory Nemotron investigation endpoint."""

from __future__ import annotations

from pydantic import BaseModel, Field


class InvestigationRead(BaseModel):
    """A bounded investigation brief. It contains advice, never an executable action."""

    detection_id: str
    detection_type: str
    risk_level: str
    summary: str
    severity_interpretation: str
    why_it_matters: list[str]
    hypotheses: list[str]
    evidence_used: list[str]
    checks: list[str]
    recommended_containment: list[str]
    confidence: str
    uncertainties: list[str]
    do_not_do: list[str]
    model: str
    correlation_id: str | None
    input_truncated: bool = Field(
        description="True when the server bounded or redacted the detection before sending it to Nemotron."
    )
    evidence_digest: str = Field(
        min_length=64,
        max_length=64,
        description="SHA-256 of the exact bounded evidence representation sent to the model; not source data.",
    )
    action_taken: bool = Field(
        default=False,
        description="Always false: this endpoint cannot authorize or execute anything.",
    )


class InvestigationUnavailable(BaseModel):
    """Stable error shape for an optional, credentialed integration."""

    code: str
    message: str
