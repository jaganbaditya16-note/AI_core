"""Contracts for the optional Nebius/NVIDIA advisory layer.

The request deliberately accepts only structured, bounded incident signals.
Arbitrary prompts are not forwarded to the model, which keeps the feature from
becoming an ungoverned general-purpose proxy.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class IntelligenceSignal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    value: str = Field(min_length=1, max_length=500)


class IntelligenceAdvisoryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_type: str = Field(min_length=1, max_length=80)
    risk_level: str = Field(min_length=1, max_length=24)
    affected_agent: str | None = Field(default=None, max_length=120)
    signals: list[IntelligenceSignal] = Field(default_factory=list, max_length=12)
    requested_focus: str = Field(default="Explain likely causes and safe next steps.", max_length=300)


class IntelligenceAdvisoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    model: str
    generated_at: str
    advisory: str
    likely_causes: list[str]
    safe_next_steps: list[str]
    questions_for_reviewer: list[str]
    safety_note: str
