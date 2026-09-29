"""Public contract for advisory Nemotron security investigations."""
from __future__ import annotations

from pydantic import BaseModel, Field


class InvestigationRequest(BaseModel):
    question: str | None = Field(default=None, max_length=1000)


class InvestigationResponse(BaseModel):
    detection_id: str
    model: str
    provider: str = "Nebius Token Factory"
    advisory_only: bool = True
    summary: str
    observations: list[str]
    hypotheses: list[str]
    reviewer_questions: list[str]
    confidence: str
    limitations: list[str]
