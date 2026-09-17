"""Health and error schemas.

These models are the source of truth for the OpenAPI document and are mirrored
in TypeScript by ``packages/types``.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

CheckStatus = Literal["ok", "error"]


class HealthResponse(BaseModel):
    """Liveness: the process is up and serving requests."""

    status: Literal["ok"] = "ok"
    service: str = Field(description="Service identifier, e.g. aicore-api")
    version: str = Field(description="Running application version")
    environment: str = Field(description="Deployment environment (development, production, …)")


class ReadinessCheck(BaseModel):
    """Result of a single dependency probe."""

    name: str = Field(description="Dependency identifier, e.g. database")
    status: CheckStatus
    detail: str | None = Field(
        default=None,
        description="Human-readable detail; error text is sanitized and never contains credentials",
    )


class ReadinessResponse(BaseModel):
    """Readiness: the service can serve traffic (all dependencies reachable)."""

    status: Literal["ok", "error"]
    checks: list[ReadinessCheck]


class ErrorBody(BaseModel):
    """Machine-readable error payload."""

    code: str = Field(description="Stable error code, e.g. not_found, internal_error")
    message: str = Field(description="Human-readable summary, safe to display")
    details: object | None = Field(default=None, description="Optional structured details")
    request_id: str | None = Field(default=None, description="Correlation id for log lookup")


class ErrorResponse(BaseModel):
    """Envelope returned for every non-2xx API response."""

    error: ErrorBody
