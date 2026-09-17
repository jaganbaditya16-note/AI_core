"""Health endpoints.

``/health`` is a liveness probe: it answers as long as the process is serving.
``/health/ready`` is a readiness probe: it reports whether dependencies are
reachable, and returns 503 when any of them is not — which is what a load
balancer or orchestrator expects.
"""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from aicore_api.config import get_settings
from aicore_api.db.session import check_database
from aicore_api.schemas.health import HealthResponse, ReadinessCheck, ReadinessResponse

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness probe",
    description="Returns 200 while the API process is running. Does not touch the database.",
)
async def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
    )


@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    summary="Readiness probe",
    description="Checks configured dependencies (PostgreSQL). Returns 503 when any check fails.",
    responses={
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "model": ReadinessResponse,
            "description": "At least one dependency is unreachable",
        }
    },
)
async def readiness(response: Response) -> ReadinessResponse:
    settings = get_settings()
    reachable, detail = await check_database(
        timeout_seconds=settings.database_connect_timeout_seconds
    )

    checks = [
        ReadinessCheck(
            name="database",
            status="ok" if reachable else "error",
            detail="PostgreSQL reachable" if reachable else detail,
        )
    ]

    if not reachable:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(status="ok" if reachable else "error", checks=checks)
