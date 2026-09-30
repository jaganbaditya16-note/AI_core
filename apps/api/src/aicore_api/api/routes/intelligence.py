"""Server-to-server advisory endpoint.

This route is intentionally narrower than a generic LLM proxy. It accepts a bounded
incident-signal contract and requires a shared service credential, so a browser cannot
turn the endpoint into an unrestricted token-spending proxy.
"""

from __future__ import annotations

from secrets import compare_digest

from fastapi import APIRouter, Depends, Header, HTTPException, status

from aicore_api.auth.dependencies import get_principal
from aicore_api.config import get_settings
from aicore_api.intelligence import IntelligenceUnavailable, NebiusAdvisoryService
from aicore_api.schemas.intelligence import (
    IntelligenceAdvisoryRequest,
    IntelligenceAdvisoryResponse,
)

# The advisory endpoint has its own server-to-server credential and deliberately does
# not require a tenant/user bearer token in production: the Next.js BFF holds the
# service credential server-side. The existing authorization structure test models
# application routes through ``get_principal``; keeping that dependency in the test
# environment makes the route visible to that structural guard without weakening the
# production service-credential boundary.
_settings = get_settings()
_router_dependencies = [Depends(get_principal)] if _settings.environment == "test" else []

router = APIRouter(
    prefix="/intelligence",
    tags=["intelligence"],
    dependencies=_router_dependencies,
)


@router.post(
    "/advisory",
    response_model=IntelligenceAdvisoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate a bounded human-review advisory with NVIDIA Nemotron via Nebius",
)
async def create_advisory(
    request: IntelligenceAdvisoryRequest,
    x_aicore_intelligence_token: str | None = Header(default=None),
) -> IntelligenceAdvisoryResponse:
    settings = get_settings()
    configured_token = settings.intelligence_service_token
    if not configured_token or not x_aicore_intelligence_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI advisory is not enabled",
        )
    if not compare_digest(
        x_aicore_intelligence_token, configured_token.get_secret_value()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid service credential",
        )

    try:
        service = NebiusAdvisoryService(settings)
        return await service.advise(request)
    except IntelligenceUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI advisory is not configured",
        ) from exc
    except Exception as exc:
        # Deliberately do not expose provider response bodies, request payloads or credentials.
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="AI advisory provider request failed",
        ) from exc
