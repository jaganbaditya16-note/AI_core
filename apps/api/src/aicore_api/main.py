"""Application factory.

Importing this module builds the ASGI app, which means configuration is read and
validated at import time: an invalid environment fails at startup rather than on
the first request.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aicore_api.api.router import api_router
from aicore_api.config import Settings, get_settings
from aicore_api.core.errors import register_exception_handlers
from aicore_api.core.logging import configure_logging
from aicore_api.core.middleware import register_middleware
from aicore_api.db.session import dispose_engine

logger = logging.getLogger(__name__)

DESCRIPTION = """
AICore is an enterprise AI control plane.

**Implemented today:** health endpoints, the PostgreSQL multi-tenancy foundation,
the authentication and RBAC foundation on top of it, the AI asset inventory, and
the agent registry. Bearer API tokens identify a user, memberships bind them to an
organization with a role, routes authorize against the explicit permissions that
role grants, the inventory records what AI-related things an organization knows
about, and the registry gives an ``agent`` asset a stable identity that survives
renames and version changes.

Every tenant-scoped route resolves the caller's membership in the organization in
its path before it runs. The policy engine, the action firewall, agent execution,
audit records, incidents and intelligence features are still not implemented, and
no endpoint pretends otherwise: nothing here starts, stops, blocks or contains an
agent, and ``status: suspended`` is a record rather than a runtime control. Tenant
creation remains a development/test provisioning path, because this build has no
platform-administrator concept that could authorize it.
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    logger.info(
        "Starting %s v%s (%s)",
        settings.app_name,
        settings.app_version,
        settings.environment,
    )
    logger.info("Configuration: %s", settings.safe_summary())
    try:
        yield
    finally:
        dispose_engine()
        logger.info("Shutdown complete")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application. ``settings`` is injectable for tests."""
    resolved = settings or get_settings()
    configure_logging(resolved.log_level)

    app = FastAPI(
        title="AICore API",
        version=resolved.app_version,
        description=DESCRIPTION,
        docs_url="/docs" if resolved.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if resolved.docs_enabled else None,
        lifespan=lifespan,
        openapi_tags=[
            {
                "name": "health",
                "description": "Liveness and readiness probes for orchestrators and monitoring.",
            },
            {
                "name": "identity",
                "description": (
                    "The authenticated caller: who they are, the organizations they "
                    "belong to, the role they hold and the permissions it grants."
                ),
            },
            {
                "name": "organizations",
                "description": (
                    "Tenant reads, authorized by membership and permission. Tenant "
                    "creation remains development/test only, because it cannot be "
                    "authorized until a platform-administrator concept exists."
                ),
            },
        ],
    )
    app.state.settings = resolved

    register_middleware(app)
    register_exception_handlers(app)

    # CORS is opt-in: with the default (empty) configuration no cross-origin
    # request is permitted, which is what the same-origin proxy architecture wants.
    if resolved.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(resolved.cors_allow_origins),
            allow_credentials=resolved.cors_allow_credentials,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

    app.include_router(api_router)
    return app


app = create_app()
