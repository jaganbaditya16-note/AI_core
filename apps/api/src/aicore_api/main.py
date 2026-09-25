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
the authentication and RBAC foundation on top of it, the AI asset inventory, the
agent registry, the authorization foundation, the context-aware policy engine, the
action firewall, the audit trail, and monitoring over it. Bearer API tokens identify a
user, memberships
bind them to an organization with a role, routes authorize against explicit
permissions written as ``resource.action`` over closed vocabularies, the inventory
records what AI-related things an organization knows about, the registry gives an
``agent`` asset a stable identity that survives renames and version changes, an
organization can define policies — effect, priority and structured conditions over a
closed field vocabulary — that refine those permissions by context, one endpoint can
run an action from a closed, code-level catalogue through all of it, and every
security-relevant thing that happens is recorded in an append-only trail that the
organization can read back, and that record can be counted — activity, refusals,
failures, changes and trends, per window and per agent or action — without any of it
being turned into a score, a verdict or an alert. Every decision is deterministic
and derived from data,
never by a model: authorization answers *may this caller use this permission*, the
policy engine answers *given that, does the context satisfy the organization's
policy*, the firewall combines both into one outcome — allow, deny, or require
approval — where only allow reaches an adapter and neither layer can ever widen the
other, and the audit trail records what the others decided without deciding anything
itself.

Every tenant-scoped route resolves the caller's membership in the organization in
its path before it runs. The catalogue holds one action today, and it reads and
reports: ``agent.posture_check`` assesses facts this system already stores about one
registered agent, and its adapter opens no connection, no file and no socket. The
audit trail is written by the platform and read through one endpoint; no route lets a
client create, change or delete an event, and no permission grants one. Agent
execution, approval workflows, anomaly detection, risk scoring, incidents, alerting,
the kill switch and intelligence features are still not implemented, and no endpoint
pretends otherwise: monitoring counts what the trail recorded and states no opinion
about it, nothing here starts, stops, blocks, approves or contains an agent,
``status: suspended`` is a record rather than a runtime control, an approval
requirement is a value with no workflow behind it, the audit trail is evidence rather
than detection, and a policy evaluation is a dry run that reports what the policies
say and changes nothing. Tenant creation remains a development/test provisioning
path, because this build has no platform-administrator concept that could authorize
it.
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
            {
                "name": "policies",
                "description": (
                    "The organization's policy record: definitions, conditions, "
                    "lifecycle, version history, and a dry-run evaluation endpoint. "
                    "The policy engine evaluates; it does not enforce, and nothing "
                    "here executes, blocks, suspends or approves anything."
                ),
            },
            {
                "name": "actions",
                "description": (
                    "The action firewall: one endpoint that runs an action from this "
                    "build's closed catalogue, and only when authorization, the "
                    "organization's policies and the firewall all permit it. A refusal "
                    "is an error naming its reason; an approval requirement is returned "
                    "as a value and never executed."
                ),
            },
            {
                "name": "audit",
                "description": (
                    "The organization's audit trail: one read-only endpoint over an "
                    "append-only record of what happened — who caused it, what was "
                    "decided, and what came of it. There is deliberately no endpoint "
                    "that creates, changes or deletes an event, and no permission that "
                    "grants one."
                ),
            },
            {
                "name": "monitoring",
                "description": (
                    "The same record, counted: what ran, what was refused, what failed and "
                    "what changed, over a bounded window. Read-only, deterministic, and "
                    "deliberately without a verdict — there is no score, no baseline, no "
                    "threshold and no alert, and a spike is reported as a bigger number "
                    "rather than as a finding."
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
