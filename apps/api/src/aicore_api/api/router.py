"""Aggregate API router.

Keeping a single place where routers are mounted makes the URL surface of the API
reviewable at a glance. The investigation router is deliberately placed after risk: it
can explain a recorded finding, but it cannot authorize or execute an action.
"""

from __future__ import annotations

from fastapi import APIRouter

from aicore_api.api.routes import (
    actions,
    agents,
    assets,
    audit,
    health,
    identity,
    investigation,
    monitoring,
    organizations,
    policies,
    risk,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(identity.router)
api_router.include_router(organizations.router)
api_router.include_router(assets.router)
api_router.include_router(agents.router)
api_router.include_router(policies.router)
api_router.include_router(actions.router)
api_router.include_router(audit.router)
api_router.include_router(monitoring.router)
api_router.include_router(risk.router)
api_router.include_router(investigation.router)
