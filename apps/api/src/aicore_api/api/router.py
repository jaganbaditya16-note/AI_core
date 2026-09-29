"""Aggregate API router for the AICore control plane."""
from __future__ import annotations

from fastapi import APIRouter

from aicore_api.api.routes import (
    actions,
    agents,
    assets,
    audit,
    health,
    identity,
    intelligence,
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
api_router.include_router(intelligence.router)
