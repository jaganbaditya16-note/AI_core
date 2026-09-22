"""Aggregate API router.

Keeping a single place where routers are mounted means the URL surface of the
API is reviewable at a glance — important for a control plane.
"""

from __future__ import annotations

from fastapi import APIRouter

from aicore_api.api.routes import health, identity, organizations

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(identity.router)
api_router.include_router(organizations.router)
