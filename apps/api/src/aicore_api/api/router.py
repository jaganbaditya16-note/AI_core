"""Aggregate API router.

Keeping a single place where routers are mounted means the URL surface of the API
is reviewable at a glance — important for a control plane. The inventory's and the
agent registry's and the policy record's routes are mounted under the same
``/organizations`` prefix as the membership and role routes: the tenant boundary is
resolved once, from the path, for every tenant-scoped operation in the
application.
"""

from __future__ import annotations

from fastapi import APIRouter

from aicore_api.api.routes import agents, assets, health, identity, organizations, policies

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(identity.router)
api_router.include_router(organizations.router)
api_router.include_router(assets.router)
api_router.include_router(agents.router)
api_router.include_router(policies.router)
