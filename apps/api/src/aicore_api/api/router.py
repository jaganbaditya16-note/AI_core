"""Aggregate API router.

Keeping a single place where routers are mounted means the URL surface of the API
is reviewable at a glance — important for a control plane. The inventory's, the agent
registry's, the policy record's, the action firewall's and the audit trail's routes are
mounted under the same ``/organizations`` prefix as the membership and role routes: the
tenant boundary is resolved once, from the path, for every tenant-scoped operation in the
application.

The action router is the only one that can execute something, and it is last but one on
purpose: the execution path is the deepest in the application, and the surface above it
should read as the layers it passes through. The audit router comes after it for a
different reason — it is the one router that only ever reads, and it reads the record of
what every router before it did.
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
    organizations,
    policies,
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
