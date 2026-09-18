"""Minimal organization persistence path.

Phase 1 adds the smallest API that proves the database foundation: create a
tenant, read a tenant back. That is what the phase's verification needs, and
nothing more — a full organization management API (rename, suspend, delete,
members, roles) belongs to the identity phase, where it can be properly
authorized.

**Access control, stated plainly.** There is no authentication in this build, so
these endpoints cannot be authorized. Rather than shipping an unauthenticated
endpoint that creates tenants in production, the router is only mounted when the
configured environment is ``development`` or ``test``; every other environment
gets a 404 for these paths, and the OpenAPI document does not advertise them.
This is a scope limitation, not a security control — the endpoint is simply not
part of the production surface yet.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from aicore_api.api.deps import get_session
from aicore_api.core.domain_errors import ConflictError, NotFoundError
from aicore_api.db.repositories.organizations import OrganizationRepository
from aicore_api.schemas.organizations import OrganizationCreate, OrganizationRead

router = APIRouter(prefix="/organizations", tags=["organizations"])

#: Session dependency, in the form FastAPI recommends (no call in a default).
SessionDep = Annotated[Session, Depends(get_session)]

#: Environments where unauthenticated tenant creation is acceptable.
_ENABLED_ENVIRONMENTS = frozenset({"development", "test"})


def organizations_enabled(request: Request) -> None:
    """Refuse these routes outside development/test.

    Mounting-time filtering would also work, but a runtime check cannot be lost
    by a future refactor of router wiring, and it makes the condition visible in
    the request path.
    """
    settings = request.app.state.settings
    if settings.environment not in _ENABLED_ENVIRONMENTS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


@router.post(
    "",
    response_model=OrganizationRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create an organization (development/test only)",
    description=(
        "Persists a tenant. Requires no authentication, so it is available only in the "
        "development and test environments; production returns 404 until identity exists."
    ),
    dependencies=[Depends(organizations_enabled)],
    responses={
        status.HTTP_409_CONFLICT: {"description": "Slug already exists"},
        status.HTTP_422_UNPROCESSABLE_ENTITY: {"description": "Invalid name or slug"},
    },
)
async def create_organization(payload: OrganizationCreate, session: SessionDep) -> OrganizationRead:
    repository = OrganizationRepository(session)
    try:
        organization = repository.create(name=payload.name, slug=payload.slug)
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return OrganizationRead.model_validate(organization)


@router.get(
    "/{organization_id}",
    response_model=OrganizationRead,
    summary="Read an organization (development/test only)",
    description=(
        "Returns one tenant. There is no authentication yet, so this route is limited to "
        "the development and test environments."
    ),
    dependencies=[Depends(organizations_enabled)],
    responses={status.HTTP_404_NOT_FOUND: {"description": "No such organization"}},
)
async def get_organization(organization_id: uuid.UUID, session: SessionDep) -> OrganizationRead:
    repository = OrganizationRepository(session)
    try:
        organization = repository.get(organization_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return OrganizationRead.model_validate(organization)
