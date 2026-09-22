"""Organization routes: one authorized tenant read, plus a minimal dev-only create.

Phase 1 shipped a create-and-read-back pair with no authentication, restricted to
development and test environments. Phase 2 changes exactly one half of that:

- **Reading a tenant is now an authorized operation.** ``GET /organizations/{id}``
  requires credentials, an active membership and the ``organization.read``
  permission. A caller who is not a member gets 404 — the same answer as for an
  organization that does not exist, so the endpoint cannot be used to enumerate
  tenants. The environment gate is gone from this route because it is no longer
  what protects it.
- **Creating a tenant is still not.** There is no platform-administrator concept
  in Phase 2, so nothing could authorize tenant creation; the route therefore
  remains limited to development and test, where it is how a first organization
  is provisioned. In a real deployment, provisioning is an operator action
  (``python -m aicore_api.cli bootstrap``). A scope limitation, stated rather
  than hidden.

The three sub-resources are deliberately read-only. Membership, role and
permission *reads* are what this phase needs; adding, changing or removing a
member is a user-management API with its own authorization questions (who may
grant a role? may an admin demote an owner?) and belongs to the phase that
implements those controls.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from aicore_api.api.deps import get_session
from aicore_api.auth.authorization import OrganizationContext
from aicore_api.auth.dependencies import require_permission
from aicore_api.core.domain_errors import ConflictError
from aicore_api.core.permissions import Permission, parse_permission_code, sort_permissions
from aicore_api.db.models.rbac import Permission as PermissionRow
from aicore_api.db.repositories.memberships import MembershipRepository
from aicore_api.db.repositories.organizations import OrganizationRepository
from aicore_api.db.repositories.rbac import RoleCatalog
from aicore_api.schemas.identity import (
    MemberListResponse,
    MemberRead,
    PermissionListResponse,
    PermissionRead,
    RoleListResponse,
    RoleRead,
    RoleSummary,
    UserRead,
    membership_status,
)
from aicore_api.schemas.organizations import OrganizationCreate, OrganizationRead

router = APIRouter(prefix="/organizations", tags=["organizations"])

#: Session dependency, in the form FastAPI recommends (no call in a default).
SessionDep = Annotated[Session, Depends(get_session)]

#: Each route's requirement, declared once at the top so the whole authorization
#: surface is reviewable at a glance: three permissions guard four operations.
ReadOrganization = Annotated[
    OrganizationContext, Depends(require_permission(Permission.ORGANIZATION_READ))
]
ReadMembers = Annotated[OrganizationContext, Depends(require_permission(Permission.USER_READ))]
ReadRoles = Annotated[OrganizationContext, Depends(require_permission(Permission.ROLE_READ))]

#: Environments where unauthenticated tenant creation is acceptable.
_ENABLED_ENVIRONMENTS = frozenset({"development", "test"})


def organizations_enabled(request: Request) -> None:
    """Refuse tenant creation outside development/test.

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
        "Persists a tenant. Unauthenticated by design, so it is available only in the "
        "development and test environments; every other environment returns 404, "
        "because Phase 2 has no platform-administrator concept that could authorize "
        "tenant creation."
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
    summary="Read an organization",
    description=(
        "Returns one tenant. Requires an authenticated caller with an active "
        "membership here and the `organization.read` permission. A caller without a "
        "membership receives 404, whether or not the organization exists."
    ),
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Missing or invalid credentials"},
        status.HTTP_403_FORBIDDEN: {"description": "The caller's membership is not active"},
        status.HTTP_404_NOT_FOUND: {"description": "No such organization, or not a member"},
    },
)
def read_organization(context: ReadOrganization) -> OrganizationRead:
    return OrganizationRead.model_validate(context.organization)


@router.get(
    "/{organization_id}/members",
    response_model=MemberListResponse,
    summary="List an organization's members",
    description=(
        "The member directory of one organization: each member's identity, role and "
        "membership status. Requires the `user.read` permission in that organization."
    ),
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Missing or invalid credentials"},
        status.HTTP_403_FORBIDDEN: {"description": "Membership lacks user.read"},
        status.HTTP_404_NOT_FOUND: {"description": "No such organization, or not a member"},
    },
)
def list_members(context: ReadMembers, session: SessionDep) -> MemberListResponse:
    memberships = MembershipRepository(session, context.organization_id).list_members()
    return MemberListResponse(
        organization_id=context.organization_id,
        members=[
            MemberRead(
                user=UserRead.model_validate(membership.user),
                role=RoleSummary(code=membership.role.code, name=membership.role.name),
                status=membership_status(membership.status),
                created_at=membership.created_at,
            )
            for membership in memberships
        ],
    )


@router.get(
    "/{organization_id}/roles",
    response_model=RoleListResponse,
    summary="List the roles available in an organization",
    description=(
        "The role catalog with the permissions each role grants. Access is scoped to "
        "the organization (`role.read` there), but the catalog itself is "
        "installation-wide reference data: roles are defined by AICore, and what is "
        "per-tenant is which member holds which role."
    ),
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Missing or invalid credentials"},
        status.HTTP_403_FORBIDDEN: {"description": "Membership lacks role.read"},
        status.HTTP_404_NOT_FOUND: {"description": "No such organization, or not a member"},
    },
)
def list_roles(context: ReadRoles, session: SessionDep) -> RoleListResponse:
    roles = RoleCatalog(session).list_roles()
    return RoleListResponse(
        organization_id=context.organization_id,
        roles=[
            RoleRead(
                code=role.code,
                name=role.name,
                description=role.description,
                permissions=sort_permissions(grant.code for grant in role.grants),
            )
            for role in roles
        ],
    )


def _permission_read(permission: PermissionRow) -> PermissionRead:
    """Publish one catalog row with the resource and action its code names.

    ``parse_permission_code`` raises for a code this build cannot classify. That is
    deliberate and consistent with an unknown role: a catalog row the application
    cannot reason about is a deployment defect (the seed and the code disagree), so
    it fails loudly rather than being published as an unclassifiable string.
    """
    resource, action = parse_permission_code(permission.code)
    return PermissionRead(
        code=permission.code,
        resource=resource,
        action=action,
        description=permission.description,
    )


@router.get(
    "/{organization_id}/permissions",
    response_model=PermissionListResponse,
    summary="List the permissions an organization's roles can grant",
    description=(
        "Every permission the application knows how to check. Requires `role.read` in "
        "the organization, because a permission only means something as part of a role."
    ),
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Missing or invalid credentials"},
        status.HTTP_403_FORBIDDEN: {"description": "Membership lacks role.read"},
        status.HTTP_404_NOT_FOUND: {"description": "No such organization, or not a member"},
    },
)
def list_permissions(context: ReadRoles, session: SessionDep) -> PermissionListResponse:
    permissions = RoleCatalog(session).list_permissions()
    return PermissionListResponse(
        organization_id=context.organization_id,
        permissions=[_permission_read(permission) for permission in permissions],
    )
