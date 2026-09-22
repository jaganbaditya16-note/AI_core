"""``GET /me`` — the caller's own identity, memberships, roles and permissions.

This is the endpoint that makes the Phase 2 model inspectable from outside: it
answers all five questions in one round trip, and it is the only route in the API
that is not scoped to a single organization — because it is about the caller
themselves, across every organization they belong to.

That cross-organization reach is why it is built on
:func:`aicore_api.db.repositories.memberships.memberships_for_user`, which takes
the tenancy guard's single documented escape and filters on the *authenticated
user's* id. The user id comes from the credential, never from the request: there
is no path, query or body parameter that could point this route at somebody
else's memberships.
"""

from __future__ import annotations

from fastapi import APIRouter, status

from aicore_api.auth.dependencies import PrincipalDep, SessionDep
from aicore_api.core.permissions import permissions_for, sort_permissions
from aicore_api.db.models.membership import MembershipStatus
from aicore_api.db.repositories.memberships import memberships_for_user
from aicore_api.schemas.identity import (
    MembershipRead,
    MeResponse,
    OrganizationSummary,
    RoleSummary,
    UserRead,
    membership_status,
)

router = APIRouter(tags=["identity"])


@router.get(
    "/me",
    response_model=MeResponse,
    summary="Who am I, and what may I do?",
    description=(
        "Returns the authenticated user and every organization they belong to, with "
        "the role they hold and the permissions that role grants. Permissions are "
        "listed per membership: the same person can be an owner in one organization "
        "and a viewer in another. A membership that is not active reports no "
        "permissions, because it authorizes nothing."
    ),
    responses={
        status.HTTP_401_UNAUTHORIZED: {"description": "Missing or invalid credentials"},
    },
)
def read_me(principal: PrincipalDep, session: SessionDep) -> MeResponse:
    memberships = [
        MembershipRead(
            organization=OrganizationSummary.model_validate(organization),
            role=RoleSummary(code=membership.role.code, name=membership.role.name),
            status=membership_status(membership.status),
            # An unknown role code raises rather than reporting an empty set: if
            # the database holds a policy this build cannot interpret, saying
            # nothing would be worse than failing. See core/permissions.py.
            permissions=(
                sort_permissions(permissions_for(membership.role.code))
                if membership.status == MembershipStatus.ACTIVE.value
                else []
            ),
        )
        for membership, organization in memberships_for_user(session, principal.user_id)
    ]

    return MeResponse(
        user=UserRead(
            id=principal.user_id,
            email=principal.email,
            full_name=principal.full_name,
            status=principal.status,
        ),
        memberships=memberships,
    )
