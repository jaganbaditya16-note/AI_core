"""FastAPI dependencies: how a route states what it requires.

A protected route declares its requirement in its signature, and FastAPI refuses
the request before the handler body runs:

    @router.get("/organizations/{organization_id}")
    def read_organization(
        context: Annotated[
            OrganizationContext, Depends(require_permission(Permission.ORGANIZATION_READ))
        ],
    ) -> OrganizationRead: ...

Two things are worth noting about the design:

- **Requirements are permissions, not roles.** ``require_permission(Permission.USER_READ)``
  says what the operation needs. A route can never ask "is this user an ADMIN?",
  so privilege changes are made in one table
  (:data:`aicore_api.core.permissions.ROLE_PERMISSIONS` and its seed) rather than
  in route handlers.
- **The organization comes from the path, the caller from the credential.** The
  dependency resolves the path's ``organization_id`` against the authenticated
  principal's memberships, so a client cannot point a request at another tenant's
  data by editing a URL (there is no organization in a body or a header that
  could be trusted instead).

Failures are translated here, at the HTTP boundary, from transport-agnostic
domain errors: :class:`NotFoundError` → 404 (a non-member learns nothing about
whether the tenant exists) and :class:`PermissionDeniedError` → 403.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Annotated, Protocol

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from aicore_api.api.deps import get_session
from aicore_api.auth.authorization import OrganizationContext, resolve_organization_context
from aicore_api.auth.principal import Principal
from aicore_api.auth.providers import (
    AuthenticationProvider,
    build_authentication_provider,
    parse_authorization_header,
)
from aicore_api.config import Settings
from aicore_api.core.domain_errors import NotFoundError, PermissionDeniedError
from aicore_api.core.permissions import Permission

__all__ = [
    "PrincipalDep",
    "SessionDep",
    "get_principal",
    "require_permission",
]


class PermissionRequirement(Protocol):
    """A route requirement built by :func:`require_permission`.

    The structural contract test reads ``required_permission`` off the route's
    dependencies, so the attribute is part of the module's interface rather than
    an implementation detail.
    """

    required_permission: Permission

    def __call__(
        self, organization_id: uuid.UUID, principal: Principal, session: Session
    ) -> OrganizationContext: ...


SessionDep = Annotated[Session, Depends(get_session)]

#: Identical for "no such organization" and "you are not a member of it". The
#: caller must not be able to tell the two apart; that is the whole point.
_ORGANIZATION_NOT_FOUND = "Organization not found"


def app_settings(request: Request) -> Settings:
    """The settings the running application was built with."""
    settings: Settings = request.app.state.settings
    return settings


def get_authentication_provider(request: Request, session: SessionDep) -> AuthenticationProvider:
    """Build the configured provider for this request."""
    return build_authentication_provider(app_settings(request), session)


def _unauthorized(detail: str) -> HTTPException:
    """A 401 that tells the client how to authenticate, and nothing more."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_principal(
    request: Request,
    provider: Annotated[AuthenticationProvider, Depends(get_authentication_provider)],
) -> Principal:
    """Identify the caller, or refuse the request with a 401.

    Every rejection returns the same shape: no credential, a malformed header, an
    unknown token, a revoked token, an expired token and a suspended user are
    indistinguishable to the client.
    """
    header = request.headers.get("authorization")
    credentials = parse_authorization_header(header)
    if credentials is None:
        if header is None:
            raise _unauthorized("Authentication required")
        raise _unauthorized("Invalid credentials")

    principal = provider.authenticate(credentials)
    if principal is None:
        raise _unauthorized("Invalid credentials")
    return principal


PrincipalDep = Annotated[Principal, Depends(get_principal)]


def require_permission(permission: Permission) -> Callable[..., OrganizationContext]:
    """Build the dependency that authorizes one permission in the path's organization.

    The returned callable is the route's requirement, expressed as a permission.
    It resolves and verifies everything the request needs — caller, organization,
    membership, role, permissions — and hands the handler an
    :class:`OrganizationContext` that is already authorized.
    """

    def dependency(
        organization_id: uuid.UUID,
        principal: PrincipalDep,
        session: SessionDep,
    ) -> OrganizationContext:
        try:
            return resolve_organization_context(
                session, principal, organization_id, required=permission
            )
        except NotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=_ORGANIZATION_NOT_FOUND
            ) from exc
        except PermissionDeniedError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    # The permission a route enforces is stamped onto its dependency so the
    # requirement is *readable from the route*, not buried in a handler body.
    # tests/test_authorization.py walks the built application and reads it, which
    # is how "every tenant-scoped route states a permission" is asserted rather
    # than assumed.
    dependency.required_permission = permission  # type: ignore[attr-defined]
    return dependency
