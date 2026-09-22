"""Instance-level authorization at the HTTP boundary.

A route that addresses one row has two questions to answer, not one:

1. *may this caller use this permission in this organization?* — the
   ``require_permission`` dependency, resolved before the handler body runs;
2. *is the row the handler just loaded actually part of that organization?* —
   this module.

The second question looks redundant, and in a correct build it is: every
repository is tenant-scoped, so a row that came back from one cannot belong to
another organization. That is exactly why the check belongs here — it turns a
*property of the query* into an *assertion about the answer*, so a repository that
loses its tenant filter (a bug, not a policy) fails closed with the same 404 the
caller would get for a row that does not exist, instead of serving another
organization's record. Defence in depth, in the one place where "the query was
scoped" would otherwise be the only thing standing between tenants.

It re-asserts the permission too, through
:func:`aicore_api.auth.authorization.authorize_instance`, which is what makes this
an authorization check rather than a filter: the decision is the same
:class:`~aicore_api.auth.authorization.AuthorizationDecision` the dependency
produced, computed again against the concrete row.

Denial mapping, following the phase's contract:

- a row outside the caller's organization → **404**, identical to "no such row";
- a caller without the permission → **403**, which cannot leak a row's existence
  because it does not depend on whether the row exists.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, status

from aicore_api.auth.authorization import (
    AuthorizationDecision,
    DecisionReason,
    OrganizationContext,
    ResourceScope,
    authorize_instance,
)
from aicore_api.core.permissions import Permission

__all__ = ["require_instance_scope"]


def require_instance_scope(
    context: OrganizationContext,
    instance: Any,
    *,
    permission: Permission,
    detail: str,
) -> AuthorizationDecision:
    """Assert ``instance`` is in the caller's organization and they may act on it.

    Returns the decision so a handler can pass it on (a future audit phase records
    it); raises the HTTP error the API publishes for each denial.
    """
    decision = authorize_instance(context, ResourceScope.of(instance), permission=permission)
    if decision.allowed:
        return decision

    if decision.reason is DecisionReason.MISSING_PERMISSION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"this operation requires the {permission} permission",
        )
    # A row in another organization is answered exactly like one that is not
    # there: any difference would be an existence oracle.
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
