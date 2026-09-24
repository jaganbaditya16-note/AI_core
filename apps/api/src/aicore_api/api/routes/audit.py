"""Audit routes: one endpoint, and it only ever reads.

The audit trail is written by the platform and read by people. There is no route that
creates an event, none that changes one and none that deletes one — not because nobody
built them yet, but because a trail that a client can write or edit is not evidence of
anything. The only HTTP method this module declares is ``GET``, and
``test_audit_api.py`` asserts that against the published document rather than trusting
this paragraph.

The route is guarded by ``audit.read`` — the permission Phase 2 already declared for
exactly this purpose — so the phase adds a table and an endpoint but no new capability:
the owner and the security administrator hold it, the administrator deliberately does
not ("oversight is not administration", as the role matrix puts it), and an analyst
reads security findings rather than the history of who did what.

Everything the endpoint returns is tenant-scoped by construction: the organization comes
from the path, the caller's membership in it was verified before the handler ran, and the
repository filters every statement on that organization. A caller who is not a member
gets the same 404 as one asking about an organization that does not exist.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from aicore_api.auth.authorization import OrganizationContext
from aicore_api.auth.dependencies import SessionDep, require_permission
from aicore_api.core.actions import ACTION_ID_PATTERN
from aicore_api.core.audit import (
    ActorType,
    AuditDecision,
    AuditEventType,
    AuditMetadataError,
    AuditOutcome,
    AuditResourceType,
    AuditSource,
    sanitize_metadata,
)
from aicore_api.core.permissions import Permission
from aicore_api.core.request_context import MAX_LENGTH as REQUEST_ID_MAX_LENGTH
from aicore_api.db.models.audit_event import AuditEvent
from aicore_api.db.repositories.audit_events import AuditEventRepository
from aicore_api.schemas.audit import AuditEventListResponse, AuditEventRead

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/organizations", tags=["audit"])

#: Reading the trail is a permission, not a role check — the same rule every other route
#: follows. It is checked before the handler runs, so an unauthorized caller never learns
#: whether the organization has any events at all.
ReadAudit = Annotated[OrganizationContext, Depends(require_permission(Permission.AUDIT_READ))]

#: The same ceiling the other listings use. It is what makes "no unbounded event list" a
#: property of the endpoint rather than a hope about its callers.
_MAX_OFFSET = 100_000

#: The alphabet a correlation identity may use — the same one the request middleware
#: accepts, so a shape the application could not have produced is refused at the edge
#: instead of quietly matching nothing. Written out rather than imported because it is a
#: query-string contract, not an internal constant.
_CORRELATION_ID_PATTERN = r"^[A-Za-z0-9._:-]{1,64}$"

_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"description": "Missing or invalid credentials"},
    403: {"description": "The caller lacks the audit.read permission"},
    404: {"description": "The organization does not exist or the caller is not a member"},
    422: {"description": "A filter value is outside the vocabulary or malformed"},
}


def _event_read(row: AuditEvent) -> AuditEventRead:
    """Serialize one row, re-sanitizing its metadata on the way out.

    The write boundary already redacts credentials and refuses payloads, so this is the
    second pass over the same rule rather than the first — and it is here because the
    table can also be written by a migration or a data fix, which do not go through the
    writer. Metadata that still fails the boundary is replaced with nothing rather than
    echoed: an unreadable summary is better than a leaked one, and the row itself stays
    complete in the database.
    """
    try:
        metadata = sanitize_metadata(row.event_metadata)
    except AuditMetadataError:
        logger.warning(
            "audit event %s carries metadata this build will not publish; returning none",
            row.id,
        )
        metadata = {}
    # The row holds the value the database stored; the response publishes the closed
    # vocabulary it belongs to. Coercing here rather than trusting the column is the same
    # rule the ledger's repository follows — and the ``CHECK`` constraints make a value
    # outside the vocabulary unrepresentable, so a failure here is a schema that drifted
    # from the code, which should be loud.
    return AuditEventRead(
        id=row.id,
        organization_id=row.organization_id,
        event_type=AuditEventType(row.event_type),
        schema_version=row.schema_version,
        occurred_at=row.occurred_at,
        actor_type=ActorType(row.actor_type),
        actor_id=row.actor_id,
        actor_membership_id=row.actor_membership_id,
        agent_id=row.agent_id,
        resource_type=AuditResourceType(row.resource_type),
        resource_id=row.resource_id,
        action=row.action,
        decision=None if row.decision is None else AuditDecision(row.decision),
        outcome=AuditOutcome(row.outcome),
        correlation_id=row.correlation_id,
        request_id=row.request_id,
        source=AuditSource(row.source),
        metadata=metadata,
    )


@router.get(
    "/{organization_id}/audit-events",
    response_model=AuditEventListResponse,
    summary="List the organization's audit trail",
    responses=_RESPONSES,
)
def list_audit_events(
    context: ReadAudit,
    session: SessionDep,
    event_type: Annotated[
        list[AuditEventType] | None,
        Query(description="Repeatable; values are ORed"),
    ] = None,
    actor_type: Annotated[list[ActorType] | None, Query()] = None,
    actor_id: Annotated[uuid.UUID | None, Query()] = None,
    agent_id: Annotated[uuid.UUID | None, Query()] = None,
    resource_type: Annotated[list[AuditResourceType] | None, Query()] = None,
    resource_id: Annotated[uuid.UUID | None, Query()] = None,
    action: Annotated[
        str | None,
        Query(
            pattern=ACTION_ID_PATTERN,
            description=(
                "A registered action's identifier, or the ``resource.action`` permission "
                "that guarded a lifecycle change"
            ),
        ),
    ] = None,
    decision: Annotated[list[AuditDecision] | None, Query()] = None,
    outcome: Annotated[list[AuditOutcome] | None, Query()] = None,
    correlation_id: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=REQUEST_ID_MAX_LENGTH,
            pattern=_CORRELATION_ID_PATTERN,
            description="Everything that happened in one request or flow",
        ),
    ] = None,
    start_time: Annotated[datetime | None, Query(description="Inclusive lower bound")] = None,
    end_time: Annotated[datetime | None, Query(description="Inclusive upper bound")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=_MAX_OFFSET)] = 0,
    total: Annotated[
        bool, Query(description="Include the filtered total; costs a second query")
    ] = False,
) -> AuditEventListResponse:
    """A page of this organization's audit trail, newest first.

    Every filter is optional and repeatable: values within one filter are ORed, different
    filters are ANDed. None of them can widen the tenant boundary — the organization comes
    from the path and the repository filters on it, so a filter can only narrow what the
    caller could already see.

    ``start_time``/``end_time`` are checked against each other before the query runs: an
    inverted range is a client mistake, and answering it with an empty page would make it
    look like there is simply nothing to find.
    """
    if start_time is not None and end_time is not None and start_time > end_time:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="start_time must not be later than end_time",
        )

    repository = AuditEventRepository(session, context.organization_id)
    filters: dict[str, Any] = {
        "event_types": event_type,
        "actor_types": actor_type,
        "actor_id": actor_id,
        "agent_id": agent_id,
        "resource_types": resource_type,
        "resource_id": resource_id,
        "action": action,
        "decisions": decision,
        "outcomes": outcome,
        "correlation_id": correlation_id,
        "start_time": start_time,
        "end_time": end_time,
    }
    items = repository.page(limit=limit, offset=offset, **filters)
    count = repository.count(**filters) if total else None
    return AuditEventListResponse(
        organization_id=context.organization_id,
        items=[_event_read(row) for row in items],
        limit=limit,
        offset=offset,
        count=len(items),
        total=count,
    )
