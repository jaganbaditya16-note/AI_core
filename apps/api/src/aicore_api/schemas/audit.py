"""Audit contract: what the trail reports, and what it deliberately does not.

The read side of Phase 8 is one endpoint, and these models are its whole surface.

**Reading is the only client operation.** There is no request model in this module
because there is no write endpoint: audit events are written by the platform, never by a
caller. A client cannot create one, change one or delete one — the trail would be worth
nothing if it could — and the absence of those models is how that shows up in the
contract.

**The response is an explicit shape, not a JSON blob.** Every field is named and typed
here rather than being returned straight from the row, so adding a column to the table
cannot silently publish it. ``metadata`` is the one open field, and it is re-sanitized on
the way out: the write boundary already redacts credentials and refuses payloads, and the
read boundary applies the same rule again so a row written by a migration or a data fix
cannot leak through the API. That second pass is defence in depth, not a substitute for
the first.

**No arguments, no payloads, no credentials.** Nothing in this module has a field for the
data an action operated on, the body a request carried, a token or a header, because
nothing in the table stores one. ``Test`` side: ``test_audit_api.py`` asserts a
secret-shaped metadata value written straight into the table comes back redacted.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from aicore_api.core.audit import (
    ActorType,
    AuditDecision,
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
    AuditSource,
)

__all__ = ["AuditEventListResponse", "AuditEventRead"]


class AuditEventRead(BaseModel):
    """One recorded event.

    The fields are the questions an investigation asks: what happened, when, in which
    organization, who caused it, which agent was involved, which resource it was about,
    what was decided, what came of it, and which request ties it to its neighbours.
    """

    id: uuid.UUID
    organization_id: uuid.UUID = Field(
        description="The tenant the event belongs to. Never taken from a request."
    )
    event_type: AuditEventType
    schema_version: int = Field(description="The shape of the row this event was written in.")
    occurred_at: datetime = Field(
        description="The server's clock at the moment of the event, in UTC."
    )
    actor_type: ActorType = Field(
        description=(
            "``human`` for an authenticated caller, ``system`` for an operation nobody "
            "performed. The actor is resolved by the server from the credential."
        )
    )
    actor_id: uuid.UUID | None = Field(
        description="The authenticated person; null for a system event."
    )
    actor_membership_id: uuid.UUID | None = Field(
        description=(
            "The membership that carried the role in this organization. Together with "
            "``actor_id`` it is what makes attribution structured rather than a name."
        )
    )
    agent_id: uuid.UUID | None = Field(
        description=(
            "The agent an execution was attributed to, when the request named one. "
            "Attribution, not identity: the actor is still the authenticated person."
        )
    )
    resource_type: AuditResourceType
    resource_id: uuid.UUID | None = Field(
        description="The row the event was about, as it was; null when the event is not about one."
    )
    action: str | None = Field(
        description=(
            "The operation: the registered action's identifier for an execution, or the "
            "``resource.action`` permission for a lifecycle change."
        )
    )
    decision: AuditDecision | None = Field(
        description=(
            "The decision recorded, in the vocabulary the policy engine and the firewall "
            "already use. Null for a system operation and for a request that has only "
            "been admitted."
        )
    )
    outcome: AuditOutcome
    correlation_id: str = Field(
        description="Groups the events of one flow; server-established, never client-claimed."
    )
    request_id: str | None = Field(
        description="The originating HTTP request; null for an internal path such as ingestion."
    )
    source: AuditSource
    metadata: dict[str, Any] = Field(
        description=(
            "Sanitized summary facts. Credential-shaped keys and values are redacted at "
            "the write boundary and again here; action arguments are never stored."
        )
    )


class AuditEventListResponse(BaseModel):
    """``GET /organizations/{organization_id}/audit-events``.

    ``total`` is present only when the caller asked for it (``?total=true``): a count
    costs a second query over the same predicate, and an investigation paging through a
    trail rarely needs one. ``count`` always describes the page itself.
    """

    organization_id: uuid.UUID
    items: list[AuditEventRead]
    limit: int
    offset: int
    count: int
    total: int | None = None
