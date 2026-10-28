"""The domain-event seam: one place where a change announces itself.

Phase 8 built the audit trail, and this is where it was plugged in. Phase 3 wrote the
boundary so that phase would not have to hunt for write paths:

    emit_event(DomainEvent(...))                      → one structured log line
    emit_event(DomainEvent(...), session=session)     → *and* one audit event

The session is the switch, and it is explicit on purpose. An event with no session is a
log line and nothing more — which is what a migration, a data fix or a unit test gets,
because neither has a request, an actor or a tenant to attribute anything to. An event
*with* a session is a durable record, written through
:class:`~aicore_api.audit.writer.AuditWriter` in the same transaction the caller is
already using.

Attribution comes from the event, never from the caller's argument list: an event that
names both a person and a membership is a human action, and an event that names neither
is a system operation. There is no third case, because there is no third origin in this
build — and :class:`~aicore_api.core.audit.AuditActor` refuses to represent one.

Why not an ORM hook or a SQLAlchemy event listener? Because the interesting part of
an event is *who did it and why*, which lives in the request, not in the session —
and an implicit mechanism would also fire for fixtures, migrations and data fixes,
producing events nobody performed. That reasoning predates Phase 8 and is exactly why
``emit_event`` takes a session rather than discovering one.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from aicore_api.audit.writer import AuditWriter
from aicore_api.core.audit import AuditSource

if TYPE_CHECKING:  # pragma: no cover - imported for its type, not at runtime
    from sqlalchemy.orm import Session

__all__ = ["DomainEvent", "emit_event"]

logger = logging.getLogger(__name__)

#: Event names are stable identifiers: they will appear in audit records, so
#: renaming one is a migration of the record, not a refactor.
ASSET_CREATED = "asset.created"
ASSET_UPDATED = "asset.updated"
ASSET_DELETED = "asset.deleted"
ASSET_DISCOVERED = "asset.discovered"

#: Phase 4's registry events. A registration is not an "asset created" event with
#: extra fields: it is the moment an agent acquired an identity, which a later
#: audit phase will want to read on its own — and the inventory record it brings
#: with it is reported as an asset event too, because that is what happened.
AGENT_REGISTERED = "agent.registered"
AGENT_UPDATED = "agent.updated"
AGENT_DELETED = "agent.deleted"

#: Phase 6's policy events. A version publication and a lifecycle move are separate
#: events rather than one "policy updated": they answer different questions — *what
#: does it say now* and *is it in force* — and a later audit view will want to read
#: either on its own. Editing a policy's definition never reports an in-place change,
#: because there is no such thing: the previous version is still there.
#:
#: There is no event for evaluating a policy. An evaluation changes nothing — no row,
#: no state, no decision that binds anyone — and emitting an event for a read would
#: make the event stream a request log, which is a different thing with different
#: retention questions.
POLICY_CREATED = "policy.created"
POLICY_UPDATED = "policy.updated"
POLICY_VERSION_PUBLISHED = "policy.version_published"
POLICY_STATUS_CHANGED = "policy.status_changed"
POLICY_DELETED = "policy.deleted"

#: Phase 7's action event: one registered action ran, because this build admitted it.
#: That is a change the system caused on someone's behalf, which is what the audit
#: trail records — and the data carries the decision, the adapter and the outcome's
#: digest, never the arguments a caller sent.
#:
#: There is deliberately **no** event here for a refusal, and none for a firewall
#: decision. This seam is the *change* stream: every value it carries is a mutation
#: somebody has to be told about, and a refusal mutates nothing. Refusals are recorded
#: — Phase 8's trail has an event for each way the pipeline can say no — but they are
#: written by the pipeline through the audit writer, not emitted here, because the two
#: are different questions: "what changed?" and "what was attempted?".
ACTION_EXECUTED = "action.executed"


@dataclass(frozen=True, slots=True)
class DomainEvent:
    """Something that happened, in the tenant it happened to.

    ``actor_id`` is the authenticated person who caused it and ``actor_membership_id``
    the membership that carried the role, or both ``None`` when nothing a person did
    caused it (an ingestion run, a migration). Keeping the actor optional is
    deliberate: attributing an automated change to whichever human happened to be
    nearby is worse than recording that no human was involved, and the pair is what
    makes the attribution structured — one person belongs to many organizations, so a
    membership alone does not name an actor.
    """

    name: str
    organization_id: uuid.UUID
    resource_type: str
    resource_id: uuid.UUID
    #: The membership that carried the role in this organization.
    actor_membership_id: uuid.UUID | None = None
    #: The authenticated person. Phase 8 added it because the audit trail answers "who"
    #: with the person *and* the membership: one person belongs to many organizations, so
    #: a membership alone does not name an actor. Both are set by the caller from the
    #: authorized request context, never from a request body.
    actor_id: uuid.UUID | None = None
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    #: Small, JSON-serializable context (changed field names, a discovery source).
    #: Not the row: an event should stay small enough to read in a log line.
    data: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def as_log_fields(self) -> dict[str, Any]:
        """A flat, JSON-serializable view, for structured logging."""
        return {
            "event": self.name,
            "organization_id": str(self.organization_id),
            "resource_type": self.resource_type,
            "resource_id": str(self.resource_id),
            "actor_id": str(self.actor_id) if self.actor_id else None,
            "actor_membership_id": (
                str(self.actor_membership_id) if self.actor_membership_id else None
            ),
            "occurred_at": self.occurred_at.isoformat(),
            "data": dict(self.data),
        }


def emit_event(
    event: DomainEvent,
    *,
    session: Session | None = None,
    source: AuditSource = AuditSource.API,
) -> None:
    """Record that ``event`` happened: always a log line, and a trail row with a session.

    The log line is unconditional and unchanged — it is where an operator watching a
    deployment sees things happen, with the correlation id attached. The audit event is
    written only when the caller passes the session its unit of work is already using,
    because a record that nothing can attribute is a row nobody can trust, and because
    a log line is allowed to be best-effort while a trail entry is not.

    A session turns the log line into a promise: if the write fails, this raises. That is
    the fail-closed direction — a caller that could not record what it did has not
    finished doing it, and swallowing the failure would leave a change nobody can account
    for. Callers that cannot be interrupted after the fact (the execution path, which has
    already acted by the time it records the outcome) handle that explicitly rather than
    relying on this function to decide for them.

    ``source`` distinguishes an authenticated request from an internal path. It defaults
    to the API because that is where almost every event comes from, and the ingestion path
    states its own; the database refuses the combination
    ``source = 'api'`` with no request id, so a mislabelled event cannot claim to have
    come from a request that does not exist.
    """
    logger.info("domain event %s", event.as_log_fields())
    if session is None:
        return
    AuditWriter(session).record_domain_event(event, source=source)
