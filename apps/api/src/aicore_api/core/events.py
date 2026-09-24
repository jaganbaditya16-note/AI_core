"""The domain-event seam: one place where a change announces itself.

Phase 8 builds the audit trail. Phase 3 must not build a second one — but asset
lifecycle changes are exactly the events an audit trail will need, and discovering
that requirement *after* the write paths exist means retrofitting a call into every
one of them. So the call is made now, into the smallest possible boundary:

    emit_event(DomainEvent(...))  →  currently: one structured log line

That is the whole mechanism. There is no event table, no queue, no subscriber
registry and no delivery guarantee, because each of those is a design with
consequences (retention, ordering, replay, failure handling) that belongs to the
phase that owns the audit trail. What exists today is the *boundary*: a single,
typed, reviewable function that every inventory mutation already calls, so Phase 8
changes one function instead of hunting for write paths.

Why not an ORM hook or a SQLAlchemy event listener? Because the interesting part of
an event is *who did it and why*, which lives in the request, not in the session —
and an implicit mechanism would also fire for fixtures, migrations and data fixes,
producing events nobody performed.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

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
#: That is a change the system caused on someone's behalf, which is what a later audit
#: view is for — and the data carries the decision, the adapter and the outcome's
#: digest, never the arguments a caller sent.
#:
#: There is deliberately **no** event for a refusal, and none for a firewall decision.
#: A refusal changes nothing: no row, no state, nobody's data. The response records why
#: it was refused, and turning every refused attempt into an event would make this
#: stream a request log — a different thing, with different retention questions, owned
#: by the phase that owns the audit trail.
ACTION_EXECUTED = "action.executed"


@dataclass(frozen=True, slots=True)
class DomainEvent:
    """Something that happened, in the tenant it happened to.

    ``actor_membership_id`` is the membership that caused it, or ``None`` when
    nothing a person did caused it (an ingestion run, a migration). Keeping the
    actor optional is deliberate: attributing an automated change to whichever
    human happened to be nearby is worse than recording that no human was
    involved.
    """

    name: str
    organization_id: uuid.UUID
    resource_type: str
    resource_id: uuid.UUID
    actor_membership_id: uuid.UUID | None = None
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
            "actor_membership_id": (
                str(self.actor_membership_id) if self.actor_membership_id else None
            ),
            "occurred_at": self.occurred_at.isoformat(),
            "data": dict(self.data),
        }


def emit_event(event: DomainEvent) -> None:
    """Record that ``event`` happened.

    Today: one log line at INFO, which is where an operator can already find it and
    where the request's correlation id is attached. Tomorrow: the audit store. The
    signature is the contract — every inventory mutation calls this before it
    returns, and a test asserts that each one does.
    """
    logger.info("domain event %s", event.as_log_fields())
