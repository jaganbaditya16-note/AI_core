"""The audit store: append one event, read the trail back, and nothing else.

The repository is deliberately smaller than it looks like it should be. There is no
``update`` and no ``delete``, because there is no such operation: an audit event is a
record of something that happened, and rewriting it would make the whole trail
worthless. The database refuses both as well — a trigger on ``aicore.audit_events``
raises on ``UPDATE``, ``DELETE`` and ``TRUNCATE`` — so the rule holds for a data fix or
a future script, not only for the code that exists today.

Two operations do exist:

- :meth:`AuditEventRepository.append` writes one event. It is the only write in this
  module, and the only write in the application that targets this table.
- :meth:`AuditEventRepository.page` and :meth:`AuditEventRepository.count` read the trail
  back, tenant-scoped and filtered. ``limit`` is required, so "read every event" cannot
  be expressed — the same rule the inventory follows.

Reading across tenants is impossible by construction (the base class filters on the
organization), and a foreign event is therefore indistinguishable from one that does
not exist. :func:`audit_retention_override` is the single, named, greppable exception to
append-only, and it exists for test teardown: a fixture that removes an organization
must remove its events first (the tenant foreign key is ``RESTRICT``), and pretending
otherwise would mean either a weaker constraint or fixtures that leak rows.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime
from typing import Any

from sqlalchemy import Select, text
from sqlalchemy.orm import Session

from aicore_api.core.audit import (
    AUDIT_SCHEMA_VERSION,
    AuditActor,
    AuditDecision,
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
    AuditSource,
)
from aicore_api.db.models.audit_event import AuditEvent
from aicore_api.db.repositories.organizations import OrganizationScopedRepository

__all__ = ["AuditEventRepository", "audit_retention_override"]

#: The session setting the trigger looks for. Named after the action it permits rather
#: than after the caller, so ``grep -rn audit_retention_override`` finds every place that
#: can set it and ``grep -rn aicore.audit_retention`` finds every place that reads it.
_RETENTION_SETTING = "aicore.audit_retention"


@contextmanager
def audit_retention_override(session: Session, reason: str) -> Iterator[str]:
    """Permit ``DELETE`` against the audit trail for the current transaction.

    The one exception to append-only, and it is deliberately awkward:

    - it must be asked for in code, by name, with a stated reason;
    - it is transaction-local (``SET LOCAL``), so it cannot leak into the next request
      that borrows the connection, and it cannot be configured globally;
    - it permits ``DELETE`` **only**: ``UPDATE`` is refused whatever the setting says,
      because there is no maintenance operation that needs to rewrite history.

    Phase 8 has one caller: the test fixtures, which must remove an organization's events
    before they can remove the organization. Retention is a later phase's decision, and
    when it makes one it will find this function already stating its terms.
    """
    if not reason.strip():
        raise ValueError("audit_retention_override requires a reason")
    session.execute(
        text(f"SELECT set_config('{_RETENTION_SETTING}', :reason, true)"),
        {"reason": reason},
    )
    try:
        yield reason
    finally:
        # ``true`` (is_local) already ties the setting to the transaction; resetting as
        # well means a caller that keeps the session alive cannot accidentally extend the
        # window by opening another transaction on it.
        session.execute(text(f"SELECT set_config('{_RETENTION_SETTING}', '', true)"))


class AuditEventRepository(OrganizationScopedRepository):
    """One organization's audit trail."""

    def append(
        self,
        *,
        event_type: AuditEventType,
        actor: AuditActor,
        resource_type: AuditResourceType,
        outcome: AuditOutcome,
        source: AuditSource,
        correlation_id: str,
        resource_id: uuid.UUID | None = None,
        agent_id: uuid.UUID | None = None,
        action: str | None = None,
        decision: AuditDecision | None = None,
        request_id: str | None = None,
        event_metadata: Mapping[str, Any] | None = None,
    ) -> AuditEvent:
        """Write one event and commit it.

        The caller passes values the *server* resolved: the actor from the authenticated
        membership, the organization from this repository's tenant, the correlation id
        from the request context. Nothing here accepts a client-supplied identifier, and
        nothing here decides anything — the event describes a decision someone else made.

        The row is inserted with the database's own defaults for its identifier and its
        timestamp, then re-read, so the caller gets the values PostgreSQL actually stored
        rather than the ones Python hoped for.
        """
        row = AuditEvent(
            organization_id=self.organization_id,
            event_type=event_type.value,
            schema_version=AUDIT_SCHEMA_VERSION,
            actor_type=actor.type.value,
            actor_id=actor.user_id,
            actor_membership_id=actor.membership_id,
            agent_id=agent_id,
            resource_type=resource_type.value,
            resource_id=resource_id,
            action=action,
            decision=None if decision is None else decision.value,
            outcome=outcome.value,
            correlation_id=correlation_id,
            request_id=request_id,
            source=source.value,
            event_metadata=dict(event_metadata or {}),
        )
        with self.writing():
            self.session.add(row)
            self.session.flush()
            self.session.commit()
            # ``occurred_at`` and ``id`` are server defaults. Refreshing inside the bound
            # scope is what lets the caller read them: a statement against a tenant-owned
            # table is refused without the tenant, and that includes this one.
            self.session.refresh(row)
        return row

    def page(
        self,
        *,
        limit: int,
        offset: int,
        event_types: Sequence[str] | None = None,
        actor_types: Sequence[str] | None = None,
        actor_id: uuid.UUID | None = None,
        agent_id: uuid.UUID | None = None,
        resource_types: Sequence[str] | None = None,
        resource_id: uuid.UUID | None = None,
        action: str | None = None,
        decisions: Sequence[str] | None = None,
        outcomes: Sequence[str] | None = None,
        correlation_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[AuditEvent]:
        """A page of this organization's events, newest first.

        ``limit`` is required and has no default: the API caps it, but nothing in this
        layer can be asked for "everything", so an unbounded read cannot be written by
        accident. Ordering is ``(occurred_at DESC, id DESC)`` — the identifier breaks
        ties, so paging cannot skip or repeat a row.
        """
        statement = self._filtered(
            self._scoped(AuditEvent),
            event_types=event_types,
            actor_types=actor_types,
            actor_id=actor_id,
            agent_id=agent_id,
            resource_types=resource_types,
            resource_id=resource_id,
            action=action,
            decisions=decisions,
            outcomes=outcomes,
            correlation_id=correlation_id,
            start_time=start_time,
            end_time=end_time,
        )
        statement = (
            statement.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.execute(statement).scalars().unique().all())

    def count(
        self,
        *,
        event_types: Sequence[str] | None = None,
        actor_types: Sequence[str] | None = None,
        actor_id: uuid.UUID | None = None,
        agent_id: uuid.UUID | None = None,
        resource_types: Sequence[str] | None = None,
        resource_id: uuid.UUID | None = None,
        action: str | None = None,
        decisions: Sequence[str] | None = None,
        outcomes: Sequence[str] | None = None,
        correlation_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """How many events match the same filters.

        Optional for the caller (``GET /audit-events?total=true``) because it is a second
        pass over the same predicate. Its own helper in the base class because the obvious
        spelling of a count is the one that forgets the tenant filter.
        """
        statement = self._filtered(
            self._scoped_count(AuditEvent),
            event_types=event_types,
            actor_types=actor_types,
            actor_id=actor_id,
            agent_id=agent_id,
            resource_types=resource_types,
            resource_id=resource_id,
            action=action,
            decisions=decisions,
            outcomes=outcomes,
            correlation_id=correlation_id,
            start_time=start_time,
            end_time=end_time,
        )
        return int(self.execute(statement).scalar_one())

    def _filtered(
        self,
        statement: Select[Any],
        *,
        event_types: Sequence[str] | None,
        actor_types: Sequence[str] | None,
        actor_id: uuid.UUID | None,
        agent_id: uuid.UUID | None,
        resource_types: Sequence[str] | None,
        resource_id: uuid.UUID | None,
        action: str | None,
        decisions: Sequence[str] | None,
        outcomes: Sequence[str] | None,
        correlation_id: str | None,
        start_time: datetime | None,
        end_time: datetime | None,
    ) -> Select[Any]:
        """Apply the filters a caller asked for, and nothing else.

        One place, so the list and the count cannot disagree about what they are counting.
        Values within one filter are ORed, different filters are ANDed — the same contract
        the inventory's listing states.
        """
        if event_types:
            statement = statement.where(AuditEvent.event_type.in_(list(event_types)))
        if actor_types:
            statement = statement.where(AuditEvent.actor_type.in_(list(actor_types)))
        if actor_id is not None:
            statement = statement.where(AuditEvent.actor_id == actor_id)
        if agent_id is not None:
            statement = statement.where(AuditEvent.agent_id == agent_id)
        if resource_types:
            statement = statement.where(AuditEvent.resource_type.in_(list(resource_types)))
        if resource_id is not None:
            statement = statement.where(AuditEvent.resource_id == resource_id)
        if action is not None:
            statement = statement.where(AuditEvent.action == action)
        if decisions:
            statement = statement.where(AuditEvent.decision.in_(list(decisions)))
        if outcomes:
            statement = statement.where(AuditEvent.outcome.in_(list(outcomes)))
        if correlation_id is not None:
            statement = statement.where(AuditEvent.correlation_id == correlation_id)
        if start_time is not None:
            statement = statement.where(AuditEvent.occurred_at >= start_time)
        if end_time is not None:
            statement = statement.where(AuditEvent.occurred_at <= end_time)
        return statement
