"""The internal audit writer: the only thing in this application that writes a trail row.

Every audit event in AICore is written through :class:`AuditWriter`, and that is the
point of the class existing at all. If each route wrote its own row it would each have to
remember the rules — that the actor comes from the credential and not from the request,
that the organization comes from the resolved context, that the timestamp is the server's,
that metadata is a summary and never a payload — and the first one to forget would be the
one whose events are missing from an investigation.

So the rules live here instead, once:

- **Attribution is resolved, never accepted.** :meth:`AuditWriter.record` takes the
  authorized :class:`~aicore_api.auth.authorization.OrganizationContext` that the route
  already holds, and derives the organization, the person and the membership from it. There
  is no parameter for any of the three, so a route *cannot* record an event as somebody
  else or against another tenant. :meth:`AuditWriter.record_system` is the other origin:
  an internal operation, which names no person at all.
- **Correlation comes from the request context.** The request id is the one the middleware
  sanitized for this request; the writer reads it rather than being told it. A correlation
  id may be supplied when a flow already has one (the action firewall does), and it is
  accepted only if it is a value the request layer could have produced.
- **Metadata goes through one boundary.** :func:`~aicore_api.core.audit.sanitize_metadata`
  bounds it, and redacts anything whose key or shape says "credential".
- **Nothing here decides anything.** The writer records what the caller already decided.
  It is not consulted by the firewall, it cannot change an outcome, and it cannot cause an
  execution: it runs after the decision, and a failure inside it raises rather than
  answering a question about whether something may run.

This is an internal service. No route accepts an event from a client, and no permission
grants one: a caller that could fabricate a trail entry could hide what it did.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from aicore_api.auth.authorization import OrganizationContext
from aicore_api.core.audit import (
    LIFECYCLE_ACTIONS,
    AuditActor,
    AuditDecision,
    AuditError,
    AuditEventType,
    AuditMetadataError,
    AuditOutcome,
    AuditResourceType,
    AuditSource,
    resolve_event_type,
    sanitize_metadata,
)
from aicore_api.core.request_context import (
    get_current_request_id,
    is_safe_request_id,
    new_request_id,
)
from aicore_api.db.models.audit_event import AuditEvent
from aicore_api.db.repositories.audit_events import AuditEventRepository

if TYPE_CHECKING:  # pragma: no cover - imported for its type, not at runtime
    # A forward reference rather than a runtime import: this module is reached from
    # ``core.events`` (the seam calls the writer), and importing back would close the
    # cycle. The writer only ever *reads* the attributes of the value it is handed, so
    # nothing here needs the class at runtime.
    from aicore_api.core.events import DomainEvent

__all__ = ["AuditWriter"]

logger = logging.getLogger(__name__)


class AuditWriter:
    """Writes audit events for one organization, on one session.

    A value, not a singleton: it is constructed per request (or per ingestion call) from
    the session the caller already has, so an event is committed in the same place as
    everything else that request did.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # ── The two origins ──────────────────────────────────────────────────────

    def record(
        self,
        event_type: AuditEventType | str,
        *,
        context: OrganizationContext,
        resource_type: AuditResourceType | str,
        resource_id: uuid.UUID | None = None,
        agent_id: uuid.UUID | None = None,
        action: str | None = None,
        decision: AuditDecision | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        correlation_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuditEvent:
        """Record an event a person caused, through an authenticated request.

        The organization, the person and the membership come from ``context`` — the value
        the authorization dependency resolved from the credential and the path — so this
        call cannot attribute the event to anyone else, or to another tenant.
        """
        return self._write(
            event_type,
            organization_id=context.organization_id,
            actor=AuditActor.human(user_id=context.user_id, membership_id=context.membership_id),
            source=AuditSource.API,
            request_id=self._request_id(),
            resource_type=resource_type,
            resource_id=resource_id,
            agent_id=agent_id,
            action=action,
            decision=decision,
            outcome=outcome,
            correlation_id=correlation_id,
            metadata=metadata,
        )

    def record_system(
        self,
        event_type: AuditEventType | str,
        *,
        organization_id: uuid.UUID,
        source: AuditSource,
        resource_type: AuditResourceType | str,
        resource_id: uuid.UUID | None = None,
        action: str | None = None,
        decision: AuditDecision | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        metadata: Mapping[str, Any] | None = None,
    ) -> AuditEvent:
        """Record an event nobody performed: an integration's report, a future worker.

        Two parameters are required rather than defaulted, because both would be guesses
        otherwise: the organization the event belongs to (an internal caller has no
        credential to derive it from, so it must state it) and the origin it came from. The
        actor is always the system — there is no parameter for one.

        No request id is recorded, because there was no request; the correlation id is
        generated for the call so that the events of one ingestion run group together.
        """
        if not isinstance(organization_id, uuid.UUID):
            raise AuditMetadataError(
                "a system event must name its organization as a UUID; there is no credential "
                "to resolve one from"
            )
        return self._write(
            event_type,
            organization_id=organization_id,
            actor=AuditActor.system(),
            source=source,
            request_id=None,
            resource_type=resource_type,
            resource_id=resource_id,
            agent_id=None,
            action=action,
            decision=decision,
            outcome=outcome,
            correlation_id=None,
            metadata=metadata,
        )

    def record_domain_event(
        self,
        event: DomainEvent,
        *,
        source: AuditSource = AuditSource.API,
    ) -> AuditEvent:
        """Record one domain event from the seam in ``aicore_api.core.events``.

        The seam's events carry everything attribution needs and nothing it does not: the
        organization and the resource from the code that changed them, and the actor from
        the authorized request context. This method turns that into a trail row — which is
        the whole of Phase 8's integration with Phases 3, 4 and 6, and the reason
        ``emit_event`` takes a session.

        Two deliberate choices:

        - **The event name must be a declared event type.** An invented name raises rather
          than being stored: a trail whose rows say things no vocabulary admits cannot be
          queried, summarized or trusted.
        - **The timestamp is the database's, not the event's.** The seam stamps a Python
          timestamp for its log line; the row's ``occurred_at`` comes from PostgreSQL's
          clock, because a trail's timeline should be one clock — the one the storage
          agrees on — rather than whichever process happened to write it.
        """
        event_type = resolve_event_type(event.name)
        actor = self._actor_from(event)
        if source is not AuditSource.API and actor.is_human:
            raise AuditError(
                f"a {source.value} event cannot be attributed to a person: an internal "
                "operation has no authenticated caller"
            )
        return self._write(
            event_type,
            organization_id=event.organization_id,
            actor=actor,
            source=source,
            request_id=self._request_id() if source is AuditSource.API else None,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            agent_id=None,
            action=LIFECYCLE_ACTIONS.get(event_type),
            decision=None,
            outcome=AuditOutcome.SUCCESS,
            correlation_id=None,
            metadata=event.data,
        )

    # ── The one write ────────────────────────────────────────────────────────

    def _write(
        self,
        event_type: AuditEventType | str,
        *,
        organization_id: uuid.UUID,
        actor: AuditActor,
        source: AuditSource,
        request_id: str | None,
        resource_type: AuditResourceType | str,
        resource_id: uuid.UUID | None,
        agent_id: uuid.UUID | None,
        action: str | None,
        decision: AuditDecision | None,
        outcome: AuditOutcome,
        correlation_id: str | None,
        metadata: Mapping[str, Any] | None,
    ) -> AuditEvent:
        """Validate, sanitize, persist and log one event. The single path to the table."""
        resolved_type = resolve_event_type(event_type)
        resolved_resource = self._resource_type(resource_type)
        clean_metadata = sanitize_metadata(metadata)
        resolved_correlation = self._correlation_id(correlation_id, request_id)

        row = AuditEventRepository(self._session, organization_id).append(
            event_type=resolved_type,
            actor=actor,
            resource_type=resolved_resource,
            outcome=outcome,
            source=source,
            correlation_id=resolved_correlation,
            resource_id=resource_id,
            agent_id=agent_id,
            action=action,
            decision=decision,
            request_id=request_id,
            event_metadata=clean_metadata,
        )

        # The table is the record. This line is a convenience for an operator reading logs
        # live, and it carries the same sanitized metadata — never the request, never a
        # credential, never an argument.
        logger.info(
            "audit event %s",
            {
                "event": row.event_type,
                "organization_id": str(row.organization_id),
                "resource_type": row.resource_type,
                "resource_id": None if row.resource_id is None else str(row.resource_id),
                "actor_type": row.actor_type,
                "action": row.action,
                "decision": row.decision,
                "outcome": row.outcome,
                "correlation_id": row.correlation_id,
                "metadata": clean_metadata,
            },
        )
        return row

    # ── Context, resolved rather than accepted ───────────────────────────────

    @staticmethod
    def _request_id() -> str:
        """The request id the middleware established, or a fresh one if there is none.

        There is no request-id parameter anywhere in this class, on purpose: an event that
        carried a caller-supplied identifier would let a client choose which request its
        action appears to belong to. When no request context exists (a script calling into
        the API layer directly), a server-generated id is used rather than nothing, so the
        ``source = 'api'`` tie in the schema still holds.
        """
        request_id = get_current_request_id()
        # ``is_safe_request_id`` is a plain predicate, not a narrowing one: it answers a
        # question about a value, and the explicit ``isinstance`` is what tells the type
        # checker the same thing it tells the reader.
        if isinstance(request_id, str) and is_safe_request_id(request_id):
            return request_id
        return new_request_id()

    @staticmethod
    def _correlation_id(candidate: str | None, request_id: str | None) -> str:
        """The identifier that groups the events of one flow.

        A caller may pass the correlation id its flow already established (the action
        pipeline passes the firewall's). It is accepted only if the request layer could
        have produced it; anything else is replaced by the request's own id rather than
        stored. The event is never dropped over a correlation value: losing a record to keep
        a grouping consistent would be the wrong trade.
        """
        if candidate is not None and is_safe_request_id(candidate):
            return candidate
        if candidate is not None:  # pragma: no cover - every caller passes a sanitized value
            logger.warning("audit correlation id was not a safe identifier; using the request id")
        if request_id is not None:
            return request_id
        return new_request_id()

    @staticmethod
    def _actor_from(event: DomainEvent) -> AuditActor:
        """Resolve the actor an event describes, refusing a half-attributed one.

        Both identifiers make a person; neither makes a system. One of them alone is not a
        third case — it is an event that claims a person acted without being able to say
        who they were or which membership carried the role, and :class:`AuditActor`
        refuses to represent that rather than guessing.
        """
        if event.actor_id is not None or event.actor_membership_id is not None:
            if event.actor_id is None or event.actor_membership_id is None:
                raise AuditError(
                    "an event attributed to a person must name both the person and the "
                    "membership; naming one is not attribution"
                )
            return AuditActor.human(user_id=event.actor_id, membership_id=event.actor_membership_id)
        return AuditActor.system()

    @staticmethod
    def _resource_type(resource_type: AuditResourceType | str) -> AuditResourceType:
        """Coerce the resource type, refusing anything outside the vocabulary."""
        if isinstance(resource_type, AuditResourceType):
            return resource_type
        try:
            return AuditResourceType(resource_type)
        except ValueError as exc:
            declared = ", ".join(sorted(value.value for value in AuditResourceType))
            raise AuditMetadataError(
                f"{resource_type!r} is not a declared audit resource type; declared: {declared}"
            ) from exc
