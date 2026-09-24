"""The audit subsystem: the memory of what the platform decided and did.

Phase 8 is the first phase whose subject is *remembering*. Phases 5, 6 and 7 decide —
authorization, policy, firewall — and Phase 7 acts on one of those decisions, but nothing
kept a durable, queryable, tenant-scoped record of any of it. This package is that record.

Two modules, and the split is the whole design:

- :mod:`aicore_api.core.audit` is the **vocabulary**: the closed set of event types, the
  actor model, the decision and outcome vocabularies, and the metadata boundary that keeps
  secrets and payloads out of the trail. It is pure — no database, no session, no I/O.
- :mod:`aicore_api.audit.writer` is the **only writer**: an internal service that resolves
  attribution from the authorized request context, stamps the server's identifiers and
  goes through that metadata boundary on the way to the table.

The storage itself lives where every other table does (``db/models/audit_event.py`` and
``db/repositories/audit_events.py``), and the read API lives with the other routes.

What this package is not, and will not become: a monitoring system, an anomaly detector or
an incident manager. Those are later phases. Audit answers "what happened, who did it, what
was decided and what came of it" — and it answers by *recording* decisions other layers
made, never by making one. The firewall's authority is untouched: an audit write cannot
turn a refusal into an execution, and the writer is never consulted before a decision.
"""

from __future__ import annotations

from aicore_api.audit.writer import AuditWriter

__all__ = ["AuditWriter"]
