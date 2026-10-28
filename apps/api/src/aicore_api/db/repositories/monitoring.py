"""Monitoring queries: aggregation over the audit trail, and nothing else.

One table is read — ``aicore.audit_events`` — and every statement in this module is
shaped by three rules that the class refuses to express otherwise:

- **Tenant-scoped.** :class:`MonitoringRepository` extends
  :class:`~aicore_api.db.repositories.organizations.OrganizationScopedRepository`, so a
  tenant must be bound before a statement can be built *or* executed, and every query
  carries ``organization_id = :tenant``. Cross-tenant monitoring is not a rule this
  module follows; it is a statement it cannot write.
- **Window-bounded.** ``start`` and ``end`` are required keyword arguments on every
  method, with no default and no ``None``. There is no method here that means "everything
  this organization ever recorded" — the aggregate that would answer that question is
  priced by how long the tenant has existed, which is the query a monitoring endpoint
  must never be able to run by accident.
- **Read-only.** There is no ``append``, no ``update``, no ``delete`` and no raw SQL
  escape hatch. The trail is append-only in the database (triggers refuse ``UPDATE``,
  ``DELETE`` and ``TRUNCATE``), and this layer is read-only by construction on top of
  that. ``test_monitoring_read_only.py`` asserts both halves: the absence of a write
  method here, and that calling every read leaves the trail byte-for-byte unchanged.

The SQL is generated from the counter tables in :mod:`aicore_api.core.monitoring` rather
than restating them, so a metric's name, its definition and the column the API publishes
come from one place. Aggregation happens in PostgreSQL — ``count(*) FILTER (WHERE …)``,
``GROUP BY`` and ``date_trunc`` — rather than by fetching rows and counting them in
Python, because the row count is the tenant's, not this module's, business.

What this module deliberately cannot do: it cannot tell whether a number is *unusual*.
There is no baseline, no comparison against a previous window, no threshold and no score.
It counts what happened in the window it was given, and a caller who wants to compare
windows compares two responses — which keeps the comparing — and the judgement that may
follow it — out of the measurement layer.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from sqlalchemy import ColumnElement, Select, distinct, func, select

from aicore_api.core.audit import AuditDecision, AuditEventType
from aicore_api.core.monitoring import (
    ACTION_ACTIVITY_COUNTERS,
    ACTION_DECISION_COUNTERS,
    AGENT_ACTIVITY_COUNTERS,
    SUMMARY_COUNTERS,
    TREND_COUNTERS,
    UNSPECIFIED_REASON,
    TimeInterval,
)
from aicore_api.db.models.audit_event import AuditEvent
from aicore_api.db.repositories.organizations import OrganizationScopedRepository

__all__ = ["MonitoringRepository"]

#: The event types that describe the *action pipeline* — a decision and what came of it.
#: The per-action view is restricted to these, because ``action`` is also the column a
#: lifecycle event uses for its permission code (``asset.create``): without the filter,
#: the action view would list inventory operations next to registered actions, which is
#: the one thing it is meant to distinguish.
_ACTION_PIPELINE_TYPES: tuple[AuditEventType, ...] = tuple(
    dict.fromkeys(
        event_type
        for event_types in ACTION_ACTIVITY_COUNTERS.values()
        for event_type in event_types
    )
)

#: The metadata key Phase 7 writes the firewall's reason under. Read (never written) here
#: so a denial can be attributed to the layer that refused it — ``policy_denied``,
#: ``authorization_denied``, ``target_not_found``, ``environment_mismatch`` — which is the
#: difference between "eight refusals" and "eight refusals, six of them because a policy
#: said no".
_REASON_KEY = "reason"

#: The most rows a grouped per-action response may carry. The action catalogue is closed
#: and code-level, so this is a backstop rather than a page size: it exists so that the
#: one query in this module without a caller-supplied ``limit`` still has one.
MAX_ACTION_ROWS = 200


def _count_expressions(
    counters: Mapping[str, tuple[AuditEventType, ...]],
) -> list[ColumnElement[int]]:
    """Turn a counter table into ``count(*) FILTER (WHERE …)`` expressions.

    A counter that names every event type is a plain ``count(*)``: the filter would be a
    tautology, and spelling it out is how a counter silently stops covering an event type
    added later. The check is against the *vocabulary*, not a literal list, so it stays
    true when the vocabulary grows.
    """
    vocabulary = set(AuditEventType)
    expressions: list[ColumnElement[int]] = []
    for name, event_types in counters.items():
        if set(event_types) >= vocabulary:
            expressions.append(func.count().label(name))
        else:
            values = [event_type.value for event_type in event_types]
            expressions.append(func.count().filter(AuditEvent.event_type.in_(values)).label(name))
    return expressions


def _decision_expressions(
    counters: Mapping[str, AuditDecision],
) -> list[ColumnElement[int]]:
    """Turn a *decision* table into ``count(*) FILTER (WHERE decision = …)`` expressions.

    The same idea as :func:`_count_expressions`, over the other axis: a metric defined as
    "rows the firewall permitted" is generated from the decision vocabulary rather than
    written as a literal, so the name and the value it counts cannot drift apart.
    """
    return [
        func.count().filter(AuditEvent.decision == decision.value).label(name)
        for name, decision in counters.items()
    ]


def _counts(row: Mapping[str, Any], counters: Mapping[str, Any]) -> dict[str, int]:
    """Read the counter columns out of one aggregate row."""
    return {name: int(row[name]) for name in counters}


class MonitoringRepository(OrganizationScopedRepository):
    """One organization's activity, measured over a bounded window.

    Every method takes ``start`` and ``end``. The service above decides what those are;
    this layer refuses to guess, so a missing window is a programming error rather than a
    full-table scan.
    """

    # ── The windowed aggregate every query starts from ───────────────────────

    def _windowed(self, *expressions: Any, start: datetime, end: datetime) -> Select[Any]:
        """A statement over this organization's events inside ``[start, end]``.

        Inclusive at both ends: a window that ends at 10:00 includes the event at exactly
        10:00, which is what a caller reading two adjacent windows expects — the boundary
        event belongs to both, and neither response has a hole. (Buckets make the same
        choice per bucket's start, so a series and a summary agree.)
        """
        self._require_tenant_owned(AuditEvent)
        return (
            select(*expressions)
            .select_from(AuditEvent)
            .where(
                AuditEvent.organization_id == self.organization_id,
                AuditEvent.occurred_at >= start,
                AuditEvent.occurred_at <= end,
            )
        )

    # ── Summary ──────────────────────────────────────────────────────────────

    def summary(self, *, start: datetime, end: datetime) -> dict[str, int]:
        """Every summary counter, plus the total, in one pass over the window.

        One query rather than one per metric: eighteen counters that each scanned the same
        slice would do eighteen times the work to answer one question, and PostgreSQL can
        compute them all from a single scan.
        """
        row = (
            self.execute(
                self._windowed(
                    func.count().label("events"),
                    *_count_expressions(SUMMARY_COUNTERS),
                    start=start,
                    end=end,
                )
            )
            .mappings()
            .one()
        )
        return {"events": int(row["events"]), **_counts(row, SUMMARY_COUNTERS)}

    def active_identifiers(self, *, start: datetime, end: datetime) -> tuple[int, int]:
        """How many distinct agents and assets the window's events mention.

        Both are counts of *activity*, not of inventory: an agent with nothing in the
        window is not counted (and is not reported as idle — this build has no clock on
        agents, only events). ``count(distinct …)`` ignores NULLs, so events with no agent
        attributed are simply not agents here.

        Assets are counted from ``resource_id`` where the event is about an asset, which is
        the same identifier the inventory would use — not a name, and not a count of rows
        that mention one.
        """
        row = (
            self.execute(
                self._windowed(
                    func.count(distinct(AuditEvent.agent_id)).label("agents"),
                    func.count(distinct(AuditEvent.resource_id))
                    .filter(AuditEvent.resource_type == "asset")
                    .label("assets"),
                    start=start,
                    end=end,
                )
            )
            .mappings()
            .one()
        )
        return int(row["agents"]), int(row["assets"])

    def denial_reasons(self, *, start: datetime, end: datetime) -> dict[str, int]:
        """How many refusals each layer produced.

        A refusal is one event (Phase 8 records one per refused request, not one per layer
        that could have refused it), and the reason it carries is the firewall's own closed
        vocabulary. This is the breakdown that turns "eight denials" into "six a policy
        refused, two authorization did" — still a count, and still not a judgement about
        whether eight is a lot.
        """
        reason = func.coalesce(
            AuditEvent.event_metadata[_REASON_KEY].astext, UNSPECIFIED_REASON
        ).label("reason")
        rows = (
            self.execute(
                self._windowed(reason, func.count().label("denials"), start=start, end=end)
                .where(AuditEvent.event_type == AuditEventType.ACTION_DENIED.value)
                .group_by(reason)
                .order_by(reason)
            )
            .mappings()
            .all()
        )
        return {str(row["reason"]): int(row["denials"]) for row in rows}

    def decision_counts(self, *, start: datetime, end: datetime) -> dict[str, int]:
        """How the action pipeline answered, by decision, over the window.

        The decision axis as Phase 6 and Phase 7 defined it (``allow``, ``deny``,
        ``require_approval``), counted over the events that carry one. Rows without a
        decision — a lifecycle change, an admitted-but-undecided request — are not
        decisions and are not counted here; the summary counts those by event type.
        """
        rows = (
            self.execute(
                self._windowed(
                    AuditEvent.decision.label("decision"),
                    func.count().label("events"),
                    start=start,
                    end=end,
                )
                .where(AuditEvent.decision.is_not(None))
                .group_by(AuditEvent.decision)
                .order_by(AuditEvent.decision)
            )
            .mappings()
            .all()
        )
        return {str(row["decision"]): int(row["events"]) for row in rows}

    # ── Per agent ────────────────────────────────────────────────────────────

    def agent_activity(
        self,
        *,
        start: datetime,
        end: datetime,
        limit: int,
        offset: int,
        agent_id: uuid.UUID | None = None,
    ) -> list[Mapping[str, Any]]:
        """One row per agent with activity in the window, most active first.

        Ordered by event count descending and then by identifier ascending: the first key
        is what an operator is looking for ("which agents are doing things?"), and the
        second makes the order total, so a page cannot repeat or skip an agent the way it
        could if two rows tied and the database were free to choose.

        An agent with no events in the window is absent rather than reported as a row of
        zeros: this build knows what happened, and it has no way to tell "idle" from
        "never registered" — reporting both as zeros would invent the difference.
        """
        counters = _count_expressions(AGENT_ACTIVITY_COUNTERS)
        last_activity = func.max(AuditEvent.occurred_at).label("last_activity_at")
        statement = (
            self._windowed(
                AuditEvent.agent_id.label("agent_id"),
                *counters,
                last_activity,
                start=start,
                end=end,
            )
            .where(AuditEvent.agent_id.is_not(None))
            .group_by(AuditEvent.agent_id)
            .order_by(counters[0].desc(), AuditEvent.agent_id.asc())
            .limit(limit)
            .offset(offset)
        )
        if agent_id is not None:
            statement = statement.where(AuditEvent.agent_id == agent_id)
        return list(self.execute(statement).mappings().all())

    def count_agents(
        self, *, start: datetime, end: datetime, agent_id: uuid.UUID | None = None
    ) -> int:
        """How many agents the window has activity for — the total behind a page."""
        statement = self._windowed(AuditEvent.agent_id, start=start, end=end).where(
            AuditEvent.agent_id.is_not(None)
        )
        if agent_id is not None:
            statement = statement.where(AuditEvent.agent_id == agent_id)
        inner = statement.group_by(AuditEvent.agent_id).subquery()
        return int(self.execute(select(func.count()).select_from(inner)).scalar_one())

    # ── Per action ───────────────────────────────────────────────────────────

    def action_activity(
        self,
        *,
        start: datetime,
        end: datetime,
        action: str | None = None,
        limit: int = MAX_ACTION_ROWS,
    ) -> list[Mapping[str, Any]]:
        """One row per registered action that ran or was refused in the window.

        Ordered by identifier: the set is the closed action catalogue (a handful of
        identifiers fixed in code), so insertion order would be arbitrary and count order
        would move a row every time a request arrived. Alphabetical is stable, and a client
        can index the row it wants without searching.

        ``allowed`` is the decision axis rather than an event type — see
        :data:`~aicore_api.core.monitoring.ACTION_DECISION_COUNTERS` — which is why it is
        counted from the ``decision`` column while the rest are counted from
        ``event_type``.
        """
        counters = _count_expressions(ACTION_ACTIVITY_COUNTERS)
        statement = (
            self._windowed(
                AuditEvent.action.label("action"),
                *counters,
                *_decision_expressions(ACTION_DECISION_COUNTERS),
                start=start,
                end=end,
            )
            .where(
                AuditEvent.action.is_not(None),
                AuditEvent.event_type.in_(
                    [event_type.value for event_type in _ACTION_PIPELINE_TYPES]
                ),
            )
            .group_by(AuditEvent.action)
            .order_by(AuditEvent.action.asc())
            .limit(limit)
        )
        if action is not None:
            statement = statement.where(AuditEvent.action == action)
        return list(self.execute(statement).mappings().all())

    # ── Over time ────────────────────────────────────────────────────────────

    def trend(
        self, *, start: datetime, end: datetime, interval: TimeInterval
    ) -> list[Mapping[str, Any]]:
        """Activity per time bucket, as PostgreSQL computes it.

        The bucket is floored in UTC on the *database* side too — ``timezone('UTC', …)``
        around ``date_trunc`` — so the series does not change shape when a session's
        ``TimeZone`` does. Buckets with no events are absent from these rows; the service
        fills them in, because a chart needs the zeros and this layer reports facts.

        Only the buckets that exist in the data are returned, which is bounded by the
        window: the caller's interval is checked against
        :data:`~aicore_api.core.monitoring.MAX_BUCKETS` before this runs.
        """
        bucket = func.timezone(
            "UTC", func.date_trunc(interval.value, func.timezone("UTC", AuditEvent.occurred_at))
        ).label("bucket")
        rows = (
            self.execute(
                self._windowed(
                    bucket,
                    func.count().label("events"),
                    *_count_expressions(TREND_COUNTERS),
                    start=start,
                    end=end,
                )
                .group_by(bucket)
                .order_by(bucket)
            )
            .mappings()
            .all()
        )
        return list(rows)
