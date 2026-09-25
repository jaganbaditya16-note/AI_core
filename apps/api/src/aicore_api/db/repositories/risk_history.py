"""Risk history: the bounded aggregates the anomaly engine compares, and nothing else.

One table is read — ``aicore.audit_events`` — and every statement here obeys four rules:

- **Tenant-scoped.** :class:`RiskHistoryRepository` extends
  :class:`~aicore_api.db.repositories.organizations.OrganizationScopedRepository`: a tenant
  is bound when a statement runs, and every statement carries ``organization_id = :tenant``.
- **Window-bounded.** Every method takes the resolved
  :class:`~aicore_api.core.risk.AnalysisWindows`, and every statement is restricted to
  ``[baseline_start, observation_end)`` — at most 30 days plus 24 hours. There is no method
  that reads "all history": the baseline is a named, closed window, never "since the
  tenant began".
- **Aggregated in PostgreSQL.** Rows never reach Python. Each method returns *one row per
  agent* (the hour-of-day profile: at most 24), computed with ``GROUP BY`` and
  ``count(*) FILTER (WHERE …)``, so the cost of an analysis page in Python is priced by
  the page size, not by how busy the agents were. Novelty is a set difference computed in
  SQL, returning counts and a short sorted sample — not the sets.
- **Read-only, and blind to payloads.** No write method exists here. ``metadata`` — the
  one column that could carry anything an operator wrote — is never selected, filtered on
  or grouped by: the engine sees event types, agents, actions, targets and timestamps, and
  its evidence cannot contain what it never read.

Every statement matches the ``(organization_id, event_type, occurred_at)`` index the trail
already has, and a page is six statements whatever its size (``agent_id IN (…)``), so there
is no per-agent query and no N+1.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import ColumnElement, Integer, Select, Text, cast, func, select
from sqlalchemy.dialects.postgresql import aggregate_order_by, array_agg
from sqlalchemy.orm import InstrumentedAttribute

from aicore_api.core.audit import AuditEventType
from aicore_api.core.risk import (
    BURST_BUCKET,
    MAX_EVIDENCE_ITEMS,
    AgentProfile,
    AnalysisWindows,
)
from aicore_api.db.models.audit_event import AuditEvent
from aicore_api.db.repositories.organizations import OrganizationScopedRepository

__all__ = ["MAX_ANALYSIS_PAGE", "RiskHistoryRepository"]

#: The largest number of agents one analysis page may cover. Six statements a page, each
#: returning at most this many rows (24 times this for hours).
MAX_ANALYSIS_PAGE = 100

_REQUESTED = AuditEventType.ACTION_REQUESTED
_DENIED = AuditEventType.ACTION_DENIED
_EXECUTED = AuditEventType.ACTION_EXECUTED
_FAILED = AuditEventType.ACTION_FAILED
_OUTCOMES = (_DENIED, _EXECUTED, _FAILED)

_BUCKET_SECONDS = int(BURST_BUCKET.total_seconds())


def _epoch() -> ColumnElement[Any]:
    """Seconds since the Unix epoch of ``occurred_at`` — the unit every bucket uses."""
    return func.extract("epoch", AuditEvent.occurred_at)


class RiskHistoryRepository(OrganizationScopedRepository):
    """Per-agent aggregates over one organization's trail, for one analysis."""

    # ── The scope every statement starts from ────────────────────────────────

    def _scope(
        self,
        *expressions: Any,
        windows: AnalysisWindows,
        event_types: Sequence[AuditEventType],
    ) -> Select[Any]:
        """This organization's attributed events of ``event_types`` inside the analysis.

        Half-open, ``[baseline_start, observation_end)``, matching the windows: the event
        at exactly ``observation_end`` belongs to the next analysis, and the event at
        exactly ``observation_start`` belongs to the observation, never to the baseline.
        """
        self._require_tenant_owned(AuditEvent)
        return (
            select(*expressions)
            .select_from(AuditEvent)
            .where(
                AuditEvent.organization_id == self.organization_id,
                AuditEvent.event_type.in_([event_type.value for event_type in event_types]),
                AuditEvent.occurred_at >= windows.baseline_start,
                AuditEvent.occurred_at < windows.observation_end,
                AuditEvent.agent_id.is_not(None),
            )
        )

    @staticmethod
    def _in_baseline(windows: AnalysisWindows) -> ColumnElement[bool]:
        return AuditEvent.occurred_at < windows.observation_start

    @staticmethod
    def _in_observation(windows: AnalysisWindows) -> ColumnElement[bool]:
        return AuditEvent.occurred_at >= windows.observation_start

    # ── Which agents an analysis covers ──────────────────────────────────────

    def agent_page(
        self,
        windows: AnalysisWindows,
        *,
        limit: int,
        offset: int,
        agent_id: uuid.UUID | None = None,
    ) -> list[uuid.UUID]:
        """Agents with at least one action request in the analysis, by identifier.

        Ordered by identifier so a page is stable and total. An agent that requested
        nothing in either window is not covered: there is nothing to compare.
        """
        if not 1 <= limit <= MAX_ANALYSIS_PAGE:
            raise ValueError(f"limit must be between 1 and {MAX_ANALYSIS_PAGE}")
        if offset < 0:
            raise ValueError("offset must not be negative")
        statement = self._scope(AuditEvent.agent_id, windows=windows, event_types=(_REQUESTED,))
        if agent_id is not None:
            statement = statement.where(AuditEvent.agent_id == agent_id)
        statement = (
            statement.group_by(AuditEvent.agent_id)
            .order_by(AuditEvent.agent_id.asc())
            .limit(limit)
            .offset(offset)
        )
        return [row[0] for row in self.execute(statement).all()]

    def count_agents(self, windows: AnalysisWindows, *, agent_id: uuid.UUID | None = None) -> int:
        """How many agents :meth:`agent_page` would cover in total."""
        statement = self._scope(
            func.count(func.distinct(AuditEvent.agent_id)),
            windows=windows,
            event_types=(_REQUESTED,),
        )
        if agent_id is not None:
            statement = statement.where(AuditEvent.agent_id == agent_id)
        return int(self.execute(statement).scalar_one())

    # ── The six aggregates of a page ─────────────────────────────────────────

    def _rates(
        self, windows: AnalysisWindows, agent_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, Mapping[str, Any]]:
        """Per-slot request counts, reduced to sums: the input of mean and stddev.

        Slots are observation-length buckets numbered from 0 at ``baseline_start``; the
        observation is slot ``windows.slots``. Empty slots produce no row, which is why the
        engine takes the slot count from the windows rather than from this query.
        """
        origin = int(windows.baseline_start.timestamp())
        slot = cast(func.floor((_epoch() - origin) / windows.slot_seconds), Integer)
        per_slot = (
            self._scope(
                AuditEvent.agent_id.label("agent_id"),
                slot.label("slot"),
                func.count().label("requests"),
                windows=windows,
                event_types=(_REQUESTED,),
            )
            .where(AuditEvent.agent_id.in_(agent_ids))
            .group_by(AuditEvent.agent_id, slot)
            .subquery()
        )
        in_baseline = per_slot.c.slot < windows.slots
        statement = select(
            per_slot.c.agent_id,
            func.coalesce(func.sum(per_slot.c.requests).filter(in_baseline), 0).label(
                "baseline_requests"
            ),
            func.coalesce(
                func.sum(per_slot.c.requests * per_slot.c.requests).filter(in_baseline), 0
            ).label("baseline_sum_squares"),
            func.min(per_slot.c.slot).filter(in_baseline).label("first_active_slot"),
            func.count().filter(in_baseline).label("active_slots"),
            func.coalesce(func.sum(per_slot.c.requests).filter(~in_baseline), 0).label(
                "observed_requests"
            ),
        ).group_by(per_slot.c.agent_id)
        return {row["agent_id"]: row for row in self.execute(statement).mappings().all()}

    def _outcomes(
        self, windows: AnalysisWindows, agent_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, Mapping[str, Any]]:
        """Refusals, executions and failures per period, in one pass."""
        baseline, observation = self._in_baseline(windows), self._in_observation(windows)
        columns = []
        for period_name, period in (("baseline", baseline), ("observed", observation)):
            for name, event_type in (
                ("denials", _DENIED),
                ("executions", _EXECUTED),
                ("failures", _FAILED),
            ):
                columns.append(
                    func.count()
                    .filter(period, AuditEvent.event_type == event_type.value)
                    .label(f"{period_name}_{name}")
                )
        statement = (
            self._scope(
                AuditEvent.agent_id.label("agent_id"),
                *columns,
                windows=windows,
                event_types=_OUTCOMES,
            )
            .where(AuditEvent.agent_id.in_(agent_ids))
            .group_by(AuditEvent.agent_id)
        )
        return {row["agent_id"]: row for row in self.execute(statement).mappings().all()}

    def _novelty(
        self,
        windows: AnalysisWindows,
        agent_ids: Sequence[uuid.UUID],
        *,
        item: ColumnElement[Any] | InstrumentedAttribute[Any],
        present: ColumnElement[bool],
    ) -> dict[uuid.UUID, Mapping[str, Any]]:
        """What the observation named that the baseline never did — counted in SQL.

        Returns the distinct counts per period, how many observed items are absent from the
        baseline, and the first :data:`MAX_EVIDENCE_ITEMS` of those in sorted order.
        """
        per_item = (
            self._scope(
                AuditEvent.agent_id.label("agent_id"),
                item.label("item"),
                func.count().filter(self._in_baseline(windows)).label("baseline"),
                func.count().filter(self._in_observation(windows)).label("observed"),
                windows=windows,
                event_types=(_REQUESTED,),
            )
            .where(AuditEvent.agent_id.in_(agent_ids), present)
            .group_by(AuditEvent.agent_id, item)
            .subquery()
        )
        # The sample is capped with a window function rather than an array slice: the
        # engine's tenancy guard renders every statement generically before it runs, and
        # ``row_number()`` renders everywhere. Ranked within (agent, novel?) by item, so the
        # sample is the first novel items in sorted order — deterministic.
        is_novel = (per_item.c.observed > 0) & (per_item.c.baseline == 0)
        ranked = select(
            per_item.c.agent_id,
            per_item.c.item,
            per_item.c.baseline,
            per_item.c.observed,
            is_novel.label("novel"),
            func.row_number()
            .over(partition_by=(per_item.c.agent_id, is_novel), order_by=per_item.c.item.asc())
            .label("rank"),
        ).subquery()
        sample = array_agg(aggregate_order_by(ranked.c.item, ranked.c.item.asc())).filter(
            ranked.c.novel, ranked.c.rank <= MAX_EVIDENCE_ITEMS
        )
        statement = select(
            ranked.c.agent_id,
            func.count().filter(ranked.c.baseline > 0).label("baseline_distinct"),
            func.count().filter(ranked.c.observed > 0).label("observed_distinct"),
            func.count().filter(ranked.c.novel).label("novel_count"),
            sample.label("novel_sample"),
        ).group_by(ranked.c.agent_id)
        return {row["agent_id"]: row for row in self.execute(statement).mappings().all()}

    def _hours(
        self, windows: AnalysisWindows, agent_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, tuple[list[int], list[int]]]:
        """Requests per UTC hour of day, per period: at most 24 rows per agent."""
        hour = cast(func.extract("hour", func.timezone("UTC", AuditEvent.occurred_at)), Integer)
        statement = (
            self._scope(
                AuditEvent.agent_id.label("agent_id"),
                hour.label("hour"),
                func.count().filter(self._in_baseline(windows)).label("baseline"),
                func.count().filter(self._in_observation(windows)).label("observed"),
                windows=windows,
                event_types=(_REQUESTED,),
            )
            .where(AuditEvent.agent_id.in_(agent_ids))
            .group_by(AuditEvent.agent_id, hour)
        )
        hours: dict[uuid.UUID, tuple[list[int], list[int]]] = {}
        for row in self.execute(statement).mappings().all():
            baseline, observed = hours.setdefault(row["agent_id"], ([0] * 24, [0] * 24))
            baseline[row["hour"]] = int(row["baseline"])
            observed[row["hour"]] = int(row["observed"])
        return hours

    def _peaks(
        self, windows: AnalysisWindows, agent_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, Mapping[str, Any]]:
        """The busiest five-minute bucket per period.

        Buckets are aligned to the epoch, and both window boundaries are whole hours, so no
        bucket straddles the baseline and the observation.
        """
        bucket = cast(func.floor(_epoch() / _BUCKET_SECONDS), Integer)
        per_bucket = (
            self._scope(
                AuditEvent.agent_id.label("agent_id"),
                bucket.label("bucket"),
                func.count().label("requests"),
                windows=windows,
                event_types=(_REQUESTED,),
            )
            .where(AuditEvent.agent_id.in_(agent_ids))
            .group_by(AuditEvent.agent_id, bucket)
            .subquery()
        )
        boundary = int(windows.observation_start.timestamp()) // _BUCKET_SECONDS
        statement = select(
            per_bucket.c.agent_id,
            func.coalesce(
                func.max(per_bucket.c.requests).filter(per_bucket.c.bucket < boundary), 0
            ).label("baseline_peak"),
            func.coalesce(
                func.max(per_bucket.c.requests).filter(per_bucket.c.bucket >= boundary), 0
            ).label("observed_peak"),
        ).group_by(per_bucket.c.agent_id)
        return {row["agent_id"]: row for row in self.execute(statement).mappings().all()}

    # ── Assembly ─────────────────────────────────────────────────────────────

    def profiles(
        self, windows: AnalysisWindows, agent_ids: Sequence[uuid.UUID]
    ) -> list[AgentProfile]:
        """One :class:`AgentProfile` per agent, in the order given. Six statements total."""
        if not agent_ids:
            return []
        if len(agent_ids) > MAX_ANALYSIS_PAGE:
            raise ValueError(f"at most {MAX_ANALYSIS_PAGE} agents are profiled at once")
        ids = list(dict.fromkeys(agent_ids))
        rates = self._rates(windows, ids)
        outcomes = self._outcomes(windows, ids)
        actions = self._novelty(
            windows, ids, item=AuditEvent.action, present=AuditEvent.action.is_not(None)
        )
        target = AuditEvent.resource_type + ":" + cast(AuditEvent.resource_id, Text)
        resources = self._novelty(
            windows, ids, item=target, present=AuditEvent.resource_id.is_not(None)
        )
        hours = self._hours(windows, ids)
        peaks = self._peaks(windows, ids)

        profiles: list[AgentProfile] = []
        empty: Mapping[str, Any] = {}
        for agent_id in ids:
            rate = rates.get(agent_id, empty)
            outcome = outcomes.get(agent_id, empty)
            action = actions.get(agent_id, empty)
            resource = resources.get(agent_id, empty)
            baseline_hours, observed_hours = hours.get(agent_id, ([0] * 24, [0] * 24))
            peak = peaks.get(agent_id, empty)
            first_active = rate.get("first_active_slot")
            profiles.append(
                AgentProfile(
                    agent_id=agent_id,
                    baseline_requests=int(rate.get("baseline_requests", 0)),
                    baseline_sum_squares=int(rate.get("baseline_sum_squares", 0)),
                    first_active_slot=None if first_active is None else int(first_active),
                    active_slots=int(rate.get("active_slots", 0)),
                    baseline_denials=int(outcome.get("baseline_denials", 0)),
                    baseline_executions=int(outcome.get("baseline_executions", 0)),
                    baseline_failures=int(outcome.get("baseline_failures", 0)),
                    observed_requests=int(rate.get("observed_requests", 0)),
                    observed_denials=int(outcome.get("observed_denials", 0)),
                    observed_executions=int(outcome.get("observed_executions", 0)),
                    observed_failures=int(outcome.get("observed_failures", 0)),
                    baseline_distinct_actions=int(action.get("baseline_distinct", 0)),
                    observed_distinct_actions=int(action.get("observed_distinct", 0)),
                    novel_action_count=int(action.get("novel_count", 0)),
                    novel_actions=tuple(action.get("novel_sample") or ()),
                    baseline_distinct_resources=int(resource.get("baseline_distinct", 0)),
                    observed_distinct_resources=int(resource.get("observed_distinct", 0)),
                    novel_resource_count=int(resource.get("novel_count", 0)),
                    novel_resources=tuple(resource.get("novel_sample") or ()),
                    baseline_hours=tuple(baseline_hours),
                    observed_hours=tuple(observed_hours),
                    baseline_peak=int(peak.get("baseline_peak", 0)),
                    observed_peak=int(peak.get("observed_peak", 0)),
                )
            )
        return profiles
