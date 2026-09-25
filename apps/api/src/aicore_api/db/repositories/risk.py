"""Risk reads and detection records: aggregates from the trail, and one append-only table.

Two repositories, deliberately in one module so the boundary between them is visible at a
glance.

:class:`RiskRepository` **reads** — the audit trail, aggregated. Every statement it can
build is shaped by the same three rules Phase 9's monitoring repository follows, and for
the same reasons: a tenant must be bound before a statement exists, ``start`` and ``end``
are required keyword arguments with no default (there is no method here that means
"everything this organization ever recorded"), and there is no write method at all. It
counts events into hourly buckets with ``count(*) FILTER (…)`` and ``date_trunc`` in
PostgreSQL rather than fetching rows and counting them in Python, because the row count is
the tenant's business and not this module's memory.

:class:`DetectionRepository` **records** — one table, and only ever one table:
``aicore.anomaly_detections``. Its writes are the phase's *only* writes, which is the
reason they live in a separate class: a reader can see that everything else in the risk
layer cannot change a row, and that the one thing that can writes to a table that holds
findings and nothing else. It cannot touch ``audit_events``, ``agents``, ``policies``,
``permissions`` or ``action_executions``; it cannot append to the trail; it cannot call an
adapter.

**Deduplication is the database's job.** An assessment's identity is the tuple the unique
constraint names — organization, entity, observation window, baseline window, schema
version — and the insert is ``ON CONFLICT DO NOTHING``. Two identical requests cannot both
write, whether they arrive together or a week apart, and the guarantee does not depend on
this code having checked first. When the insert does nothing, the row that already exists
is read back and returned as it is: the first analysis of a closed window is its record.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from aicore_api.core.audit import AuditEventType
from aicore_api.core.monitoring import TimeInterval
from aicore_api.core.risk import (
    ACTION_PIPELINE_TYPES,
    RISK_SCHEMA_VERSION,
    ActivityFrame,
    BucketCounts,
    EntityType,
    ResourceKey,
    RiskError,
    hour_bucket,
)
from aicore_api.db.models.anomaly_detection import AnomalyDetection
from aicore_api.db.models.audit_event import AuditEvent
from aicore_api.db.repositories.organizations import OrganizationScopedRepository

__all__ = ["MAX_FRAME_AGENTS", "DetectionDraft", "DetectionRepository", "RiskRepository"]

#: The most agents one frame request may cover. The API pages at a hundred, so this is a
#: backstop rather than a page size: it exists so that a caller who assembles an unbounded
#: identifier list gets a refusal instead of a query whose ``IN`` clause has no ceiling.
MAX_FRAME_AGENTS = 200

#: The pipeline's event types as SQL values — read from the vocabulary rather than typed
#: out, so a type added to the pipeline is counted here on the day it is added.
_PIPELINE_VALUES = sorted(event_type.value for event_type in ACTION_PIPELINE_TYPES)

#: The event types whose ``action`` column holds a registered action identifier. Reused
#: from the same vocabulary for the same reason.
_ACTION_VALUES = _PIPELINE_VALUES

_REPLAYS = AuditEventType.ACTION_REPLAYED.value
_EXECUTIONS = AuditEventType.ACTION_EXECUTED.value
_FAILURES = AuditEventType.ACTION_FAILED.value
_REQUESTS = AuditEventType.ACTION_REQUESTED.value
_DENIALS = AuditEventType.ACTION_DENIED.value
_APPROVALS = AuditEventType.ACTION_REQUIRE_APPROVAL.value


def _count_of(event_type: str) -> ColumnElement[int]:
    """A ``count(*) FILTER (WHERE event_type = …)`` column, labelled after the count."""
    return func.count().filter(AuditEvent.event_type == event_type)


def _bucket_series(*, start: datetime, end: datetime) -> tuple[datetime, ...]:
    """Every UTC hour bucket the window touches, oldest first.

    The series a frame is densified onto. It starts at the hour the window opens inside and
    ends at the hour it closes inside, which is exactly what ``date_trunc('hour', …)`` in
    the query produces — so a bucket the trail has rows for always has a place in the
    series, and a bucket it does not have rows for is present as zero rather than absent.
    """
    first = hour_bucket(start)
    last = hour_bucket(end)
    hours = int((last - first).total_seconds() // 3600)
    return tuple(first + timedelta(hours=index) for index in range(hours + 1))


def _densify(
    counted: Mapping[datetime, BucketCounts], series: tuple[datetime, ...]
) -> tuple[BucketCounts, ...]:
    """Place counted buckets onto the series, filling the gaps with zeros.

    An hour nobody did anything in is *zero activity*, not missing data — and the
    difference decides what a baseline mean means. Counting only the hours that saw
    activity would report an entity that acts in a burst every evening as though it acted
    all day, inflating its baseline and making its real behaviour look unremarkable. Filling
    the gaps makes the mean what it should be: this entity's requests per hour over the
    window, quiet hours included.
    """
    return tuple(
        counted.get(bucket)
        or BucketCounts(
            bucket=bucket,
            events=0,
            requests=0,
            executions=0,
            failures=0,
            denials=0,
            approval_required=0,
            replays=0,
        )
        for bucket in series
    )


class RiskRepository(OrganizationScopedRepository):
    """One organization's activity as the engine reads it: three queries per window.

    The unit is a :class:`~aicore_api.core.risk.ActivityFrame` — one agent's hourly
    buckets plus the actions and resources its requests mention, over one window. The
    caller asks for frames for the agents it cares about (a page from the registry, or one
    agent), so the queries carry an ``IN`` list rather than scanning the tenant, and the
    window bounds are the only thing that could make them large.
    """

    def _pipeline(self, *, start: datetime, end: datetime) -> Any:
        """The tenant-scoped, window-bounded, pipeline-only statement every read starts from."""
        self._require_tenant_owned(AuditEvent)
        return (
            select()
            .select_from(AuditEvent)
            .where(
                AuditEvent.organization_id == self.organization_id,
                AuditEvent.occurred_at >= start,
                AuditEvent.occurred_at <= end,
                AuditEvent.event_type.in_(_PIPELINE_VALUES),
            )
        )

    def activity(
        self, *, start: datetime, end: datetime, agent_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, ActivityFrame]:
        """The frames for ``agent_ids`` over ``[start, end]``; empty frames where quiet.

        An agent the window holds nothing for is present in the result with an empty frame
        rather than missing: "this agent did nothing" is a measurement, and it is the one
        that a drop in activity is made of. An identifier the window has rows for but the
        caller did not ask about is simply not returned — the population is the caller's
        decision, and it is the registry's list.
        """
        wanted = list(dict.fromkeys(agent_ids))
        if not wanted:
            return {}
        if len(wanted) > MAX_FRAME_AGENTS:
            raise RiskError(
                f"a frame request covers at most {MAX_FRAME_AGENTS} agents; this one covers "
                f"{len(wanted)}"
            )

        buckets = self._bucket_rows(start=start, end=end, agent_ids=wanted)
        actions = self._action_rows(start=start, end=end, agent_ids=wanted)
        resources = self._resource_rows(start=start, end=end, agent_ids=wanted)
        series = _bucket_series(start=start, end=end)

        frames: dict[uuid.UUID, ActivityFrame] = {}
        for agent_id in wanted:
            frames[agent_id] = ActivityFrame(
                start=start,
                end=end,
                buckets=_densify(buckets.get(agent_id, {}), series),
                actions=dict(actions.get(agent_id, {})),
                resources=dict(resources.get(agent_id, {})),
            )
        return frames

    def _bucket_rows(
        self, *, start: datetime, end: datetime, agent_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, dict[datetime, BucketCounts]]:
        """Hourly counts per agent, floored in UTC so the answer is not session-dependent."""
        bucket = func.timezone(
            "UTC",
            func.date_trunc(TimeInterval.HOUR.value, func.timezone("UTC", AuditEvent.occurred_at)),
        ).label("bucket")
        rows = (
            self.execute(
                self._pipeline(start=start, end=end)
                .with_only_columns(
                    AuditEvent.agent_id.label("agent_id"),
                    bucket,
                    func.count().label("events"),
                    _count_of(_REQUESTS).label("requests"),
                    _count_of(_EXECUTIONS).label("executions"),
                    _count_of(_FAILURES).label("failures"),
                    _count_of(_DENIALS).label("denials"),
                    _count_of(_APPROVALS).label("approval_required"),
                    _count_of(_REPLAYS).label("replays"),
                )
                .where(AuditEvent.agent_id.in_(agent_ids))
                .group_by(AuditEvent.agent_id, bucket)
                .order_by(AuditEvent.agent_id, bucket)
            )
            .mappings()
            .all()
        )
        grouped: dict[uuid.UUID, dict[datetime, BucketCounts]] = {}
        for row in rows:
            agent_id = row["agent_id"]
            grouped.setdefault(agent_id, {})[row["bucket"]] = BucketCounts(
                bucket=row["bucket"],
                events=int(row["events"]),
                requests=int(row["requests"]),
                executions=int(row["executions"]),
                failures=int(row["failures"]),
                denials=int(row["denials"]),
                approval_required=int(row["approval_required"]),
                replays=int(row["replays"]),
            )
        return grouped

    def _action_rows(
        self, *, start: datetime, end: datetime, agent_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, dict[str, int]]:
        """Per agent, how often each registered action appears in the window."""
        rows = (
            self.execute(
                self._pipeline(start=start, end=end)
                .with_only_columns(
                    AuditEvent.agent_id.label("agent_id"),
                    AuditEvent.action.label("action"),
                    func.count().label("events"),
                )
                .where(
                    AuditEvent.agent_id.in_(agent_ids),
                    AuditEvent.action.is_not(None),
                    AuditEvent.event_type.in_(_ACTION_VALUES),
                )
                .group_by(AuditEvent.agent_id, AuditEvent.action)
                .order_by(AuditEvent.agent_id, AuditEvent.action)
            )
            .mappings()
            .all()
        )
        grouped: dict[uuid.UUID, dict[str, int]] = {}
        for row in rows:
            grouped.setdefault(row["agent_id"], {})[str(row["action"])] = int(row["events"])
        return grouped

    def _resource_rows(
        self, *, start: datetime, end: datetime, agent_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, dict[ResourceKey, int]]:
        """Per agent, how often each addressed resource appears in the window."""
        rows = (
            self.execute(
                self._pipeline(start=start, end=end)
                .with_only_columns(
                    AuditEvent.agent_id.label("agent_id"),
                    AuditEvent.resource_type.label("resource_type"),
                    AuditEvent.resource_id.label("resource_id"),
                    func.count().label("events"),
                )
                .where(
                    AuditEvent.agent_id.in_(agent_ids),
                    AuditEvent.resource_id.is_not(None),
                )
                .group_by(AuditEvent.agent_id, AuditEvent.resource_type, AuditEvent.resource_id)
                .order_by(AuditEvent.agent_id, AuditEvent.resource_type, AuditEvent.resource_id)
            )
            .mappings()
            .all()
        )
        grouped: dict[uuid.UUID, dict[ResourceKey, int]] = {}
        for row in rows:
            key = ResourceKey(
                resource_type=str(row["resource_type"]), resource_id=row["resource_id"]
            )
            grouped.setdefault(row["agent_id"], {})[key] = int(row["events"])
        return grouped


@dataclass(frozen=True, slots=True)
class DetectionDraft:
    """One assessment, ready to be recorded.

    The columns of a :class:`~aicore_api.db.models.anomaly_detection.AnomalyDetection` row
    except the ones the database owns (``id``, ``detected_at``) and except the tenant,
    which comes from the repository rather than from anything a caller passed. Every value
    here was computed by the engine or resolved by the server's clock; none of it is a
    client's.
    """

    entity_type: EntityType
    entity_id: uuid.UUID
    status: str
    anomaly: bool
    risk_level: str
    detection_type: str | None
    observation_start: datetime
    observation_end: datetime
    baseline_start: datetime
    baseline_end: datetime
    baseline_window: str
    evidence: Mapping[str, Any]
    factors: Sequence[Mapping[str, Any]]
    schema_version: int = RISK_SCHEMA_VERSION

    def to_columns(self, organization_id: uuid.UUID) -> dict[str, Any]:
        """The insert's values: the draft, plus the tenant the repository was built with."""
        return {
            "organization_id": organization_id,
            "entity_type": self.entity_type.value,
            "entity_id": self.entity_id,
            "status": self.status,
            "anomaly": self.anomaly,
            "risk_level": self.risk_level,
            "detection_type": self.detection_type,
            "observation_start": self.observation_start,
            "observation_end": self.observation_end,
            "baseline_start": self.baseline_start,
            "baseline_end": self.baseline_end,
            "baseline_window": self.baseline_window,
            "schema_version": self.schema_version,
            "evidence": dict(self.evidence),
            "factors": [dict(factor) for factor in self.factors],
        }

    def identity(self, organization_id: uuid.UUID) -> dict[str, Any]:
        """The tuple that identifies this assessment — the unique constraint's columns.

        Kept next to :meth:`to_columns` so the two cannot drift: the conflict clause and
        the lookup that follows it are the same key by construction.
        """
        return {
            "organization_id": organization_id,
            "entity_type": self.entity_type.value,
            "entity_id": self.entity_id,
            "observation_start": self.observation_start,
            "observation_end": self.observation_end,
            "baseline_start": self.baseline_start,
            "baseline_end": self.baseline_end,
            "schema_version": self.schema_version,
        }


class DetectionRepository(OrganizationScopedRepository):
    """The one place a detection is written, and the ways it is read back.

    There is no update and no delete. A finding that could be edited after the fact would
    be worth less than none at all, and the database refuses both regardless — the trigger
    installed with the table is the enforcement, and the absence of a method here is the
    courtesy of not offering what would fail.
    """

    def record(self, draft: DetectionDraft) -> tuple[AnomalyDetection, bool]:
        """Record ``draft``, or return the identical assessment already recorded.

        Returns the row and whether this call created it. The conflict clause is what
        makes repeated analysis safe: a second request for the same closed window neither
        duplicates the record nor overwrites it, and no read-then-write in this method
        could make that true under concurrency.
        """
        identity = draft.identity(self.organization_id)
        statement = (
            pg_insert(AnomalyDetection)
            .values(**draft.to_columns(self.organization_id))
            .on_conflict_do_nothing(index_elements=list(identity))
            .returning(AnomalyDetection.id)
        )
        inserted = self.execute(statement).scalar_one_or_none()
        # Committed here rather than left to the caller, the way the audit writer commits:
        # a record is this phase's durable output, and a response that reported a finding a
        # crash could erase would be reporting something that never happened.
        self.session.commit()
        return self._by_identity(draft, inserted), inserted is not None

    def _by_identity(self, draft: DetectionDraft, inserted: uuid.UUID | None) -> AnomalyDetection:
        """The row this assessment is recorded as — the one just written, or its predecessor.

        A primary-key lookup carries no organization filter — ``session.get`` is exactly how
        a cross-tenant read starts — so the row is read through the tenant-scoped statement
        either way, which also makes "the row the identity names" and "the row just written"
        the same query.
        """
        statement = self._scoped(AnomalyDetection)
        if inserted is not None:
            statement = statement.where(AnomalyDetection.id == inserted)
        else:
            for column, value in draft.identity(self.organization_id).items():
                statement = statement.where(getattr(AnomalyDetection, column) == value)
        row = self.execute(statement).scalars().one_or_none()
        if row is None:  # pragma: no cover - the row was just written or already existed
            raise RiskError("a detection was reported as recorded but cannot be read back")
        return row

    def find(self, detection_id: uuid.UUID) -> AnomalyDetection | None:
        """One detection by identifier, or ``None``.

        A detection belonging to another organization is ``None`` here exactly as an
        unknown identifier is: the caller learns that this organization has no such record
        and learns nothing else.
        """
        return (
            self.execute(self._scoped(AnomalyDetection).where(AnomalyDetection.id == detection_id))
            .scalars()
            .one_or_none()
        )

    def _filtered(
        self,
        *,
        entity_id: uuid.UUID | None = None,
        detection_type: str | None = None,
        risk_level: str | None = None,
        status: str | None = None,
    ) -> Any:
        """The tenant's detections, narrowed by the filters the endpoint exposes."""
        statement = self._scoped(AnomalyDetection)
        if entity_id is not None:
            statement = statement.where(AnomalyDetection.entity_id == entity_id)
        if detection_type is not None:
            statement = statement.where(AnomalyDetection.detection_type == detection_type)
        if risk_level is not None:
            statement = statement.where(AnomalyDetection.risk_level == risk_level)
        if status is not None:
            statement = statement.where(AnomalyDetection.status == status)
        return statement

    def page(
        self,
        *,
        limit: int,
        offset: int,
        entity_id: uuid.UUID | None = None,
        detection_type: str | None = None,
        risk_level: str | None = None,
        status: str | None = None,
    ) -> list[AnomalyDetection]:
        """A page of detections, newest first.

        Ordered by ``detected_at`` descending and then by identifier descending: the first
        key is what a reader wants (the most recent conclusion), and the second makes the
        order total, so a page cannot skip or repeat a record.
        """
        statement = (
            self._filtered(
                entity_id=entity_id,
                detection_type=detection_type,
                risk_level=risk_level,
                status=status,
            )
            .order_by(AnomalyDetection.detected_at.desc(), AnomalyDetection.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.execute(statement).scalars().all())

    def count(
        self,
        *,
        entity_id: uuid.UUID | None = None,
        detection_type: str | None = None,
        risk_level: str | None = None,
        status: str | None = None,
    ) -> int:
        """How many detections match the same filters, for an opt-in ``?total=true``."""
        statement = self._filtered(
            entity_id=entity_id, detection_type=detection_type, risk_level=risk_level, status=status
        )
        inner = statement.with_only_columns(AnomalyDetection.id).subquery()
        return int(self.execute(select(func.count()).select_from(inner)).scalar_one())
