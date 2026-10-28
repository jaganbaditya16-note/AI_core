"""The anomaly detection record: findings, never incidents.

One row per detection the Phase 10 engine produced and an operator chose to record —
this entity, this detection type, over these exact baseline and observation windows,
under this version of the rules. The row is derived data: everything in it was computed
by the server from the organization's own audit trail, and nothing in it was supplied by
a client (there is no route that writes here; see ``aicore_api.risk.cli``).

Four properties are enforced by the schema rather than trusted to the writer:

- **Tenant-owned.** :class:`~aicore_api.db.base.TenantOwnedMixin`, like every other
  tenant table: the isolation guard refuses unscoped access, and the foreign key is
  ``RESTRICT``.
- **Deduplicated.** ``UNIQUE (organization_id, fingerprint)``. The fingerprint is the
  hash of what was assessed (entity, type, windows, engine version), so repeating an
  analysis cannot add a second row for the same finding.
- **Closed vocabularies, and only anomalies.** Detection type, risk level, windows and
  entity type are ``CHECK``-constrained to the engine's vocabulary. ``risk_level`` cannot
  be ``none`` and ``anomaly_state`` can only be ``anomalous``: an entity with insufficient
  history, or one with nothing unusual, is never written here.
- **Immutable.** Triggers refuse ``UPDATE`` and ``TRUNCATE``. A detection has no lifecycle — no
  acknowledge, assign, resolve or close — because those are incident-management verbs, and
  Phase 10 does not manage incidents. Rows may be deleted with a scoped ``DELETE`` (the data
  is re-derivable from the trail, and a tenant must be removable).

It deliberately has no foreign key to ``agents``: the agent may since have been deleted,
and a finding about it is still a finding — the same rule the audit trail follows.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    SmallInteger,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column

from aicore_api.core.risk import (
    DETECTION_SCHEMA_VERSION,
    RISK_ENGINE_VERSION,
    AnalysisStatus,
    AnomalyState,
    BaselineWindow,
    DetectionType,
    EntityType,
    ObservationWindow,
    RiskLevel,
)
from aicore_api.db.base import Base, TenantOwnedMixin, UUIDPrimaryKeyMixin

__all__ = ["MAX_STORED_EVIDENCE_BYTES", "TABLE_COMMENT", "AnomalyDetection"]

#: Mirrored literally in the migration; ``alembic check`` compares the two.
TABLE_COMMENT = (
    "Anomaly detections derived by the deterministic Phase 10 engine from this "
    "organization's audit trail: one immutable row per entity, detection type and "
    "analysis window. A finding, not an incident, and never an input to authorization."
)

#: The database backstop for evidence and factor documents. The engine applies a smaller
#: bound (``core.risk.MAX_EVIDENCE_BYTES``) before a row is built.
MAX_STORED_EVIDENCE_BYTES = 16384

#: A SHA-256 digest, lowercase hex.
FINGERPRINT_SQL_PATTERN = "^[0-9a-f]{64}$"

#: A detection states at least one risk factor, as a JSON array.
RISK_FACTORS_STATED_SQL = (
    "CASE WHEN jsonb_typeof(risk_factors) = 'array' "
    "THEN jsonb_array_length(risk_factors) > 0 ELSE false END"
)


def _values(values: type[StrEnum], *, exclude: tuple[StrEnum, ...] = ()) -> str:
    """Render an enum's values as a ``CHECK`` literal list, derived from the code."""
    return ", ".join(f"'{value.value}'" for value in values if value not in exclude)


class AnomalyDetection(UUIDPrimaryKeyMixin, TenantOwnedMixin, Base):
    """One recorded finding, in the organization whose trail produced it."""

    __tablename__ = "anomaly_detections"

    #: The row's shape, and the rules that produced it. Both pinned to this build.
    schema_version: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default=text(str(DETECTION_SCHEMA_VERSION))
    )
    engine_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)

    #: When the row was recorded, by the server's clock.
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    #: What the finding is about. ``agent`` is the only entity with attributable history.
    entity_type: Mapped[str] = mapped_column(String(16), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)

    detection_type: Mapped[str] = mapped_column(String(32), nullable=False)
    analysis_status: Mapped[str] = mapped_column(String(24), nullable=False)
    anomaly_state: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)

    #: The windows that were compared, by name and by bound. Half-open, and adjacent.
    baseline_window: Mapped[str] = mapped_column(String(8), nullable=False)
    observation_window: Mapped[str] = mapped_column(String(8), nullable=False)
    baseline_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    baseline_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observation_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observation_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    #: The measurements, the comparison and the context — see ``docs/risk.md``, *Evidence*.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    #: Why the level is what it is: a non-empty list of structured factors.
    risk_factors: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)

    #: The identity of the finding; see ``core.risk.detection_fingerprint``.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        # One row per finding per tenant: the deduplication, enforced by the database.
        UniqueConstraint("organization_id", "fingerprint"),
        # The listing: newest first, with the identifier breaking ties.
        Index(
            "ix_anomaly_detections_organization_id_detected_at_id",
            "organization_id",
            "detected_at",
            "id",
        ),
        # "What has been found about this agent?"
        Index(
            "ix_anomaly_detections_organization_id_entity_id_observation_end",
            "organization_id",
            "entity_id",
            "observation_end",
        ),
        CheckConstraint(
            f"schema_version = {DETECTION_SCHEMA_VERSION}", name="schema_version_valid"
        ),
        CheckConstraint(f"engine_version = {RISK_ENGINE_VERSION}", name="engine_version_valid"),
        CheckConstraint(f"entity_type IN ({_values(EntityType)})", name="entity_type_valid"),
        CheckConstraint(
            f"detection_type IN ({_values(DetectionType)})", name="detection_type_valid"
        ),
        CheckConstraint(
            f"analysis_status = '{AnalysisStatus.ANALYZED.value}'", name="analysis_status_valid"
        ),
        CheckConstraint(
            f"anomaly_state = '{AnomalyState.ANOMALOUS.value}'", name="anomaly_state_valid"
        ),
        # A detection is always above ``none``: an entity with nothing to report is not a row.
        CheckConstraint(
            f"risk_level IN ({_values(RiskLevel, exclude=(RiskLevel.NONE,))})",
            name="risk_level_valid",
        ),
        CheckConstraint(
            f"baseline_window IN ({_values(BaselineWindow)})", name="baseline_window_valid"
        ),
        CheckConstraint(
            f"observation_window IN ({_values(ObservationWindow)})",
            name="observation_window_valid",
        ),
        # The baseline ends exactly where the observation starts: no overlap, no gap.
        CheckConstraint("baseline_end = observation_start", name="windows_adjacent"),
        CheckConstraint("baseline_start < baseline_end", name="baseline_ordered"),
        CheckConstraint("observation_start < observation_end", name="observation_ordered"),
        CheckConstraint(f"fingerprint ~ '{FINGERPRINT_SQL_PATTERN}'", name="fingerprint_shape"),
        CheckConstraint("jsonb_typeof(evidence) = 'object'", name="evidence_is_object"),
        CheckConstraint(
            f"length(evidence::text) <= {MAX_STORED_EVIDENCE_BYTES}", name="evidence_bounded"
        ),
        # ``CASE`` rather than ``AND``: PostgreSQL does not promise to evaluate ``AND`` left
        # to right, and ``jsonb_array_length`` raises on a non-array instead of answering.
        CheckConstraint(RISK_FACTORS_STATED_SQL, name="risk_factors_stated"),
        CheckConstraint(
            f"length(risk_factors::text) <= {MAX_STORED_EVIDENCE_BYTES}",
            name="risk_factors_bounded",
        ),
        {"comment": TABLE_COMMENT},
    )

    def __repr__(self) -> str:
        """Identify the row without rendering its evidence."""
        return (
            f"<AnomalyDetection {self.id!s} type={self.detection_type!r} risk={self.risk_level!r}>"
        )
