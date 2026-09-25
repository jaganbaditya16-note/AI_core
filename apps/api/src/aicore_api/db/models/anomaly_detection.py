"""The detection table: what the engine concluded, and the numbers it concluded it from.

One row per recorded assessment of one entity over one closed window. The row is written by
:class:`~aicore_api.db.repositories.risk.DetectionRepository` and by nothing else, and it is
never updated: an assessment of a closed window does not change, so a record that changed
would be a record that had been edited.

Three design decisions are worth stating where they are enforced.

**A detection records its own windows.** ``observation_start``/``observation_end`` and
``baseline_start``/``baseline_end`` are columns, not conventions, and a check constraint
requires the baseline to end at or before the observation begins. That is the phase's
central invariant — an observation is never part of its own baseline — stated in the schema
rather than trusted to the code that builds the insert.

**The conclusion and its evidence are separate columns.** ``status``, ``anomaly``,
``risk_level`` and ``detection_type`` are the conclusion; ``evidence`` and ``factors`` are
the measurements behind it. The check constraints tie them together: a row that says
``deviating`` must name a detection type, a row with no anomaly must be at level ``none``,
and a deviating row must carry at least one factor. A conclusion without its evidence, or
evidence contradicting its conclusion, cannot be stored.

**The identity is the assessment.** ``uq_anomaly_detections_identity`` covers the
organization, the entity, the two intervals and the schema version — so the same assessment
can be recorded once, whatever asks for it and however often. ``schema_version`` is part of
the identity rather than a label: if a factor's meaning changes, the records written under
the old meaning stay distinguishable instead of silently disagreeing.
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
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column

from aicore_api.core.risk import (
    RISK_SCHEMA_VERSION,
    AssessmentStatus,
    BaselineWindow,
    DetectionType,
    EntityType,
    RiskLevel,
)
from aicore_api.db.base import Base, TenantOwnedMixin, UUIDPrimaryKeyMixin

TABLE_COMMENT = (
    "Assessments the anomaly and risk engine recorded: one row per entity, observation "
    "window and baseline. Append-only; the conclusion columns are constrained to agree "
    "with each other and with the evidence beside them."
)

#: How large the two JSON documents may be. They are rendered from typed models rather than
#: posted by a client, so the ceiling is not a defence against a hostile payload — it is a
#: statement that an assessment's evidence is a bounded table of numbers and not a place
#: where arbitrary documents accumulate.
MAX_EVIDENCE_BYTES = 32_768
MAX_FACTORS_BYTES = 16_384

#: Column widths from the vocabulary's own shape. Generous rather than exact — a member
#: added later must not need a migration to fit — with the CHECK constraint doing the real
#: work of keeping the column inside the closed set.
ENTITY_TYPE_MAX_LENGTH = 16
STATUS_MAX_LENGTH = 24
RISK_LEVEL_MAX_LENGTH = 16
DETECTION_TYPE_MAX_LENGTH = 32
BASELINE_WINDOW_MAX_LENGTH = 8


def _value_list(enum: type[StrEnum]) -> str:
    """The declared members of an enum, as the literal list a ``CHECK`` constraint wants."""
    return ", ".join(f"'{member.value}'" for member in enum)


class AnomalyDetection(UUIDPrimaryKeyMixin, TenantOwnedMixin, Base):
    """One recorded assessment: what the engine measured, and what it concluded."""

    __tablename__ = "anomaly_detections"

    #: When the engine looked. The database's clock, not a client's: a record that could be
    #: dated by its caller could be placed anywhere in the history.
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    #: What was assessed. The type is a column rather than an assumption so a later phase
    #: can record a different subject without rewriting this one's rows.
    entity_type: Mapped[str] = mapped_column(String(ENTITY_TYPE_MAX_LENGTH), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)

    #: The conclusion.
    status: Mapped[str] = mapped_column(String(STATUS_MAX_LENGTH), nullable=False)
    anomaly: Mapped[bool] = mapped_column(nullable=False)
    risk_level: Mapped[str] = mapped_column(String(RISK_LEVEL_MAX_LENGTH), nullable=False)
    detection_type: Mapped[str | None] = mapped_column(
        String(DETECTION_TYPE_MAX_LENGTH), nullable=True
    )

    #: The two windows the conclusion is about, and which named baseline the second one is.
    observation_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observation_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    baseline_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    baseline_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    baseline_window: Mapped[str] = mapped_column(String(BASELINE_WINDOW_MAX_LENGTH), nullable=False)

    #: The shape version of everything above. Part of the identity, not decoration.
    schema_version: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default=text(str(RISK_SCHEMA_VERSION))
    )

    #: The measurements, and the factors computed from them. Both are rendered from the
    #: response models, so a stored record and a computed one cannot drift into different
    #: shapes.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    factors: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)

    __table_args__ = (
        # The listing: this organization's records, newest first, with the identifier
        # breaking ties so a page cannot skip or repeat a row.
        Index(
            "ix_anomaly_detections_organization_id_detected_at_id",
            "organization_id",
            "detected_at",
            "id",
        ),
        # One entity's history: the filter a reader reaches for second.
        Index(
            "ix_anomaly_detections_organization_id_entity_id_detected_at",
            "organization_id",
            "entity_id",
            "detected_at",
        ),
        # The identity of an assessment. Everything in it was decided before the row was
        # written, so a repeated analysis of a closed window is a conflict rather than a
        # second record — and the database, not the handler, is what makes that true.
        UniqueConstraint(
            "organization_id",
            "entity_type",
            "entity_id",
            "observation_start",
            "observation_end",
            "baseline_start",
            "baseline_end",
            "schema_version",
            name="uq_anomaly_detections_identity",
        ),
        CheckConstraint(f"entity_type IN ({_value_list(EntityType)})", name="entity_type_valid"),
        CheckConstraint(f"status IN ({_value_list(AssessmentStatus)})", name="status_valid"),
        CheckConstraint(f"risk_level IN ({_value_list(RiskLevel)})", name="risk_level_valid"),
        CheckConstraint(
            f"detection_type IS NULL OR detection_type IN ({_value_list(DetectionType)})",
            name="detection_type_valid",
        ),
        CheckConstraint(
            f"baseline_window IN ({_value_list(BaselineWindow)})",
            name="baseline_window_valid",
        ),
        CheckConstraint(f"schema_version = {RISK_SCHEMA_VERSION}", name="schema_version_supported"),
        # The phase's central invariant, in the schema: an observation is never compared
        # against a window that contains it.
        CheckConstraint("baseline_end <= observation_start", name="baseline_precedes_observation"),
        CheckConstraint("baseline_end > baseline_start", name="baseline_not_empty"),
        CheckConstraint("observation_end > observation_start", name="observation_not_empty"),
        CheckConstraint(
            "observation_end - observation_start <= interval '30 days'",
            name="observation_bounded",
        ),
        # The named span and the interval it resolved to cannot disagree.
        CheckConstraint(
            "(baseline_window = '24h' AND baseline_end - baseline_start = interval '1 day')"
            " OR (baseline_window = '7d' AND baseline_end - baseline_start = interval '7 days')"
            " OR (baseline_window = '14d' AND baseline_end - baseline_start = interval '14 days')"
            " OR (baseline_window = '30d' AND baseline_end - baseline_start = interval '30 days')",
            name="baseline_span_matches_window",
        ),
        # The conclusion and the measurements must agree with each other.
        CheckConstraint("(status = 'deviating') = anomaly", name="anomaly_matches_status"),
        CheckConstraint("(risk_level = 'none') = NOT anomaly", name="level_matches_anomaly"),
        CheckConstraint(
            "(status = 'deviating') = (detection_type IS NOT NULL)",
            name="type_matches_status",
        ),
        CheckConstraint(
            "jsonb_typeof(evidence) = 'object'",
            name="evidence_is_an_object",
        ),
        CheckConstraint(
            "jsonb_typeof(factors) = 'array'",
            name="factors_are_an_array",
        ),
        CheckConstraint(
            f"pg_column_size(evidence) <= {MAX_EVIDENCE_BYTES}",
            name="evidence_bounded",
        ),
        CheckConstraint(
            f"pg_column_size(factors) <= {MAX_FACTORS_BYTES}",
            name="factors_bounded",
        ),
        CheckConstraint(
            "(status = 'deviating') = (jsonb_array_length(factors) > 0)",
            name="factors_present_when_deviating",
        ),
        {"comment": TABLE_COMMENT},
    )
