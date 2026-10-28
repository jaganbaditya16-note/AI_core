"""Phase 10: anomaly detections — one immutable table of findings, and nothing else.

This revision adds a table and a trigger. It changes no earlier table: the audit trail's
columns, constraints, indexes and append-only guard are exactly as Phase 8 left them, and
Phase 10 reads that trail without writing to it. No permission is added and no role grant
changes — the risk routes are guarded by ``audit.read`` together with ``security.read``,
both already seeded (see ``docs/risk.md``, *RBAC*).

**What the table is for.** Recorded findings of the deterministic anomaly and risk engine:
one row per entity, detection type and analysis window, carrying the structured evidence
and risk factors that explain it. Rows are derived from the organization's own trail by the
server and written by an operator command, never by an HTTP request, so no client can
submit or spoof a detection, a risk level, a baseline, a statistic or a factor.

**Deduplicated by the database.** ``UNIQUE (organization_id, fingerprint)``, where the
fingerprint hashes what was assessed — entity, detection type, both windows and the engine
version. Re-running an analysis with the same ``as_of`` inserts nothing new.

**Findings, not incidents.** There is no status lifecycle: no acknowledge, assign, resolve
or close. Triggers refuse ``UPDATE`` (so a detection cannot be turned into a work item by a
data fix either) and ``TRUNCATE`` (which would empty every tenant at once). ``DELETE`` is
allowed — the rows are re-derivable, and a tenant must be
removable (the tenant foreign key is ``RESTRICT``, as everywhere).

**Only anomalies.** ``risk_level`` cannot be ``none`` and ``anomaly_state`` can only be
``anomalous``: an entity with insufficient history, or with nothing unusual, is not a row.

Revision ID: 0008_anomaly_detections
Revises: 0007_audit_events
Create Date: 2026-09-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_anomaly_detections"
down_revision: str | None = "0007_audit_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "aicore"

# Literals, not imports: a migration describes the database at one point in time.
# ``tests/test_risk_contract.py`` compares every one of these with ``aicore_api.core.risk``
# and the model, so the copy in the database cannot drift from the copy in the code.
DETECTION_TYPES = (
    "action_rate_spike",
    "action_rate_drop",
    "failure_rate_spike",
    "denial_rate_spike",
    "novel_action",
    "novel_resource",
    "unusual_time",
    "unusual_frequency",
)
STORED_RISK_LEVELS = ("low", "medium", "high", "critical")
ENTITY_TYPES = ("agent",)
BASELINE_WINDOWS = ("7d", "14d", "30d")
OBSERVATION_WINDOWS = ("1h", "6h", "24h")

SCHEMA_VERSION = 1
ENGINE_VERSION = 1
MAX_STORED_EVIDENCE_BYTES = 16384
FINGERPRINT_SQL_PATTERN = "^[0-9a-f]{64}$"
RISK_FACTORS_STATED_SQL = (
    "CASE WHEN jsonb_typeof(risk_factors) = 'array' "
    "THEN jsonb_array_length(risk_factors) > 0 ELSE false END"
)

#: Kept identical to the model's ``TABLE_COMMENT``: ``alembic check`` compares the two.
TABLE_COMMENT = (
    "Anomaly detections derived by the deterministic Phase 10 engine from this "
    "organization's audit trail: one immutable row per entity, detection type and "
    "analysis window. A finding, not an incident, and never an input to authorization."
)

_IMMUTABLE_FUNCTION = f"{SCHEMA}.anomaly_detections_are_immutable"


def _values(values: tuple[str, ...]) -> str:
    """Render a value list as the SQL literal list a CHECK constraint expects."""
    return ", ".join(f"'{value}'" for value in values)


def upgrade() -> None:
    op.create_table(
        "anomaly_detections",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "schema_version",
            sa.SmallInteger(),
            server_default=sa.text(str(SCHEMA_VERSION)),
            nullable=False,
        ),
        sa.Column("engine_version", sa.SmallInteger(), nullable=False),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("entity_type", sa.String(length=16), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("detection_type", sa.String(length=32), nullable=False),
        sa.Column("analysis_status", sa.String(length=24), nullable=False),
        sa.Column("anomaly_state", sa.String(length=16), nullable=False),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("baseline_window", sa.String(length=8), nullable=False),
        sa.Column("observation_window", sa.String(length=8), nullable=False),
        sa.Column("baseline_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("baseline_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "risk_factors", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            [f"{SCHEMA}.organizations.id"],
            name=op.f("fk_anomaly_detections_organization_id_organizations"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_anomaly_detections")),
        sa.UniqueConstraint(
            "organization_id",
            "fingerprint",
            name=op.f("uq_anomaly_detections_organization_id_fingerprint"),
        ),
        sa.CheckConstraint(
            f"schema_version = {SCHEMA_VERSION}",
            name=op.f("ck_anomaly_detections_schema_version_valid"),
        ),
        sa.CheckConstraint(
            f"engine_version = {ENGINE_VERSION}",
            name=op.f("ck_anomaly_detections_engine_version_valid"),
        ),
        sa.CheckConstraint(
            f"entity_type IN ({_values(ENTITY_TYPES)})",
            name=op.f("ck_anomaly_detections_entity_type_valid"),
        ),
        sa.CheckConstraint(
            f"detection_type IN ({_values(DETECTION_TYPES)})",
            name=op.f("ck_anomaly_detections_detection_type_valid"),
        ),
        sa.CheckConstraint(
            "analysis_status = 'analyzed'",
            name=op.f("ck_anomaly_detections_analysis_status_valid"),
        ),
        sa.CheckConstraint(
            "anomaly_state = 'anomalous'",
            name=op.f("ck_anomaly_detections_anomaly_state_valid"),
        ),
        sa.CheckConstraint(
            f"risk_level IN ({_values(STORED_RISK_LEVELS)})",
            name=op.f("ck_anomaly_detections_risk_level_valid"),
        ),
        sa.CheckConstraint(
            f"baseline_window IN ({_values(BASELINE_WINDOWS)})",
            name=op.f("ck_anomaly_detections_baseline_window_valid"),
        ),
        sa.CheckConstraint(
            f"observation_window IN ({_values(OBSERVATION_WINDOWS)})",
            name=op.f("ck_anomaly_detections_observation_window_valid"),
        ),
        sa.CheckConstraint(
            "baseline_end = observation_start",
            name=op.f("ck_anomaly_detections_windows_adjacent"),
        ),
        sa.CheckConstraint(
            "baseline_start < baseline_end",
            name=op.f("ck_anomaly_detections_baseline_ordered"),
        ),
        sa.CheckConstraint(
            "observation_start < observation_end",
            name=op.f("ck_anomaly_detections_observation_ordered"),
        ),
        sa.CheckConstraint(
            f"fingerprint ~ '{FINGERPRINT_SQL_PATTERN}'",
            name=op.f("ck_anomaly_detections_fingerprint_shape"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(evidence) = 'object'",
            name=op.f("ck_anomaly_detections_evidence_is_object"),
        ),
        sa.CheckConstraint(
            f"length(evidence::text) <= {MAX_STORED_EVIDENCE_BYTES}",
            name=op.f("ck_anomaly_detections_evidence_bounded"),
        ),
        sa.CheckConstraint(
            RISK_FACTORS_STATED_SQL,
            name=op.f("ck_anomaly_detections_risk_factors_stated"),
        ),
        sa.CheckConstraint(
            f"length(risk_factors::text) <= {MAX_STORED_EVIDENCE_BYTES}",
            name=op.f("ck_anomaly_detections_risk_factors_bounded"),
        ),
        schema=SCHEMA,
        comment=TABLE_COMMENT,
    )

    op.create_index(
        op.f("ix_anomaly_detections_organization_id"),
        "anomaly_detections",
        ["organization_id"],
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_anomaly_detections_organization_id_detected_at_id"),
        "anomaly_detections",
        ["organization_id", "detected_at", "id"],
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_anomaly_detections_organization_id_entity_id_observation_end"),
        "anomaly_detections",
        ["organization_id", "entity_id", "observation_end"],
        schema=SCHEMA,
    )

    # Immutable: a detection is recorded once and never rewritten. Row-level, UPDATE only.
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION {_IMMUTABLE_FUNCTION}() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION
                'aicore.anomaly_detections is immutable: % is refused', TG_OP
                USING ERRCODE = 'restrict_violation';
        END;
        $$
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER anomaly_detections_immutable
        BEFORE UPDATE ON {SCHEMA}.anomaly_detections
        FOR EACH ROW EXECUTE FUNCTION {_IMMUTABLE_FUNCTION}()
        """
    )
    # TRUNCATE empties every tenant's findings in one statement and bypasses row triggers,
    # so it is refused too; removing one tenant's detections is a scoped DELETE.
    op.execute(
        f"""
        CREATE TRIGGER anomaly_detections_no_truncate
        BEFORE TRUNCATE ON {SCHEMA}.anomaly_detections
        FOR EACH STATEMENT EXECUTE FUNCTION {_IMMUTABLE_FUNCTION}()
        """
    )


def downgrade() -> None:
    # The guard first, so no function outlives the table it protected.
    for trigger in ("anomaly_detections_no_truncate", "anomaly_detections_immutable"):
        op.execute(f"DROP TRIGGER IF EXISTS {trigger} ON {SCHEMA}.anomaly_detections")
    op.execute(f"DROP FUNCTION IF EXISTS {_IMMUTABLE_FUNCTION}()")

    for name in (
        "ix_anomaly_detections_organization_id_entity_id_observation_end",
        "ix_anomaly_detections_organization_id_detected_at_id",
        "ix_anomaly_detections_organization_id",
    ):
        op.drop_index(op.f(name), table_name="anomaly_detections", schema=SCHEMA)

    # The findings go with the table: they are derived from the audit trail, which this
    # downgrade does not touch, so re-running the engine after an upgrade reproduces them.
    op.drop_table("anomaly_detections", schema=SCHEMA)
