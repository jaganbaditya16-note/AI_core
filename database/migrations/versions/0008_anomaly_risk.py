"""Phase 10: the anomaly and risk engine's durable records, and the capability to write one.

This revision adds one table and one permission, and nothing else. It does not touch
``audit_events`` (Phase 8's trail is read-only to this phase, and stays exactly as it was),
it does not change any earlier table, and it does not add a resource type or an action to
the authorization vocabulary: ``security.create`` is a *grant*, not a new concept — the
security resource and the ``create`` action both already exist — and ``security.read``,
declared in Phase 2 and reserved by Phase 9's documentation for exactly this subject,
already guards the read side.

**Why a table at all.** An assessment is computable from the trail at any moment, so a
table is not required for the engine to work. What it is required for is history: "was this
agent's behaviour assessed, over which window, against which baseline, and what did the
engine conclude?" is a question the trail cannot answer, because the trail records what the
platform did and not what the platform observed about what it did. The row is deliberately
*frozen*: it holds the conclusion, the two windows, the evidence and the factors, so a later
reader does not need the trail (which ages out of the baseline ceiling) to check the
arithmetic.

**Append-only, enforced by the database.** The same two triggers Phase 8 installed on the
trail — row-level for ``UPDATE`` and ``DELETE``, statement-level for ``TRUNCATE`` — call a
function that raises unless the transaction has said out loud that it is deleting detection
records: ``SET LOCAL aicore.risk_retention = '<reason>'``. ``UPDATE`` is refused even then.
A detection that could be rewritten would be a record of what somebody *wanted* to have
found, which is the opposite of evidence.

**The conclusion cannot contradict itself or its evidence.** Five ``CHECK`` constraints tie
the columns together: a row that is ``deviating`` must be an anomaly, must name a detection
type, must not be at level ``none``, and must carry at least one factor; a row that is not
an anomaly must be at level ``none`` and carry no factors. Two more bound the JSON columns —
an object and an array, each with a size ceiling — and one requires the baseline to end at or
before the observation begins, which is the phase's central invariant written as data.

**The identity is the assessment.** ``uq_anomaly_detections_identity`` covers the tenant,
the entity, the observation window, the baseline window and the schema version. Repeated
analysis of a closed window therefore *cannot* produce a second record — the database is the
arbiter, not the handler that had hoped to check first.

Revision ID: 0008_anomaly_risk
Revises: 0007_audit_events
Create Date: 2026-09-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008_anomaly_risk"
down_revision: str | None = "0007_audit_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "aicore"

# Literals, not imports from the models: a migration describes the database at one point in
# time. ``tests/test_risk_engine.py`` and ``tests/test_risk_recording.py`` compare these
# vocabularies with ``aicore_api.core.risk`` and the model, so the copy in the database
# cannot drift from the copy in the code without a test failing.
ENTITY_TYPES = ("agent",)
STATUSES = ("insufficient_data", "within_baseline", "deviating")
RISK_LEVELS = ("none", "low", "medium", "high", "critical")
DETECTION_TYPES = (
    "action_rate_drop",
    "action_rate_spike",
    "denial_rate_spike",
    "failure_rate_spike",
    "novel_action",
    "novel_resource",
    "unusual_time",
)
BASELINE_WINDOWS = ("14d", "24h", "30d", "7d")

SCHEMA_VERSION = 1
MAX_EVIDENCE_BYTES = 32_768
MAX_FACTORS_BYTES = 16_384

#: Kept identical to the model's ``TABLE_COMMENT``: ``alembic check`` compares the two, so a
#: comment that drifts turns into a detected "pending migration" rather than silent
#: divergence.
ANOMALY_DETECTIONS_TABLE_COMMENT = (
    "Assessments the anomaly and risk engine recorded: one row per entity, observation "
    "window and baseline. Append-only; the conclusion columns are constrained to agree "
    "with each other and with the evidence beside them."
)

#: The permission this revision introduces, and the roles it is granted to. Analysts read
#: findings — ``security.read`` is theirs from Phase 2 — but recording one writes a row,
#: so it is a separate capability rather than a side effect of being able to look.
PERMISSIONS: tuple[tuple[str, str], ...] = (
    (
        "security.create",
        "Record the risk findings the analysis engine computes for this organization.",
    ),
)
RISK_GRANTS: dict[str, tuple[str, ...]] = {
    "owner": ("security.create",),
    "security_admin": ("security.create",),
    "admin": (),
    "ai_admin": (),
    "analyst": (),
    "viewer": (),
}

#: The setting :func:`aicore_api.db.repositories.risk.detection_retention_override` sets.
#: Named here as a literal for the same reason every other string is: the migration must
#: describe the database even if the code that reads it changes.
RETENTION_SETTING = "aicore.risk_retention"

_APPEND_ONLY_FUNCTION = f"{SCHEMA}.anomaly_detections_are_append_only"

_GRANT_STATEMENT = sa.text(
    f"INSERT INTO {SCHEMA}.role_permissions (role_id, permission_id) "
    f"SELECT r.id, p.id FROM {SCHEMA}.roles AS r, {SCHEMA}.permissions AS p "
    "WHERE r.code = :role_code AND p.code = :permission_code"
)
_REVOKE_STATEMENT = sa.text(
    f"DELETE FROM {SCHEMA}.role_permissions WHERE role_id = "
    f"(SELECT id FROM {SCHEMA}.roles WHERE code = :role_code) AND permission_id = "
    f"(SELECT id FROM {SCHEMA}.permissions WHERE code = :permission_code)"
)


def _values(values: tuple[str, ...]) -> str:
    """Render a value list as the SQL literal list a CHECK constraint expects."""
    return ", ".join(f"'{value}'" for value in values)


def _create_append_only_guard() -> None:
    """Install the triggers that make "append-only" a property of the database.

    The same shape as the trail's guard: ``UPDATE`` is always refused, ``DELETE`` is refused
    unless the transaction has set a named, transaction-local reason, and ``TRUNCATE`` — the
    other way rows disappear, and one a row trigger never sees — is refused outright.
    """
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION {_APPEND_ONLY_FUNCTION}() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE'
               AND coalesce(current_setting('{RETENTION_SETTING}', true), '') <> '' THEN
                RETURN OLD;
            END IF;
            RAISE EXCEPTION
                'aicore.anomaly_detections is append-only: % is refused', TG_OP
                USING ERRCODE = 'restrict_violation';
        END;
        $$
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER anomaly_detections_append_only
        BEFORE UPDATE OR DELETE ON {SCHEMA}.anomaly_detections
        FOR EACH ROW EXECUTE FUNCTION {_APPEND_ONLY_FUNCTION}()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER anomaly_detections_append_only_truncate
        BEFORE TRUNCATE ON {SCHEMA}.anomaly_detections
        FOR EACH STATEMENT EXECUTE FUNCTION {_APPEND_ONLY_FUNCTION}()
        """
    )


def _drop_append_only_guard() -> None:
    """Remove the triggers and the function they call, guards first."""
    for trigger in (
        "anomaly_detections_append_only",
        "anomaly_detections_append_only_truncate",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS {trigger} ON {SCHEMA}.anomaly_detections")
    op.execute(f"DROP FUNCTION IF EXISTS {_APPEND_ONLY_FUNCTION}()")


def upgrade() -> None:
    # ── The authorization catalog ────────────────────────────────────────────
    for code, description in PERMISSIONS:
        op.execute(
            sa.text(
                f"INSERT INTO {SCHEMA}.permissions (code, description) "
                "VALUES (:code, :description)"
            ).bindparams(code=code, description=description)
        )

    for role_code, permission_codes in RISK_GRANTS.items():
        for permission_code in permission_codes:
            op.execute(
                _GRANT_STATEMENT.bindparams(
                    role_code=role_code, permission_code=permission_code
                )
            )

    # ── The detection records ────────────────────────────────────────────────
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
            "detected_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("entity_type", sa.String(length=16), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("anomaly", sa.Boolean(), nullable=False),
        sa.Column("risk_level", sa.String(length=16), nullable=False),
        sa.Column("detection_type", sa.String(length=32), nullable=True),
        sa.Column("observation_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("baseline_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("baseline_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("baseline_window", sa.String(length=8), nullable=False),
        sa.Column(
            "schema_version",
            sa.SmallInteger(),
            server_default=sa.text(str(SCHEMA_VERSION)),
            nullable=False,
        ),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("factors", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            [f"{SCHEMA}.organizations.id"],
            name="fk_anomaly_detections_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_anomaly_detections"),
        sa.UniqueConstraint(
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
        sa.CheckConstraint(
            f"entity_type IN ({_values(ENTITY_TYPES)})",
            name="ck_anomaly_detections_entity_type_valid",
        ),
        sa.CheckConstraint(
            f"status IN ({_values(STATUSES)})", name="ck_anomaly_detections_status_valid"
        ),
        sa.CheckConstraint(
            f"risk_level IN ({_values(RISK_LEVELS)})",
            name="ck_anomaly_detections_risk_level_valid",
        ),
        sa.CheckConstraint(
            "detection_type IS NULL OR detection_type IN"
            f" ({_values(DETECTION_TYPES)})",
            name="ck_anomaly_detections_detection_type_valid",
        ),
        sa.CheckConstraint(
            f"baseline_window IN ({_values(BASELINE_WINDOWS)})",
            name="ck_anomaly_detections_baseline_window_valid",
        ),
        sa.CheckConstraint(
            f"schema_version = {SCHEMA_VERSION}",
            name="ck_anomaly_detections_schema_version_supported",
        ),
        sa.CheckConstraint(
            "baseline_end <= observation_start",
            name="ck_anomaly_detections_baseline_precedes_observation",
        ),
        sa.CheckConstraint(
            "baseline_end > baseline_start", name="ck_anomaly_detections_baseline_not_empty"
        ),
        sa.CheckConstraint(
            "observation_end > observation_start",
            name="ck_anomaly_detections_observation_not_empty",
        ),
        sa.CheckConstraint(
            "observation_end - observation_start <= interval '30 days'",
            name="ck_anomaly_detections_observation_bounded",
        ),
        sa.CheckConstraint(
            "(baseline_window = '24h' AND baseline_end - baseline_start = interval '1 day')"
            " OR (baseline_window = '7d' AND baseline_end - baseline_start = interval '7 days')"
            " OR (baseline_window = '14d' AND baseline_end - baseline_start = interval '14 days')"
            " OR (baseline_window = '30d' AND baseline_end - baseline_start = interval '30 days')",
            name="ck_anomaly_detections_baseline_span_matches_window",
        ),
        sa.CheckConstraint(
            "(status = 'deviating') = anomaly",
            name="ck_anomaly_detections_anomaly_matches_status",
        ),
        sa.CheckConstraint(
            "(risk_level = 'none') = NOT anomaly",
            name="ck_anomaly_detections_level_matches_anomaly",
        ),
        sa.CheckConstraint(
            "(status = 'deviating') = (detection_type IS NOT NULL)",
            name="ck_anomaly_detections_type_matches_status",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(evidence) = 'object'",
            name="ck_anomaly_detections_evidence_is_an_object",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(factors) = 'array'",
            name="ck_anomaly_detections_factors_are_an_array",
        ),
        sa.CheckConstraint(
            f"pg_column_size(evidence) <= {MAX_EVIDENCE_BYTES}",
            name="ck_anomaly_detections_evidence_bounded",
        ),
        sa.CheckConstraint(
            f"pg_column_size(factors) <= {MAX_FACTORS_BYTES}",
            name="ck_anomaly_detections_factors_bounded",
        ),
        sa.CheckConstraint(
            "(status = 'deviating') = (jsonb_array_length(factors) > 0)",
            name="ck_anomaly_detections_factors_present_when_deviating",
        ),
        schema=SCHEMA,
        comment=ANOMALY_DETECTIONS_TABLE_COMMENT,
    )

    # The tenant column every tenant-owned table indexes: the mixin declares it, so the
    # migration creates it — ``alembic check`` compares the two and would otherwise report
    # a pending index.
    op.create_index(
        op.f("ix_anomaly_detections_organization_id"),
        "anomaly_detections",
        ["organization_id"],
        schema=SCHEMA,
    )
    # The listing: tenant, newest first, identifier breaking ties.
    op.create_index(
        op.f("ix_anomaly_detections_organization_id_detected_at_id"),
        "anomaly_detections",
        ["organization_id", "detected_at", "id"],
        schema=SCHEMA,
    )
    # One entity's history: the filter a reader reaches for second.
    op.create_index(
        op.f("ix_anomaly_detections_organization_id_entity_id_detected_at"),
        "anomaly_detections",
        ["organization_id", "entity_id", "detected_at"],
        schema=SCHEMA,
    )

    _create_append_only_guard()


def downgrade() -> None:
    # The guard goes first: dropping the table would leave the function behind, and a
    # function that raises on writes to a table nobody has is a leftover, not a control.
    _drop_append_only_guard()

    op.drop_index(
        op.f("ix_anomaly_detections_organization_id_entity_id_detected_at"),
        table_name="anomaly_detections",
        schema=SCHEMA,
    )
    op.drop_index(
        op.f("ix_anomaly_detections_organization_id"),
        table_name="anomaly_detections",
        schema=SCHEMA,
    )
    op.drop_index(
        op.f("ix_anomaly_detections_organization_id_detected_at_id"),
        table_name="anomaly_detections",
        schema=SCHEMA,
    )

    # The rows go with the table: a downgrade ends the revision that can read or write
    # them, and leaving the table behind would leave a table no revision owns. An operator
    # who needs the records takes a dump first, which ``docs/risk.md`` states.
    op.drop_table("anomaly_detections", schema=SCHEMA)

    # Revoke before deleting: the grants reference the permission this revision added.
    for role_code, permission_codes in RISK_GRANTS.items():
        for permission_code in permission_codes:
            op.execute(
                _REVOKE_STATEMENT.bindparams(
                    role_code=role_code, permission_code=permission_code
                )
            )

    for code, _ in PERMISSIONS:
        op.execute(
            sa.text(f"DELETE FROM {SCHEMA}.permissions WHERE code = :code").bindparams(code=code)
        )
