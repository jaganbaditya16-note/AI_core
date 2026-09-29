"""Phase 11: tenant-scoped incidents and single-use human approvals."""
from __future__ import annotations
from collections.abc import Sequence
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009_incident_approvals"
down_revision: str | None = "0008_anomaly_detections"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
SCHEMA = "aicore"


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(24), server_default="open", nullable=False),
        sa.Column("severity", sa.String(16), server_default="medium", nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_detection_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incidents")),
        sa.ForeignKeyConstraint(["organization_id"], [f"{SCHEMA}.organizations.id"], name=op.f("fk_incidents_organization_id_organizations"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], [f"{SCHEMA}.users.id"], name=op.f("fk_incidents_created_by_users"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["source_detection_id"], [f"{SCHEMA}.anomaly_detections.id"], name=op.f("fk_incidents_source_detection_id_anomaly_detections"), ondelete="SET NULL"),
        sa.CheckConstraint("status IN ('open','acknowledged','investigating','contained','resolved','closed')", name=op.f("ck_incidents_status_valid")),
        sa.CheckConstraint("severity IN ('low','medium','high','critical')", name=op.f("ck_incidents_severity_valid")),
        sa.CheckConstraint("char_length(btrim(title)) BETWEEN 1 AND 160", name=op.f("ck_incidents_title_length")),
        sa.CheckConstraint("char_length(description) BETWEEN 1 AND 10000", name=op.f("ck_incidents_description_length")),
        schema=SCHEMA,
    )
    op.create_index(op.f("ix_incidents_organization_id_created_at"), "incidents", ["organization_id", "created_at", "id"], schema=SCHEMA)
    op.create_index(op.f("ix_incidents_organization_id_status"), "incidents", ["organization_id", "status"], schema=SCHEMA)

    op.create_table(
        "incident_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("detection_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reference_type", sa.String(32), nullable=False),
        sa.Column("reference_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("label", sa.String(160), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_evidence")),
        sa.ForeignKeyConstraint(["organization_id"], [f"{SCHEMA}.organizations.id"], name=op.f("fk_incident_evidence_organization_id_organizations"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["incident_id"], [f"{SCHEMA}.incidents.id"], name=op.f("fk_incident_evidence_incident_id_incidents"), ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["detection_id"], [f"{SCHEMA}.anomaly_detections.id"], name=op.f("fk_incident_evidence_detection_id_anomaly_detections"), ondelete="RESTRICT"),
        sa.UniqueConstraint("organization_id", "incident_id", "reference_type", "reference_id", name=op.f("uq_incident_evidence_reference")),
        sa.CheckConstraint("reference_type IN ('anomaly_detection','audit_event')", name=op.f("ck_incident_evidence_reference_type_valid")),
        sa.CheckConstraint("jsonb_typeof(metadata) = 'object'", name=op.f("ck_incident_evidence_metadata_object")),
        schema=SCHEMA,
    )

    op.create_table(
        "approval_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("requester_membership_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reviewer_membership_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action_id", sa.String(64), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("action_fingerprint", sa.String(64), nullable=False),
        sa.Column("policy_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), server_default="pending", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("denied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_approval_requests")),
        sa.ForeignKeyConstraint(["organization_id"], [f"{SCHEMA}.organizations.id"], name=op.f("fk_approval_requests_organization_id_organizations"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["requester_membership_id"], [f"{SCHEMA}.memberships.id"], name=op.f("fk_approval_requests_requester_membership_id_memberships"), ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["reviewer_membership_id"], [f"{SCHEMA}.memberships.id"], name=op.f("fk_approval_requests_reviewer_membership_id_memberships"), ondelete="RESTRICT"),
        sa.UniqueConstraint("organization_id", "requester_membership_id", "idempotency_key", name=op.f("uq_approval_request_idempotency")),
        sa.CheckConstraint("status IN ('pending','approved','denied','expired','cancelled')", name=op.f("ck_approval_requests_status_valid")),
        sa.CheckConstraint("action_fingerprint ~ '^[0-9a-f]{64}$'", name=op.f("ck_approval_requests_fingerprint_shape")),
        sa.CheckConstraint("policy_digest ~ '^[0-9a-f]{64}$'", name=op.f("ck_approval_requests_policy_digest_shape")),
        schema=SCHEMA,
    )
    op.create_index(op.f("ix_approval_requests_organization_id_status_expires_at"), "approval_requests", ["organization_id", "status", "expires_at"], schema=SCHEMA)

    # The approval permission is deliberately not executable authority. Owner and security
    # administrator may review; analysts may read incidents; AI_ADMIN gains no approval power.
    permissions = [
        ("action.approve", "Review and approve a pending action request."),
        ("incident.read", "Read security incidents and their bounded evidence references."),
        ("incident.create", "Create a security incident."),
        ("incident.update", "Update and transition a security incident."),
    ]
    for code, description in permissions:
        op.execute(sa.text(f"INSERT INTO {SCHEMA}.permissions (code, description) VALUES (:code, :description) ON CONFLICT (code) DO NOTHING"), {"code": code, "description": description})
    grants = {
        "owner": [p[0] for p in permissions],
        "security_admin": [p[0] for p in permissions],
        "analyst": ["incident.read"],
    }
    for role, codes in grants.items():
        for code in codes:
            op.execute(sa.text(f"""INSERT INTO {SCHEMA}.role_permissions (role_id, permission_id)
                SELECT r.id, p.id FROM {SCHEMA}.roles r, {SCHEMA}.permissions p
                WHERE r.code=:role AND p.code=:permission ON CONFLICT DO NOTHING"""), {"role": role, "permission": code})


def downgrade() -> None:
    for name in ("ix_approval_requests_organization_id_status_expires_at",):
        op.drop_index(op.f(name), table_name="approval_requests", schema=SCHEMA)
    op.drop_table("approval_requests", schema=SCHEMA)
    op.drop_table("incident_evidence", schema=SCHEMA)
    for name in ("ix_incidents_organization_id_status", "ix_incidents_organization_id_created_at"):
        op.drop_index(op.f(name), table_name="incidents", schema=SCHEMA)
    op.drop_table("incidents", schema=SCHEMA)
    op.execute(sa.text(f"DELETE FROM {SCHEMA}.role_permissions WHERE permission_id IN (SELECT id FROM {SCHEMA}.permissions WHERE code IN ('action.approve','incident.read','incident.create','incident.update'))"))
    op.execute(sa.text(f"DELETE FROM {SCHEMA}.permissions WHERE code IN ('action.approve','incident.read','incident.create','incident.update')"))
