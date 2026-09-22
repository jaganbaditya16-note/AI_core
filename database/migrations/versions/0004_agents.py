"""Phase 4: the agent registry.

Creates ``aicore.agents`` — the stable identity of an ``agent`` asset, with the
category and version it was registered at — and extends the authorization
catalogue with the four agent-registry permissions.

Three things in this revision are worth understanding before changing it.

**Identity is a database value, not an application string.** ``identity_id`` has
``gen_random_uuid()`` as its server default, is immutable in practice (no write
path sets it) and is unique per organization. Nothing derives it from a display
name, so renaming an agent — or shipping version 1.3 of it — cannot change who the
agent is. The uniqueness is per tenant rather than global because the tenant is
the security boundary here, and a per-tenant identifier is what a per-tenant
lookup needs.

**The registry is not a second inventory.** Display name, description, lifecycle
status, environment and owner stay on ``assets``, where Phase 3 models them with
their own constraints (including the composite foreign key that makes a
cross-tenant owner unrepresentable). This table holds identity and registry facts
only, and its reference to the asset is
``(organization_id, asset_id) → assets(organization_id, id)``: a registry record
whose asset belongs to another organization cannot be inserted. That reference
needs ``uq_assets_organization_id_id`` — redundant with the primary key, and added
here on purpose, because PostgreSQL can only point a foreign key at a unique set
of columns.

**One identity per asset, and none without one.** ``asset_id`` is unique, so two
registry records cannot claim the same asset. The reference cascades on delete:
removing the inventory record removes its identity, so an orphaned identity is not
a state the database can reach.

The permission seed follows migrations 0002 and 0003, and the same rule applies:
the seeded grants are asserted to equal
``aicore_api.core.permissions.ROLE_PERMISSIONS`` exactly, so the policy the
database ships with cannot drift from the policy the application enforces.

Revision ID: 0004_agents
Revises: 0003_assets
Create Date: 2026-09-22
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_agents"
down_revision: str | None = "0003_assets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "aicore"

# Literals, not imports from the models: a migration describes the database at one
# point in time. tests/test_migrations.py compares this schema with the models, and
# tests/test_agents.py compares the seeded permissions and grants with the catalog
# in aicore_api.core.permissions and aicore_api.core.agents.
AGENT_CATEGORIES = (
    "assistant",
    "workflow",
    "autonomous",
    "coding",
    "customer_support",
    "data",
    "security",
    "other",
)

CATEGORY_MAX_LENGTH = 32
VERSION_MAX_LENGTH = 64
BUILD_REVISION_MAX_LENGTH = 128
FRAMEWORK_MAX_LENGTH = 64

PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("agent.read", "See the agents registered in the organization."),
    ("agent.create", "Register an agent and its stable identity."),
    ("agent.update", "Change a registered agent's record, version or lifecycle state."),
    ("agent.delete", "Remove an agent identity and its inventory record."),
)

#: Only the grants this revision introduces. Role codes and the other permission
#: codes were seeded by 0002 and 0003 and are referenced, never created, here.
AGENT_GRANTS: dict[str, tuple[str, ...]] = {
    "owner": ("agent.read", "agent.create", "agent.update", "agent.delete"),
    "admin": ("agent.read", "agent.create", "agent.update", "agent.delete"),
    "security_admin": ("agent.read", "agent.update"),
    "ai_admin": ("agent.read", "agent.create", "agent.update"),
    "analyst": ("agent.read",),
    "viewer": ("agent.read",),
}

TABLE_COMMENT = (
    "AI agent registry: the stable identity of one agent asset, with the category "
    "and version it was registered at. Tenant-owned; the referenced asset and the "
    "asset's owner membership must belong to the same organization, enforced by "
    "composite foreign keys."
)

_GRANT_STATEMENT = sa.text(
    f"INSERT INTO {SCHEMA}.role_permissions (role_id, permission_id) "
    f"SELECT r.id, p.id FROM {SCHEMA}.roles AS r, {SCHEMA}.permissions AS p "
    "WHERE r.code = :role_code AND p.code = :permission_code"
)

_REVOKE_STATEMENT = sa.text(
    f"DELETE FROM {SCHEMA}.role_permissions AS rp "
    f"USING {SCHEMA}.roles AS r, {SCHEMA}.permissions AS p "
    "WHERE rp.role_id = r.id AND rp.permission_id = p.id "
    "AND r.code = :role_code AND p.code = :permission_code"
)


def _values(values: tuple[str, ...]) -> str:
    """Render a value list as the SQL literal list a CHECK constraint expects."""
    return ", ".join(f"'{value}'" for value in values)


def upgrade() -> None:
    # ── The composite target the registry foreign key references ──────────────
    # Created *before* the table that points at it: PostgreSQL checks the
    # referenced column list for uniqueness when the foreign key is created, and a
    # foreign key to a unique set that does not exist yet is refused.
    op.create_unique_constraint(
        op.f("uq_assets_organization_id_id"),
        "assets",
        ["organization_id", "id"],
        schema=SCHEMA,
    )

    # ── The registry table ───────────────────────────────────────────────────
    op.create_table(
        "agents",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "identity_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("asset_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("category", sa.String(length=CATEGORY_MAX_LENGTH), nullable=False),
        sa.Column("version", sa.String(length=VERSION_MAX_LENGTH), nullable=False),
        sa.Column("build_revision", sa.String(length=BUILD_REVISION_MAX_LENGTH), nullable=True),
        sa.Column("framework", sa.String(length=FRAMEWORK_MAX_LENGTH), nullable=True),
        sa.Column(
            "identity_metadata",
            sa.dialects.postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agents")),
        # CASCADE, not RESTRICT: deleting the inventory record removes the identity
        # with it, because an identity whose agent is gone is an orphan — and the
        # composite key means the asset is in this record's own organization.
        # The tenant boundary itself: RESTRICT, so deleting an organization can
        # never silently remove its agents (and their identities) as a side effect.
        sa.ForeignKeyConstraint(
            ["organization_id"],
            [f"{SCHEMA}.organizations.id"],
            name=op.f("fk_agents_organization_id_organizations"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "asset_id"],
            [f"{SCHEMA}.assets.organization_id", f"{SCHEMA}.assets.id"],
            name=op.f("fk_agents_organization_id_assets"),
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("asset_id", name=op.f("uq_agents_asset_id")),
        sa.UniqueConstraint(
            "organization_id",
            "identity_id",
            name=op.f("uq_agents_organization_id_identity_id"),
        ),
        sa.CheckConstraint(
            f"category IN ({_values(AGENT_CATEGORIES)})",
            name=op.f("ck_agents_category_valid"),
        ),
        sa.CheckConstraint(
            f"char_length(btrim(version)) BETWEEN 1 AND {VERSION_MAX_LENGTH}",
            name=op.f("ck_agents_version_length"),
        ),
        sa.CheckConstraint(
            "build_revision IS NULL OR char_length(btrim(build_revision)) "
            f"BETWEEN 1 AND {BUILD_REVISION_MAX_LENGTH}",
            name=op.f("ck_agents_build_revision_length"),
        ),
        sa.CheckConstraint(
            "framework IS NULL OR char_length(btrim(framework)) "
            f"BETWEEN 1 AND {FRAMEWORK_MAX_LENGTH}",
            name=op.f("ck_agents_framework_length"),
        ),
        sa.CheckConstraint(
            "identity_metadata IS NULL OR jsonb_typeof(identity_metadata) = 'object'",
            name=op.f("ck_agents_identity_metadata_is_object"),
        ),
        schema=SCHEMA,
        comment=TABLE_COMMENT,
    )

    # ── Indexes ──────────────────────────────────────────────────────────────
    # The tenant filter every registry query leads with, and the one filter an
    # agent list is actually interrogated with. ``asset_id`` and
    # ``(organization_id, identity_id)`` are served by their unique constraints.
    op.create_index(
        op.f("ix_agents_organization_id"), "agents", ["organization_id"], schema=SCHEMA
    )
    op.create_index(
        op.f("ix_agents_organization_id_category"),
        "agents",
        ["organization_id", "category"],
        schema=SCHEMA,
    )

    # ── Extend the authorization catalog ─────────────────────────────────────
    for code, description in PERMISSIONS:
        op.execute(
            sa.text(
                f"INSERT INTO {SCHEMA}.permissions (code, description) "
                "VALUES (:code, :description)"
            ).bindparams(code=code, description=description)
        )

    for role_code, permission_codes in AGENT_GRANTS.items():
        for permission_code in permission_codes:
            op.execute(
                _GRANT_STATEMENT.bindparams(
                    role_code=role_code, permission_code=permission_code
                )
            )


def downgrade() -> None:
    # Revoke first: the grants reference the permissions, and the permissions are
    # what this revision added. Roles and the other permissions stay.
    for role_code, permission_codes in AGENT_GRANTS.items():
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

    # The table goes before the constraint it depends on.
    op.drop_index(
        op.f("ix_agents_organization_id_category"), table_name="agents", schema=SCHEMA
    )
    op.drop_index(op.f("ix_agents_organization_id"), table_name="agents", schema=SCHEMA)
    op.drop_table("agents", schema=SCHEMA)

    op.drop_constraint(
        op.f("uq_assets_organization_id_id"), "assets", type_="unique", schema=SCHEMA
    )
