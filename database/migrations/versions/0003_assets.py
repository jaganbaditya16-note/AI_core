"""Phase 3: the AI asset inventory.

Creates ``aicore.assets`` — one tenant-owned table for every kind of AI asset —
and extends the authorization catalog with the four asset permissions and their
role grants.

Three things in this revision are worth understanding before changing it.

**One table, not seven.** Asset types (agent, application, model, tool, MCP
server, API, data source) differ in their metadata, not in their identity. They
share the tenant boundary, the owner, the lifecycle and the discovery state, and
those are the parts a security decision is read from — so they are the parts that
must not be allowed to drift apart. Type-specific fields live in a validated
``JSONB`` column (``aicore_api.core.assets``), because seven sparse columns per
type would be mostly NULL and entirely untyped.

**Ownership is enforced by the database.** ``owner_membership_id`` references
``(organization_id, id)`` on ``memberships``, so the owner is a member *of the
asset's own organization* or the row cannot exist. That reference needs
``uq_memberships_organization_id_id`` — a unique constraint that is redundant with
the primary key and is added here on purpose, because PostgreSQL can only point a
foreign key at a unique set of columns.

**Deduplication is a partial unique index.** An asset reported by an integration
is unique by ``(organization_id, asset_type, external_identifier)``; an asset
registered by hand has no external identifier and is therefore not colliding with
anything. Names are deliberately not part of it: the same name may legitimately
appear twice, and nothing is looked up by name.

The permission seed follows migration 0002 and the same rule applies: the seeded
grants are asserted to equal ``aicore_api.core.permissions.ROLE_PERMISSIONS``
exactly, so the policy the database ships with cannot drift from the policy the
application enforces.

Revision ID: 0003_assets
Revises: 0002_identity_and_rbac
Create Date: 2026-09-22
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_assets"
down_revision: str | None = "0002_identity_and_rbac"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "aicore"

# Literals, not imports from the models: a migration describes the database at one
# point in time. tests/test_migrations.py compares this schema with the models, and
# tests/test_assets.py compares the seeded permissions and grants with the catalog
# in aicore_api.core.permissions.
ASSET_TYPES = ("agent", "application", "model", "tool", "mcp_server", "api", "data_source")
ASSET_STATUSES = ("draft", "active", "suspended", "retired")
DISCOVERY_STATES = ("managed", "unknown", "shadow")
ENVIRONMENTS = ("development", "staging", "production", "unknown")
RISK_CLASSIFICATIONS = ("low", "medium", "high", "critical", "unassessed")

NAME_MAX_LENGTH = 200
DESCRIPTION_MAX_LENGTH = 2000
EXTERNAL_IDENTIFIER_MAX_LENGTH = 512
DISCOVERY_SOURCE_MAX_LENGTH = 100

#: ``jsonb_typeof`` is checked rather than trusted: an array or a scalar in this
#: column is not "flexible metadata", it is a shape no reader can rely on.
_METADATA_CHECK = "metadata IS NULL OR jsonb_typeof(metadata) = 'object'"

#: A CHECK constraint lists its allowed values as SQL string literals. Rendered by
#: a helper rather than inline f-strings, because ``f"{value}"`` produces an
#: unquoted identifier and PostgreSQL then reads ``agent`` as a column name.
def _values(values: tuple[str, ...]) -> str:
    """Render a value list as the SQL literal list a CHECK constraint expects."""
    return ", ".join(f"'{value}'" for value in values)


PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("asset.read", "See the AI assets the organization has recorded."),
    ("asset.create", "Register an AI asset in the organization's inventory."),
    ("asset.update", "Change an inventory record: ownership, lifecycle, discovery, risk."),
    ("asset.delete", "Remove an AI asset from the organization's inventory."),
)

#: Only the grants this revision introduces. Role codes and the other permission
#: codes are seeded by 0002 and are referenced, never created, here.
ASSET_GRANTS: dict[str, tuple[str, ...]] = {
    "owner": ("asset.read", "asset.create", "asset.update", "asset.delete"),
    "admin": ("asset.read", "asset.create", "asset.update", "asset.delete"),
    "security_admin": ("asset.read", "asset.update"),
    "ai_admin": ("asset.read", "asset.create", "asset.update"),
    "analyst": ("asset.read",),
    "viewer": ("asset.read",),
}

TABLE_COMMENT = (
    "AI asset inventory: every AI-related thing an organization knows about, "
    "whatever its type. Tenant-owned; the owner is a membership of the same "
    "organization, enforced by a composite foreign key."
)

_GRANT_STATEMENT = sa.text(
    f"INSERT INTO {SCHEMA}.role_permissions (role_id, permission_id) "
    f"SELECT r.id, p.id FROM {SCHEMA}.roles AS r, {SCHEMA}.permissions AS p "
    "WHERE r.code = :role_code AND p.code = :permission_code"
)


def upgrade() -> None:
    # ── The composite target the owner foreign key references ────────────────
    # Created *before* the table that points at it: PostgreSQL checks the
    # referenced column list for uniqueness when the foreign key is created, and a
    # foreign key to a unique set that does not exist yet is refused.
    op.create_unique_constraint(
        op.f("uq_memberships_organization_id_id"),
        "memberships",
        ["organization_id", "id"],
        schema=SCHEMA,
    )

    # ── The inventory table ──────────────────────────────────────────────────
    op.create_table(
        "assets",
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
        sa.Column("owner_membership_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("name", sa.String(length=NAME_MAX_LENGTH), nullable=False),
        sa.Column("description", sa.String(length=DESCRIPTION_MAX_LENGTH), nullable=True),
        sa.Column("asset_type", sa.String(length=32), nullable=False),
        sa.Column(
            "status", sa.String(length=32), server_default=sa.text("'draft'"), nullable=False
        ),
        sa.Column(
            "environment",
            sa.String(length=32),
            server_default=sa.text("'unknown'"),
            nullable=False,
        ),
        sa.Column(
            "discovery_state",
            sa.String(length=32),
            server_default=sa.text("'managed'"),
            nullable=False,
        ),
        sa.Column(
            "risk_classification",
            sa.String(length=32),
            server_default=sa.text("'unassessed'"),
            nullable=False,
        ),
        sa.Column(
            "external_identifier",
            sa.String(length=EXTERNAL_IDENTIFIER_MAX_LENGTH),
            nullable=True,
        ),
        sa.Column(
            "discovery_source",
            sa.String(length=DISCOVERY_SOURCE_MAX_LENGTH),
            server_default=sa.text("'manual'"),
            nullable=False,
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", sa.dialects.postgresql.JSONB(astext_type=sa.Text()), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assets")),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            [f"{SCHEMA}.organizations.id"],
            name=op.f("fk_assets_organization_id_organizations"),
            ondelete="RESTRICT",
        ),
        # The owner must be a member of this asset's organization. RESTRICT, not
        # CASCADE: removing a member who still owns inventory is refused rather
        # than quietly leaving assets unowned.
        sa.ForeignKeyConstraint(
            ["organization_id", "owner_membership_id"],
            [f"{SCHEMA}.memberships.organization_id", f"{SCHEMA}.memberships.id"],
            name=op.f("fk_assets_organization_id_memberships"),
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            f"char_length(btrim(name)) BETWEEN 1 AND {NAME_MAX_LENGTH}",
            name=op.f("ck_assets_name_length"),
        ),
        sa.CheckConstraint(
            "description IS NULL OR char_length(btrim(description)) BETWEEN 1 "
            f"AND {DESCRIPTION_MAX_LENGTH}",
            name=op.f("ck_assets_description_length"),
        ),
        sa.CheckConstraint(
            f"external_identifier IS NULL OR char_length(btrim(external_identifier)) "
            f"BETWEEN 1 AND {EXTERNAL_IDENTIFIER_MAX_LENGTH}",
            name=op.f("ck_assets_external_identifier_length"),
        ),
        sa.CheckConstraint(
            f"char_length(btrim(discovery_source)) BETWEEN 1 AND {DISCOVERY_SOURCE_MAX_LENGTH}",
            name=op.f("ck_assets_discovery_source_length"),
        ),
        sa.CheckConstraint(
            f"asset_type IN ({_values(ASSET_TYPES)})",
            name=op.f("ck_assets_asset_type_valid"),
        ),
        sa.CheckConstraint(
            f"status IN ({_values(ASSET_STATUSES)})",
            name=op.f("ck_assets_status_valid"),
        ),
        sa.CheckConstraint(
            f"discovery_state IN ({_values(DISCOVERY_STATES)})",
            name=op.f("ck_assets_discovery_state_valid"),
        ),
        sa.CheckConstraint(
            f"environment IN ({_values(ENVIRONMENTS)})",
            name=op.f("ck_assets_environment_valid"),
        ),
        sa.CheckConstraint(
            f"risk_classification IN ({_values(RISK_CLASSIFICATIONS)})",
            name=op.f("ck_assets_risk_classification_valid"),
        ),
        sa.CheckConstraint(_METADATA_CHECK, name=op.f("ck_assets_metadata_is_object")),
        schema=SCHEMA,
    )
    op.execute(
        sa.text(
            f"COMMENT ON TABLE \"{SCHEMA}\".assets IS "
            f"'{TABLE_COMMENT}'"
        )
    )

    # ── Indexes ──────────────────────────────────────────────────────────────
    # Every index leads with organization_id: no query in the application looks at
    # assets without a tenant bound, so a tenant-less index would never be chosen.
    op.create_index(op.f("ix_assets_organization_id"), "assets", ["organization_id"], schema=SCHEMA)
    op.create_index(
        op.f("ix_assets_organization_id_asset_type"),
        "assets",
        ["organization_id", "asset_type"],
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_assets_organization_id_discovery_state"),
        "assets",
        ["organization_id", "discovery_state"],
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_assets_owner_membership_id"), "assets", ["owner_membership_id"], schema=SCHEMA
    )
    # Deduplication. Partial, because a hand-registered asset has no external
    # identifier and two such assets are not duplicates of each other.
    op.create_index(
        op.f("uq_assets_organization_id_asset_type_external_identifier"),
        "assets",
        ["organization_id", "asset_type", "external_identifier"],
        unique=True,
        schema=SCHEMA,
        postgresql_where=sa.text("external_identifier IS NOT NULL"),
    )

    # ── Extend the authorization catalog ─────────────────────────────────────
    for code, description in PERMISSIONS:
        op.execute(
            sa.text(
                f"INSERT INTO {SCHEMA}.permissions (code, description) "
                "VALUES (:code, :description)"
            ).bindparams(code=code, description=description)
        )

    for role_code, permission_codes in ASSET_GRANTS.items():
        for permission_code in permission_codes:
            op.execute(
                _GRANT_STATEMENT.bindparams(
                    role_code=role_code, permission_code=permission_code
                )
            )


def downgrade() -> None:
    # Revoke first: the grants reference the permissions, and the permissions are
    # what this revision added. Roles and the other permissions are 0002's and stay.
    for role_code, permission_codes in ASSET_GRANTS.items():
        for permission_code in permission_codes:
            op.execute(
                sa.text(
                    f"DELETE FROM {SCHEMA}.role_permissions AS rp "
                    f"USING {SCHEMA}.roles AS r, {SCHEMA}.permissions AS p "
                    "WHERE rp.role_id = r.id AND rp.permission_id = p.id "
                    "AND r.code = :role_code AND p.code = :permission_code"
                ).bindparams(role_code=role_code, permission_code=permission_code)
            )

    for code, _ in PERMISSIONS:
        op.execute(
            sa.text(f"DELETE FROM {SCHEMA}.permissions WHERE code = :code").bindparams(code=code)
        )

    # The table goes before the constraint it depends on.
    op.drop_index(
        op.f("uq_assets_organization_id_asset_type_external_identifier"),
        table_name="assets",
        schema=SCHEMA,
    )
    op.drop_index(op.f("ix_assets_owner_membership_id"), table_name="assets", schema=SCHEMA)
    op.drop_index(
        op.f("ix_assets_organization_id_discovery_state"), table_name="assets", schema=SCHEMA
    )
    op.drop_index(
        op.f("ix_assets_organization_id_asset_type"), table_name="assets", schema=SCHEMA
    )
    op.drop_index(op.f("ix_assets_organization_id"), table_name="assets", schema=SCHEMA)
    op.drop_table("assets", schema=SCHEMA)

    op.drop_constraint(
        op.f("uq_memberships_organization_id_id"), "memberships", type_="unique", schema=SCHEMA
    )
