"""Phase 1: the tenant root and the multi-tenancy boundary.

Creates:

- the ``aicore`` schema namespace (idempotent — ``database/init/01-init.sql``
  may already have created it on a Docker volume);
- ``aicore.organizations``, the tenant root.

No other table is created. Agents, models, tools, data sources, policies, events
and incidents arrive in later phases; they will inherit the tenant boundary
defined in ``aicore_api.db.base.TenantOwnedMixin`` rather than restating it.

Revision ID: 0001_organizations
Revises:
Create Date: 2026-09-18
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_organizations"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "aicore"

# Kept as literals rather than imported from the model: a migration describes the
# database at one point in time and must not change when a model changes. The
# schema-drift test (tests/test_migrations.py) fails if the two disagree.
SLUG_PATTERN = r"^[a-z0-9]+(-[a-z0-9]+)*$"
STATUS_VALUES = ("active", "suspended", "archived")


def upgrade() -> None:
    op.execute(sa.text(f'CREATE SCHEMA IF NOT EXISTS "{SCHEMA}"'))

    op.create_table(
        "organizations",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("slug", sa.String(length=63), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            server_default=sa.text("'active'"),
            nullable=False,
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organizations")),
        sa.UniqueConstraint("slug", name=op.f("uq_organizations_slug")),
        sa.CheckConstraint(
            "char_length(btrim(name)) BETWEEN 1 AND 200",
            name=op.f("ck_organizations_name_length"),
        ),
        sa.CheckConstraint(
            f"slug ~ '{SLUG_PATTERN}'",
            name=op.f("ck_organizations_slug_format"),
        ),
        sa.CheckConstraint(
            "status IN ({})".format(", ".join(f"'{value}'" for value in STATUS_VALUES)),
            name=op.f("ck_organizations_status_valid"),
        ),
        schema=SCHEMA,
    )

    op.execute(
        sa.text(
            f"COMMENT ON TABLE \"{SCHEMA}\".organizations IS "
            "'AICore tenant root. Every tenant-owned table carries a foreign key "
            "to this table; deleting a row is RESTRICTed while such rows exist.'"
        )
    )


def downgrade() -> None:
    # The schema itself is left in place: it is a namespace, it may pre-date this
    # migration (database/init/01-init.sql), and dropping it could take objects
    # that belong to a different revision. Only this migration's table is removed.
    op.drop_table("organizations", schema=SCHEMA)
