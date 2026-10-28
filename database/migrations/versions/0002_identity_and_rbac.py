"""Phase 2: identity, memberships and the role/permission catalog.

Creates:

- ``aicore.users`` — global identity (a person may belong to several
  organizations);
- ``aicore.api_tokens`` — bearer credentials, stored as hashes only;
- ``aicore.roles`` / ``aicore.permissions`` / ``aicore.role_permissions`` — the
  reference catalog authorization resolves against;
- ``aicore.memberships`` — the tenant-owned grant that ties a user to an
  organization and carries their role.

It then seeds the catalog: six roles, eight permissions, and the grants that
connect them. The seed is deliberately *data in the migration* rather than code
applied at startup: the schema and the policy that ships with it are one
reviewed, reversible step, and the test suite asserts the seeded grants equal
``aicore_api.core.permissions.ROLE_PERMISSIONS`` exactly.

Reference data is global, tenant data is not: only ``memberships`` carries
``organization_id``. That is what makes "who may do what in organization X" a
join from a tenant-owned row into shared catalogs, rather than a second copy of
the policy per tenant.

Revision ID: 0002_identity_and_rbac
Revises: 0001_organizations
Create Date: 2026-09-22
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_identity_and_rbac"
down_revision: str | None = "0001_organizations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "aicore"

# Literals, not imports from the models: a migration describes the database at one
# point in time. tests/test_migrations.py compares this schema with the models and
# tests/test_authorization.py compares the seed below with the code catalog.
CODE_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"
EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
USER_STATUSES = ("active", "suspended")
MEMBERSHIP_STATUSES = ("active", "suspended")

PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("organization.read", "Read the organization's own record and settings."),
    ("organization.update", "Change the organization's own settings and lifecycle."),
    ("user.read", "See who belongs to the organization."),
    ("user.manage", "Add, change and remove members of the organization."),
    ("role.read", "See the roles that exist and the permissions they grant."),
    ("role.manage", "Decide which roles exist and who may hold them."),
    ("audit.read", "Read the organization's audit trail."),
    ("security.read", "Read the organization's security posture and findings."),
)

ROLES: tuple[tuple[str, str, str], ...] = (
    ("owner", "Owner", "Full organization administration, including roles."),
    ("admin", "Administrator", "General organization administration."),
    ("security_admin", "Security administrator", "Security posture, audit trail and containment."),
    ("ai_admin", "AI administrator", "AI asset and AI platform administration."),
    ("analyst", "Analyst", "Read and analyse AI and security information."),
    ("viewer", "Viewer", "Read-only access to permitted resources."),
)

#: The role model, as data. Read this table: it is the whole policy.
ROLE_GRANTS: dict[str, tuple[str, ...]] = {
    "owner": (
        "organization.read",
        "organization.update",
        "user.read",
        "user.manage",
        "role.read",
        "role.manage",
        "audit.read",
        "security.read",
    ),
    "admin": (
        "organization.read",
        "organization.update",
        "user.read",
        "user.manage",
        "role.read",
    ),
    "security_admin": (
        "organization.read",
        "user.read",
        "audit.read",
        "security.read",
    ),
    "ai_admin": (
        "organization.read",
        "user.read",
    ),
    "analyst": (
        "organization.read",
        "security.read",
    ),
    "viewer": ("organization.read",),
}

_GRANT_STATEMENT = sa.text(
    f"INSERT INTO {SCHEMA}.role_permissions (role_id, permission_id) "
    f"SELECT r.id, p.id FROM {SCHEMA}.roles AS r, {SCHEMA}.permissions AS p "
    "WHERE r.code = :role_code AND p.code = :permission_code"
)


def upgrade() -> None:
    op.execute(sa.text(f'CREATE SCHEMA IF NOT EXISTS "{SCHEMA}"'))

    # ── Identity ─────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("full_name", sa.String(length=200), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
        sa.CheckConstraint("email = lower(btrim(email))", name=op.f("ck_users_email_normalized")),
        sa.CheckConstraint(f"email ~ '{EMAIL_PATTERN}'", name=op.f("ck_users_email_format")),
        sa.CheckConstraint(
            "char_length(btrim(full_name)) BETWEEN 1 AND 200",
            name=op.f("ck_users_full_name_length"),
        ),
        sa.CheckConstraint(
            "status IN ({})".format(", ".join(f"'{value}'" for value in USER_STATUSES)),
            name=op.f("ck_users_status_valid"),
        ),
        schema=SCHEMA,
    )
    op.execute(
        sa.text(
            f"COMMENT ON TABLE \"{SCHEMA}\".users IS "
            "'AICore identity. Global on purpose: a user may belong to several "
            "organizations; tenant visibility comes from memberships, never from this "
            "table. Holds no credential of any kind.'"
        )
    )

    # ── Catalog ──────────────────────────────────────────────────────────────
    op.create_table(
        "roles",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("code", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_roles")),
        sa.UniqueConstraint("code", name=op.f("uq_roles_code")),
        sa.CheckConstraint(f"code ~ '{CODE_PATTERN}'", name=op.f("ck_roles_code_format")),
        sa.CheckConstraint(
            "char_length(btrim(name)) BETWEEN 1 AND 64", name=op.f("ck_roles_name_length")
        ),
        schema=SCHEMA,
    )
    op.execute(
        sa.text(
            f"COMMENT ON TABLE \"{SCHEMA}\".roles IS "
            "'System role catalog (reference data). Which role a member holds is "
            "recorded on memberships, which are tenant-owned.'"
        )
    )

    op.create_table(
        "permissions",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("description", sa.String(length=300), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_permissions")),
        sa.UniqueConstraint("code", name=op.f("uq_permissions_code")),
        sa.CheckConstraint(f"code ~ '{CODE_PATTERN}'", name=op.f("ck_permissions_code_format")),
        sa.CheckConstraint(
            "char_length(btrim(description)) BETWEEN 1 AND 300",
            name=op.f("ck_permissions_description_length"),
        ),
        schema=SCHEMA,
    )
    op.execute(
        sa.text(
            f"COMMENT ON TABLE \"{SCHEMA}\".permissions IS "
            "'Permission catalog: the explicit capabilities authorization checks. "
            "Reference data, shared by every organization.'"
        )
    )

    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("permission_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        sa.PrimaryKeyConstraint("role_id", "permission_id", name=op.f("pk_role_permissions")),
        sa.ForeignKeyConstraint(
            ["role_id"],
            [f"{SCHEMA}.roles.id"],
            name=op.f("fk_role_permissions_role_id_roles"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            [f"{SCHEMA}.permissions.id"],
            name=op.f("fk_role_permissions_permission_id_permissions"),
            ondelete="RESTRICT",
        ),
        schema=SCHEMA,
    )
    op.execute(
        sa.text(
            f"COMMENT ON TABLE \"{SCHEMA}\".role_permissions IS "
            "'Which permissions each role grants. Seeded by migration and asserted "
            "against the code catalog in aicore_api.core.permissions.'"
        )
    )

    # ── Membership (tenant-owned: the only table here carrying organization_id) ──
    op.create_table(
        "memberships",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_memberships")),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            [f"{SCHEMA}.organizations.id"],
            name=op.f("fk_memberships_organization_id_organizations"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{SCHEMA}.users.id"],
            name=op.f("fk_memberships_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            [f"{SCHEMA}.roles.id"],
            name=op.f("fk_memberships_role_id_roles"),
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "user_id",
            name=op.f("uq_memberships_organization_id_user_id"),
        ),
        sa.CheckConstraint(
            "status IN ({})".format(", ".join(f"'{value}'" for value in MEMBERSHIP_STATUSES)),
            name=op.f("ck_memberships_status_valid"),
        ),
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_memberships_organization_id"), "memberships", ["organization_id"], schema=SCHEMA
    )
    op.create_index(op.f("ix_memberships_user_id"), "memberships", ["user_id"], schema=SCHEMA)
    op.create_index(op.f("ix_memberships_role_id"), "memberships", ["role_id"], schema=SCHEMA)
    op.execute(
        sa.text(
            f"COMMENT ON TABLE \"{SCHEMA}\".memberships IS "
            "'Membership of a user in an organization, carrying the role that grants "
            "their permissions. Tenant-owned: reads require a bound organization.'"
        )
    )

    # ── Credentials ──────────────────────────────────────────────────────────
    op.create_table(
        "api_tokens",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("token_prefix", sa.String(length=16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_tokens")),
        sa.ForeignKeyConstraint(
            ["user_id"],
            [f"{SCHEMA}.users.id"],
            name=op.f("fk_api_tokens_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("token_hash", name=op.f("uq_api_tokens_token_hash")),
        sa.CheckConstraint(
            "char_length(token_hash) = 64", name=op.f("ck_api_tokens_token_hash_length")
        ),
        sa.CheckConstraint(
            "char_length(btrim(name)) BETWEEN 1 AND 100", name=op.f("ck_api_tokens_name_length")
        ),
        schema=SCHEMA,
    )
    op.create_index(op.f("ix_api_tokens_user_id"), "api_tokens", ["user_id"], schema=SCHEMA)
    op.execute(
        sa.text(
            f"COMMENT ON TABLE \"{SCHEMA}\".api_tokens IS "
            "'API tokens for machine and developer access. Only a SHA-256 hash of the "
            "token is stored; the plaintext exists once, when it is issued. Tokens "
            "authenticate a user; authorization comes from their memberships.'"
        )
    )

    # ── Seed the catalog ─────────────────────────────────────────────────────
    for code, description in PERMISSIONS:
        op.execute(
            sa.text(
                f"INSERT INTO {SCHEMA}.permissions (code, description) "
                "VALUES (:code, :description)"
            ).bindparams(code=code, description=description)
        )

    for code, name, description in ROLES:
        op.execute(
            sa.text(
                f"INSERT INTO {SCHEMA}.roles (code, name, description) "
                "VALUES (:code, :name, :description)"
            ).bindparams(code=code, name=name, description=description)
        )

    for role_code, permission_codes in ROLE_GRANTS.items():
        for permission_code in permission_codes:
            op.execute(
                _GRANT_STATEMENT.bindparams(
                    role_code=role_code, permission_code=permission_code
                )
            )


def downgrade() -> None:
    # Seeds live in these tables, so dropping them removes the catalog too: there
    # is no separate data step to forget. Each table is dropped with the objects
    # that depend on it (indexes and constraints), and the schema namespace is
    # left in place for the same reason as in 0001.
    op.drop_index(op.f("ix_api_tokens_user_id"), table_name="api_tokens", schema=SCHEMA)
    op.drop_table("api_tokens", schema=SCHEMA)

    op.drop_index(op.f("ix_memberships_role_id"), table_name="memberships", schema=SCHEMA)
    op.drop_index(op.f("ix_memberships_user_id"), table_name="memberships", schema=SCHEMA)
    op.drop_index(
        op.f("ix_memberships_organization_id"), table_name="memberships", schema=SCHEMA
    )
    op.drop_table("memberships", schema=SCHEMA)

    op.drop_table("role_permissions", schema=SCHEMA)
    op.drop_table("permissions", schema=SCHEMA)
    op.drop_table("roles", schema=SCHEMA)
    op.drop_table("users", schema=SCHEMA)
