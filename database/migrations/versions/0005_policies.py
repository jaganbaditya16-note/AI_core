"""Phase 6: the context-aware policy record.

Creates ``aicore.policies`` and ``aicore.policy_versions``, and extends the
authorization catalogue with the four policy permissions.

Four things in this revision are worth understanding before changing it.

**Two tables, because a policy and its definition have different lifetimes.**
``policies`` is the identity and the life of a policy: its name, why it exists,
where it is in its lifecycle, and which version is current. ``policy_versions`` is
the definition itself, one row per version, **append-only**: editing a policy's
definition adds a row and moves ``policies.current_version`` forward, and nothing
ever rewrites a version. That is what makes a recorded decision reproducible — a
decision names a policy *and a version*, and the row those name still says what it
said at the time.

**A version cannot belong to another organization's policy.**
``policy_versions`` references ``policies(organization_id, id)`` rather than
``policies(id)``, using ``uq_policies_organization_id_id`` — a constraint that is
redundant with the primary key and added on purpose, because PostgreSQL can only
point a foreign key at a unique set of columns. The same technique makes
``agents`` unable to reference another tenant's asset; here it additionally keeps
the tenant column on the version row honest rather than vestigial.

**The constraints enforce shapes, not opinions.** ``effect``, ``status``,
``resource`` and ``action`` are closed sets checked by the database; ``priority``
is bounded; the conditions column must be a JSON array of at most 32 entries. What
the database deliberately does *not* try to express is the condition language
itself — which operators suit which fields, which values a closed field accepts —
because that is a fact about the application's vocabulary, and a second copy of it
in SQL would be a second thing to keep in sync. The application validates every
write path and re-validates on read; ``tests/test_policies.py`` asserts the
constraint sets equal the vocabulary in ``aicore_api.core.policy``.

**Deleting a policy deletes its history; deleting an organization deletes
nothing.** ``policy_versions`` cascades from ``policies`` — a version whose policy
is gone is unreachable — while ``policies`` is ``ON DELETE RESTRICT`` from
``organizations`` through ``TenantOwnedMixin``'s foreign key: removing a tenant is
an explicit operational procedure, never a side effect of a DELETE.

The permission seed follows migrations 0002–0004, and the same rule applies: the
seeded grants are asserted to equal ``aicore_api.core.permissions.ROLE_PERMISSIONS``
exactly, so the policy the database ships with cannot drift from the policy the
application enforces.

Revision ID: 0005_policies
Revises: 0004_agents
Create Date: 2026-09-23
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_policies"
down_revision: str | None = "0004_agents"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "aicore"

# Literals, not imports from the models: a migration describes the database at one
# point in time. tests/test_policies.py compares this schema with the models, and
# the seeded permissions and grants with aicore_api.core.permissions and the policy
# vocabulary in aicore_api.core.policy — including the condition bound below, which
# is ``core.policy.MAX_CONDITIONS`` and has to stay equal to it.
MAX_CONDITIONS = 8
POLICY_NAME_MAX_LENGTH = 96
POLICY_DESCRIPTION_MAX_LENGTH = 500
POLICY_EFFECT_MAX_LENGTH = 32
POLICY_STATUS_MAX_LENGTH = 16
POLICY_RESOURCE_MAX_LENGTH = 32
POLICY_ACTION_MAX_LENGTH = 16
PRIORITY_MIN = 0
PRIORITY_MAX = 1000

POLICY_STATUSES = ("draft", "active", "disabled", "retired")
POLICY_EFFECTS = ("allow", "deny", "require_approval")

#: The resources and actions a policy may target: the permission catalogue's
#: vocabulary, spelled out as the SQL literals the CHECK constraints carry.
POLICY_RESOURCES = (
    "organization",
    "user",
    "role",
    "audit",
    "security",
    "asset",
    "agent",
    "policy",
)
POLICY_ACTIONS = ("read", "create", "update", "delete", "manage")

PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("policy.read", "See the policies an organization has defined."),
    ("policy.create", "Define a policy for the organization."),
    ("policy.update", "Change a policy's label, rationale, definition or lifecycle state."),
    ("policy.delete", "Remove a policy and its version history."),
)

#: Only the grants this revision introduces. Role codes and the other permission
#: codes were seeded by 0002–0004 and are referenced, never created, here. These are
#: the *permission* codes that guard the policy record: evaluating policies is a
#: read of them (no separate ``policy.evaluate``), and enforcing an evaluation stays
#: a later phase's permission — deliberately absent so no role can appear to hold it.
POLICY_GRANTS: dict[str, tuple[str, ...]] = {
    "owner": ("policy.read", "policy.create", "policy.update", "policy.delete"),
    "admin": ("policy.read", "policy.create", "policy.update", "policy.delete"),
    "security_admin": ("policy.read", "policy.create", "policy.update"),
    "ai_admin": (),
    "analyst": (),
    "viewer": (),
}

POLICIES_TABLE_COMMENT = (
    "Organization policies: the identity, rationale and lifecycle of one policy, "
    "pointing at its current version. Tenant-owned; a policy belongs to exactly one "
    "organization."
)
POLICY_VERSIONS_TABLE_COMMENT = (
    "Append-only policy definitions: target, effect, priority and conditions, one row "
    "per version. A published version is never edited, so a recorded decision that "
    "names a version can always be read back."
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
    # ── Policies ─────────────────────────────────────────────────────────────
    op.create_table(
        "policies",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=POLICY_NAME_MAX_LENGTH), nullable=False),
        sa.Column(
            "description", sa.String(length=POLICY_DESCRIPTION_MAX_LENGTH), nullable=False
        ),
        sa.Column(
            "status",
            sa.String(length=POLICY_STATUS_MAX_LENGTH),
            server_default=sa.text("'draft'"),
            nullable=False,
        ),
        sa.Column("current_version", sa.Integer(), server_default=sa.text("1"), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["organization_id"],
            [f"{SCHEMA}.organizations.id"],
            name=op.f("fk_policies_organization_id_organizations"),
            ondelete="RESTRICT",
        ),
        # One name per policy per organization: a duplicated name makes every
        # conversation, audit record and review that quotes it ambiguous.
        sa.UniqueConstraint(
            "organization_id", "name", name=op.f("uq_policies_organization_id_name")
        ),
        # Redundant with the primary key, and required: policy_versions references
        # (organization_id, id) so that a version cannot be attached to another
        # tenant's policy, and PostgreSQL can only reference a unique set of columns.
        sa.UniqueConstraint("organization_id", "id", name=op.f("uq_policies_organization_id_id")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_policies")),
        sa.CheckConstraint(
            f"char_length(btrim(name)) BETWEEN 1 AND {POLICY_NAME_MAX_LENGTH}",
            name=op.f("ck_policies_name_length"),
        ),
        sa.CheckConstraint("name = btrim(name)", name=op.f("ck_policies_name_normalized")),
        sa.CheckConstraint(
            "char_length(btrim(description)) BETWEEN 1 AND "
            f"{POLICY_DESCRIPTION_MAX_LENGTH}",
            name=op.f("ck_policies_description_length"),
        ),
        sa.CheckConstraint(
            "description = btrim(description)",
            name=op.f("ck_policies_description_normalized"),
        ),
        sa.CheckConstraint(
            f"status IN ({_values(POLICY_STATUSES)})", name=op.f("ck_policies_status_valid")
        ),
        sa.CheckConstraint(
            "current_version >= 1", name=op.f("ck_policies_current_version_positive")
        ),
        schema=SCHEMA,
        comment=POLICIES_TABLE_COMMENT,
    )
    op.create_index(
        op.f("ix_policies_organization_id"),
        "policies",
        ["organization_id"],
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_policies_organization_id_status"),
        "policies",
        ["organization_id", "status"],
        schema=SCHEMA,
    )

    # ── Policy versions ──────────────────────────────────────────────────────
    op.create_table(
        "policy_versions",
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("effect", sa.String(length=POLICY_EFFECT_MAX_LENGTH), nullable=False),
        sa.Column("resource", sa.String(length=POLICY_RESOURCE_MAX_LENGTH), nullable=False),
        sa.Column("action", sa.String(length=POLICY_ACTION_MAX_LENGTH), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("conditions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "policy_id"],
            [f"{SCHEMA}.policies.organization_id", f"{SCHEMA}.policies.id"],
            name=op.f("fk_policy_versions_organization_id_policies"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("policy_id", "version", name=op.f("pk_policy_versions")),
        sa.CheckConstraint(
            "version >= 1", name=op.f("ck_policy_versions_version_positive")
        ),
        sa.CheckConstraint(
            f"effect IN ({_values(POLICY_EFFECTS)})", name=op.f("ck_policy_versions_effect_valid")
        ),
        sa.CheckConstraint(
            f"resource IN ({_values(POLICY_RESOURCES)})",
            name=op.f("ck_policy_versions_resource_valid"),
        ),
        sa.CheckConstraint(
            f"action IN ({_values(POLICY_ACTIONS)})",
            name=op.f("ck_policy_versions_action_valid"),
        ),
        sa.CheckConstraint(
            f"priority BETWEEN {PRIORITY_MIN} AND {PRIORITY_MAX}",
            name=op.f("ck_policy_versions_priority_range"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(conditions) = 'array'",
            name=op.f("ck_policy_versions_conditions_is_array"),
        ),
        sa.CheckConstraint(
            f"jsonb_array_length(conditions) <= {MAX_CONDITIONS}",
            name=op.f("ck_policy_versions_conditions_length"),
        ),
        schema=SCHEMA,
        comment=POLICY_VERSIONS_TABLE_COMMENT,
    )
    op.create_index(
        op.f("ix_policy_versions_organization_id"),
        "policy_versions",
        ["organization_id"],
        schema=SCHEMA,
    )
    # The evaluation query: tenant, then the target it is asked about.
    op.create_index(
        op.f("ix_policy_versions_organization_id_resource_action"),
        "policy_versions",
        ["organization_id", "resource", "action"],
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

    for role_code, permission_codes in POLICY_GRANTS.items():
        for permission_code in permission_codes:
            op.execute(
                _GRANT_STATEMENT.bindparams(
                    role_code=role_code, permission_code=permission_code
                )
            )


def downgrade() -> None:
    # Revoke first: the grants reference the permissions, and the permissions are
    # what this revision added. Roles and the other permissions stay.
    for role_code, permission_codes in POLICY_GRANTS.items():
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

    # Versions first: they reference the policies they belong to. Dropping the
    # table removes its indexes and constraints with it.
    op.drop_index(
        op.f("ix_policy_versions_organization_id_resource_action"),
        table_name="policy_versions",
        schema=SCHEMA,
    )
    op.drop_index(
        op.f("ix_policy_versions_organization_id"),
        table_name="policy_versions",
        schema=SCHEMA,
    )
    op.drop_table("policy_versions", schema=SCHEMA)

    op.drop_index(
        op.f("ix_policies_organization_id_status"), table_name="policies", schema=SCHEMA
    )
    op.drop_index(op.f("ix_policies_organization_id"), table_name="policies", schema=SCHEMA)
    op.drop_table("policies", schema=SCHEMA)
