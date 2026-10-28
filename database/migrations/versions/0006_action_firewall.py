"""Phase 7: the action firewall's ledger, and the permission that guards execution.

Three things change in this revision, and each one is a decision worth reading.

**A new table, for one narrow purpose.** ``action_executions`` is the idempotency
ledger: one row per caller-supplied key per organization, holding what an admitted
execution reported, so that a request retried after a lost answer returns the recorded
result instead of running the action twice. The guarantee is a
``UNIQUE (organization_id, idempotency_key)`` constraint — not a lock, not a lease and
nothing distributed: two concurrent requests cannot both proceed, because PostgreSQL
will not let both rows exist. It is explicitly **not** the audit trail: there is no
actor, no rationale, no decision history and no row for a refusal. What happened, for
whom and whether it was allowed is Phase 8's system.

The status column and the columns that accompany it are tied together by ``CHECK``
constraints (``reserved`` has no outcome and no completion time, ``executed`` has an
outcome and no error, ``failed`` has an error and no outcome), so a row cannot claim to
have run something without the record of what it reported. The key and the fingerprint
are checked against the same shapes the application enforces — an opaque bounded token
and a 64-character hex digest — so a value the application would refuse cannot arrive
through a data fix either. ``organization_id`` is ``ON DELETE RESTRICT``, as everywhere:
removing a tenant is an operational procedure, never a side effect of a DELETE.

**One permission: ``action.execute``.** The smallest capability that describes this
phase: run *one registered action* through the firewall. It is deliberately not
``agent.execute`` (this phase runs registered actions; it does not run agents), not a
wildcard, and not a per-action permission — the authorization question ("may this
person run registered actions here?") is one question, and the contextual question
("should this action on this target run?") is a policy on this permission's target.
Owner, administrator and security administrator hold it; the AI administrator and the
analyst deliberately do not, because the party whose work a policy constrains does not
also run what it governs — ``tests/test_permissions.py`` asserts the matrix literally.

**The policy vocabulary grows by one pair, and the ``CHECK``s move with it.** A
permission is also a policy target, so ``action.execute`` becomes a target an
organization may write a policy about; ``policy_versions.resource`` and
``policy_versions.action`` must therefore accept ``'action'`` and ``'execute'``. The
constraints are replaced rather than widened in place (PostgreSQL has no "add a value to
a CHECK"), and the replacement lists are written out as literals because a migration
describes the database at one point in time. ``tests/test_policies.py`` compares them
with the code vocabulary, which is what keeps the two copies from drifting.

Revision ID: 0006_action_firewall
Revises: 0005_policies
Create Date: 2026-09-24
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import SQLAlchemyError

revision: str = "0006_action_firewall"
down_revision: str | None = "0005_policies"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "aicore"

# Literals, not imports from the models: a migration describes the database at one
# point in time. tests/test_policies.py compares the policy target constraints with
# aicore_api.core.permissions (and so with core.policy's derived target map), and
# tests/test_action_execution.py compares the ledger's constraints with
# aicore_api.core.actions — including the pattern below, which is
# core.actions.IDEMPOTENCY_KEY_PATTERN written out as SQL.
ACTION_ID_MAX_LENGTH = 64
IDEMPOTENCY_KEY_MAX_LENGTH = 128
IDEMPOTENCY_KEY_SQL_PATTERN = "^[A-Za-z0-9._:-]{1,128}$"
FINGERPRINT_LENGTH = 64
ERROR_CODE_MAX_LENGTH = 64

EXECUTION_STATUSES = ("reserved", "executed", "failed")

#: The policy target vocabulary *after* this revision. The first eight resources and the
#: first five actions are the sets revision 0005 created; the last entry of each is what
#: this revision adds, and both lists are spelled out in full because a ``CHECK`` states
#: a complete set, never a delta.
POLICY_RESOURCES_BEFORE = (
    "organization",
    "user",
    "role",
    "audit",
    "security",
    "asset",
    "agent",
    "policy",
)
POLICY_RESOURCES_AFTER = (*POLICY_RESOURCES_BEFORE, "action")
#: Sorted, because that is how the model renders the action set.
POLICY_ACTIONS_BEFORE = ("read", "create", "update", "delete", "manage")
POLICY_ACTIONS_AFTER = ("create", "delete", "execute", "manage", "read", "update")

PERMISSIONS: tuple[tuple[str, str], ...] = (
    (
        "action.execute",
        "Run one registered action through the action firewall.",
    ),
)

#: Only the grants this revision introduces. Role codes and the other permission codes
#: were seeded by 0002–0006 (this one) and are referenced, never created, here — and
#: ``tests/test_migrations.py`` asserts these equal
#: ``aicore_api.core.permissions.ROLE_PERMISSIONS`` exactly, so the policy the database
#: ships with cannot drift from the policy the application enforces.
ACTION_GRANTS: dict[str, tuple[str, ...]] = {
    "owner": ("action.execute",),
    "admin": ("action.execute",),
    "security_admin": ("action.execute",),
    "ai_admin": (),
    "analyst": (),
    "viewer": (),
}

#: Spelled out rather than imported, like every other literal here, and kept identical
#: to the model's ``TABLE_COMMENT``: ``alembic check`` compares the two, so a comment
#: that drifts turns into a detected "pending migration" rather than silent divergence.
ACTION_EXECUTIONS_TABLE_COMMENT = (
    "Idempotency ledger for admitted actions: one row per idempotency key per "
    "organization, holding the recorded outcome so a retry returns it instead of "
    "executing again. Not an audit trail: no actor, no refusals, no decision history."
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


def _drop_target_constraint(column: str) -> str:
    """Drop one ``policy_versions`` target constraint and name it.

    Dropped and re-added rather than altered: a ``CHECK`` states a complete set, and
    PostgreSQL has no way to extend one. The name is preserved exactly — it is part of
    the schema's contract, and ``tests/test_policies.py`` looks the constraint up by it.
    """
    constraint = op.f(f"ck_policy_versions_{column}_valid")
    op.drop_constraint(constraint, "policy_versions", schema=SCHEMA, type_="check")
    return constraint


def _replace_target_constraint(column: str, values: tuple[str, ...]) -> None:
    """Narrow or widen one target constraint, with the new list."""
    constraint = _drop_target_constraint(column)
    op.create_check_constraint(
        constraint, "policy_versions", f"{column} IN ({_values(values)})", schema=SCHEMA
    )


def upgrade() -> None:
    # ── The idempotency ledger ────────────────────────────────────────────────
    op.create_table(
        "action_executions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("idempotency_key", sa.String(length=IDEMPOTENCY_KEY_MAX_LENGTH), nullable=False),
        sa.Column("action_id", sa.String(length=ACTION_ID_MAX_LENGTH), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=FINGERPRINT_LENGTH), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("outcome", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("error_code", sa.String(length=ERROR_CODE_MAX_LENGTH), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            [f"{SCHEMA}.organizations.id"],
            name=op.f("fk_action_executions_organization_id_organizations"),
            ondelete="RESTRICT",
        ),
        # The idempotency guarantee, expressed as the one thing that cannot be raced:
        # two rows with one key in one tenant are not a state this schema can hold.
        sa.UniqueConstraint(
            "organization_id",
            "idempotency_key",
            name=op.f("uq_action_executions_organization_id_idempotency_key"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_action_executions")),
        sa.CheckConstraint(
            f"status IN ({_values(EXECUTION_STATUSES)})",
            name=op.f("ck_action_executions_status_valid"),
        ),
        sa.CheckConstraint(
            f"char_length(request_fingerprint) = {FINGERPRINT_LENGTH}",
            name=op.f("ck_action_executions_fingerprint_length"),
        ),
        sa.CheckConstraint(
            f"idempotency_key ~ '{IDEMPOTENCY_KEY_SQL_PATTERN}'",
            name=op.f("ck_action_executions_idempotency_key_shape"),
        ),
        sa.CheckConstraint(
            "(status = 'reserved') = (completed_at IS NULL)",
            name=op.f("ck_action_executions_completion_consistent"),
        ),
        sa.CheckConstraint(
            "(status = 'executed') = (outcome IS NOT NULL)",
            name=op.f("ck_action_executions_outcome_consistent"),
        ),
        sa.CheckConstraint(
            "(status = 'failed') = (error_code IS NOT NULL)",
            name=op.f("ck_action_executions_error_consistent"),
        ),
        schema=SCHEMA,
        comment=ACTION_EXECUTIONS_TABLE_COMMENT,
    )
    op.create_index(
        op.f("ix_action_executions_organization_id"),
        "action_executions",
        ["organization_id"],
        schema=SCHEMA,
    )

    # ── The policy target vocabulary, widened by one pair ─────────────────────
    _replace_target_constraint("resource", POLICY_RESOURCES_AFTER)
    _replace_target_constraint("action", POLICY_ACTIONS_AFTER)

    # ── Extend the authorization catalog ──────────────────────────────────────
    for code, description in PERMISSIONS:
        op.execute(
            sa.text(
                f"INSERT INTO {SCHEMA}.permissions (code, description) "
                "VALUES (:code, :description)"
            ).bindparams(code=code, description=description)
        )

    for role_code, permission_codes in ACTION_GRANTS.items():
        for permission_code in permission_codes:
            op.execute(
                _GRANT_STATEMENT.bindparams(role_code=role_code, permission_code=permission_code)
            )


def downgrade() -> None:
    # Revoke first: the grants reference the permission, and the permission is what this
    # revision added. Roles and the other permissions stay.
    for role_code, permission_codes in ACTION_GRANTS.items():
        for permission_code in permission_codes:
            op.execute(
                _REVOKE_STATEMENT.bindparams(role_code=role_code, permission_code=permission_code)
            )

    for code, _ in PERMISSIONS:
        op.execute(
            sa.text(f"DELETE FROM {SCHEMA}.permissions WHERE code = :code").bindparams(code=code)
        )

    # The vocabulary narrows back to what revision 0005 declared — and it refuses to
    # narrow over live data. A policy targeting ``action.execute`` can only exist while
    # this revision is applied, and 0005's constraint cannot represent it, so the honest
    # outcomes are "delete the organization's policy" or "refuse". It refuses: silently
    # discarding a security policy as a side effect of a schema change is data
    # destruction, and an operator who meant it can retarget or delete the policy and run
    # the downgrade again. PostgreSQL performs the check while adding the constraint —
    # this revision asks it rather than inspecting the rows itself, which keeps the
    # migration out of tenant-owned data (the isolation guard refuses unscoped reads of
    # it, correctly).
    for column, values, added in (
        ("action", POLICY_ACTIONS_BEFORE, "'execute'"),
        ("resource", POLICY_RESOURCES_BEFORE, "'action'"),
    ):
        constraint = _drop_target_constraint(column)
        try:
            op.create_check_constraint(
                constraint, "policy_versions", f"{column} IN ({_values(values)})", schema=SCHEMA
            )
        except SQLAlchemyError as exc:
            raise RuntimeError(
                "refusing to downgrade: this database stores a policy version whose "
                f"{column} is {added}, which revision 0005 cannot represent. Retarget or "
                "delete those policies and run the downgrade again; this revision will not "
                "discard an organization's policy to make a schema change succeed."
            ) from exc

    # The ledger last, and its rows with it: nothing else references it, and a ledger
    # row is only meaningful to the revision that can answer a retry with it.
    op.drop_index(
        op.f("ix_action_executions_organization_id"),
        table_name="action_executions",
        schema=SCHEMA,
    )
    op.drop_table("action_executions", schema=SCHEMA)
