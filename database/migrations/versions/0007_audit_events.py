"""Phase 8: the audit trail — one append-only table, and the trigger that keeps it so.

This revision adds a table and nothing else: no permission, no role grant, no change to
any earlier table. ``audit.read`` already exists — Phase 2 declared it for exactly this
purpose — so the query API can be guarded with the vocabulary that is already seeded
instead of a new one, and the role matrix is untouched. That is the whole reason a phase
about security history needs one table: the authority it records (Phase 5 authorization,
Phase 6 policy, Phase 7 firewall) already exists, and this is the memory of what they
decided.

**What the table is for.** One row per security-relevant event, in the organization it
happened to, with server-resolved attribution, the decision, the outcome, the correlation
identity and a sanitized summary. It is not the application log (logs rotate and are not
queryable per tenant), and it is not Phase 7's ``action_executions`` ledger (that table
holds one row per idempotency key and forgets refusals; this one holds a refusal and has
no key).

**Append-only, enforced by the database.** Two triggers — row-level for ``UPDATE`` and
``DELETE``, statement-level for ``TRUNCATE`` — call one function that raises unless the
transaction has explicitly asked for an exception. Application code cannot rewrite an
event, a data fix cannot, and a future retention script will have to say out loud that it
is deleting audit history: ``SET LOCAL aicore.audit_retention = '<reason>'``, which is
transaction-local and greppable. ``UPDATE`` is refused even then: no maintenance operation
needs to rewrite history, and a trail that can be edited is not evidence.

**Closed vocabularies and honest attribution, as constraints.** Event types, actor types,
resource types, decisions, outcomes and sources are all ``CHECK``-constrained to the values
this build can produce, so a row saying something the application never says cannot be
written through any path. Two ties make partial or invented attribution unrepresentable:
a ``human`` row must name both the person and the membership, and a ``system`` row must
name neither; and a ``source = 'api'`` row must carry a request id, while an internal row
must not, which is what keeps "this came from a request" a fact rather than a label. The
correlation and request identifiers are checked against the same allow-list the request
layer applies, so a value the application could not have produced cannot arrive through a
data fix either.

**No foreign keys out of the table except the tenant.** An event describes a resource that
may since have been deleted — that is the point of a trail — so asset, agent and policy
identifiers are kept as plain values, and the reference to ``organizations`` is
``ON DELETE RESTRICT`` like every other tenant-owned table: removing a tenant is an
operational procedure, never a side effect of a DELETE.

**On tamper evidence.** A hash chain is deliberately *not* implemented here, and the
reasoning is in ``docs/audit.md`` rather than in a comment: a plain SHA-256 chain stored in
the same database is recomputable by anyone who can write the table, and a chain that
looks like proof while being recomputable is worse than no chain. What this revision
implements instead is the part that is real without a key-management design — a schema that
cannot represent an edit — and the documentation states what a keyed chain would need.

Revision ID: 0007_audit_events
Revises: 0006_action_firewall
Create Date: 2026-09-24
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007_audit_events"
down_revision: str | None = "0006_action_firewall"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SCHEMA = "aicore"

# Literals, not imports from the models: a migration describes the database at one point in
# time. ``tests/test_audit.py`` compares these vocabularies with
# ``aicore_api.core.audit`` (and the model), so the copy in the database cannot drift from
# the copy in the code without a test failing.
AUDIT_EVENT_TYPES = (
    "action.denied",
    "action.executed",
    "action.failed",
    "action.replayed",
    "action.requested",
    "action.require_approval",
    "agent.deleted",
    "agent.registered",
    "agent.updated",
    "asset.created",
    "asset.deleted",
    "asset.discovered",
    "asset.updated",
    "policy.created",
    "policy.deleted",
    "policy.status_changed",
    "policy.updated",
    "policy.version_published",
)
ACTOR_TYPES = ("human", "system")
RESOURCE_TYPES = ("agent", "asset", "policy")
DECISIONS = ("allow", "deny", "require_approval")
OUTCOMES = ("blocked", "failed", "not_executed", "pending", "replayed", "success")
SOURCES = ("api", "ingestion")

SCHEMA_VERSION = 1
MAX_METADATA_BYTES = 8192
ACTION_ID_MAX_LENGTH = 64
REQUEST_ID_MAX_LENGTH = 64
REQUEST_ID_SQL_PATTERN = "^[A-Za-z0-9._:-]{1,64}$"
ACTION_SQL_PATTERN = "^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)*$"

#: Kept identical to the model's ``TABLE_COMMENT``: ``alembic check`` compares the two, so
#: a comment that drifts turns into a detected "pending migration" rather than silent
#: divergence.
AUDIT_EVENTS_TABLE_COMMENT = (
    "Append-only audit trail: one row per security-relevant event in this "
    "organization, with server-resolved attribution, the decision and outcome the "
    "platform recorded, and metadata that holds summaries rather than payloads. Not "
    "an execution ledger and not an application log."
)

#: The setting :func:`aicore_api.db.repositories.audit_events.audit_retention_override`
#: sets. Named here as a literal for the same reason every other string is: the migration
#: must describe the database even if the code that reads it changes.
RETENTION_SETTING = "aicore.audit_retention"

_APPEND_ONLY_FUNCTION = f"{SCHEMA}.audit_events_are_append_only"


def _values(values: tuple[str, ...]) -> str:
    """Render a value list as the SQL literal list a CHECK constraint expects."""
    return ", ".join(f"'{value}'" for value in values)


def _create_append_only_guard() -> None:
    """Install the trigger that makes "append-only" a property of the database.

    One function, three triggers. The row-level one covers ``UPDATE`` and ``DELETE``; the
    statement-level one covers ``TRUNCATE``, which is the other way rows disappear and which
    a row trigger never sees. Both raise, so the failure is loud at the point of the write
    rather than a hole discovered during an investigation.

    The single exception is a transaction that states, in a session setting, that it is
    deleting audit history: ``SET LOCAL aicore.audit_retention = '<reason>'``. It is
    deliberately narrow — ``DELETE`` only, transaction-local, and impossible to set
    globally through configuration — because its purpose is bounded (test fixtures must be
    able to remove an organization, and the tenant foreign key is ``RESTRICT``) and a
    retention policy is a later phase's decision, which will find the terms written here.
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
                'aicore.audit_events is append-only: % is refused', TG_OP
                USING ERRCODE = 'restrict_violation';
        END;
        $$
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER audit_events_append_only
        BEFORE UPDATE OR DELETE ON {SCHEMA}.audit_events
        FOR EACH ROW EXECUTE FUNCTION {_APPEND_ONLY_FUNCTION}()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER audit_events_append_only_truncate
        BEFORE TRUNCATE ON {SCHEMA}.audit_events
        FOR EACH STATEMENT EXECUTE FUNCTION {_APPEND_ONLY_FUNCTION}()
        """
    )


def _drop_append_only_guard() -> None:
    """Remove the guard, so the table can be dropped by a downgrade.

    Dropped before the table and, more importantly, ``DROP TABLE`` is DDL: the trigger would
    not stop it. The explicit drop is here so the downgrade leaves no function behind.
    """
    op.execute(f"DROP TRIGGER IF EXISTS audit_events_append_only ON {SCHEMA}.audit_events")
    op.execute(
        f"DROP TRIGGER IF EXISTS audit_events_append_only_truncate ON {SCHEMA}.audit_events"
    )
    op.execute(f"DROP FUNCTION IF EXISTS {_APPEND_ONLY_FUNCTION}()")


def upgrade() -> None:
    # ── The audit trail ──────────────────────────────────────────────────────
    op.create_table(
        "audit_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column(
            "schema_version",
            sa.SmallInteger(),
            server_default=sa.text(str(SCHEMA_VERSION)),
            nullable=False,
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_membership_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("agent_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("resource_type", sa.String(length=16), nullable=False),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(length=ACTION_ID_MAX_LENGTH), nullable=True),
        sa.Column("decision", sa.String(length=16), nullable=True),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("correlation_id", sa.String(length=REQUEST_ID_MAX_LENGTH), nullable=False),
        sa.Column("request_id", sa.String(length=REQUEST_ID_MAX_LENGTH), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            [f"{SCHEMA}.organizations.id"],
            name=op.f("fk_audit_events_organization_id_organizations"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
        sa.CheckConstraint(
            f"event_type IN ({_values(AUDIT_EVENT_TYPES)})",
            name=op.f("ck_audit_events_event_type_valid"),
        ),
        sa.CheckConstraint(
            f"schema_version = {SCHEMA_VERSION}",
            name=op.f("ck_audit_events_schema_version_valid"),
        ),
        sa.CheckConstraint(
            f"actor_type IN ({_values(ACTOR_TYPES)})", name=op.f("ck_audit_events_actor_type_valid")
        ),
        sa.CheckConstraint(
            f"resource_type IN ({_values(RESOURCE_TYPES)})",
            name=op.f("ck_audit_events_resource_type_valid"),
        ),
        sa.CheckConstraint(
            f"decision IS NULL OR decision IN ({_values(DECISIONS)})",
            name=op.f("ck_audit_events_decision_valid"),
        ),
        sa.CheckConstraint(
            f"outcome IN ({_values(OUTCOMES)})", name=op.f("ck_audit_events_outcome_valid")
        ),
        sa.CheckConstraint(
            f"source IN ({_values(SOURCES)})", name=op.f("ck_audit_events_source_valid")
        ),
        sa.CheckConstraint(
            "(actor_type = 'human') = (actor_id IS NOT NULL)",
            name=op.f("ck_audit_events_actor_named"),
        ),
        sa.CheckConstraint(
            "(actor_type = 'human') = (actor_membership_id IS NOT NULL)",
            name=op.f("ck_audit_events_actor_membership_named"),
        ),
        sa.CheckConstraint(
            "(source = 'api') = (request_id IS NOT NULL)",
            name=op.f("ck_audit_events_source_request_consistent"),
        ),
        sa.CheckConstraint(
            "(outcome = 'pending') = (event_type = 'action.requested')",
            name=op.f("ck_audit_events_pending_consistent"),
        ),
        sa.CheckConstraint(
            f"action IS NULL OR action ~ '{ACTION_SQL_PATTERN}'",
            name=op.f("ck_audit_events_action_shape"),
        ),
        sa.CheckConstraint(
            f"correlation_id ~ '{REQUEST_ID_SQL_PATTERN}'",
            name=op.f("ck_audit_events_correlation_id_shape"),
        ),
        sa.CheckConstraint(
            f"request_id IS NULL OR request_id ~ '{REQUEST_ID_SQL_PATTERN}'",
            name=op.f("ck_audit_events_request_id_shape"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(metadata) = 'object'", name=op.f("ck_audit_events_metadata_is_object")
        ),
        sa.CheckConstraint(
            f"length(metadata::text) <= {MAX_METADATA_BYTES}",
            name=op.f("ck_audit_events_metadata_bounded"),
        ),
        schema=SCHEMA,
        comment=AUDIT_EVENTS_TABLE_COMMENT,
    )

    # The tenant boundary index every tenant-owned table carries, then the five that match
    # the query filters the endpoint exposes. Each one answers a question an investigator
    # actually asks; none of them is speculative, and none is a duplicate of another.
    op.create_index(
        op.f("ix_audit_events_organization_id"),
        "audit_events",
        ["organization_id"],
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_audit_events_organization_id_occurred_at_id"),
        "audit_events",
        ["organization_id", "occurred_at", "id"],
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_audit_events_organization_id_event_type_occurred_at"),
        "audit_events",
        ["organization_id", "event_type", "occurred_at"],
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_audit_events_organization_id_actor_id_occurred_at"),
        "audit_events",
        ["organization_id", "actor_id", "occurred_at"],
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_audit_events_organization_id_correlation_id"),
        "audit_events",
        ["organization_id", "correlation_id"],
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_audit_events_organization_id_resource_type_resource_id"),
        "audit_events",
        ["organization_id", "resource_type", "resource_id"],
        schema=SCHEMA,
    )

    _create_append_only_guard()


def downgrade() -> None:
    # The guard goes first: dropping the table would leave the function behind, and a
    # function that raises on writes to a table nobody has is a leftover, not a control.
    _drop_append_only_guard()

    for name in (
        "ix_audit_events_organization_id_resource_type_resource_id",
        "ix_audit_events_organization_id_correlation_id",
        "ix_audit_events_organization_id_actor_id_occurred_at",
        "ix_audit_events_organization_id_event_type_occurred_at",
        "ix_audit_events_organization_id_occurred_at_id",
        "ix_audit_events_organization_id",
    ):
        op.drop_index(op.f(name), table_name="audit_events", schema=SCHEMA)

    # The rows go with the table. Unlike Phase 7's ledger there is nothing to refuse here:
    # a downgrade ends the revision that can read or write the trail, and the alternative —
    # leaving the table behind — would leave a table no revision owns. An operator who
    # needs the history takes a dump first, which is stated in docs/audit.md.
    op.drop_table("audit_events", schema=SCHEMA)
