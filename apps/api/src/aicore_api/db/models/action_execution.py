"""The idempotency ledger: one row per admitted action, keyed by the caller's key.

This table exists for exactly one purpose, and the schema says so: a client that
retries a request whose answer it never saw must get the same answer, not a second
execution. The key is the caller's, unique per organization, and the row records what
the admitted run reported.

**It is not an audit trail, and must not grow into one.** There is no actor, no
rationale, no role, no decision history and no row for a refusal — an action that was
denied or that required approval leaves nothing here, because nothing happened. What
happened, for whom, whether it was allowed and what it changed is the audit system
Phase 8 owns; adding any of it here would be building that system in a table named
after a different problem.

Two shapes are enforced here rather than by convention, because a ledger that can hold
an impossible row is a ledger whose answers cannot be trusted:

- **completed means frozen.** ``status`` and the columns that accompany it are tied
  together by ``CHECK`` constraints: ``reserved`` has no outcome and no completion
  time, ``executed`` has an outcome and no error, ``failed`` has an error and no
  outcome. A row cannot claim to have run something and be missing the record of it.
- **the key is opaque and bounded.** The identifier and fingerprint columns are
  validated by ``CHECK`` against the same shapes the application uses, so a value that
  the application would refuse cannot arrive through a migration or a data fix either.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column

from aicore_api.core.actions import (
    ACTION_ID_MAX_LENGTH,
    IDEMPOTENCY_KEY_MAX_LENGTH,
    ExecutionStatus,
)
from aicore_api.db.base import Base, TenantOwnedMixin, UUIDPrimaryKeyMixin

TABLE_COMMENT = (
    "Idempotency ledger for admitted actions: one row per idempotency key per "
    "organization, holding the recorded outcome so a retry returns it instead of "
    "executing again. Not an audit trail: no actor, no refusals, no decision history."
)

#: The fingerprint is a SHA-256 hex digest, so it is exactly 64 characters of hex.
FINGERPRINT_LENGTH = 64

#: Bounded so a defect cannot fill a log or a response with an unbounded code.
ERROR_CODE_MAX_LENGTH = 64

#: The same allow-list the request layer applies (``core.actions.IDEMPOTENCY_KEY_PATTERN``),
#: expressed as a SQL regular expression: the database refuses a key the application
#: would refuse, whatever path wrote it.
IDEMPOTENCY_KEY_SQL_PATTERN = "^[A-Za-z0-9._:-]{1,128}$"


def _status_values() -> str:
    """The ledger's states, as the literal list a ``CHECK`` constraint wants."""
    return ", ".join(f"'{status.value}'" for status in ExecutionStatus)


class ActionExecution(UUIDPrimaryKeyMixin, TenantOwnedMixin, Base):
    """One admitted execution of one registered action."""

    __tablename__ = "action_executions"

    #: The caller's idempotency key. Opaque: stored, compared and echoed, never
    #: interpreted, and never used to build a query or a path.
    idempotency_key: Mapped[str] = mapped_column(String(IDEMPOTENCY_KEY_MAX_LENGTH), nullable=False)

    #: Which registered action ran. The identifier is from this build's closed
    #: catalogue rather than free text, and it is the action's name — not a module, not
    #: a function and not anything that could be resolved into code.
    action_id: Mapped[str] = mapped_column(String(ACTION_ID_MAX_LENGTH), nullable=False)

    #: The row the action addressed. A bare identifier rather than a foreign key: the
    #: ledger must survive the target's deletion, or a retry after the row is gone would
    #: execute the action a second time.
    target_id: Mapped[uuid.UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), nullable=False)

    #: A digest of what the request asked for, so a key reused for a *different*
    #: request is refused instead of answered with someone else's result.
    request_fingerprint: Mapped[str] = mapped_column(String(FINGERPRINT_LENGTH), nullable=False)

    #: ``reserved`` / ``executed`` / ``failed``. See the module docstring: the states
    #: and the columns that accompany them are tied together by constraint.
    status: Mapped[str] = mapped_column(String(16), nullable=False)

    #: What the adapter reported, when it finished. ``NULL`` while reserved or failed.
    outcome: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True), nullable=True)

    #: A stable code for a failure, when the adapter was reached and did not finish.
    #: A code, never a message: nothing an adapter saw or a client sent is stored here.
    error_code: Mapped[str | None] = mapped_column(String(ERROR_CODE_MAX_LENGTH), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    #: When the reservation reached its end. ``NULL`` means the action has not run —
    #: the state a request that claimed the key and never finished leaves behind, which
    #: is what stops a retry from running it twice.
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # One row per key per organization: this constraint *is* the idempotency
        # guarantee. Two concurrent requests cannot both proceed, and no lock or
        # coordination is involved — the database's uniqueness is the arbiter.
        UniqueConstraint("organization_id", "idempotency_key"),
        CheckConstraint(f"status IN ({_status_values()})", name="status_valid"),
        CheckConstraint("char_length(request_fingerprint) = 64", name="fingerprint_length"),
        CheckConstraint(
            f"idempotency_key ~ '{IDEMPOTENCY_KEY_SQL_PATTERN}'",
            name="idempotency_key_shape",
        ),
        # The three ties that make an impossible row unrepresentable: a reservation has
        # not completed, an execution has an outcome and no error, a failure has an
        # error and no outcome. Each is written as an equality between two states of
        # *one* column, so a status this build does not know fails the constraint rather
        # than passing by default.
        CheckConstraint(
            "(status = 'reserved') = (completed_at IS NULL)", name="completion_consistent"
        ),
        CheckConstraint("(status = 'executed') = (outcome IS NOT NULL)", name="outcome_consistent"),
        CheckConstraint("(status = 'failed') = (error_code IS NOT NULL)", name="error_consistent"),
        {"comment": TABLE_COMMENT},
    )

    def __repr__(self) -> str:
        """Identify the row without rendering the outcome it holds."""
        return (
            f"<ActionExecution {str(self.id)!s} action={self.action_id!r} status={self.status!r}>"
        )
