"""The idempotency ledger's repository: claim a key, record an outcome, answer a retry.

Three operations, and each of them exists because of a way an execution path can
double-run or lie:

- :meth:`ActionExecutionRepository.find_by_key` answers "has this key been used in this
  organization?" — the read that lets a retry be answered instead of re-run;
- :meth:`ActionExecutionRepository.reserve` *claims* the key with an INSERT guarded by
  the ``uq_action_executions_organization_id_idempotency_key`` constraint. Two
  concurrent requests carrying one key cannot both proceed, and nothing here coordinates
  that: the database's uniqueness is the arbiter, which is why there is no lock, no
  lease and no distributed anything in this phase;
- :meth:`ActionExecutionRepository.record_outcome` writes the ending — the reported
  outcome, or the code of a failure — and nothing else. A reserved row that is never
  completed stays incomplete on purpose: a retry must not re-run an action whose
  effects are unknown.

The repository is tenant-scoped like every other one, so a key belonging to another
organization is indistinguishable from a key nobody has used. That is not a detail: an
idempotency key is chosen by the client, and a shared keyspace between tenants would
let one tenant's retry see — or collide with — another's.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from sqlalchemy.exc import IntegrityError

from aicore_api.core.execution import (
    ExecutionRecord,
    ExecutionStatus,
    IdempotencyConflictError,
)
from aicore_api.db.models.action_execution import ActionExecution
from aicore_api.db.repositories.organizations import OrganizationScopedRepository

__all__ = ["ActionExecutionRepository"]


def _record(row: ActionExecution) -> ExecutionRecord:
    """Read a row into the service's value type.

    An explicit conversion rather than returning the ORM object: the execution service
    is not a database client, and handing it a live, mutable row would make it possible
    for it to change one by accident.
    """
    return ExecutionRecord(
        id=row.id,
        organization_id=row.organization_id,
        idempotency_key=row.idempotency_key,
        action_id=row.action_id,
        target_id=row.target_id,
        request_fingerprint=row.request_fingerprint,
        status=ExecutionStatus(row.status),
        outcome=None if row.outcome is None else dict(row.outcome),
        error_code=row.error_code,
        created_at=row.created_at,
        completed_at=row.completed_at,
    )


class ActionExecutionRepository(OrganizationScopedRepository):
    """The idempotency ledger for one organization."""

    def find_by_key(self, idempotency_key: str) -> ExecutionRecord | None:
        """The record that holds ``idempotency_key`` here, if any.

        Filtered by the tenant *and* the key: the unique constraint is per organization,
        so a lookup that named only the key would be a cross-tenant read.
        """
        row = self.execute(
            self._scoped(ActionExecution).where(ActionExecution.idempotency_key == idempotency_key)
        ).scalar_one_or_none()
        return None if row is None else _record(row)

    def reserve(
        self,
        *,
        idempotency_key: str,
        action_id: str,
        target_id: uuid.UUID,
        request_fingerprint: str,
    ) -> ExecutionRecord:
        """Claim ``idempotency_key`` for this request, or refuse because it is taken.

        The refusal is a :class:`~aicore_api.core.execution.IdempotencyConflictError`
        rather than a retry: the caller of this method is the execution service, which
        has already looked the key up and decided this is a new request. Reaching the
        constraint therefore means another request claimed the key in between — a race
        — and the honest answer to a race is "not now", not "run it anyway".
        """
        row = ActionExecution(
            organization_id=self.organization_id,
            idempotency_key=idempotency_key,
            action_id=action_id,
            target_id=target_id,
            request_fingerprint=request_fingerprint,
            status=ExecutionStatus.RESERVED.value,
        )
        try:
            with self.writing():
                self.session.add(row)
                self.session.flush()
                self.session.commit()
        except IntegrityError as exc:
            # The session is unusable until it is rolled back, and nothing else in this
            # request has pending writes: the execution service reads, decides and
            # evaluates before it ever reaches this point.
            self.session.rollback()
            raise IdempotencyConflictError(
                "another request with this idempotency key is already in progress; use a new key"
            ) from exc
        row = self._reload(row)
        return _record(row)

    def record_outcome(
        self,
        record: ExecutionRecord,
        *,
        status: ExecutionStatus,
        outcome: Mapping[str, Any] | None,
        error_code: str | None,
        completed_at: datetime,
    ) -> ExecutionRecord:
        """Write the ending of a reserved execution and hand back the stored row.

        ``reserved`` is refused here: a reservation is created by :meth:`reserve`, and
        letting this method write one would be a second way to claim a key.
        """
        if status is ExecutionStatus.RESERVED:
            raise ValueError("a reservation is created by reserve(), not recorded afterwards")
        with self.writing():
            row = self.session.get(ActionExecution, record.id)
            if row is None:  # pragma: no cover - the row was inserted moments ago
                raise IdempotencyConflictError(
                    "the reservation for this idempotency key disappeared while it was running"
                )
            row.status = status.value
            row.outcome = None if outcome is None else dict(outcome)
            row.error_code = error_code
            row.completed_at = completed_at
            self.session.flush()
            self.session.commit()
        row = self._reload(row)
        return _record(row)

    def _reload(self, row: ActionExecution) -> ActionExecution:
        """Re-read a row the database finished writing. Freshness is not optional here.

        ``created_at`` is a server default and the row was flushed — not refreshed —
        before the commit, so the values the caller gets back must come from the
        database rather than from the identity map. The refresh is a statement against
        a tenant-owned table like any other, so it is issued with the tenant bound;
        reading it back unscoped would be refused by the same guard that keeps every
        other query inside its organization.
        """
        with self.writing():
            self.session.refresh(row)
        return row
