"""User repository.

``users`` is global (see the model docstring), so this repository is *not*
tenant-scoped: it holds identity, not tenant data. Nothing here may be used to
decide what a caller can see — membership resolution does that, and it goes
through :class:`aicore_api.db.repositories.memberships.MembershipRepository`.

Creating a user is a provisioning action (the CLI, a future SCIM importer, a
test), which is why it lives here rather than behind an HTTP route: Phase 2 has
no user-management API.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aicore_api.core.domain_errors import ConflictError
from aicore_api.db.models.user import User, UserStatus, normalize_email

__all__ = ["UserRepository"]


class UserRepository:
    """Reads and writes to the identity table."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create(
        self,
        *,
        email: str,
        full_name: str,
        status: UserStatus = UserStatus.ACTIVE,
    ) -> User:
        """Create an identity.

        The address is normalised here and the database enforces that it stayed
        normalised (``ck_users_email_normalized``), so "same address, different
        case" cannot become two accounts with separate grants.
        """
        user = User(email=normalize_email(email), full_name=full_name.strip(), status=status.value)
        self._session.add(user)
        try:
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise ConflictError("a user with that email address already exists") from exc
        self._session.commit()
        self._session.refresh(user)
        return user

    def get(self, user_id: uuid.UUID) -> User | None:
        """Load a user by id; ``None`` when absent."""
        return self._session.get(User, user_id)

    def find_by_email(self, email: str) -> User | None:
        """Look a user up by normalised address; ``None`` when absent."""
        return self._session.execute(
            select(User).where(User.email == normalize_email(email))
        ).scalar_one_or_none()

    def get_many(self, user_ids: Iterable[uuid.UUID]) -> Sequence[User]:
        """Load several users at once (used to render a member directory)."""
        identifiers = list(user_ids)
        if not identifiers:
            return []
        return self._session.execute(select(User).where(User.id.in_(identifiers))).scalars().all()
