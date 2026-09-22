"""API token repository.

Issuing a token is the only moment the plaintext exists. :meth:`ApiTokenRepository.issue`
returns it to the caller and stores only the hash and prefix, so there is no
code path — not even an administrative one — that can read a credential back out
of the database.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from aicore_api.auth.tokens import generate_token, hash_token
from aicore_api.db.models.api_token import ApiToken

__all__ = ["ApiTokenRepository"]


class ApiTokenRepository:
    """Persistence for bearer credentials."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def issue(
        self,
        *,
        user_id: uuid.UUID,
        name: str,
        expires_at: datetime | None = None,
    ) -> tuple[str, ApiToken]:
        """Mint a token for ``user_id``.

        Returns ``(plaintext, row)``. The plaintext is the caller's to show once;
        this method does not log it, and nothing stores it.
        """
        plaintext, prefix, digest = generate_token()
        token = ApiToken(
            user_id=user_id,
            name=name.strip(),
            token_hash=digest,
            token_prefix=prefix,
            expires_at=expires_at,
        )
        self._session.add(token)
        self._session.commit()
        self._session.refresh(token)
        return plaintext, token

    def find_by_hash(self, digest: str) -> ApiToken | None:
        """Look a credential up by its hash. Called with ``hash_token(value)``."""
        return self._session.execute(
            select(ApiToken).where(ApiToken.token_hash == digest)
        ).scalar_one_or_none()

    def find(self, token_id: uuid.UUID) -> ApiToken | None:
        return self._session.get(ApiToken, token_id)

    def list_for_user(self, user_id: uuid.UUID) -> list[ApiToken]:
        """Every credential belonging to a user, newest first."""
        return list(
            self._session.execute(
                select(ApiToken).where(ApiToken.user_id == user_id).order_by(ApiToken.created_at)
            )
            .scalars()
            .all()
        )

    def revoke(self, token: ApiToken) -> ApiToken:
        """Mark a credential unusable, keeping the record.

        A timestamp rather than a DELETE: "this credential existed and was
        revoked at T" is information worth keeping, and deleting the row would
        hide the credential's history without improving security.
        """
        if token.revoked_at is None:
            token.revoked_at = datetime.now(UTC)
            self._session.commit()
            self._session.refresh(token)
        return token

    @staticmethod
    def hash(value: str) -> str:
        """The digest used for lookup, exposed so callers never hand a raw token to a query."""
        return hash_token(value)
