"""API tokens: the Phase 2 authentication mechanism.

Design notes that matter for security:

- **Only a hash is stored.** The plaintext token exists once, in the response of
  the command that issued it, and never in the database, a log or this
  repository. A leaked database therefore leaks no usable credential.
- **The token is not a password.** It is 256 bits of CSPRNG output, so there is
  nothing to guess and no need for a slow password hash: SHA-256 over a
  256-bit random value cannot be brute-forced. (There is no password anywhere in
  AICore; human sign-in arrives with an external identity provider in a later
  phase, where the provider — not this application — holds the credential.)
- **Tokens belong to a user, not to a tenant.** A token authenticates *who* is
  calling; *what* they may do comes from their memberships. That is why this
  table is global rather than tenant-owned: it carries no tenant data, and
  revoking it can never affect another organization's access.
- **Lifecycle is explicit:** a token can expire, be revoked, or die with its
  user (CASCADE). Revocation is a timestamp, not a delete, so the record of what
  existed survives.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from aicore_api.db.base import APP_SCHEMA, Base, TimestampMixin, UUIDPrimaryKeyMixin

NAME_MAX_LENGTH = 100
TOKEN_HASH_LENGTH = 64  # SHA-256, hex encoded
TOKEN_PREFIX_MAX_LENGTH = 16

TABLE_COMMENT = (
    "API tokens for machine and developer access. Only a SHA-256 hash of the token "
    "is stored; the plaintext exists once, when it is issued. Tokens authenticate a "
    "user; authorization comes from their memberships."
)


class ApiToken(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A bearer credential belonging to one user."""

    __tablename__ = "api_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey(f"{APP_SCHEMA}.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(NAME_MAX_LENGTH), nullable=False)

    #: Unique so authentication is a single indexed lookup by hash. The hash is
    #: only ever compared by equality — never rendered into a response or a log.
    token_hash: Mapped[str] = mapped_column(String(TOKEN_HASH_LENGTH), nullable=False)

    #: The first characters of the token, for identifying which credential is
    #: which in a listing ("aicore_9f2c…"). Too short to be usable, long enough
    #: to be useful to a human.
    token_prefix: Mapped[str] = mapped_column(String(TOKEN_PREFIX_MAX_LENGTH), nullable=False)

    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("token_hash"),
        CheckConstraint(f"char_length(token_hash) = {TOKEN_HASH_LENGTH}", name="token_hash_length"),
        CheckConstraint(
            f"char_length(btrim(name)) BETWEEN 1 AND {NAME_MAX_LENGTH}", name="name_length"
        ),
        {"comment": TABLE_COMMENT},
    )

    def __repr__(self) -> str:
        """The prefix identifies the token; the hash never appears."""
        return f"<ApiToken id={self.id} prefix={self.token_prefix!r} user_id={self.user_id}>"


__all__ = ["NAME_MAX_LENGTH", "ApiToken"]
