"""Users: the identity half of authentication.

A user is **global**, not tenant-owned — deliberately. Identity is a property of
a person (or a service account), and the same person can belong to several
organizations in the same installation. What is tenant-owned is the *membership*
(:mod:`aicore_api.db.models.membership`), which is what grants access inside one
organization.

That split is a security property, not a data-modelling preference: reading this
table tells you who exists, never what anyone may do. Every tenant-visible path
to a user goes through a membership, and the isolation guard does not protect
this table precisely because it holds no tenant data. See
``docs/authentication.md``.

No password, no password hash and no credential of any kind is stored here.
Authentication is by API token or, in a later phase, by an external identity
provider; there is nothing to leak from this row.
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import CheckConstraint, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from aicore_api.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

#: RFC 5321 caps an address at 320 characters (64 local part + @ + 255 domain).
EMAIL_MAX_LENGTH = 320
FULL_NAME_MAX_LENGTH = 200
STATUS_MAX_LENGTH = 32

#: Deliberately permissive. The API validates addresses properly (Pydantic);
#: this is the database's last-line sanity check against a row that is obviously
#: not an address at all.
EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


class UserStatus(StrEnum):
    """Lifecycle of an identity.

    ``suspended`` authenticates **nothing**: the authentication layer refuses a
    suspended user's credentials, so suspending an identity is how access is cut
    off without deleting the rows that record who did what.
    """

    ACTIVE = "active"
    SUSPENDED = "suspended"


_STATUS_CHECK = "status IN ({})".format(", ".join(f"'{status.value}'" for status in UserStatus))

TABLE_COMMENT = (
    "AICore identity. Global on purpose: a user may belong to several "
    "organizations; tenant visibility comes from memberships, never from this "
    "table. Holds no credential of any kind."
)


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A person or service account that can be granted memberships."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(EMAIL_MAX_LENGTH), nullable=False)
    full_name: Mapped[str] = mapped_column(String(FULL_NAME_MAX_LENGTH), nullable=False)
    status: Mapped[str] = mapped_column(
        String(STATUS_MAX_LENGTH),
        nullable=False,
        server_default=UserStatus.ACTIVE.value,
    )

    __table_args__ = (
        # Stored normalised, and the database enforces it: two rows that differ
        # only in case or padding would otherwise be two accounts for one person,
        # with two independent sets of grants.
        UniqueConstraint("email"),
        CheckConstraint("email = lower(btrim(email))", name="email_normalized"),
        CheckConstraint(f"email ~ '{EMAIL_PATTERN}'", name="email_format"),
        CheckConstraint(
            f"char_length(btrim(full_name)) BETWEEN 1 AND {FULL_NAME_MAX_LENGTH}",
            name="full_name_length",
        ),
        CheckConstraint(_STATUS_CHECK, name="status_valid"),
        {"comment": TABLE_COMMENT},
    )

    def __repr__(self) -> str:
        """Identifiers only: an address is personal data and stays out of logs."""
        return f"<User id={self.id} status={self.status!r}>"


def normalize_email(email: str) -> str:
    """The one canonical form of an address, applied before it reaches the database.

    Keeping this next to the model means the API, the CLI and any future
    importer normalise identically, and the ``email_normalized`` CHECK refuses
    anything that skipped this function.
    """
    return email.strip().lower()


__all__ = [
    "EMAIL_MAX_LENGTH",
    "FULL_NAME_MAX_LENGTH",
    "User",
    "UserStatus",
    "normalize_email",
]
