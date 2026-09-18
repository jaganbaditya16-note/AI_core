"""Organizations: the tenant root.

An organization *is* the tenant — it is the one table in the schema that is not
tenant-owned, because it defines the tenant. Everything AICore stores later
(agents, models, tools, data sources, policies, events, incidents) hangs off it
through :class:`aicore_api.db.base.TenantOwnedMixin` and carries its
``organization_id``.

Phase 1 intentionally stops here: no agent/model/tool/policy table exists yet.
What exists is the boundary those tables will inherit.
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import CheckConstraint, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from aicore_api.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

#: Maximum lengths, enforced in the database as well as at the API boundary.
NAME_MAX_LENGTH = 200
SLUG_MAX_LENGTH = 63
STATUS_MAX_LENGTH = 32


class OrganizationStatus(StrEnum):
    """Lifecycle of a tenant.

    Stored as ``VARCHAR`` + ``CHECK`` rather than a PostgreSQL ``ENUM`` type:
    adding or renaming a state is an ordinary, transactional migration instead
    of ``ALTER TYPE`` (which cannot be used in the same transaction that
    consumes the new value). The allowed set stays enforced by the database.
    """

    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


#: A slug is what appears in URLs, config and support tickets, so its shape is
#: constrained: lowercase alphanumeric groups separated by single hyphens.
SLUG_PATTERN = r"^[a-z0-9]+(-[a-z0-9]+)*$"

TABLE_COMMENT = (
    "AICore tenant root. Every tenant-owned table carries a foreign key to this "
    "table; deleting a row is RESTRICTed while such rows exist."
)

_STATUS_CHECK = "status IN ({})".format(
    ", ".join(f"'{status.value}'" for status in OrganizationStatus)
)


class Organization(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A tenant. Globally unique by :attr:`slug`."""

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(NAME_MAX_LENGTH), nullable=False)
    slug: Mapped[str] = mapped_column(String(SLUG_MAX_LENGTH), nullable=False)
    status: Mapped[str] = mapped_column(
        String(STATUS_MAX_LENGTH),
        nullable=False,
        server_default=OrganizationStatus.ACTIVE.value,
    )

    __table_args__ = (
        # No explicit name: the naming convention renders this as
        # `uq_organizations_slug`. An explicit name would *override* the
        # convention and quietly disagree with the migration.
        UniqueConstraint("slug"),
        CheckConstraint(
            f"char_length(btrim(name)) BETWEEN 1 AND {NAME_MAX_LENGTH}",
            name="name_length",
        ),
        CheckConstraint(f"slug ~ '{SLUG_PATTERN}'", name="slug_format"),
        CheckConstraint(_STATUS_CHECK, name="status_valid"),
        # Declared so the schema the models describe is exactly the schema the
        # migration created (`COMMENT ON TABLE`), leaving no diff for autogenerate.
        {"comment": TABLE_COMMENT},
    )

    def __repr__(self) -> str:
        """Identifiers only — names and slugs are tenant data and stay out of logs."""
        return f"<Organization id={self.id} status={self.status!r}>"
