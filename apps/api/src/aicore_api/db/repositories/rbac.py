"""The role and permission catalog, read from the database.

Authorization resolves against **these** rows, not against
:mod:`aicore_api.core.permissions`: the catalog in code describes what the
application is prepared to enforce, while the database records what a deployment
actually grants. They are kept identical by the migration seed and asserted
equal by ``tests/test_migrations.py`` — and the resolver refuses to guess if a
role in the database is unknown to the code.

Both tables are reference data (not tenant-owned), so these reads are unscoped by
design: reading the catalog reveals what roles *exist*, never who holds one.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from aicore_api.core.domain_errors import NotFoundError
from aicore_api.db.models.rbac import Permission, Role

__all__ = ["RoleCatalog"]


class RoleCatalog:
    """Read access to the role and permission catalogs."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_by_code(self, code: str) -> Role:
        """Load a role by its code, or raise :class:`NotFoundError`."""
        role = self._session.execute(select(Role).where(Role.code == code)).scalar_one_or_none()
        if role is None:
            raise NotFoundError(f"role {code!r} is not part of the catalog")
        return role

    def list_roles(self) -> list[Role]:
        """Every role, ordered by code, with the permissions each one grants."""
        return list(self._session.execute(select(Role).order_by(Role.code)).scalars().all())

    def list_permissions(self) -> list[Permission]:
        """Every permission, ordered by code."""
        return list(
            self._session.execute(select(Permission).order_by(Permission.code)).scalars().all()
        )

    def grants_by_role_code(self) -> dict[str, set[str]]:
        """The seeded policy, as ``{role code: {permission code, …}}``.

        This is the shape the migration seeds and the shape the code catalog
        declares, so comparing the two is a direct drift check.
        """
        return {
            role.code: {permission.code for permission in role.grants} for role in self.list_roles()
        }
