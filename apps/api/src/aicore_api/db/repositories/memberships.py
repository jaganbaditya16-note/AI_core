"""Membership repository — the grant table, and the one cross-tenant read.

Two shapes live here, and the difference between them is the point:

- :class:`MembershipRepository` is an
  :class:`~aicore_api.db.repositories.organizations.OrganizationScopedRepository`.
  It cannot be constructed without an organization, and every query it builds is
  filtered to that organization by the base class. This is how the API reaches a
  member directory or a caller's own membership inside one tenant.
- :func:`memberships_for_user` answers the one question that is cross-tenant by
  nature: *which organizations does this person belong to?* It filters on the
  authenticated user's id — never on anything from the request — and takes the
  tenancy guard's single documented escape
  (:func:`aicore_api.db.tenancy.cross_tenant_read`), so this file is where "can
  see across tenants" is reviewed.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aicore_api.core.domain_errors import ConflictError, InvalidReferenceError
from aicore_api.db.models.membership import Membership, MembershipStatus
from aicore_api.db.models.organization import Organization
from aicore_api.db.repositories.organizations import OrganizationScopedRepository
from aicore_api.db.repositories.rbac import RoleCatalog
from aicore_api.db.tenancy import cross_tenant_read

__all__ = ["MembershipRepository", "memberships_for_user"]


class MembershipRepository(OrganizationScopedRepository):
    """Memberships of exactly one organization."""

    def add_member(
        self,
        *,
        user_id: uuid.UUID,
        role_code: str,
        status: MembershipStatus = MembershipStatus.ACTIVE,
    ) -> Membership:
        """Grant ``user_id`` a role in this repository's organization.

        Integrity errors are translated by constraint name, so "that person is
        already a member" and "there is no such user" are distinguishable to the
        caller (the database still decides, so there is no check-then-act race).
        """
        role = RoleCatalog(self.session).get_by_code(role_code)
        membership = Membership(
            organization_id=self.organization_id,
            user_id=user_id,
            role_id=role.id,
            status=status.value,
        )
        with self.writing():
            self.session.add(membership)
            try:
                self.session.flush()
            except IntegrityError as exc:
                self.session.rollback()
                raise _translate_integrity_error(exc) from exc
            self.session.commit()
            self.session.refresh(membership)
        return membership

    def find_for_user(self, user_id: uuid.UUID) -> Membership | None:
        """This user's membership in this organization, or ``None``.

        ``None`` is the non-member case, and callers must turn it into the same
        404 an unknown organization produces — see
        :func:`aicore_api.auth.authorization.resolve_organization_context`.
        """
        statement = self._scoped(Membership).where(Membership.user_id == user_id)
        return self.execute(statement).scalars().unique().one_or_none()

    def list_members(self) -> list[Membership]:
        """Every member of this organization, oldest membership first.

        Users and roles are loaded with the rows (``lazy="joined"`` on the
        model), so rendering the directory is a single tenant-scoped query — no
        per-member lookup that could drift outside the tenant filter.
        """
        statement = self._scoped(Membership).order_by(Membership.created_at)
        return list(self.execute(statement).scalars().unique().all())

    def count(self) -> int:
        """How many memberships this organization has."""
        statement = self._scoped(func.count()).select_from(Membership)
        return int(self.execute(statement).scalar_one())


def memberships_for_user(
    session: Session, user_id: uuid.UUID
) -> list[tuple[Membership, Organization]]:
    """Every organization ``user_id`` belongs to, with the membership that says so.

    The tenancy guard is escaped deliberately and narrowly here: the filter is the
    authenticated user's own id, and ``user_id`` must come from the principal that
    was just authenticated — never from a request parameter, a header or a body
    field. Passing anything else here would turn this function into a
    cross-tenant disclosure.
    """
    statement = (
        select(Membership, Organization)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(Membership.user_id == user_id)
        .order_by(Organization.slug)
    )
    with cross_tenant_read("a user's own memberships across organizations"):
        rows = session.execute(statement).all()
    return [(row[0], row[1]) for row in rows]


def _translate_integrity_error(exc: IntegrityError) -> Exception:
    """Turn a constraint violation into the domain error it means."""
    constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
    if constraint == "uq_memberships_organization_id_user_id":
        return ConflictError("that user is already a member of this organization")
    if constraint == "fk_memberships_user_id_users":
        return InvalidReferenceError("no such user")
    return ConflictError("the membership could not be created")
