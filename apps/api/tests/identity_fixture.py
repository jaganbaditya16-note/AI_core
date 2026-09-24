"""Real identities for tests: a user, a tenant, a membership and a live token.

Phase 2's tests have to prove things about authenticated HTTP requests, which
means they need credentials that actually work. There is no test-only
authentication shortcut to provide them — a test that authenticated differently
from production would prove nothing about production — so this module provisions
identities the way an operator does: through the repositories, against the real
PostgreSQL that ``scripts/test-db.sh`` starts, subject to the same constraints.

Everything here is *committed*, on purpose. The application under test runs in its
own session and can only see committed rows, which is what makes a request through
``TestClient`` a genuine end-to-end exercise rather than a mock. ``purge_identity``
puts the database back, in foreign-key order, so the suite leaves no residue.

These helpers use ``aicore_api``'s own repositories to set the scene, but nothing
here is what the tests assert: the tests make HTTP requests and read responses. A
bug in the repositories fails the assertions; it cannot quietly satisfy them.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from sqlalchemy import Engine, delete, select, update
from sqlalchemy.orm import Session, sessionmaker

from aicore_api.db.models.api_token import ApiToken
from aicore_api.db.models.asset import Asset
from aicore_api.db.models.audit_event import AuditEvent
from aicore_api.db.models.membership import Membership, MembershipStatus
from aicore_api.db.models.organization import Organization
from aicore_api.db.models.policy import Policy
from aicore_api.db.models.user import User, UserStatus
from aicore_api.db.repositories.api_tokens import ApiTokenRepository
from aicore_api.db.repositories.audit_events import audit_retention_override
from aicore_api.db.repositories.memberships import MembershipRepository
from aicore_api.db.repositories.organizations import OrganizationRepository
from aicore_api.db.repositories.users import UserRepository
from aicore_api.db.tenancy import bind_tenant

__all__ = [
    "Identity",
    "IdentityFactory",
    "expire_token",
    "find_identity",
    "join_organization",
    "provision_identity",
    "purge_identities",
    "purge_identity",
    "revoke_token",
    "suspend_membership",
    "suspend_user",
]


@dataclass(frozen=True, slots=True)
class Identity:
    """A provisioned person: their credentials, and everything they were granted."""

    user_id: uuid.UUID
    email: str
    organization_id: uuid.UUID
    organization_slug: str
    role_code: str
    membership_id: uuid.UUID
    token_id: uuid.UUID
    #: The only copy of the plaintext credential; the database stores its hash.
    token: str
    #: Whether this call created the organization, and must therefore remove it.
    owns_organization: bool
    #: Further ``(organization, membership)`` pairs, when one person belongs to
    #: more than one tenant. See :func:`join_organization`.
    extra_memberships: tuple[tuple[uuid.UUID, uuid.UUID], ...] = ()

    def memberships(self) -> tuple[tuple[uuid.UUID, uuid.UUID], ...]:
        """Every ``(organization, membership)`` pair this identity holds."""
        return ((self.organization_id, self.membership_id), *self.extra_memberships)


@contextmanager
def _session(engine: Engine) -> Iterator[Session]:
    """A committed session per call: fixtures are visible outside the transaction."""
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as session:
        try:
            yield session
        finally:
            session.close()


def provision_identity(
    engine: Engine,
    *,
    role_code: str = "owner",
    email: str | None = None,
    full_name: str = "Test Person",
    organization_id: uuid.UUID | None = None,
    organization_name: str | None = None,
    membership_status: MembershipStatus = MembershipStatus.ACTIVE,
    token_expires_in: timedelta | None = None,
) -> Identity:
    """Create a committed user with a membership, a role and a bearer token.

    Pass ``organization_id`` to place a second person inside an organization that
    already exists — a directory needs more than one member, and a cross-tenant
    test needs someone who belongs somewhere else. Only the call that created an
    organization purges it.
    """
    suffix = uuid.uuid4().hex[:8]
    email = email or f"person-{suffix}@example.test"

    with _session(engine) as session:
        if organization_id is None:
            name = organization_name or f"Tenant {suffix}"
            organization = OrganizationRepository(session).create(
                name=name, slug=f"tenant-{suffix}"
            )
            organization_id = organization.id
            organization_slug = organization.slug
            owns_organization = True
        else:
            existing = session.get(Organization, organization_id)
            assert existing is not None, "the fixture was given an unknown organization"
            organization_slug = existing.slug
            owns_organization = False

        user = UserRepository(session).create(email=email, full_name=full_name)
        membership = MembershipRepository(session, organization_id).add_member(
            user_id=user.id, role_code=role_code, status=membership_status
        )
        expires_at = None if token_expires_in is None else datetime.now(UTC) + token_expires_in
        plaintext, token = ApiTokenRepository(session).issue(
            user_id=user.id, name="test", expires_at=expires_at
        )

    return Identity(
        user_id=user.id,
        email=user.email,
        organization_id=organization_id,
        organization_slug=organization_slug,
        role_code=role_code,
        membership_id=membership.id,
        token_id=token.id,
        token=plaintext,
        owns_organization=owns_organization,
    )


def join_organization(
    engine: Engine,
    identity: Identity,
    *,
    organization_id: uuid.UUID,
    role_code: str = "viewer",
) -> Identity:
    """Give an existing person a second membership, returning the updated fixture.

    One user genuinely can belong to several organizations, and ``GET /me`` exists
    to say so — which cannot be tested with a fixture that only ever holds one
    membership. The dataclass is frozen, so this returns a *new* fixture carrying
    the extra pair; purge removes it along with the rest.

    The organization is not created here: pass one that another identity already
    owns, so exactly one fixture is responsible for deleting it.
    """
    with _session(engine) as session:
        membership = MembershipRepository(session, organization_id).add_member(
            user_id=identity.user_id, role_code=role_code
        )
    return replace(
        identity,
        extra_memberships=(*identity.extra_memberships, (organization_id, membership.id)),
    )


def find_identity(
    engine: Engine,
    *,
    organization_slug: str,
    email: str,
    token: str,
) -> Identity:
    """Locate an identity by the unique values it was created with.

    Needed when the thing that created it was not this module: the provisioning
    CLI writes committed rows and *prints* the results rather than returning them,
    so a test asserts against what the operator received and looks the rows up
    here in order to clean up. The lookup is deliberately by value — slug, email,
    token prefix — so it fails loudly if the CLI wrote something unexpected.
    """
    with _session(engine) as session:
        organization = OrganizationRepository(session).find_by_slug(organization_slug)
        assert organization is not None, f"no organization with slug {organization_slug!r}"
        user = UserRepository(session).find_by_email(email)
        assert user is not None, f"no user with email {email!r}"
        membership = MembershipRepository(session, organization.id).find_for_user(user.id)
        assert membership is not None, "the person has no membership in the organization"
        tokens = [
            row
            for row in ApiTokenRepository(session).list_for_user(user.id)
            if token.startswith(row.token_prefix)
        ]
        assert len(tokens) == 1, f"expected exactly one matching token, found {len(tokens)}"

        return Identity(
            user_id=user.id,
            email=user.email,
            organization_id=organization.id,
            organization_slug=organization.slug,
            role_code=membership.role.code,
            membership_id=membership.id,
            token_id=tokens[0].id,
            token=token,
            owns_organization=True,
        )


def revoke_token(engine: Engine, token_id: uuid.UUID) -> None:
    """Revoke a token, the way the application would.

    The repository revokes a *row* (it stamps ``revoked_at`` and keeps the
    record), so this loads it first — passing an id where a row is expected is
    exactly the mistake this wrapper exists to absorb once.
    """
    with _session(engine) as session:
        repository = ApiTokenRepository(session)
        token = repository.find(token_id)
        assert token is not None, "the fixture was given an unknown token"
        repository.revoke(token)


def expire_token(engine: Engine, token_id: uuid.UUID) -> None:
    """Move a token's expiry into the past.

    A direct ``UPDATE`` rather than a repository call: expiry is the passage of
    time, and a test cannot wait ninety days for it.
    """
    with _session(engine) as session:
        session.execute(
            update(ApiToken)
            .where(ApiToken.id == token_id)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        session.commit()


def suspend_user(engine: Engine, user_id: uuid.UUID) -> None:
    """Suspend an account. ``users`` is not tenant-owned, so nothing is bound."""
    with _session(engine) as session:
        session.execute(
            update(User).where(User.id == user_id).values(status=UserStatus.SUSPENDED.value)
        )
        session.commit()


def suspend_membership(engine: Engine, identity: Identity) -> None:
    """Suspend one membership.

    ``memberships`` *is* tenant-owned, so this write binds the tenant and filters
    on it — the same requirement application code is held to, and the reason this
    helper is not a one-liner like :func:`suspend_user`.
    """
    with _session(engine) as session:
        with bind_tenant(identity.organization_id):
            session.execute(
                update(Membership)
                .where(Membership.id == identity.membership_id)
                .where(Membership.organization_id == identity.organization_id)
                .values(status=MembershipStatus.SUSPENDED.value)
            )
        session.commit()


def stored_token_rows(engine: Engine, token_id: uuid.UUID) -> ApiToken:
    """The stored credential row, for tests that assert what is *not* in it."""
    with _session(engine) as session:
        row = session.execute(select(ApiToken).where(ApiToken.id == token_id)).scalar_one()
        session.expunge(row)
        return row


class IdentityFactory:
    """Provisions identities for one test, and removes all of them afterwards.

    A class rather than a bare callable because one operation needs memory:
    :meth:`join` adds a second membership to a person who already exists, and
    cleanup has to know about it. Keeping that bookkeeping in the factory means a
    test cannot forget it — the alternative is a fixture that leaves rows behind
    exactly when it is doing something interesting.
    """

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._created: list[Identity] = []

    def __call__(self, **kwargs: object) -> Identity:
        """Provision a user, organization, membership, role and token."""
        identity = provision_identity(self._engine, **kwargs)  # type: ignore[arg-type]
        self._created.append(identity)
        return identity

    def join(
        self,
        identity: Identity,
        *,
        organization_id: uuid.UUID,
        role_code: str = "viewer",
    ) -> Identity:
        """Put an existing person into another organization.

        Returns the updated identity (the dataclass is frozen) and records it, so
        cleanup removes the added membership too.
        """
        updated = join_organization(
            self._engine, identity, organization_id=organization_id, role_code=role_code
        )
        for index, recorded in enumerate(self._created):
            if recorded.user_id == updated.user_id:
                self._created[index] = updated
                break
        return updated

    def purge(self) -> None:
        """Delete everything this factory created."""
        purge_identities(self._engine, self._created)


def purge_identities(engine: Engine, identities: Iterable[Identity]) -> None:
    """Remove every fixture identity, in dependency order.

    Deliberately *not* reverse-creation order: once one person can belong to an
    organization that another fixture created, "newest first" is not enough — the
    older tenant would still be referenced by the newer person's membership, and
    the foreign key (correctly) refuses the delete. So: every credential, then the
    audit trail (which only an explicit override may delete), then every owned
    resource, then every membership, then the organizations, then the people. Each
    phase is one statement per row, all committed together.
    """
    identities = list(identities)
    with _session(engine) as session:
        for identity in identities:
            session.execute(delete(ApiToken).where(ApiToken.user_id == identity.user_id))

        for identity in identities:
            # The inventory goes first: an asset's owner is a membership of its own
            # organization, and that foreign key is RESTRICT — so a membership with
            # assets cannot be removed, and deletion order is not a detail.
            with bind_tenant(identity.organization_id):
                session.execute(
                    delete(Asset).where(Asset.organization_id == identity.organization_id)
                )

        for identity in identities:
            # The audit trail goes first of all, because it is the one table that refuses
            # to be deleted. A fixture that removes a tenant must remove its events too (the
            # tenant foreign key is RESTRICT), and the override states out loud that this is
            # teardown rather than a retention policy — which is the only reason the guard
            # has an exception at all.
            with audit_retention_override(session, "test fixture teardown"):
                for identity in identities:
                    for organization_id, _membership_id in identity.memberships():
                        with bind_tenant(organization_id):
                            session.execute(
                                delete(AuditEvent).where(
                                    AuditEvent.organization_id == organization_id
                                )
                            )

        for identity in identities:
            # Policies go with the inventory, and for the same reason: a policy
            # references the organization with RESTRICT, so an organization that
            # still has one cannot be deleted. Unlike an asset, a policy is not
            # owned by a membership, so this phase sweeps *every* organization the
            # identity belongs to — which is where a test could have made one. The
            # version history follows by cascade.
            for organization_id, _membership_id in identity.memberships():
                with bind_tenant(organization_id):
                    session.execute(delete(Policy).where(Policy.organization_id == organization_id))

        for identity in identities:
            for organization_id, membership_id in identity.memberships():
                with bind_tenant(organization_id):
                    session.execute(
                        delete(Membership)
                        .where(Membership.id == membership_id)
                        .where(Membership.organization_id == organization_id)
                    )

        for identity in identities:
            if identity.owns_organization:
                # Every membership is gone, so the RESTRICT from memberships is too.
                with bind_tenant(identity.organization_id):
                    session.execute(
                        delete(Organization).where(Organization.id == identity.organization_id)
                    )

        for identity in identities:
            session.execute(delete(User).where(User.id == identity.user_id))
        session.commit()


def purge_identity(engine: Engine, identity: Identity) -> None:
    """Remove one fixture identity. See :func:`purge_identities`."""
    purge_identities(engine, [identity])
