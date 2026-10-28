"""Operator CLI: provision identities, memberships and credentials.

Phase 2 has no user-management API and no sign-up — deliberately. Creating the
first organization, the first user and the first token is a *provisioning*
action, and provisioning belongs to whoever holds database access (an operator,
a deployment job, a test), not to an unauthenticated HTTP route.

    bash scripts/py.sh -m aicore_api.cli bootstrap \\
        --email owner@example.com --full-name "Ada Lovelace" \\
        --organization-name "Acme Corporation" --organization-slug acme

    bash scripts/py.sh -m aicore_api.cli create-api-token --email owner@example.com --name laptop

Everything it creates is real: a user row, a membership with a role from the
seeded catalog, and a token whose plaintext is printed exactly once. There is no
development-only authentication path — a test that authenticated differently from
production would prove nothing about production.

The CLI talks to the data layer directly (repositories), so it does not need the
API to be running, and it never bypasses a constraint: uniqueness, foreign keys
and the role catalog all still decide.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from aicore_api.config import get_settings
from aicore_api.core.domain_errors import ConflictError, DomainError, NotFoundError
from aicore_api.core.permissions import RoleCode
from aicore_api.db.models.organization import Organization
from aicore_api.db.repositories.api_tokens import ApiTokenRepository
from aicore_api.db.repositories.memberships import MembershipRepository
from aicore_api.db.repositories.organizations import OrganizationRepository
from aicore_api.db.repositories.rbac import RoleCatalog
from aicore_api.db.repositories.users import UserRepository
from aicore_api.db.session import get_session_factory

DEFAULT_TOKEN_LIFETIME_DAYS = 90

__all__ = ["main"]


def _session() -> Session:
    """A session for the whole command (the CLI is one unit of work)."""
    return get_session_factory()()


def _resolve_organization(session: Session, identifier: str) -> Organization:
    """Find a tenant by UUID or by slug."""
    repository = OrganizationRepository(session)
    try:
        organization_id = uuid.UUID(identifier)
    except ValueError:
        organization = repository.find_by_slug(identifier)
        if organization is None:
            raise NotFoundError(f"no organization with slug {identifier!r}") from None
        return organization
    return repository.get(organization_id)


def _cmd_create_user(args: argparse.Namespace) -> int:
    with _session() as session:
        user = UserRepository(session).create(email=args.email, full_name=args.full_name)
    print(f"user {user.id} ({user.email}) created")
    return 0


def _cmd_add_member(args: argparse.Namespace) -> int:
    with _session() as session:
        user = UserRepository(session).find_by_email(args.email)
        if user is None:
            raise NotFoundError(f"no user with email {args.email!r}")
        organization = _resolve_organization(session, args.organization)
        RoleCatalog(session).get_by_code(args.role)  # fail before writing
        membership = MembershipRepository(session, organization.id).add_member(
            user_id=user.id, role_code=args.role
        )
    print(f"{user.email} is now {membership.role.code} of {organization.slug} ({organization.id})")
    return 0


def _cmd_create_api_token(args: argparse.Namespace) -> int:
    expires_at = (
        None if args.no_expiry else datetime.now(UTC) + timedelta(days=args.expires_in_days)
    )
    with _session() as session:
        user = UserRepository(session).find_by_email(args.email)
        if user is None:
            raise NotFoundError(f"no user with email {args.email!r}")
        plaintext, token = ApiTokenRepository(session).issue(
            user_id=user.id, name=args.name, expires_at=expires_at
        )

    settings = get_settings()
    if settings.is_production:
        print(
            "[warning] this is a production environment: the token below is a live credential",
            file=sys.stderr,
        )
    print(f"token {token.token_prefix}… for {user.email} ({token.id})")
    print(f"expires: {expires_at.isoformat() if expires_at else 'never'}")
    print()
    print(plaintext)
    print()
    print(
        "This is the only time the token is shown: only its hash is stored, so it "
        "cannot be recovered — one can only be revoked and replaced.",
        file=sys.stderr,
    )
    return 0


def _cmd_bootstrap(args: argparse.Namespace) -> int:
    """Organization + owner + token, in one step, for a fresh installation."""
    with _session() as session:
        organization = OrganizationRepository(session).create(
            name=args.organization_name, slug=args.organization_slug
        )
        user = UserRepository(session).create(email=args.email, full_name=args.full_name)
        membership = MembershipRepository(session, organization.id).add_member(
            user_id=user.id, role_code=RoleCode.OWNER.value
        )
        expires_at = (
            None if args.no_expiry else datetime.now(UTC) + timedelta(days=args.expires_in_days)
        )
        plaintext, token = ApiTokenRepository(session).issue(
            user_id=user.id, name="bootstrap", expires_at=expires_at
        )

    print(f"organization {organization.slug} ({organization.id})")
    print(f"user         {user.email} ({user.id})")
    print(f"membership   {membership.role.code}")
    print(f"token        {token.token_prefix}… ({token.id})")
    print()
    print(plaintext)
    print()
    print(
        "Store this token now — it is shown once. See docs/authentication.md for how to use it.",
        file=sys.stderr,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m aicore_api.cli",
        description="Provision AICore identities, memberships and API tokens.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    create_user = subcommands.add_parser("create-user", help="create an identity")
    create_user.add_argument("--email", required=True)
    create_user.add_argument("--full-name", required=True)
    create_user.set_defaults(handler=_cmd_create_user)

    add_member = subcommands.add_parser("add-member", help="grant a user a role in an organization")
    add_member.add_argument("--organization", required=True, help="organization slug or UUID")
    add_member.add_argument("--email", required=True, help="the user's email address")
    add_member.add_argument(
        "--role",
        required=True,
        choices=[role.value for role in RoleCode],
        help="role code from the seeded catalog",
    )
    add_member.set_defaults(handler=_cmd_add_member)

    create_token = subcommands.add_parser(
        "create-api-token", help="issue a bearer token for a user"
    )
    create_token.add_argument("--email", required=True)
    create_token.add_argument("--name", required=True, help="what this token is for")
    create_token.add_argument(
        "--expires-in-days",
        type=int,
        default=DEFAULT_TOKEN_LIFETIME_DAYS,
        help=f"lifetime in days (default {DEFAULT_TOKEN_LIFETIME_DAYS})",
    )
    create_token.add_argument(
        "--no-expiry",
        action="store_true",
        help="issue a token that never expires (strongly discouraged outside a laptop)",
    )
    create_token.set_defaults(handler=_cmd_create_api_token)

    bootstrap = subcommands.add_parser(
        "bootstrap",
        help="create an organization, its owner and a token for them",
    )
    bootstrap.add_argument("--email", required=True)
    bootstrap.add_argument("--full-name", required=True)
    bootstrap.add_argument("--organization-name", required=True)
    bootstrap.add_argument("--organization-slug", required=True)
    bootstrap.add_argument("--expires-in-days", type=int, default=DEFAULT_TOKEN_LIFETIME_DAYS)
    bootstrap.add_argument("--no-expiry", action="store_true")
    bootstrap.set_defaults(handler=_cmd_bootstrap)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run a command. Returns a process exit code."""
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (ConflictError, NotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except DomainError as exc:  # pragma: no cover - none are raised today
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:  # bad UUID, unknown role code
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover - exercised as a process
    raise SystemExit(main())
