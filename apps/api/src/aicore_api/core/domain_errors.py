"""Errors raised by the data-access layer.

These are transport-agnostic: repositories raise them without knowing that HTTP
exists. Mapping them onto status codes is the API layer's job (see
``aicore_api.api.routes.organizations``), which keeps the data layer usable from
scripts, migrations and future background workers.
"""

from __future__ import annotations


class DomainError(Exception):
    """Base class for expected, non-bug failures in the data layer."""


class NotFoundError(DomainError):
    """The requested record does not exist (or is not visible to this tenant)."""


class ConflictError(DomainError):
    """A uniqueness or integrity rule rejected the write."""


class AuthenticationError(DomainError):
    """Credentials are missing, malformed, or do not identify an active user.

    The message is deliberately uniform across all of those cases: telling a
    caller *why* credentials failed turns the endpoint into an oracle for which
    tokens exist.
    """


class PermissionDeniedError(DomainError):
    """The caller is authenticated and is a member, but lacks the permission.

    Distinct from :class:`NotFoundError` on purpose: a *member* who may not do
    something is told so (403), while a *non-member* is told the organization
    does not exist (404). Returning 403 to an outsider would confirm that the
    tenant exists.
    """


class InvalidReferenceError(ValueError):
    """A referenced row does not exist.

    Distinct from :class:`NotFoundError`: the *reference* is invalid, not the
    thing being looked up (e.g. creating a record for an organization that is
    not there).
    """
