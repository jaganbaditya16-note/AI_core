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


class InvalidReferenceError(ValueError):
    """A referenced row does not exist.

    Distinct from :class:`NotFoundError`: the *reference* is invalid, not the
    thing being looked up (e.g. creating a record for an organization that is
    not there).
    """
