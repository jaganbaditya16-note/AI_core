"""The authenticated caller.

A :class:`Principal` is the *only* thing a route learns from authentication: who
is calling. It deliberately carries no permissions and no organization — those
are per-organization facts resolved afterwards from memberships, so a request
that has authenticated but not authorized cannot accidentally look authorized.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Literal

__all__ = ["Principal", "UserStatus"]

#: Mirrors the ``users.status`` check constraint. Declared here rather than
#: imported from the ORM: this module is deliberately free of database imports,
#: so that anything may depend on the shape of an authenticated caller.
UserStatus = Literal["active", "suspended"]


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated user, as established by credentials."""

    user_id: uuid.UUID
    #: Excluded from ``repr``: an address is personal data, and a principal ends
    #: up in log lines and error context.
    email: str = field(repr=False)
    full_name: str
    #: Always ``"active"``: a suspended user cannot authenticate, so reaching
    #: this object at all proves the account is usable. Carried explicitly to
    #: keep the fact visible to routes instead of implicit.
    status: UserStatus
