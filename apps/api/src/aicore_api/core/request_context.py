"""Per-request correlation id.

Every request gets an id (from the incoming ``X-Request-ID`` header when it is a
sane value, otherwise generated). The id is attached to error responses and
echoed back in the response header so a client report can be matched to logs.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar

HEADER_NAME = "X-Request-ID"
MAX_LENGTH = 64

#: Conservative allow-list: ids are used in logs and headers, never in queries.
_SAFE_ID = re.compile(rf"^[A-Za-z0-9._:-]{{1,{MAX_LENGTH}}}$")

_current_request_id: ContextVar[str | None] = ContextVar("aicore_request_id", default=None)


def new_request_id() -> str:
    return uuid.uuid4().hex


def is_safe_request_id(candidate: object) -> bool:
    """Whether ``candidate`` is a value this build would accept as a request id.

    Exposed because a correlation id travels further than the response header: the
    action firewall stamps one onto a typed :class:`~aicore_api.core.actions.ActionRequest`
    and refuses anything the request layer could not have produced. A value that fails
    this check did not come from a request, so it is not a correlation id.
    """
    return isinstance(candidate, str) and bool(_SAFE_ID.match(candidate))


def sanitize_request_id(candidate: str | None) -> str:
    """Return the client-supplied id if it is safe, otherwise a fresh one."""
    if candidate is not None and _SAFE_ID.match(candidate):
        return candidate
    return new_request_id()


def set_current_request_id(request_id: str) -> None:
    _current_request_id.set(request_id)


def get_current_request_id() -> str | None:
    return _current_request_id.get()
