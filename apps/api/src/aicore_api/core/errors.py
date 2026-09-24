"""Uniform error handling.

Every failure leaves the API as the same envelope, so clients (and the shared
TypeScript types in ``packages/types``) have one shape to handle:

    {"error": {"code": "...", "message": "...", "details": ..., "request_id": "..."}}

Internal details are logged, never returned: an unexpected exception becomes a
generic 500 with a correlation id.

Most failures travel as :class:`fastapi.HTTPException` and take the code their status
implies. That is right for "you are not allowed in" and wrong for a failure whose
*reason* is the answer: an action refused by a policy and one awaiting an approval are
both forbidden, and a client must not have to read prose to tell them apart. Those
raise :class:`ApiError`, which carries the code and structured details itself — the
same envelope, with a code that means something.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from aicore_api.core.request_context import get_current_request_id

logger = logging.getLogger(__name__)

_STATUS_TO_CODE: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}


def code_for_status(status_code: int) -> str:
    return _STATUS_TO_CODE.get(status_code, f"http_{status_code}")


class ApiError(Exception):
    """A failure with an explicit, machine-readable code.

    ``HTTPException`` maps a status to a code, which is enough when the status *is* the
    answer. It is not enough when two different answers share a status — an action
    refused by a policy (``policy_denied``) and one waiting on an approval that does not
    exist yet (``approval_required``) are both 403 — and the difference is exactly what
    the caller needs. The code is a stable identifier, so a client switches on it rather
    than matching text.

    ``details`` is structured data for the client, and it is the caller's responsibility
    that it holds no secret: this class publishes what it is given.
    """

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        details: Any | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


def error_payload(
    code: str,
    message: str,
    details: Any | None = None,
) -> dict[str, dict[str, Any]]:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details,
            "request_id": get_current_request_id(),
        }
    }


def error_response(
    status_code: int,
    message: str,
    *,
    code: str | None = None,
    details: Any | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=error_payload(code or code_for_status(status_code), message, details),
        headers=headers,
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Attach the handlers that produce the error envelope."""

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        # `detail` is the message the framework (or a route) chose; it is already
        # intended for the client, so it is passed through unchanged.
        message = exc.detail if isinstance(exc.detail, str) else "Request failed"
        return error_response(
            exc.status_code,
            message,
            details=None if isinstance(exc.detail, str) else exc.detail,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(ApiError)
    async def _api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
        # Deliberately no logging here as well: an ApiError is a *decided* refusal the
        # caller is being told about, not a defect to investigate. A route that wants a
        # line in the log emits one where it has the context to make it useful.
        return error_response(exc.status_code, exc.message, code=exc.code, details=exc.details)

    @app.exception_handler(RequestValidationError)
    async def _validation_exception_handler(
        _: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return error_response(
            422,
            "Request validation failed",
            details=[
                {
                    "location": [str(part) for part in error.get("loc", ())],
                    "message": error.get("msg", "invalid"),
                    "type": error.get("type", "unknown"),
                }
                for error in exc.errors()
            ],
        )

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
        request_id = get_current_request_id()
        logger.exception("Unhandled error (request_id=%s)", request_id)
        return error_response(500, "Internal server error")
