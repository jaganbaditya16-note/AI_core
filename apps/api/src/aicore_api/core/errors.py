"""Uniform error handling.

Every failure leaves the API as the same envelope, so clients (and the shared
TypeScript types in ``packages/types``) have one shape to handle:

    {"error": {"code": "...", "message": "...", "details": ..., "request_id": "..."}}

Internal details are logged, never returned: an unexpected exception becomes a
generic 500 with a correlation id.
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
