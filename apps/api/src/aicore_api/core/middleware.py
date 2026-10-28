"""Request middleware."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response

from aicore_api.core.request_context import HEADER_NAME, sanitize_request_id, set_current_request_id

logger = logging.getLogger(__name__)


def register_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def add_request_id(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = sanitize_request_id(request.headers.get(HEADER_NAME))
        set_current_request_id(request_id)
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers[HEADER_NAME] = request_id
        return response
