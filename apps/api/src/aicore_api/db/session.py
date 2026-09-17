"""PostgreSQL engine and connectivity probe.

The engine is created lazily so that importing the application never opens a
connection, and it is disposed on shutdown.
"""

from __future__ import annotations

import asyncio
import logging
import re
from functools import lru_cache

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from aicore_api.config import get_settings

logger = logging.getLogger(__name__)

#: Any user:password@host fragment that might appear inside a driver message.
_CREDENTIALS_IN_URL = re.compile(r"://[^/\s@]+@")
_MAX_DETAIL_LENGTH = 300


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Create the shared engine. Never logs the connection string."""
    settings = get_settings()
    return create_engine(
        settings.database_url.get_secret_value(),
        pool_pre_ping=True,
        pool_size=settings.database_pool_size,
        max_overflow=0,
        # psycopg: bound the TCP connect so a readiness probe cannot hang.
        connect_args={"connect_timeout": settings.database_connect_timeout_seconds},
    )


def dispose_engine() -> None:
    """Close pooled connections (called on application shutdown)."""
    if get_engine.cache_info().currsize == 0:
        return
    get_engine().dispose()
    get_engine.cache_clear()


def _redact(message: str) -> str:
    """Remove anything that could carry credentials, and bound the length."""
    redacted = _CREDENTIALS_IN_URL.sub("://***@", message).replace("\n", " ").strip()
    if len(redacted) > _MAX_DETAIL_LENGTH:
        redacted = f"{redacted[:_MAX_DETAIL_LENGTH]}…"
    return redacted


def _probe(engine: Engine) -> None:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))


async def check_database(timeout_seconds: float = 5.0) -> tuple[bool, str | None]:
    """Return ``(reachable, detail)`` for the configured database."""
    try:
        await asyncio.wait_for(asyncio.to_thread(_probe, get_engine()), timeout=timeout_seconds)
    except TimeoutError:
        return False, f"connection timed out after {timeout_seconds:g}s"
    except Exception as exc:
        logger.warning("Database readiness probe failed: %s", _redact(str(exc)))
        return False, _redact(str(exc))
    return True, "SELECT 1 succeeded"
