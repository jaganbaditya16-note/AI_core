"""Test configuration.

The environment is configured *before* the application module is imported, so
the app under test is built from a known, hermetic configuration: the database
URL points at a closed port, which makes readiness fail fast and deterministically
without requiring a running PostgreSQL.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

# ── Environment (must run before `aicore_api` is imported) ────────────────────
# The credentials below are fake on purpose: they point at a closed port so
# readiness fails deterministically, and they give test_health_ready.py a
# credential-bearing URL to prove the readiness detail never leaks one.
# No real password appears anywhere in this repository.
os.environ.setdefault("AICORE_ENVIRONMENT", "test")
os.environ.setdefault(
    "AICORE_DATABASE_URL", "postgresql+psycopg://aicore:aicore@127.0.0.1:1/aicore"
)
os.environ.setdefault("AICORE_DATABASE_CONNECT_TIMEOUT_SECONDS", "1")
os.environ.setdefault("AICORE_LOG_LEVEL", "warning")
os.environ.setdefault("AICORE_DEBUG", "false")

from fastapi.testclient import TestClient

from aicore_api.config import Settings, get_settings
from aicore_api.main import create_app

#: Unreachable on purpose (port 1) — readiness must fail without a live database.
OFFLINE_DATABASE_URL = "postgresql+psycopg://aicore:aicore@127.0.0.1:1/aicore"


@pytest.fixture(scope="session")
def settings() -> Settings:
    get_settings.cache_clear()
    return Settings()


@pytest.fixture(scope="session")
def client(settings: Settings) -> Iterator[TestClient]:
    app = create_app(settings)
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def offline_settings() -> Settings:
    """Settings whose database is guaranteed unreachable."""
    return Settings(  # type: ignore[call-arg]  # env supplies the remaining fields
        database_url=OFFLINE_DATABASE_URL,
        database_connect_timeout_seconds=1,
        environment="test",
    )
