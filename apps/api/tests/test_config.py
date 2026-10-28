"""Configuration validation rules."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aicore_api.config import Settings

DATABASE_URL = "postgresql+psycopg://user:password@127.0.0.1:5432/aicore"


def build_settings(**overrides: object) -> Settings:
    params: dict[str, object] = {"database_url": DATABASE_URL, **overrides}
    return Settings(_env_file=None, **params)  # type: ignore[arg-type]


def test_database_url_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without configuration the app must refuse to build (fail fast)."""
    monkeypatch.delenv("AICORE_DATABASE_URL", raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_non_postgres_database_url_is_rejected() -> None:
    with pytest.raises(ValidationError, match="must be a PostgreSQL URL"):
        build_settings(database_url="sqlite:///./aicore.db")


def test_database_url_is_not_exposed_by_repr() -> None:
    """SecretStr keeps credentials out of logs and tracebacks."""
    settings = build_settings()

    assert "password" not in repr(settings)
    assert "password" not in str(settings.safe_summary())
    assert settings.database_url.get_secret_value() == DATABASE_URL


def test_cors_origins_accept_comma_separated_string() -> None:
    settings = build_settings(cors_allow_origins="https://a.example, https://b.example")

    assert settings.cors_allow_origins == ("https://a.example", "https://b.example")


def test_cors_defaults_to_no_cross_origin_access() -> None:
    assert build_settings().cors_allow_origins == ()


def test_production_rejects_wildcard_cors() -> None:
    with pytest.raises(ValidationError, match="must not contain"):
        build_settings(environment="production", cors_allow_origins="*")


def test_production_rejects_debug() -> None:
    with pytest.raises(ValidationError, match="AICORE_DEBUG"):
        build_settings(environment="production", debug=True)


def test_unknown_environment_is_rejected() -> None:
    with pytest.raises(ValidationError):
        build_settings(environment="staging-ish")


def test_safe_summary_contains_no_secrets() -> None:
    summary = build_settings(
        environment="production", cors_allow_origins="https://app.example"
    ).safe_summary()

    serialized = str(summary)
    assert "password" not in serialized
    assert "postgresql" not in serialized
    assert summary["database_configured"] is True
