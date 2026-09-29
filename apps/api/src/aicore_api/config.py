"""Application configuration.

All configuration comes from the environment (12-factor). No secret is ever
hardcoded and no credential has a usable default: `AICORE_DATABASE_URL` is
required, so a misconfigured deployment fails fast at startup instead of
silently connecting somewhere unexpected.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]
_ALLOWED_DB_SCHEMES = ("postgresql", "postgresql+psycopg")
_ALLOWED_NEBIUS_HOSTS = {"api.tokenfactory.nebius.com", "api.tokenfactory.us-central1.nebius.com"}


class Settings(BaseSettings):
    """Runtime settings, read from environment variables prefixed ``AICORE_``."""

    model_config = SettingsConfigDict(
        env_prefix="AICORE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "aicore-api"
    app_version: str = "0.1.0"
    environment: Environment = "development"
    debug: bool = False

    api_host: str = "0.0.0.0"  # noqa: S104 - container default; bind address is explicit config
    api_port: Annotated[int, Field(ge=1, le=65535)] = 8000
    docs_enabled: bool = True
    log_level: Literal["critical", "error", "warning", "info", "debug"] = "info"

    cors_allow_origins: tuple[str, ...] = ()
    cors_allow_credentials: bool = False

    database_url: SecretStr
    database_pool_size: Annotated[int, Field(ge=1, le=50)] = 5
    database_connect_timeout_seconds: Annotated[int, Field(ge=1, le=30)] = 5

    auth_provider: Literal["api_token"] = "api_token"

    # Optional hackathon integration. The core control plane remains functional when
    # these values are absent; the investigation route returns 503 instead of faking AI.
    nebius_api_key: SecretStr | None = None
    nebius_base_url: str = "https://api.tokenfactory.nebius.com/v1"
    nebius_model: str = "nvidia/Nemotron-3_5-Lightning"
    nebius_timeout_seconds: Annotated[int, Field(ge=2, le=60)] = 20
    nebius_max_output_tokens: Annotated[int, Field(ge=128, le=2000)] = 900

    git_commit: str | None = None

    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            if value.strip() == "" or value.strip() == "[]":
                return ()
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return value

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, value: SecretStr) -> SecretStr:
        url = value.get_secret_value()
        if not url.startswith(_ALLOWED_DB_SCHEMES):
            msg = (
                "AICORE_DATABASE_URL must be a PostgreSQL URL "
                f"({' or '.join(_ALLOWED_DB_SCHEMES)}), got scheme '{url.split(':', 1)[0]}'"
            )
            raise ValueError(msg)
        return value

    @field_validator("nebius_base_url")
    @classmethod
    def _validate_nebius_base_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_NEBIUS_HOSTS:
            raise ValueError("AICORE_NEBIUS_BASE_URL must use an approved HTTPS Nebius Token Factory host")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("AICORE_NEBIUS_BASE_URL must not contain credentials, query or fragment")
        return value.rstrip("/")

    @model_validator(mode="after")
    def _enforce_production_defaults(self) -> Settings:
        if self.environment == "production":
            if self.debug:
                msg = "AICORE_DEBUG must be disabled in production"
                raise ValueError(msg)
            wildcard = [origin for origin in self.cors_allow_origins if origin == "*"]
            if wildcard:
                msg = 'AICORE_CORS_ALLOW_ORIGINS must not contain "*" in production'
                raise ValueError(msg)
            if self.cors_allow_credentials and "*" in self.cors_allow_origins:
                msg = "CORS credentials cannot be combined with a wildcard origin"
                raise ValueError(msg)
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def safe_summary(self) -> dict[str, object]:
        """Config summary safe to log: never includes the database URL or API key."""
        return {
            "app_name": self.app_name,
            "app_version": self.app_version,
            "environment": self.environment,
            "debug": self.debug,
            "docs_enabled": self.docs_enabled,
            "log_level": self.log_level,
            "cors_origins": len(self.cors_allow_origins),
            "database_configured": bool(self.database_url.get_secret_value()),
            "database_pool_size": self.database_pool_size,
            "auth_provider": self.auth_provider,
            "nebius_configured": bool(
                self.nebius_api_key and self.nebius_api_key.get_secret_value()
            ),
            "nebius_model": self.nebius_model,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor (one read per process)."""
    return Settings()  # type: ignore[call-arg]  # values are supplied by the environment
