"""Application configuration with secret-safe Nebius intelligence settings."""
from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]
_ALLOWED_DB_SCHEMES = ("postgresql", "postgresql+psycopg")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AICORE_", env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False
    )

    app_name: str = "aicore-api"
    app_version: str = "0.1.0"
    environment: Environment = "development"
    debug: bool = False
    api_host: str = "0.0.0.0"
    api_port: Annotated[int, Field(ge=1, le=65535)] = 8000
    docs_enabled: bool = True
    log_level: Literal["critical", "error", "warning", "info", "debug"] = "info"
    cors_allow_origins: tuple[str, ...] = ()
    cors_allow_credentials: bool = False
    database_url: SecretStr
    database_pool_size: Annotated[int, Field(ge=1, le=50)] = 5
    database_connect_timeout_seconds: Annotated[int, Field(ge=1, le=30)] = 5
    auth_provider: Literal["api_token"] = "api_token"

    nebius_api_key: SecretStr | None = None
    nebius_base_url: str = "https://api.tokenfactory.us-central1.nebius.com/v1/"
    nebius_model: str = "nvidia/nemotron-3-super-120b-a12b"
    nebius_timeout_seconds: Annotated[float, Field(gt=0, le=120)] = 30.0
    git_commit: str | None = None

    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            if value.strip() in {"", "[]"}:
                return ()
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return value

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, value: SecretStr) -> SecretStr:
        url = value.get_secret_value()
        if not url.startswith(_ALLOWED_DB_SCHEMES):
            raise ValueError("AICORE_DATABASE_URL must be a PostgreSQL URL")
        return value

    @field_validator("nebius_base_url")
    @classmethod
    def _validate_nebius_url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("AICORE_NEBIUS_BASE_URL must use HTTPS")
        return value.rstrip("/") + "/"

    @model_validator(mode="after")
    def _enforce_production_defaults(self) -> Settings:
        if self.environment == "production":
            if self.debug:
                raise ValueError("AICORE_DEBUG must be disabled in production")
            if "*" in self.cors_allow_origins:
                raise ValueError('AICORE_CORS_ALLOW_ORIGINS must not contain "*" in production')
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def safe_summary(self) -> dict[str, object]:
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
            "nebius_configured": bool(self.nebius_api_key),
            "nebius_model": self.nebius_model,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
