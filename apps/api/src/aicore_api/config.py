"""Application configuration.

All configuration comes from the environment (12-factor). No secret is ever
hardcoded and no credential has a usable default: `AICORE_DATABASE_URL` is
required, so a misconfigured deployment fails fast at startup instead of
silently connecting somewhere unexpected.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]

#: Schemes accepted for the database URL. Anything else (e.g. sqlite) is a
#: configuration error: AICore targets PostgreSQL by definition.
_ALLOWED_DB_SCHEMES = ("postgresql", "postgresql+psycopg")


class Settings(BaseSettings):
    """Runtime settings, read from environment variables prefixed ``AICORE_``."""

    model_config = SettingsConfigDict(
        env_prefix="AICORE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Identity ─────────────────────────────────────────────────────────────
    app_name: str = "aicore-api"
    app_version: str = "0.1.0"
    environment: Environment = "development"
    debug: bool = False

    # ── HTTP ─────────────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"  # noqa: S104 - container default; bind address is explicit config
    api_port: Annotated[int, Field(ge=1, le=65535)] = 8000
    docs_enabled: bool = True
    log_level: Literal["critical", "error", "warning", "info", "debug"] = "info"

    # ── CORS ─────────────────────────────────────────────────────────────────
    # Secure default: no cross-origin access. In the default architecture the
    # browser talks to the Next.js same-origin proxy, so this stays empty.
    cors_allow_origins: tuple[str, ...] = ()
    cors_allow_credentials: bool = False

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: SecretStr
    database_pool_size: Annotated[int, Field(ge=1, le=50)] = 5
    database_connect_timeout_seconds: Annotated[int, Field(ge=1, le=30)] = 5

    # ── Authentication ───────────────────────────────────────────────────────
    # Which provider validates credentials. Phase 2 ships bearer API tokens;
    # adding an external identity provider (OIDC) means implementing the
    # provider protocol and extending this list — the routes, dependencies and
    # authorization code do not change, because none of them know how a
    # principal was established. See docs/authentication.md.
    auth_provider: Literal["api_token"] = "api_token"

    # ── Anomaly and risk analysis (Phase 10) ─────────────────────────────────
    # The thresholds a behavioural comparison uses. They are configuration rather than
    # request parameters on purpose: a caller may choose *which* interval to analyse —
    # that is what the observation window is for — but never the bound it is measured
    # against, so tuning the detector is not something a request can attempt. Each one is
    # a floor on evidence as much as a cut-off, and each is documented in docs/risk.md.
    #
    #   risk_deviation_multiple   how many baseline standard deviations a rate must move
    #   risk_extreme_multiple     when a deviation is "far outside" for a higher level
    #   risk_rate_change_ratio    the multiple of the baseline mean also required
    #   risk_min_baseline_buckets hourly samples a rate comparison needs
    #   risk_min_baseline_events  baseline events before any rate is compared
    #   risk_min_ratio_samples    baseline buckets with a defined ratio (failure, denial)
    #   risk_min_observed_samples observed events before a ratio is computed at all
    #   risk_min_distinct_hours   clock hours the baseline must cover
    #   risk_min_novel_occurrences  occurrences of a first-use action/resource to report
    risk_deviation_multiple: Annotated[float, Field(ge=0, le=10)] = 2.0
    risk_extreme_multiple: Annotated[float, Field(ge=1, le=100)] = 3.0
    risk_rate_change_ratio: Annotated[float, Field(gt=1, le=100)] = 2.0
    risk_min_baseline_buckets: Annotated[int, Field(ge=1, le=720)] = 12
    risk_min_baseline_events: Annotated[int, Field(ge=1, le=1_000_000)] = 20
    risk_min_ratio_samples: Annotated[int, Field(ge=1, le=720)] = 8
    risk_min_observed_samples: Annotated[int, Field(ge=1, le=1_000_000)] = 4
    risk_min_distinct_hours: Annotated[int, Field(ge=0, le=24)] = 4
    risk_min_novel_occurrences: Annotated[int, Field(ge=1, le=1_000_000)] = 1

    # ── VCS / deployment metadata (informational) ────────────────────────────
    git_commit: str | None = None

    # ── Validators ───────────────────────────────────────────────────────────
    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        """Accept a comma-separated string as well as a list/JSON array."""
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

    # ── Convenience ──────────────────────────────────────────────────────────
    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def safe_summary(self) -> dict[str, object]:
        """Config summary safe to log: never includes the database URL."""
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
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor (one read per process)."""
    return Settings()  # type: ignore[call-arg]  # values are supplied by the environment
