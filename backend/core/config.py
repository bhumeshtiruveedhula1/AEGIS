"""
backend.core.config — Application Configuration Management
===========================================================
Centralised, type-safe settings using Pydantic BaseSettings.

All configuration is loaded ONCE at application startup from:
  1. Environment variables (highest priority)
  2. .env file (if present)
  3. Default values (lowest priority)

Usage
-----
    from backend.core.config import get_settings, Settings

    settings = get_settings()
    print(settings.app_env)          # "development"
    print(settings.database_url)     # "sqlite+aiosqlite:///..."
    print(settings.log_level)        # "INFO"

Design Notes
------------
- Settings are a frozen singleton — call get_settings() anywhere safely.
- Never access os.environ directly in business logic; use this module.
- Add new settings here first, then reference in .env.example.
- Future modules should add their config in clearly labelled sections.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, HttpUrl, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Complete application configuration.

    Every environment variable is documented here.  For production deployment,
    set the REQUIRED fields marked below.  See .env.example for a full template.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",   # silently ignore unknown vars (forward compat)
        frozen=True,      # immutable after construction
    )

    # -----------------------------------------------------------------------
    # Application
    # -----------------------------------------------------------------------
    app_env: Literal["development", "staging", "production"] = Field(
        default="development",
        description="Deployment environment. Controls defaults and validations.",
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Application log verbosity.",
    )
    log_format: Literal["json", "console"] = Field(
        default="console",
        description="Log output format. Use 'json' in production for structured log ingestion.",
    )
    app_host: str = Field(default="0.0.0.0", description="Server bind address.")
    app_port: int = Field(default=8000, ge=1024, le=65535, description="Server port.")

    # -----------------------------------------------------------------------
    # Security
    # -----------------------------------------------------------------------
    secret_key: SecretStr = Field(
        default="change-me-in-production-use-a-real-secret-key",
        description="REQUIRED in production. Used for signing tokens.",
    )
    api_key: SecretStr = Field(
        default="dev-api-key-change-in-production",
        description="Bearer token for service-to-service authentication.",
    )

    # -----------------------------------------------------------------------
    # Database
    # -----------------------------------------------------------------------
    database_url: str = Field(
        default="sqlite+aiosqlite:///./data/cybershield.db",
        description="Database connection string. SQLite for dev, PostgreSQL for prod.",
    )
    database_pool_size: int = Field(
        default=10,
        ge=1,
        le=100,
        description="PostgreSQL connection pool size.",
    )
    database_max_overflow: int = Field(
        default=20,
        ge=0,
        le=200,
        description="PostgreSQL max connection overflow beyond pool_size.",
    )

    # -----------------------------------------------------------------------
    # LLM (Anthropic Claude) — Module: llm
    # -----------------------------------------------------------------------
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        description="Anthropic API key. Required for LLM enrichment module.",
    )
    anthropic_model: str = Field(
        default="claude-sonnet-4-6",
        description="Claude model identifier to use for alert enrichment.",
    )
    llm_timeout_seconds: Annotated[int, Field(ge=1, le=30)] = Field(
        default=2,
        description="Per-call LLM timeout. Fail-open after this duration.",
    )
    llm_max_cost_per_call_usd: float = Field(
        default=0.01,
        ge=0.0,
        description="Maximum allowed USD cost per LLM enrichment call.",
    )

    # -----------------------------------------------------------------------
    # Anomaly Detection — Module: detection
    # -----------------------------------------------------------------------
    isolation_forest_contamination: float = Field(
        default=0.01,
        ge=0.0,
        le=0.5,
        description="Fraction of anomalies expected in normal training data.",
    )
    isolation_forest_n_estimators: int = Field(
        default=100,
        ge=10,
        le=1000,
        description="Number of trees in the Isolation Forest.",
    )
    isolation_forest_random_state: int = Field(
        default=42,
        description="Random seed for reproducible model training.",
    )
    anomaly_score_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Anomaly score above this value triggers an alert.",
    )

    # -----------------------------------------------------------------------
    # Audit & Metrics — Module: audit
    # -----------------------------------------------------------------------
    audit_log_max_records: int = Field(
        default=10000,
        ge=100,
        description="Maximum audit log records in rolling window.",
    )
    metrics_interval_seconds: int = Field(
        default=3600,
        ge=60,
        description="Interval in seconds for computing hourly metrics snapshots.",
    )

    # -----------------------------------------------------------------------
    # Data Paths
    # -----------------------------------------------------------------------
    data_dir: Path = Field(
        default=Path("./data"),
        description="Root directory for all data artifacts.",
    )
    models_dir: Path = Field(
        default=Path("./models"),
        description="Directory for trained model artifacts.",
    )
    reports_dir: Path = Field(
        default=Path("./reports"),
        description="Directory for generated reports.",
    )

    # -----------------------------------------------------------------------
    # CORS
    # -----------------------------------------------------------------------
    cors_allowed_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:8080"],
        description="Comma-separated list of allowed CORS origins.",
    )

    # -----------------------------------------------------------------------
    # Feature Flags — enable modules as they are implemented
    # -----------------------------------------------------------------------
    feature_ingestion_enabled: bool = Field(default=False)
    feature_normalization_enabled: bool = Field(default=False)
    feature_detection_enabled: bool = Field(default=False)
    feature_mitre_enabled: bool = Field(default=False)
    feature_graph_enabled: bool = Field(default=False)
    feature_llm_enabled: bool = Field(default=False)
    feature_response_enabled: bool = Field(default=False)
    feature_audit_enabled: bool = Field(default=False)
    feature_dashboard_enabled: bool = Field(default=False)

    # -----------------------------------------------------------------------
    # Validators
    # -----------------------------------------------------------------------
    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str | list[str]) -> list[str]:
        """Accept comma-separated string or list for CORS origins."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        """Enforce strong secrets in production deployments."""
        if self.app_env == "production":
            weak_key = "change-me-in-production"
            if weak_key in self.secret_key.get_secret_value():
                msg = "SECRET_KEY must be changed from the default in production."
                raise ValueError(msg)
            if self.anthropic_api_key is None and self.feature_llm_enabled:
                msg = "ANTHROPIC_API_KEY is required when feature_llm_enabled=true."
                raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def ensure_directories_exist(self) -> "Settings":
        """Create required directories if they do not exist."""
        for directory in (self.data_dir, self.models_dir, self.reports_dir):
            directory.mkdir(parents=True, exist_ok=True)
        return self

    # -----------------------------------------------------------------------
    # Convenience Properties
    # -----------------------------------------------------------------------
    @property
    def is_development(self) -> bool:
        """True when running in development mode."""
        return self.app_env == "development"

    @property
    def is_production(self) -> bool:
        """True when running in production mode."""
        return self.app_env == "production"

    @property
    def database_is_sqlite(self) -> bool:
        """True when using SQLite (development/testing)."""
        return self.database_url.startswith("sqlite")

    def __repr__(self) -> str:
        return (
            f"Settings(env={self.app_env!r}, "
            f"port={self.app_port}, "
            f"log_level={self.log_level!r})"
        )


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the application settings singleton.

    Uses lru_cache to ensure settings are constructed ONCE and shared
    across the entire application lifetime.  In tests, call:

        from unittest.mock import patch
        with patch("backend.core.config.get_settings", return_value=Settings(...)):
            ...

    Or use the conftest fixture that overrides this automatically.
    """
    return Settings()
