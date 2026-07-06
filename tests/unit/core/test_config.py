"""
tests/unit/core/test_config.py
==============================
Unit tests for backend.core.config.Settings and get_settings().
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.core.config import Settings, get_settings


# ---------------------------------------------------------------------------
# Default Settings
# ---------------------------------------------------------------------------
class TestSettingsDefaults:
    """Settings constructed with all defaults must have sensible values."""

    def test_default_app_env_is_development(self, test_settings: Settings) -> None:
        assert test_settings.app_env == "development"

    def test_default_log_level_is_info(self, test_settings: Settings) -> None:
        # test_settings overrides to DEBUG, so create a fresh one
        s = Settings(
            data_dir="/tmp/cybershield_test_data",
            models_dir="/tmp/cybershield_test_models",
            reports_dir="/tmp/cybershield_test_reports",
        )
        assert s.log_level == "INFO"

    def test_default_port_is_8000(self, test_settings: Settings) -> None:
        s = Settings(
            data_dir="/tmp/cybershield_test_data2",
            models_dir="/tmp/cybershield_test_models2",
            reports_dir="/tmp/cybershield_test_reports2",
        )
        assert s.app_port == 8000

    def test_all_feature_flags_default_false(self, test_settings: Settings) -> None:
        assert test_settings.feature_ingestion_enabled is False
        assert test_settings.feature_detection_enabled is False
        assert test_settings.feature_llm_enabled is False
        assert test_settings.feature_response_enabled is False
        assert test_settings.feature_audit_enabled is False
        assert test_settings.feature_dashboard_enabled is False


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
class TestSettingsValidation:
    """Invalid settings values must raise ValidationError."""

    def test_invalid_app_env_raises(self) -> None:
        with pytest.raises(ValidationError):
            Settings(
                app_env="invalid_env",  # type: ignore[arg-type]
                data_dir="/tmp/d",
                models_dir="/tmp/m",
                reports_dir="/tmp/r",
            )

    def test_invalid_log_level_raises(self) -> None:
        with pytest.raises(ValidationError):
            Settings(
                log_level="VERBOSE",  # type: ignore[arg-type]
                data_dir="/tmp/d2",
                models_dir="/tmp/m2",
                reports_dir="/tmp/r2",
            )

    def test_port_below_1024_raises(self) -> None:
        with pytest.raises(ValidationError):
            Settings(
                app_port=80,
                data_dir="/tmp/d3",
                models_dir="/tmp/m3",
                reports_dir="/tmp/r3",
            )

    def test_contamination_above_05_raises(self) -> None:
        with pytest.raises(ValidationError):
            Settings(
                isolation_forest_contamination=0.6,
                data_dir="/tmp/d4",
                models_dir="/tmp/m4",
                reports_dir="/tmp/r4",
            )

    def test_anomaly_threshold_above_1_raises(self) -> None:
        with pytest.raises(ValidationError):
            Settings(
                anomaly_score_threshold=1.5,
                data_dir="/tmp/d5",
                models_dir="/tmp/m5",
                reports_dir="/tmp/r5",
            )


# ---------------------------------------------------------------------------
# CORS Origins Parser
# ---------------------------------------------------------------------------
class TestCorsOriginsParser:
    """CORS origins should be accepted as string or list."""

    def test_cors_origins_as_list(self) -> None:
        s = Settings(
            cors_allowed_origins=["http://localhost:3000"],
            data_dir="/tmp/dc",
            models_dir="/tmp/mc",
            reports_dir="/tmp/rc",
        )
        assert "http://localhost:3000" in s.cors_allowed_origins

    def test_cors_origins_as_comma_string(self) -> None:
        s = Settings(
            cors_allowed_origins="http://a.com,http://b.com",
            data_dir="/tmp/dc2",
            models_dir="/tmp/mc2",
            reports_dir="/tmp/rc2",
        )
        assert len(s.cors_allowed_origins) == 2
        assert "http://a.com" in s.cors_allowed_origins


# ---------------------------------------------------------------------------
# Convenience Properties
# ---------------------------------------------------------------------------
class TestSettingsProperties:
    def test_is_development_true_for_dev_env(self, test_settings: Settings) -> None:
        assert test_settings.is_development is True

    def test_is_production_false_for_dev_env(self, test_settings: Settings) -> None:
        assert test_settings.is_production is False

    def test_database_is_sqlite_true_for_sqlite_url(self, test_settings: Settings) -> None:
        assert test_settings.database_is_sqlite is True

    def test_database_is_sqlite_false_for_postgres(self) -> None:
        s = Settings(
            database_url="postgresql+asyncpg://user:pass@localhost/db",
            data_dir="/tmp/dpg",
            models_dir="/tmp/mpg",
            reports_dir="/tmp/rpg",
        )
        assert s.database_is_sqlite is False


# ---------------------------------------------------------------------------
# get_settings Singleton
# ---------------------------------------------------------------------------
class TestGetSettings:
    def test_get_settings_returns_settings_instance(self) -> None:
        settings = get_settings()
        assert isinstance(settings, Settings)

    def test_get_settings_is_cached(self) -> None:
        """get_settings must return the same object on repeated calls."""
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2
