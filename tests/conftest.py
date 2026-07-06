"""
tests/conftest.py — Shared Pytest Fixtures
==========================================
Provides reusable fixtures available to ALL test modules via pytest's
automatic fixture discovery (no imports required in test files).

Fixture scopes:
  - session   : created once per test session (expensive setup)
  - module    : once per test module
  - function  : once per test function (default, safest for isolation)

Naming convention:
  - settings_override   : modified Settings for tests
  - test_client         : FastAPI TestClient
  - tmp_data_dir        : temporary data directory
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from backend.core.config import Settings, get_settings
from backend.core.logging import configure_logging


# ---------------------------------------------------------------------------
# Logging — configure once for the test session
# ---------------------------------------------------------------------------
def pytest_configure(config: Any) -> None:  # noqa: ARG001
    """Configure structured logging for the test session."""
    configure_logging(level="DEBUG", format="console")


# ---------------------------------------------------------------------------
# Settings Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def test_settings_factory() -> type[Settings]:
    """
    Return the Settings class pre-configured for testing.

    Usage:
        def test_something(test_settings_factory):
            settings = test_settings_factory(log_level="DEBUG")
    """
    return Settings


@pytest.fixture()
def test_settings(tmp_path: Path) -> Settings:
    """
    Return Settings configured for testing.

    - Uses temp directories for data/models/reports
    - Disables all feature flags
    - Uses SQLite in-memory (fast)
    """
    return Settings(
        app_env="development",
        log_level="DEBUG",
        log_format="console",
        secret_key="test-secret-key-do-not-use-in-production",  # noqa: S106
        api_key="test-api-key",  # noqa: S106
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        data_dir=tmp_path / "data",
        models_dir=tmp_path / "models",
        reports_dir=tmp_path / "reports",
        feature_ingestion_enabled=False,
        feature_normalization_enabled=False,
        feature_detection_enabled=False,
        feature_mitre_enabled=False,
        feature_graph_enabled=False,
        feature_llm_enabled=False,
        feature_response_enabled=False,
        feature_audit_enabled=False,
        feature_dashboard_enabled=False,
    )


# ---------------------------------------------------------------------------
# FastAPI Test Client
# ---------------------------------------------------------------------------
@pytest.fixture()
def app(test_settings: Settings) -> Any:
    """
    Create a FastAPI application instance configured for testing.

    Uses test_settings so tests don't read from real .env file.
    """
    from backend.api.app import create_app  # noqa: PLC0415

    return create_app(settings=test_settings)


@pytest.fixture()
def client(app: Any) -> Generator[TestClient, None, None]:
    """
    Provide a FastAPI TestClient for HTTP-level testing.

    Usage:
        def test_health(client):
            response = client.get("/health")
            assert response.status_code == 200
    """
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# Data / File Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def tmp_data_dir(tmp_path: Path) -> Path:
    """
    Provide a temporary directory pre-populated with data subdirectories.

    Creates: tmp_path/data/raw/, tmp_path/data/normalized/, tmp_path/data/baseline/
    """
    data_dir = tmp_path / "data"
    for subdir in ("raw", "normalized", "baseline", "attack_reference"):
        (data_dir / subdir).mkdir(parents=True)
    return data_dir


@pytest.fixture()
def sample_raw_log_sysmon() -> str:
    """Sample Sysmon process creation log line."""
    return (
        '{"UtcTime":"2024-01-15T10:30:00.000Z","ProcessGuid":"{abc123}",'
        '"ProcessId":"1234","Image":"C:\\\\Windows\\\\System32\\\\cmd.exe",'
        '"CommandLine":"cmd.exe /c whoami","User":"CORP\\\\john.doe",'
        '"ParentImage":"C:\\\\Windows\\\\explorer.exe",'
        '"EventID":1,"Computer":"web-server-01"}'
    )


@pytest.fixture()
def sample_raw_log_windows_event() -> str:
    """Sample Windows Event 4688 log line."""
    return (
        '{"EventID":4688,"TimeCreated":"2024-01-15T10:30:00.000Z",'
        '"SubjectUserName":"john.doe","SubjectDomainName":"CORP",'
        '"NewProcessName":"C:\\\\Windows\\\\System32\\\\cmd.exe",'
        '"CommandLine":"cmd.exe","ProcessId":"0x1234",'
        '"Computer":"dc-01"}'
    )


@pytest.fixture()
def utc_timestamp() -> str:
    """Return a fixed UTC ISO 8601 timestamp for deterministic tests."""
    return "2024-01-15T10:30:00.000000Z"
