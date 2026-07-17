"""
tests/unit/dashboard/conftest.py — Shared fixtures for dashboard API tests.

Uses FastAPI TestClient. All storage calls are patched to return empty-state
data so tests are hermetic (no real disk I/O needed).
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.core.config import Settings


@pytest.fixture(scope="session")
def test_settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    """Settings with a temp data_dir so storage doesn't touch real disk."""
    td = tmp_path_factory.mktemp("data")
    return Settings(data_dir=td, log_level="ERROR")



@pytest.fixture(scope="session")
def client(test_settings: Settings) -> TestClient:
    """TestClient for the full FastAPI app."""
    app = create_app(settings=test_settings)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def mock_overview_data() -> dict:
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "platform_status": {"overall_status": "healthy", "components": {}},
        "snapshot_available": False,
        "metrics": {},
        "orchestration_today": {"total": 3, "approved": 2, "rejected": 0, "pending": 1},
    }


@pytest.fixture()
def mock_incidents_data() -> dict:
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "count": 1,
        "incidents": [
            {
                "context_id": "ctx-001",
                "alert_id": "alert-001",
                "entity_id": "entity-001",
                "host": "host-01",
                "user": "user-01",
                "timestamp": datetime.now(UTC).isoformat(),
                "severity": "HIGH",
                "anomaly_score": 0.82,
                "detection_confidence": 0.91,
                "status": "ACTIVE",
            }
        ],
    }
