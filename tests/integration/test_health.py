"""
tests/integration/test_health.py
==================================
Integration tests for the /health, /ready, and /version endpoints.
These tests spin up a real FastAPI TestClient and make HTTP requests.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.mark.integration
class TestHealthEndpoint:
    """GET /health — liveness probe."""

    def test_health_returns_200(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_response_has_status_field(self, client: TestClient) -> None:
        response = client.get("/health")
        data = response.json()
        assert "status" in data
        assert data["status"] in ("healthy", "degraded", "unhealthy", "unknown")

    def test_health_response_has_version(self, client: TestClient) -> None:
        response = client.get("/health")
        data = response.json()
        assert "version" in data
        assert data["version"] == "0.1.0"

    def test_health_response_has_components(self, client: TestClient) -> None:
        response = client.get("/health")
        data = response.json()
        assert "components" in data
        assert isinstance(data["components"], list)

    def test_health_foundation_component_is_healthy(self, client: TestClient) -> None:
        response = client.get("/health")
        data = response.json()
        components = {c["name"]: c for c in data["components"]}
        assert "foundation" in components
        assert components["foundation"]["status"] == "healthy"

    def test_health_response_includes_request_id_header(self, client: TestClient) -> None:
        response = client.get("/health")
        assert "x-request-id" in response.headers

    def test_health_environment_matches_test_env(self, client: TestClient) -> None:
        response = client.get("/health")
        data = response.json()
        assert data["environment"] == "development"


@pytest.mark.integration
class TestReadyEndpoint:
    """GET /ready — readiness probe."""

    def test_ready_returns_200_when_foundation_healthy(self, client: TestClient) -> None:
        response = client.get("/ready")
        # Foundation module is always healthy, so ready should be 200
        assert response.status_code == 200

    def test_ready_response_has_status_field(self, client: TestClient) -> None:
        response = client.get("/ready")
        data = response.json()
        assert "status" in data

    def test_ready_has_checked_at_timestamp(self, client: TestClient) -> None:
        response = client.get("/ready")
        data = response.json()
        assert "checked_at" in data


@pytest.mark.integration
class TestVersionEndpoint:
    """GET /version — version info."""

    def test_version_returns_200(self, client: TestClient) -> None:
        response = client.get("/version")
        assert response.status_code == 200

    def test_version_has_correct_fields(self, client: TestClient) -> None:
        response = client.get("/version")
        data = response.json()
        assert data["name"] == "CyberShield"
        assert data["version"] == "0.1.0"
        assert data["module"] == "foundation"
        assert data["environment"] == "development"

    def test_version_includes_timestamp(self, client: TestClient) -> None:
        response = client.get("/version")
        data = response.json()
        assert "timestamp" in data


@pytest.mark.integration
class TestMiddleware:
    """Middleware behaviour verification."""

    def test_request_id_injected_in_response(self, client: TestClient) -> None:
        response = client.get("/health")
        assert "x-request-id" in response.headers
        request_id = response.headers["x-request-id"]
        assert len(request_id) == 36  # UUID v4 format

    def test_client_provided_request_id_echoed(self, client: TestClient) -> None:
        custom_id = "550e8400-e29b-41d4-a716-446655440001"
        response = client.get(
            "/health",
            headers={"X-Request-ID": custom_id},
        )
        assert response.headers.get("x-request-id") == custom_id

    def test_docs_accessible_in_development(self, client: TestClient) -> None:
        response = client.get("/docs")
        assert response.status_code == 200

    def test_unknown_route_returns_404(self, client: TestClient) -> None:
        response = client.get("/api/v1/nonexistent")
        assert response.status_code == 404
