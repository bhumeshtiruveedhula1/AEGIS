"""
tests/unit/dashboard/test_dashboard_routes.py
==============================================
Module 7.1 — Dashboard API route tests.

All storage calls are patched so no disk I/O occurs.
Tests cover: response structure, status codes, empty states, error handling.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(UTC).isoformat()


def _empty_store(cls_path: str):
    """Return a patch that makes store.load_for_date() return []."""
    mock = MagicMock()
    mock.return_value.load_for_date.return_value = []
    mock.return_value.list_ids.return_value = []
    return patch(cls_path, mock)


# ---------------------------------------------------------------------------
# 1. Health check — confirms app factory works
# ---------------------------------------------------------------------------


class TestAppHealth:
    def test_health_endpoint_returns_200(self, client: TestClient) -> None:
        r = client.get("/health")
        assert r.status_code == 200

    def test_dashboard_html_served_at_root(self, client: TestClient) -> None:
        r = client.get("/")
        # Either 200 (frontend exists) or 200 with fallback message
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]


# ---------------------------------------------------------------------------
# 2. Overview endpoint
# ---------------------------------------------------------------------------


class TestOverviewEndpoint:
    BASE = "/api/v1/dashboard/overview"

    def test_returns_200(self, client: TestClient) -> None:
        with (
            patch("backend.api.routes.dashboard.OrchestratorStore") as mock_orch,
            patch("backend.api.routes.dashboard.MetricService") as mock_ms,
        ):
            mock_orch.return_value.load_for_date.return_value = []
            mock_ms.return_value.reader.store.load_latest.return_value = None
            mock_ms.return_value.get_platform_status.return_value = MagicMock(
                model_dump=lambda **kw: {"overall_status": "healthy", "components": {}}
            )
            r = client.get(self.BASE)
        assert r.status_code == 200

    def test_response_has_required_keys(self, client: TestClient) -> None:
        with (
            patch("backend.api.routes.dashboard.OrchestratorStore") as mock_orch,
            patch("backend.api.routes.dashboard.MetricService") as mock_ms,
        ):
            mock_orch.return_value.load_for_date.return_value = []
            mock_ms.return_value.reader.store.load_latest.return_value = None
            mock_ms.return_value.get_platform_status.return_value = MagicMock(
                model_dump=lambda **kw: {"overall_status": "healthy", "components": {}}
            )
            r = client.get(self.BASE)
        body = r.json()
        assert "generated_at" in body
        assert "orchestration_today" in body
        assert "metrics" in body

    def test_orchestration_counts_when_records_exist(self, client: TestClient) -> None:
        now = datetime.now(UTC)
        approval = MagicMock()
        approval.status = "APPROVED"

        rec1 = MagicMock()
        rec1.approval.status = "APPROVED"
        rec1.created_at = now
        rec2 = MagicMock()
        rec2.approval.status = "PENDING"
        rec2.created_at = now

        with (
            patch("backend.api.routes.dashboard.OrchestratorStore") as mock_orch,
            patch("backend.api.routes.dashboard.MetricService") as mock_ms,
        ):
            mock_orch.return_value.load_for_date.return_value = [rec1, rec2]
            mock_ms.return_value.reader.store.load_latest.return_value = None
            mock_ms.return_value.get_platform_status.return_value = MagicMock(
                model_dump=lambda **kw: {"overall_status": "healthy", "components": {}}
            )
            r = client.get(self.BASE)
        body = r.json()
        assert body["orchestration_today"]["total"] == 2
        assert body["orchestration_today"]["approved"] == 1
        assert body["orchestration_today"]["pending"] == 1

    def test_snapshot_unavailable_when_store_empty(self, client: TestClient) -> None:
        with (
            patch("backend.api.routes.dashboard.OrchestratorStore") as mock_orch,
            patch("backend.api.routes.dashboard.MetricService") as mock_ms,
        ):
            mock_orch.return_value.load_for_date.return_value = []
            mock_ms.return_value.reader.store.load_latest.return_value = None
            mock_ms.return_value.get_platform_status.return_value = MagicMock(
                model_dump=lambda **kw: {}
            )
            r = client.get(self.BASE)
        assert r.json()["snapshot_available"] is False


# ---------------------------------------------------------------------------
# 3. Incidents endpoint
# ---------------------------------------------------------------------------


class TestIncidentsEndpoint:
    BASE = "/api/v1/dashboard/incidents"

    def test_returns_200(self, client: TestClient) -> None:
        with patch("backend.api.routes.dashboard.ContextStore") as mock_cs:
            mock_cs.return_value.load_for_date.return_value = []
            r = client.get(self.BASE)
        assert r.status_code == 200

    def test_empty_state_count_zero(self, client: TestClient) -> None:
        with patch("backend.api.routes.dashboard.ContextStore") as mock_cs:
            mock_cs.return_value.load_for_date.return_value = []
            r = client.get(self.BASE)
        body = r.json()
        assert body["count"] == 0
        assert body["incidents"] == []

    def test_incidents_sorted_newest_first(self, client: TestClient) -> None:
        from datetime import timedelta

        now = datetime.now(UTC)
        older = MagicMock()
        older.created_at = now - timedelta(hours=1)
        newer = MagicMock()
        newer.created_at = now
        for mock in (older, newer):
            mock.identity.alert_id = "a"
            mock.identity.entity_id = "e"
            mock.identity.host = "h"
            mock.identity.user = "u"
            mock.detection.severity = "HIGH"
            mock.detection.anomaly_score = 0.8
            mock.detection.detection_confidence = 0.9
            mock.detection.alert_status = "ACTIVE"

        with patch("backend.api.routes.dashboard.ContextStore") as mock_cs:
            # Endpoint queries today then yesterday; return records only on first call
            mock_cs.return_value.load_for_date.side_effect = [[older, newer], []]
            r = client.get(self.BASE)
        body = r.json()
        assert body["count"] == 2
        # newer should come first
        ts0 = body["incidents"][0]["timestamp"]
        ts1 = body["incidents"][1]["timestamp"]
        assert ts0 >= ts1

    def test_limit_param_respected(self, client: TestClient) -> None:
        now = datetime.now(UTC)
        recs = []
        for i in range(10):
            m = MagicMock()
            m.created_at = now
            m.identity.alert_id = f"a{i}"
            m.identity.entity_id = "e"
            m.identity.host = "h"
            m.identity.user = "u"
            m.detection.severity = "LOW"
            m.detection.anomaly_score = 0.3
            m.detection.detection_confidence = 0.5
            m.detection.alert_status = "ACTIVE"
            recs.append(m)

        with patch("backend.api.routes.dashboard.ContextStore") as mock_cs:
            mock_cs.return_value.load_for_date.return_value = recs
            r = client.get(f"{self.BASE}?limit=3")
        assert r.json()["count"] == 3


# ---------------------------------------------------------------------------
# 4. Metrics endpoint
# ---------------------------------------------------------------------------


class TestMetricsEndpoint:
    BASE = "/api/v1/dashboard/metrics"

    def test_returns_200(self, client: TestClient) -> None:
        with patch("backend.api.routes.dashboard.MetricService") as mock_ms:
            mock_ms.return_value.reader.store.load_latest.return_value = None
            r = client.get(self.BASE)
        assert r.status_code == 200

    def test_snapshot_none_when_no_data(self, client: TestClient) -> None:
        with patch("backend.api.routes.dashboard.MetricService") as mock_ms:
            mock_ms.return_value.reader.store.load_latest.return_value = None
            r = client.get(self.BASE)
        assert r.json()["snapshot"] is None

    def test_snapshot_serialized_when_present(self, client: TestClient) -> None:
        mock_snap = MagicMock()
        mock_snap.model_dump.return_value = {"pipeline": {"events_normalized": {"value": 42}}}
        with patch("backend.api.routes.dashboard.MetricService") as mock_ms:
            mock_ms.return_value.reader.store.load_latest.return_value = mock_snap
            r = client.get(self.BASE)
        body = r.json()
        assert body["snapshot"] is not None
        assert body["snapshot"]["pipeline"]["events_normalized"]["value"] == 42


# ---------------------------------------------------------------------------
# 5. Chains endpoint
# ---------------------------------------------------------------------------


class TestChainsEndpoint:
    BASE = "/api/v1/dashboard/chains"

    def test_returns_200(self, client: TestClient) -> None:
        with patch("backend.api.routes.dashboard.ContextStore") as mock_cs:
            mock_cs.return_value.load_for_date.return_value = []
            r = client.get(self.BASE)
        assert r.status_code == 200

    def test_empty_when_no_chain_data(self, client: TestClient) -> None:
        now = datetime.now(UTC)
        ctx = MagicMock()
        ctx.created_at = now
        ctx.chain = None
        with patch("backend.api.routes.dashboard.ContextStore") as mock_cs:
            mock_cs.return_value.load_for_date.return_value = [ctx]
            r = client.get(self.BASE)
        # contexts with no chain are filtered out
        assert r.json()["count"] == 0


# ---------------------------------------------------------------------------
# 6. Context detail endpoint
# ---------------------------------------------------------------------------


class TestContextEndpoint:
    BASE = "/api/v1/dashboard/context"

    def test_404_when_not_found(self, client: TestClient) -> None:
        with patch("backend.api.routes.dashboard.ContextStore") as mock_cs:
            mock_cs.return_value.load.side_effect = Exception("not found")
            r = client.get(f"{self.BASE}/nonexistent-id")
        assert r.status_code == 404

    def test_returns_context_when_found(self, client: TestClient) -> None:
        ctx = MagicMock()
        ctx.model_dump.return_value = {
            "context_id": "ctx-001",
            "identity": {},
            "detection": {},
        }
        with patch("backend.api.routes.dashboard.ContextStore") as mock_cs:
            mock_cs.return_value.load.return_value = ctx
            r = client.get(f"{self.BASE}/ctx-001")
        assert r.status_code == 200
        assert r.json()["context"]["context_id"] == "ctx-001"


# ---------------------------------------------------------------------------
# 7. Orchestrator endpoint
# ---------------------------------------------------------------------------


class TestOrchestratorEndpoint:
    BASE = "/api/v1/dashboard/orchestrator"

    def test_returns_200(self, client: TestClient) -> None:
        with patch("backend.api.routes.dashboard.OrchestratorStore") as mock_os:
            mock_os.return_value.load_for_date.return_value = []
            r = client.get(self.BASE)
        assert r.status_code == 200

    def test_empty_records(self, client: TestClient) -> None:
        with patch("backend.api.routes.dashboard.OrchestratorStore") as mock_os:
            mock_os.return_value.load_for_date.return_value = []
            r = client.get(self.BASE)
        body = r.json()
        assert body["count"] == 0
        assert body["records"] == []

    def test_records_serialized(self, client: TestClient) -> None:
        now = datetime.now(UTC)
        rec = MagicMock()
        rec.created_at = now
        rec.model_dump.return_value = {
            "orchestration_id": "orch-001",
            "playbook_id": "observe_only",
        }
        with patch("backend.api.routes.dashboard.OrchestratorStore") as mock_os:
            # Endpoint queries today then yesterday; records on today only
            mock_os.return_value.load_for_date.side_effect = [[rec], []]
            r = client.get(self.BASE)
        body = r.json()
        assert body["count"] == 1
        assert body["records"][0]["orchestration_id"] == "orch-001"

    def test_single_record_404(self, client: TestClient) -> None:
        with patch("backend.api.routes.dashboard.OrchestratorStore") as mock_os:
            mock_os.return_value.load.side_effect = Exception("not found")
            r = client.get(f"{self.BASE}/nonexistent")
        assert r.status_code == 404

    def test_single_record_found(self, client: TestClient) -> None:
        rec = MagicMock()
        rec.model_dump.return_value = {"orchestration_id": "orch-001"}
        with patch("backend.api.routes.dashboard.OrchestratorStore") as mock_os:
            mock_os.return_value.load.return_value = rec
            r = client.get(f"{self.BASE}/orch-001")
        assert r.status_code == 200
        assert r.json()["record"]["orchestration_id"] == "orch-001"


# ---------------------------------------------------------------------------
# 8. API schema / OpenAPI presence
# ---------------------------------------------------------------------------


class TestApiSchema:
    def test_openapi_schema_has_dashboard_tag(self, client: TestClient) -> None:
        r = client.get("/openapi.json")
        assert r.status_code == 200
        schema = r.json()
        # FastAPI populates tags from path operations; check paths use Dashboard tag
        all_tags: list[str] = []
        for path_item in schema.get("paths", {}).values():
            for operation in path_item.values():
                all_tags.extend(operation.get("tags", []))
        assert "Dashboard" in all_tags

    def test_all_dashboard_paths_present(self, client: TestClient) -> None:
        r = client.get("/openapi.json")
        paths = r.json().get("paths", {})
        expected = [
            "/api/v1/dashboard/overview",
            "/api/v1/dashboard/incidents",
            "/api/v1/dashboard/metrics",
            "/api/v1/dashboard/chains",
            "/api/v1/dashboard/orchestrator",
        ]
        for path in expected:
            assert path in paths, f"Missing path: {path}"


# ---------------------------------------------------------------------------
# 9. Error resilience — storage exceptions don't crash endpoints
# ---------------------------------------------------------------------------


class TestErrorResilience:
    def test_overview_survives_store_exception(self, client: TestClient) -> None:
        with (
            patch("backend.api.routes.dashboard.OrchestratorStore") as mock_orch,
            patch("backend.api.routes.dashboard.MetricService") as mock_ms,
        ):
            mock_orch.return_value.load_for_date.side_effect = Exception("disk error")
            mock_ms.return_value.reader.store.load_latest.side_effect = Exception("disk error")
            mock_ms.return_value.get_platform_status.return_value = MagicMock(
                model_dump=lambda **kw: {}
            )
            r = client.get("/api/v1/dashboard/overview")
        assert r.status_code == 200  # graceful empty state

    def test_incidents_survives_store_exception(self, client: TestClient) -> None:
        with patch("backend.api.routes.dashboard.ContextStore") as mock_cs:
            mock_cs.return_value.load_for_date.side_effect = OSError("disk error")
            r = client.get("/api/v1/dashboard/incidents")
        assert r.status_code == 200
        assert r.json()["count"] == 0
