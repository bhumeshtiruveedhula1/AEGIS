"""
tests/integration/test_ingest_route.py
=======================================
Integration test for POST /api/v1/ingest.

Strategy
--------
The DetectionService requires a trained IsolationForest model to score
events.  Because the test environment starts with an empty models/ dir,
the fixture:

  1. Generates 50 synthetic "normal" CanonicalEvents (auth success,
     business-hours, no novelty).
  2. Runs them through FeaturePipeline to obtain real FeatureRecord objects.
  3. Trains an IsolationForest in a temp models_dir using
     DetectionService.train_from_features().
  4. Creates a FastAPI test app that:
       - sets feature_ingestion_enabled=True  (activates the router)
       - points models_dir at the temp dir     (so the route's DetectionService
         auto-loads the just-trained model)
       - sets anomaly_score_threshold=0.0      (any score → alert, making the
         test deterministic — we are testing API plumbing, not model quality)
       - uses tmp_path for data writes         (context, orchestrator, etc.)

The test then POSTs a single brute-force auth event (T1110, logon_failure)
and verifies:
  - HTTP 200
  - alert_fired == True
  - a context_id is returned
  - GET /api/v1/dashboard/incidents returns the persisted context
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.baseline.models import EntityKey
from backend.core.config import Settings
from backend.features.models import FEATURE_SCHEMA_VERSION, FeatureRecord, FeatureVector
from backend.shared.utils.id_utils import generate_id

# ---------------------------------------------------------------------------
# Helpers — generate minimal FeatureRecords for model training
# ---------------------------------------------------------------------------

_FEATURE_NAMES = [
    "hour_of_day",
    "day_of_week",
    "is_business_hours",
    "hour_baseline_frequency",
    "hour_relative_frequency",
    "day_baseline_frequency",
    "is_peak_hour",
    "time_since_last_seen_hours",
    "event_type_frequency",
    "event_type_frequency_rank",
    "action_frequency",
    "result_failure_rate_baseline",
    "result_is_failure",
    "source_frequency",
    "entity_observation_count",
    "baseline_window_days",
    "auth_unexpected_failure",
    "dst_ip_is_novel",
    "src_ip_is_novel",
    "port_is_novel",
    "protocol_is_novel",
    "port_baseline_frequency",
    "protocol_baseline_frequency",
    "bytes_out_z_score",
    "bytes_out_percentile_rank",
    "unique_dst_ips_baseline",
    "connection_count_baseline",
    "process_is_novel",
    "parent_process_is_novel",
    "parent_child_pair_is_novel",
    "process_frequency_rank",
    "unique_processes_baseline",
    "process_event_count_baseline",
    "pid_z_score",
    "has_command_line",
    "logon_type_is_novel",
    "auth_package_is_novel",
    "logon_type_baseline_frequency",
    "auth_package_baseline_frequency",
    "auth_failure_rate_baseline",
    "auth_event_count_baseline",
    "windows_event_id_is_novel",
    "modbus_register_z_score",
    "modbus_value_z_score",
    "modbus_register_is_in_range",
    "modbus_value_is_in_range",
    "modbus_function_code_is_novel",
    "supervisory_host_is_novel",
    "modbus_event_count_baseline",
    "has_user_baseline",
    "has_host_baseline",
    "has_source_baseline",
    "has_user_host_baseline",
    "entity_unique_dst_ips",
    "entity_unique_processes",
    "entity_auth_failure_count",
    "entity_modbus_event_count",
]


def _make_feature_record(
    entity_id: str = "alice::dc-01",
    *,
    result_is_failure: float = 0.0,
    is_business_hours: float = 1.0,
    hour_of_day: float = 10.0,
    day_of_week: float = 1.0,
) -> FeatureRecord:
    """Return a minimal FeatureRecord with realistic normal values."""
    entity_key = EntityKey(entity_type="user_host", entity_id=entity_id)
    values: dict[str, float] = {name: 0.0 for name in _FEATURE_NAMES}
    # Populate a few that make the record look "normal"
    values.update(
        {
            "hour_of_day": hour_of_day,
            "day_of_week": day_of_week,
            "is_business_hours": is_business_hours,
            "result_is_failure": result_is_failure,
            "has_user_baseline": 1.0,
            "has_host_baseline": 1.0,
            "has_source_baseline": 1.0,
            "has_user_host_baseline": 1.0,
            "entity_observation_count": 50.0,
            "baseline_window_days": 7.0,
        }
    )
    fv = FeatureVector(
        entity_key=entity_key,
        schema_version=FEATURE_SCHEMA_VERSION,
        values=values,
        extracted_at=datetime.now(UTC),
    )
    return FeatureRecord(
        event_id=generate_id(),
        event_type="UserLogon",
        event_source="windows_event",
        event_timestamp=datetime.now(UTC),
        event_host="dc-01",
        event_user="alice",
        entity_key=entity_key,
        baseline_available=True,
        feature_vector=fv,
    )


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ingest_client(tmp_path_factory: pytest.TempPathFactory) -> TestClient:
    """
    Spin up a FastAPI TestClient with:
      - a trained IsolationForest in a temp models_dir
      - feature_ingestion_enabled=True
      - anomaly_score_threshold=0.0  (any score → alert — tests API plumbing)
      - tmp data_dir for write-side stores (context, orchestrator, etc.)
    """
    from backend.detection.service import DetectionService

    tmp = tmp_path_factory.mktemp("ingest_test")
    models_dir: Path = tmp / "models"
    data_dir: Path = tmp / "data"
    models_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    # --- Generate 50 normal FeatureRecords across a few entity IDs ---
    import random

    rng = random.Random(42)
    normal_records: list[FeatureRecord] = []
    users = ["alice", "bob", "carol", "dave", "eve"]
    hosts = ["dc-01", "ws-01", "ws-02"]
    for i in range(50):
        u = rng.choice(users)
        h = rng.choice(hosts)
        record = _make_feature_record(
            entity_id=f"{u}::{h}",
            result_is_failure=0.0,
            is_business_hours=1.0,
            hour_of_day=float(rng.randint(8, 17)),
            day_of_week=float(rng.randint(0, 4)),
        )
        normal_records.append(record)

    # --- Train a model in the temp models_dir ---
    ds = DetectionService(
        models_dir=models_dir,
        features_dir=data_dir / "features",
        auto_load=False,
        threshold=0.0,  # not used during training
    )
    ds.train_from_features(feature_records=normal_records)

    # --- Build test settings pointing at the temp dirs ---
    test_settings = Settings(
        app_env="development",
        log_level="WARNING",
        log_format="console",
        secret_key="test-secret-key-do-not-use-in-production",
        api_key="test-api-key",
        database_url=f"sqlite+aiosqlite:///{tmp / 'test.db'}",
        data_dir=data_dir,
        models_dir=models_dir,
        reports_dir=tmp / "reports",
        feature_ingestion_enabled=True,  # ← activate the ingestion router
        feature_normalization_enabled=False,
        feature_detection_enabled=False,
        feature_mitre_enabled=False,
        feature_graph_enabled=False,
        feature_llm_enabled=False,
        feature_response_enabled=False,
        feature_audit_enabled=False,
        feature_dashboard_enabled=False,
        anomaly_score_threshold=0.0,  # ← any event is an alert (plumbing test)
    )

    from backend.api.app import create_app

    app = create_app(settings=test_settings)

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# The synthetic brute-force event body
# ---------------------------------------------------------------------------

BRUTE_FORCE_EVENT = {
    "event_type": "UserLogon",
    "source": "windows_event",
    "host": "dc-01",
    "user": "administrator",
    "resource": "DOMAIN\\administrator",
    "action": "logon",
    "result": "failure",
    "source_ip": "10.0.0.99",
    "target_host": "dc-01",
    "timestamp": "2024-01-15T03:30:00Z",
    "mitre_technique_hint": "T1110",
    "synthetic": True,
    "windows_event_id": 4625,
    "logon_type": "Network",
    "auth_package": "NTLM",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIngestRoute:
    """POST /api/v1/ingest — live single-event ingestion."""

    def test_ingest_returns_200(self, ingest_client: TestClient) -> None:
        """Route must always return 200, even on normal events."""
        response = ingest_client.post("/api/v1/ingest/", json=BRUTE_FORCE_EVENT)
        assert response.status_code == 200, response.text

    def test_ingest_alert_fired(self, ingest_client: TestClient) -> None:
        """With threshold=0.0 and a trained model, alert must fire."""
        response = ingest_client.post("/api/v1/ingest/", json=BRUTE_FORCE_EVENT)
        data = response.json()
        assert data["alert_fired"] is True, f"Expected alert_fired=True, got: {data}"

    def test_ingest_returns_context_id(self, ingest_client: TestClient) -> None:
        """An AttackContext must be persisted and its ID returned."""
        response = ingest_client.post("/api/v1/ingest/", json=BRUTE_FORCE_EVENT)
        data = response.json()
        assert data.get("context_id") is not None, f"Expected a context_id, got: {data}"
        assert data["context_id"].startswith(
            "ctx-"
        ), f"context_id format unexpected: {data['context_id']}"

    def test_ingest_returns_alert_id(self, ingest_client: TestClient) -> None:
        """A DetectionAlert ID must be included in the response."""
        response = ingest_client.post("/api/v1/ingest/", json=BRUTE_FORCE_EVENT)
        data = response.json()
        assert data.get("alert_id") is not None, f"Expected alert_id, got: {data}"

    def test_ingest_returns_time_to_alert(self, ingest_client: TestClient) -> None:
        """MTTD field must be a positive number of milliseconds."""
        response = ingest_client.post("/api/v1/ingest/", json=BRUTE_FORCE_EVENT)
        data = response.json()
        assert data.get("time_to_alert_ms") is not None, f"Expected time_to_alert_ms, got: {data}"
        assert data["time_to_alert_ms"] >= 0.0

    def test_ingest_context_appears_in_incidents(self, ingest_client: TestClient) -> None:
        """
        The persisted AttackContext must appear in GET /api/v1/dashboard/incidents.

        This verifies end-to-end: ingest → persist → dashboard readable.
        """
        # POST the event
        post_resp = ingest_client.post("/api/v1/ingest/", json=BRUTE_FORCE_EVENT)
        assert post_resp.status_code == 200
        post_data = post_resp.json()
        assert post_data["alert_fired"], f"Alert did not fire: {post_data}"
        context_id = post_data["context_id"]

        # GET /incidents
        get_resp = ingest_client.get("/api/v1/dashboard/incidents")
        assert get_resp.status_code == 200, get_resp.text
        incidents_data = get_resp.json()
        assert "incidents" in incidents_data, f"Missing 'incidents' key: {incidents_data}"
        assert (
            incidents_data["count"] > 0
        ), f"Expected at least one incident, got count=0. Data: {incidents_data}"

        # The context_id from the POST must appear in the incidents list
        incident_ids = [i["context_id"] for i in incidents_data["incidents"]]
        assert (
            context_id in incident_ids
        ), f"context_id {context_id!r} not found in incidents: {incident_ids}"
