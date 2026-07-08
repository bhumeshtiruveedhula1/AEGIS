"""
tests/integration/test_metrics_pipeline.py
===========================================
End-to-end integration test for Module 2.3 Metrics Engine.

Tests the complete flow:
  BaselineProfile + NormReport + FeatureReport
    → MetricService.collect_all()
    → MetricSnapshot (all 6 domains)
    → MetricStore.save() → JSONL history + snapshot files + manifest
    → MetricReader queries (trend, compare, status)
    → Serialisation round-trip (JSONL integrity)

No mocking — uses real model construction and real disk I/O in tmp_path.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from backend.metrics.exceptions import MetricQueryError
from backend.metrics.models import (
    METRICS_SCHEMA_VERSION,
    MetricAvailability,
    MetricDomain,
    MetricRecord,
)
from backend.metrics.service import MetricService

from tests.unit.metrics.conftest import (
    make_baseline_profile,
    make_feature_pipeline_report,
    make_mock_norm_report,
)


# ===========================================================================
# Full pipeline: real data → snapshot → disk → query
# ===========================================================================

class TestFullMetricsPipeline:
    """End-to-end test: real data → MetricSnapshot → JSONL → MetricReader."""

    def test_full_pipeline_produces_snapshot(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        norm = make_mock_norm_report(normalized=5000, failed=50, duration=15.0, sources=6)
        feat = make_feature_pipeline_report(records=20000, errors=5, warnings=30, duration=8.0)
        profile = make_baseline_profile(entity_count=20)

        snap = service.collect_all(
            norm_report=norm,
            feature_report=feat,
            baseline_profile=profile,
            tags={"run": "integration-test-001"},
        )

        # Schema
        assert snap.schema_version == METRICS_SCHEMA_VERSION

        # Pipeline domain
        assert snap.pipeline.events_normalized.is_computed
        assert snap.pipeline.events_normalized.safe_float() == 5000.0
        assert snap.pipeline.events_failed.safe_float() == 50.0
        assert snap.pipeline.feature_records_produced.safe_float() == 20000.0

        # Baseline domain
        assert snap.baseline.entity_count.is_computed
        assert snap.baseline.entity_count.safe_float() == 20.0

        # Feature domain
        assert snap.feature.feature_schema_version.is_computed
        assert snap.feature.feature_dimension.safe_float() == 56.0
        assert snap.feature.total_feature_records.is_computed

        # Detection domain — always UNAVAILABLE
        assert snap.detection.detection_rate.availability == MetricAvailability.UNAVAILABLE
        assert snap.detection.false_positive_rate.availability == MetricAvailability.UNAVAILABLE

        # Response domain — always UNAVAILABLE
        assert snap.response.mean_time_to_respond_seconds.availability == MetricAvailability.UNAVAILABLE

        # Health domain
        assert snap.health.metrics_schema_version.is_computed
        assert len(snap.health.components) >= 6

        # Tags
        assert snap.tags.get("run") == "integration-test-001"

    def test_full_pipeline_persists_to_disk(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        norm = make_mock_norm_report(normalized=1000)
        snap = service.collect_all(norm_report=norm)

        # Check all three storage artifacts
        history_file = tmp_path / "history.jsonl"
        manifest_file = tmp_path / "manifest.json"
        snapshot_file = tmp_path / "snapshots" / f"{snap.snapshot_id}.json"

        assert history_file.exists(), "history.jsonl must exist"
        assert manifest_file.exists(), "manifest.json must exist"
        assert snapshot_file.exists(), "per-snapshot JSON must exist"

    def test_history_jsonl_is_valid(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        for i in range(3):
            service.collect_all(tags={"iteration": str(i)})

        history_file = tmp_path / "history.jsonl"
        lines = history_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 3
        for line in lines:
            parsed = json.loads(line)
            assert "snapshot" in parsed
            assert "record_id" in parsed

    def test_manifest_valid_json(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all()
        manifest_file = tmp_path / "manifest.json"
        m = json.loads(manifest_file.read_text(encoding="utf-8"))
        assert "entries" in m
        assert "total_snapshots" in m
        assert m["total_snapshots"] == 1

    def test_snapshot_json_roundtrip(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        snap = service.collect_all(norm_report=make_mock_norm_report(normalized=7777))
        snapshot_file = tmp_path / "snapshots" / f"{snap.snapshot_id}.json"
        raw = json.loads(snapshot_file.read_text(encoding="utf-8"))
        # Deserialise back
        reloaded = MetricRecord.model_validate(raw)
        assert reloaded.snapshot.snapshot_id == snap.snapshot_id
        events = reloaded.snapshot.pipeline.events_normalized.safe_float()
        assert events == 7777.0


# ===========================================================================
# Multi-run: trend and comparison
# ===========================================================================

class TestMultiRunAnalysis:

    def test_trend_shows_increasing_events(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        for count in [1000, 2000, 3000]:
            service.collect_all(norm_report=make_mock_norm_report(normalized=count))

        points = service.reader.trend(MetricDomain.PIPELINE, "events_normalized")
        assert len(points) == 3
        values = [v for _, v in points]
        assert values == [1000.0, 2000.0, 3000.0]

    def test_trend_empty_for_unavailable_domain(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all()
        points = service.reader.trend(MetricDomain.DETECTION, "detection_rate")
        assert points == []

    def test_compare_two_runs_detects_improvement(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all(norm_report=make_mock_norm_report(normalized=1000, failed=100))
        service.collect_all(norm_report=make_mock_norm_report(normalized=2000, failed=10))
        comp = service.compare_last_runs()
        assert comp is not None
        assert len(comp["improvements"]) > 0

    def test_compare_missing_id_raises(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all()
        with pytest.raises(MetricQueryError):
            service.reader.compare_snapshots("bad-id-1", "bad-id-2")

    def test_trend_summary_correct_values(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        for count in [100, 200, 300]:
            service.collect_all(norm_report=make_mock_norm_report(normalized=count))
        summary = service.reader.trend_summary(MetricDomain.PIPELINE, "events_normalized")
        assert summary["count"] == 3
        assert summary["min"] == 100.0
        assert summary["max"] == 300.0
        assert abs(summary["mean"] - 200.0) < 0.1


# ===========================================================================
# Platform status
# ===========================================================================

class TestPlatformStatus:

    def test_status_no_data_before_collection(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        status = service.get_platform_status()
        assert status["status"] == "no_data"

    def test_status_after_full_collection(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all(
            norm_report=make_mock_norm_report(),
            baseline_profile=make_baseline_profile(entity_count=5),
        )
        status = service.get_platform_status()
        assert status["status"] in ("healthy", "degraded", "critical")
        assert "components" in status
        assert status["snapshot_count"] == 1

    def test_status_schema_version(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all()
        status = service.get_platform_status()
        assert status["schema_version"] == METRICS_SCHEMA_VERSION


# ===========================================================================
# Edge cases
# ===========================================================================

class TestEdgeCases:

    def test_empty_collect_all_no_crash(self, tmp_path: Path) -> None:
        """collect_all with zero data must not raise."""
        service = MetricService(store_dir=tmp_path)
        snap = service.collect_all()  # no kwargs
        assert snap is not None

    def test_concurrent_saves_no_corruption(self, tmp_path: Path) -> None:
        """Simulate sequential saves that could corrupt JSONL in practice."""
        service = MetricService(store_dir=tmp_path)
        for i in range(10):
            service.collect_all(tags={"i": str(i)})
        records = list(service.store.iter_history())
        assert len(records) == 10

    def test_purge_then_new_collection(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        for _ in range(5):
            service.collect_all()
        future = datetime.now(UTC) + timedelta(days=1)
        purged = service.store.purge_before(future)
        assert purged == 5
        # Fresh collection still works
        service.collect_all()
        assert service.reader.snapshot_count() == 1

    def test_metric_availability_honesty(self, tmp_path: Path) -> None:
        """Verify no COMPUTED metrics appear with None value."""
        from backend.metrics.models import MetricValue as MV
        service = MetricService(store_dir=tmp_path)
        snap = service.collect_all()
        for domain_obj in [snap.pipeline, snap.baseline, snap.feature,
                           snap.detection, snap.response]:
            for field_name in type(domain_obj).model_fields:
                val = getattr(domain_obj, field_name)
                if isinstance(val, MV):
                    if val.availability == MetricAvailability.COMPUTED:
                        # COMPUTED must always have a non-None value
                        assert val.value is not None, (
                            f"{type(domain_obj).__name__}.{field_name} is COMPUTED but value=None"
                        )

