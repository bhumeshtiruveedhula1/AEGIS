"""
tests/unit/metrics/test_service.py
=====================================
Unit tests for MetricService orchestration.
Uses tmp_path for all disk I/O.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from backend.metrics.service import MetricService
from backend.metrics.models import MetricDomain, MetricAvailability

from tests.unit.metrics.conftest import (
    make_baseline_profile,
    make_feature_pipeline_report,
    make_mock_norm_report,
)


# ===========================================================================
# MetricService initialisation
# ===========================================================================

class TestMetricServiceInit:

    def test_service_initialises(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        assert service is not None

    def test_service_has_six_collectors(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        assert len(service._collectors) == 6

    def test_service_exposes_reader(self, tmp_path: Path) -> None:
        from backend.metrics.reader import MetricReader
        service = MetricService(store_dir=tmp_path)
        assert isinstance(service.reader, MetricReader)

    def test_service_exposes_store(self, tmp_path: Path) -> None:
        from backend.metrics.store import MetricStore
        service = MetricService(store_dir=tmp_path)
        assert isinstance(service.store, MetricStore)

    def test_default_tags_merged(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path, tags={"env": "ci"})
        snap = service.collect_all()
        assert snap.tags.get("env") == "ci"


# ===========================================================================
# MetricService.collect_all
# ===========================================================================

class TestCollectAll:

    def test_collect_all_returns_snapshot(self, tmp_path: Path) -> None:
        from backend.metrics.models import MetricSnapshot
        service = MetricService(store_dir=tmp_path)
        snap = service.collect_all()
        assert isinstance(snap, MetricSnapshot)

    def test_collect_all_persists_by_default(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all()
        assert service.reader.snapshot_count() == 1

    def test_collect_all_no_persist(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all(persist=False)
        assert service.reader.snapshot_count() == 0

    def test_collect_all_with_norm_report(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        norm = make_mock_norm_report(normalized=2000, failed=20, duration=10.0)
        snap = service.collect_all(norm_report=norm)
        assert snap.pipeline.events_normalized.is_computed
        assert snap.pipeline.events_normalized.safe_float() == 2000.0

    def test_collect_all_with_feature_report(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        feat = make_feature_pipeline_report(records=800)
        snap = service.collect_all(feature_report=feat)
        assert snap.pipeline.feature_records_produced.is_computed
        assert snap.pipeline.feature_records_produced.safe_float() == 800.0

    def test_collect_all_with_baseline_profile(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        profile = make_baseline_profile(entity_count=10)
        snap = service.collect_all(baseline_profile=profile)
        assert snap.baseline.entity_count.is_computed
        assert snap.baseline.entity_count.safe_float() == 10.0

    def test_collect_all_detection_always_unavailable(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        snap = service.collect_all()
        assert snap.detection.detection_rate.availability == MetricAvailability.UNAVAILABLE

    def test_collect_all_response_always_unavailable(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        snap = service.collect_all()
        assert snap.response.mean_time_to_respond_seconds.availability == MetricAvailability.UNAVAILABLE

    def test_collect_all_health_always_computed(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        snap = service.collect_all()
        assert snap.health.metrics_schema_version.is_computed

    def test_collect_all_custom_tags(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        snap = service.collect_all(tags={"run_id": "run-42"})
        assert snap.tags.get("run_id") == "run-42"

    def test_collect_all_duration_recorded(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        snap = service.collect_all()
        assert snap.collection_duration_seconds is not None
        assert snap.collection_duration_seconds >= 0.0

    def test_multiple_runs_cumulate(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        for _ in range(3):
            service.collect_all()
        assert service.reader.snapshot_count() == 3


# ===========================================================================
# MetricService.collect_pipeline_only
# ===========================================================================

class TestCollectPipelineOnly:

    def test_pipeline_only_returns_snapshot(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        snap = service.collect_pipeline_only()
        assert snap is not None

    def test_pipeline_only_not_persisted_by_default(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_pipeline_only()
        # Default persist=False
        assert service.reader.snapshot_count() == 0

    def test_pipeline_only_scope_tag(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        snap = service.collect_pipeline_only(persist=True)
        assert snap.tags.get("scope") == "pipeline_only"


# ===========================================================================
# MetricService.get_platform_status
# ===========================================================================

class TestGetPlatformStatus:

    def test_no_data_returns_no_data_status(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        status = service.get_platform_status()
        assert status["status"] == "no_data"

    def test_after_collection_returns_status(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all()
        status = service.get_platform_status()
        assert "status" in status
        assert status["status"] in ("healthy", "degraded", "critical")

    def test_status_has_components(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all()
        status = service.get_platform_status()
        assert "components" in status
        assert len(status["components"]) > 0

    def test_status_has_metrics_summary(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all()
        status = service.get_platform_status()
        assert "metrics_summary" in status
        assert "computed" in status["metrics_summary"]
        assert "unavailable" in status["metrics_summary"]

    def test_status_has_pipeline_section(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all()
        status = service.get_platform_status()
        assert "pipeline" in status
        assert "events_normalized" in status["pipeline"]


# ===========================================================================
# MetricService.compare_last_runs
# ===========================================================================

class TestCompareLastRuns:

    def test_none_when_single_run(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all()
        assert service.compare_last_runs() is None

    def test_comparison_returned_after_two_runs(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all()
        service.collect_all()
        result = service.compare_last_runs()
        assert result is not None
        assert "regressions" in result
        assert "improvements" in result
        assert "baseline_snapshot_id" in result

    def test_comparison_has_significant_changes_count(self, tmp_path: Path) -> None:
        service = MetricService(store_dir=tmp_path)
        service.collect_all()
        service.collect_all()
        result = service.compare_last_runs()
        assert result is not None
        assert "significant_changes" in result
        assert isinstance(result["significant_changes"], int)
