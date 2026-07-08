"""
tests/unit/metrics/test_store_reader.py
==========================================
Unit tests for MetricStore and MetricReader.
Uses tmp_path for I/O — no production data modified.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from backend.metrics.models import MetricDomain, MetricSnapshot
from backend.metrics.reader import MetricReader
from backend.metrics.store import MetricStore

from tests.unit.metrics.conftest import make_snapshot


# ===========================================================================
# MetricStore — write
# ===========================================================================

class TestMetricStoreWrite:

    def test_save_creates_history_file(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        snap = make_snapshot()
        store.save(snap)
        assert (tmp_path / "history.jsonl").exists()

    def test_save_creates_snapshot_file(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        snap = make_snapshot()
        store.save(snap)
        snapshot_file = tmp_path / "snapshots" / f"{snap.snapshot_id}.json"
        assert snapshot_file.exists()

    def test_save_creates_manifest(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        snap = make_snapshot()
        store.save(snap)
        assert (tmp_path / "manifest.json").exists()

    def test_save_returns_metric_record(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        snap = make_snapshot()
        record = store.save(snap)
        assert record.snapshot.snapshot_id == snap.snapshot_id

    def test_multiple_saves_appended(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        for i in range(3):
            store.save(make_snapshot(events_normalized=i * 100))
        history_file = tmp_path / "history.jsonl"
        lines = history_file.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_save_with_tags(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        snap = make_snapshot(tags={"run": "test-001"})
        record = store.save(snap, tags={"extra": "data"})
        # Tags merged from snap.tags + passed tags
        assert "run" in record.snapshot.tags


# ===========================================================================
# MetricStore — read
# ===========================================================================

class TestMetricStoreRead:

    def test_load_latest_none_when_empty(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        assert store.load_latest() is None

    def test_load_latest_returns_last_saved(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        for i in range(3):
            store.save(make_snapshot(events_normalized=i * 100))
        record = store.load_latest()
        assert record is not None
        assert record.snapshot.pipeline.events_normalized.safe_float() == 200.0

    def test_load_snapshot_by_id(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        snap = make_snapshot()
        store.save(snap)
        loaded = store.load_snapshot(snap.snapshot_id)
        assert loaded is not None
        assert loaded.snapshot.snapshot_id == snap.snapshot_id

    def test_load_snapshot_missing_returns_none(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        assert store.load_snapshot("nonexistent-id") is None

    def test_iter_history_yields_records(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        for i in range(5):
            store.save(make_snapshot())
        records = list(store.iter_history())
        assert len(records) == 5

    def test_iter_history_limit(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        for _ in range(10):
            store.save(make_snapshot())
        records = list(store.iter_history(limit=3))
        assert len(records) == 3

    def test_iter_history_reverse(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        snaps = [make_snapshot(events_normalized=i * 100) for i in range(3)]
        for snap in snaps:
            store.save(snap)
        records = list(store.iter_history(reverse=True))
        assert len(records) == 3

    def test_load_history_since_filter(self, tmp_path: Path) -> None:
        from datetime import UTC, datetime, timedelta
        from backend.metrics.models import MetricSnapshot
        store = MetricStore(store_dir=tmp_path)
        # Save 3 snapshots
        for i in range(3):
            store.save(make_snapshot())
        # Load all
        all_records = store.load_history()
        assert len(all_records) == 3
        # Filter with future cutoff → 0 results
        future = datetime.now(UTC) + timedelta(days=1)
        filtered = store.load_history(since=future)
        assert len(filtered) == 0

    def test_record_count(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        assert store.record_count() == 0
        for _ in range(4):
            store.save(make_snapshot())
        assert store.record_count() == 4

    def test_roundtrip_data_integrity(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        snap = make_snapshot(events_normalized=999, entity_count=42)
        store.save(snap)
        loaded = store.load_snapshot(snap.snapshot_id)
        assert loaded is not None
        events = loaded.snapshot.pipeline.events_normalized.safe_float()
        assert events == 999.0


# ===========================================================================
# MetricStore — purge
# ===========================================================================

class TestMetricStorePurge:

    def test_purge_removes_old_records(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        for _ in range(5):
            store.save(make_snapshot())
        future = datetime.now(UTC) + timedelta(days=1)
        purged = store.purge_before(future)
        assert purged == 5
        assert store.record_count() == 0

    def test_purge_zero_when_nothing_qualifies(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        for _ in range(3):
            store.save(make_snapshot())
        past = datetime(2020, 1, 1, tzinfo=UTC)
        purged = store.purge_before(past)
        assert purged == 0
        assert store.record_count() == 3


# ===========================================================================
# MetricReader
# ===========================================================================

class TestMetricReader:

    def test_latest_snapshot_none_when_empty(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        reader = MetricReader(store=store)
        assert reader.latest_snapshot() is None

    def test_latest_snapshot_returns_last(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        store.save(make_snapshot(events_normalized=100))
        store.save(make_snapshot(events_normalized=500))
        reader = MetricReader(store=store)
        snap = reader.latest_snapshot()
        assert snap is not None
        assert snap.pipeline.events_normalized.safe_float() == 500.0

    def test_get_metric_returns_metric_value(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        reader = MetricReader(store=store)
        snap = make_snapshot(events_normalized=777)
        mv = reader.get_metric(snap, MetricDomain.PIPELINE, "events_normalized")
        assert mv is not None
        assert mv.safe_float() == 777.0

    def test_get_metric_unknown_field_returns_none(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        reader = MetricReader(store=store)
        snap = make_snapshot()
        mv = reader.get_metric(snap, MetricDomain.PIPELINE, "nonexistent_field")
        assert mv is None

    def test_get_value_safe_default(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        reader = MetricReader(store=store)
        snap = make_snapshot()
        val = reader.get_value(snap, MetricDomain.PIPELINE, "nonexistent", default=42.0)
        assert val == 42.0

    def test_trend_returns_list(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        for i in range(5):
            store.save(make_snapshot(events_normalized=i * 100))
        reader = MetricReader(store=store)
        points = reader.trend(MetricDomain.PIPELINE, "events_normalized")
        assert isinstance(points, list)
        assert len(points) == 5

    def test_trend_returns_only_computed(self, tmp_path: Path) -> None:
        """Detection metrics are UNAVAILABLE — trend should return empty list."""
        store = MetricStore(store_dir=tmp_path)
        store.save(make_snapshot())
        reader = MetricReader(store=store)
        points = reader.trend(MetricDomain.DETECTION, "detection_rate")
        assert points == []

    def test_trend_ascending_order(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        for i in range(3):
            store.save(make_snapshot(events_normalized=i * 100))
        reader = MetricReader(store=store)
        points = reader.trend(MetricDomain.PIPELINE, "events_normalized")
        timestamps = [t for t, _ in points]
        assert timestamps == sorted(timestamps)

    def test_trend_summary_keys(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        for i in range(3):
            store.save(make_snapshot(events_normalized=i * 100 + 100))
        reader = MetricReader(store=store)
        summary = reader.trend_summary(MetricDomain.PIPELINE, "events_normalized")
        assert "count" in summary
        assert "mean" in summary
        assert "min" in summary
        assert "max" in summary
        assert "latest" in summary

    def test_snapshot_count(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        reader = MetricReader(store=store)
        assert reader.snapshot_count() == 0
        for _ in range(7):
            store.save(make_snapshot())
        assert reader.snapshot_count() == 7

    def test_compare_snapshots(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        snap_before = make_snapshot(events_normalized=1000)
        snap_after = make_snapshot(events_normalized=1500)
        r1 = store.save(snap_before)
        r2 = store.save(snap_after)
        reader = MetricReader(store=store)
        comp = reader.compare_snapshots(
            baseline_id=snap_before.snapshot_id,
            current_id=snap_after.snapshot_id,
        )
        assert comp.baseline_snapshot_id == snap_before.snapshot_id
        assert comp.current_snapshot_id == snap_after.snapshot_id
        assert len(comp.deltas) > 0

    def test_compare_snapshots_missing_raises(self, tmp_path: Path) -> None:
        from backend.metrics.exceptions import MetricQueryError
        store = MetricStore(store_dir=tmp_path)
        reader = MetricReader(store=store)
        with pytest.raises(MetricQueryError):
            reader.compare_snapshots("missing-id-1", "missing-id-2")

    def test_compare_last_two_none_when_single(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        store.save(make_snapshot())
        reader = MetricReader(store=store)
        assert reader.compare_last_two() is None

    def test_compare_last_two_returns_comparison(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        store.save(make_snapshot(events_normalized=100))
        store.save(make_snapshot(events_normalized=200))
        reader = MetricReader(store=store)
        comp = reader.compare_last_two()
        assert comp is not None

    def test_list_snapshots_limit(self, tmp_path: Path) -> None:
        store = MetricStore(store_dir=tmp_path)
        for _ in range(15):
            store.save(make_snapshot())
        reader = MetricReader(store=store)
        entries = reader.list_snapshots(limit=5)
        assert len(entries) == 5
