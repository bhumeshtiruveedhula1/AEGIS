"""
tests/integration/test_feature_pipeline.py
============================================
Integration tests for Module 2.2 — Behavioral Feature Engine.

Tests the full flow: events → FeaturePipeline → FeatureVectorWriter → JSONL
without mocking (no external I/O except temp directory).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.baseline.models import EntityKey
from backend.baseline.reader_api import BaselineReader
from backend.features.models import (
    ALL_FEATURE_NAMES,
    FEATURE_DIMENSION,
    FEATURE_SCHEMA_VERSION,
    FeatureRecord,
)
from backend.features.pipeline import FeaturePipeline
from backend.features.writer import FeatureVectorWriter

from tests.unit.features.conftest import (
    make_dc_event,
    make_hospital_event,
    make_ot_event,
    make_attacker_event,
    make_hospital_baseline,
    make_dc_baseline,
    make_ot_baseline,
)


# ===========================================================================
# Helper: build a mock reader without mocking infrastructure
# ===========================================================================

class _DirectReader:
    """
    Minimal BaselineReader stand-in for integration tests.
    Bypasses disk I/O by holding baselines in memory.
    """

    def __init__(self, baselines: dict) -> None:
        self._baselines = baselines  # entity_key.storage_key → EntityBaseline

    @property
    def is_ready(self) -> bool:
        return bool(self._baselines)

    @property
    def profile_id(self) -> str | None:
        return "integration-test-profile" if self._baselines else None

    def get_entity(self, key: EntityKey):
        return self._baselines.get(key.storage_key)


# ===========================================================================
# Integration: end-to-end pipeline → writer → JSONL
# ===========================================================================

class TestFeaturePipelineEndToEnd:
    """Full pipeline integration — no mocking, real JSONL output."""

    def _setup_reader(self) -> _DirectReader:
        user_bl = make_hospital_baseline(entity_id="svc-iis")
        dc_bl = make_dc_baseline(entity_id="jdoe")
        ot_bl = make_ot_baseline(entity_id="ot-node-01")
        return _DirectReader({
            user_bl.entity_key.storage_key: user_bl,
            dc_bl.entity_key.storage_key: dc_bl,
            ot_bl.entity_key.storage_key: ot_bl,
        })

    def test_pipeline_produces_feature_records(self, tmp_path: Path) -> None:
        reader = self._setup_reader()
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
            emit_all_dimensions=True,
        )
        events = [
            make_hospital_event(),
            make_dc_event(),
            make_ot_event(),
            make_attacker_event(),
        ]
        records, report = pipeline.process_batch(events)
        assert len(records) > 0
        assert report.events_read == 4

    def test_all_records_have_56_features(self, tmp_path: Path) -> None:
        reader = self._setup_reader()
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
        )
        events = [make_hospital_event(), make_dc_event(), make_ot_event()]
        records, _ = pipeline.process_batch(events)
        for record in records:
            assert len(record.feature_vector.to_array()) == FEATURE_DIMENSION

    def test_all_features_present_in_each_record(self, tmp_path: Path) -> None:
        reader = self._setup_reader()
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
        )
        records, _ = pipeline.process_batch([make_hospital_event()])
        for r in records:
            for name in ALL_FEATURE_NAMES:
                assert name in r.feature_vector.values, f"Missing: {name}"

    def test_writer_produces_valid_jsonl(self, tmp_path: Path) -> None:
        reader = self._setup_reader()
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
        )
        events = [make_hospital_event(), make_dc_event()]
        records, report = pipeline.process_batch(events)

        with FeatureVectorWriter(output_dir=tmp_path, run_id="test-run") as writer:
            writer.write_batch(records)
        
        output_file = tmp_path / "features_test-run.jsonl"
        assert output_file.exists()

        lines = output_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == len(records)

        for line in lines:
            obj = json.loads(line)
            assert "event_id" in obj
            assert "feature_vector" in obj
            assert "entity_key" in obj

    def test_writer_report_written(self, tmp_path: Path) -> None:
        reader = self._setup_reader()
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
        )
        records, report = pipeline.process_batch([make_hospital_event()])

        with FeatureVectorWriter(output_dir=tmp_path, run_id="test-run") as writer:
            writer.write_batch(records)
            writer.write_report(report)

        report_file = tmp_path / "pipeline_report.json"
        assert report_file.exists()
        obj = json.loads(report_file.read_text())
        assert "feature_schema_version" in obj

    def test_schema_version_in_all_records(self, tmp_path: Path) -> None:
        reader = self._setup_reader()
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
        )
        records, _ = pipeline.process_batch([make_hospital_event()])
        for r in records:
            assert r.schema_version == FEATURE_SCHEMA_VERSION


# ===========================================================================
# Integration: cold start (no baselines)
# ===========================================================================

class TestColdStartIntegration:

    def test_cold_start_produces_records_with_zero_vectors(self, tmp_path: Path) -> None:
        reader = _DirectReader({})  # empty — cold start
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
            emit_all_dimensions=True,
        )
        events = [make_hospital_event(), make_ot_event()]
        records, report = pipeline.process_batch(events)
        assert len(records) > 0
        # Cold-start: no baseline available for any dimension
        for r in records:
            assert r.baseline_available is False

    def test_cold_start_vector_all_finite(self, tmp_path: Path) -> None:
        import math
        reader = _DirectReader({})
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
        )
        records, _ = pipeline.process_batch([
            make_hospital_event(),
            make_dc_event(),
            make_ot_event(),
            make_attacker_event(),
        ])
        for r in records:
            assert all(
                math.isfinite(v) for v in r.feature_vector.values.values()
            ), f"Non-finite value in {r.entity_key}"

    def test_cold_start_novelty_count_zero(self, tmp_path: Path) -> None:
        reader = _DirectReader({})
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
        )
        records, _ = pipeline.process_batch([make_hospital_event()])
        for r in records:
            assert r.feature_vector.novelty_count() == 0


# ===========================================================================
# Integration: cross-source event mix
# ===========================================================================

class TestCrossSourceIntegration:

    def test_hospital_event_has_process_features(self) -> None:
        bl = make_hospital_baseline()
        reader = _DirectReader({bl.entity_key.storage_key: bl})
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
            primary_only=True,
        )
        records = pipeline.process_event(make_hospital_event())
        vec = records[0].feature_vector
        # Hospital has process context — count should be > 0
        assert vec.get("unique_processes_baseline") == 2.0

    def test_ot_event_has_modbus_features(self) -> None:
        bl = make_ot_baseline()
        reader = _DirectReader({bl.entity_key.storage_key: bl})
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
            primary_only=True,
        )
        records = pipeline.process_event(make_ot_event())
        vec = records[0].feature_vector
        assert vec.get("modbus_event_count_baseline") == 200.0

    def test_dc_event_has_auth_features(self) -> None:
        bl = make_dc_baseline()
        reader = _DirectReader({bl.entity_key.storage_key: bl})
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
            primary_only=True,
        )
        records = pipeline.process_event(make_dc_event())
        vec = records[0].feature_vector
        assert vec.get("auth_event_count_baseline") == 50.0

    def test_multiple_events_deterministic(self) -> None:
        """Same event processed twice must produce identical feature arrays."""
        bl = make_hospital_baseline()
        reader = _DirectReader({bl.entity_key.storage_key: bl})
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
            primary_only=True,
        )
        event = make_hospital_event()
        records_a = pipeline.process_event(event)
        records_b = pipeline.process_event(event)
        assert records_a[0].feature_vector.to_array() == records_b[0].feature_vector.to_array()

    def test_novel_events_flagged_correctly(self) -> None:
        """Novel events must fire the right binary features."""
        bl = make_hospital_baseline()
        reader = _DirectReader({bl.entity_key.storage_key: bl})
        pipeline = FeaturePipeline(
            baseline_reader=reader,  # type: ignore[arg-type]
            primary_only=True,
        )
        event = make_hospital_event({
            "process": "evil.exe",
            "dst_ip": "10.99.99.99",
            "port": 4444,
        })
        records = pipeline.process_event(event)
        vec = records[0].feature_vector
        assert vec.get("process_is_novel") == 1.0
        assert vec.get("dst_ip_is_novel") == 1.0
        assert vec.get("port_is_novel") == 1.0
