"""
tests/integration/test_baseline_pipeline.py
============================================
Module 2.1 Integration Tests — Full Baseline Pipeline

Validates the complete baseline pipeline end-to-end:
  Normalized JSONL (Module 1.3 output)
      ↓ NormalizedEventReader
      ↓ EventAggregator (4 dimensions)
      ↓ StatisticsComputer (per entity)
      ↓ BaselineProfile
      ↓ BaselineStore (persist JSON artefacts)
      ↓ BaselineReader (Feature Engine interface)

These tests do NOT require Docker or network.
They run entirely in memory + tmp_path.

Target: 40+ tests, all passing in < 5 seconds.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.baseline.builder import BaselineBuilder
from backend.baseline.models import BASELINE_SCHEMA_VERSION, EntityKey
from backend.baseline.reader import NormalizedEventReader
from backend.baseline.reader_api import BaselineReader
from backend.baseline.service import BaselineService
from backend.baseline.storage import BaselineStore
from backend.baseline.updater import BaselineUpdater
from tests.unit.baseline.conftest import (
    make_dc_event,
    make_hospital_batch,
    make_hospital_event,
    make_mixed_events,
    make_ot_batch,
    make_ot_event,
    write_events_jsonl,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jsonl(tmp_path: Path, n_hospital=30, n_dc=20, n_ot=15, n_att=5) -> Path:
    out = tmp_path / "data" / "normalized" / "normalized_events.jsonl"
    events = make_mixed_events(hospital=n_hospital, dc=n_dc, ot=n_ot, attacker=n_att)
    write_events_jsonl(out, events)
    return out


# ===========================================================================
# Full pipeline: JSONL → BaselineProfile → Persist → Load
# ===========================================================================

class TestFullPipeline:

    def test_pipeline_produces_profile(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path)
        store = BaselineStore(baseline_dir=tmp_path / "baseline")
        profile = BaselineBuilder(input_file=jsonl).build_from_file()
        path = store.save(profile)
        loaded = store.load(profile.profile_id)
        assert loaded.profile_id == profile.profile_id

    def test_pipeline_correct_event_count(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path, n_hospital=40, n_dc=20, n_ot=10, n_att=5)
        profile = BaselineBuilder(input_file=jsonl).build_from_file()
        assert profile.total_events_processed == 75

    def test_pipeline_all_4_source_entities(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path)
        profile = BaselineBuilder(input_file=jsonl).build_from_file()
        source_ids = {k.entity_id for k in profile.all_entity_keys() if k.entity_type == "source"}
        assert source_ids == {"hospital_server", "domain_controller", "ot_node", "attacker"}

    def test_pipeline_all_4_dimension_types(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path)
        profile = BaselineBuilder(input_file=jsonl).build_from_file()
        types = {k.entity_type for k in profile.all_entity_keys()}
        assert types == {"user", "host", "source", "user_host"}

    def test_baseline_version_correct(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path)
        profile = BaselineBuilder(input_file=jsonl).build_from_file()
        assert profile.baseline_version == BASELINE_SCHEMA_VERSION
        # All entity baselines also have correct version
        for eb in profile.entities.values():
            assert eb.baseline_version == BASELINE_SCHEMA_VERSION

    def test_manifest_created_after_save(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path)
        baseline_dir = tmp_path / "baseline"
        store = BaselineStore(baseline_dir=baseline_dir)
        profile = BaselineBuilder(input_file=jsonl).build_from_file()
        store.save(profile)
        assert (baseline_dir / "manifest.json").exists()

    def test_per_entity_json_files_created(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path)
        baseline_dir = tmp_path / "baseline"
        store = BaselineStore(baseline_dir=baseline_dir)
        profile = BaselineBuilder(input_file=jsonl).build_from_file()
        store.save(profile)
        count = store.save_profile_entities(profile)
        assert count == profile.entity_count

    def test_entity_json_files_are_readable_json(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path, n_hospital=10, n_dc=0, n_ot=0, n_att=0)
        baseline_dir = tmp_path / "baseline"
        store = BaselineStore(baseline_dir=baseline_dir)
        profile = BaselineBuilder(
            input_file=jsonl, dimensions={"user"}
        ).build_from_file()
        store.save(profile)
        store.save_profile_entities(profile)

        # Read all entity JSON files and validate they parse
        for f in (baseline_dir / "entities" / "user").glob("*.json"):
            data = json.loads(f.read_text(encoding="utf-8"))
            assert "entity_key" in data
            assert "observation_count" in data


# ===========================================================================
# BaselineService integration
# ===========================================================================

class TestBaselineService:

    def test_service_build_report_returned(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path)
        service = BaselineService(
            baseline_dir=tmp_path / "baseline",
            input_file=jsonl,
        )
        report = service.build_from_normalized_output()
        assert report is not None
        assert report.total_events_read == 70

    def test_service_status_ready_after_build(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path)
        service = BaselineService(
            baseline_dir=tmp_path / "baseline",
            input_file=jsonl,
        )
        service.build_from_normalized_output()
        status = service.get_status()
        assert status["is_ready"] is True
        assert status["entity_count"] > 0

    def test_service_status_not_ready_before_build(self, tmp_path: Path) -> None:
        service = BaselineService(baseline_dir=tmp_path / "baseline")
        status = service.get_status()
        assert status["is_ready"] is False

    def test_service_entity_update(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path)
        baseline_dir = tmp_path / "baseline"
        service = BaselineService(baseline_dir=baseline_dir, input_file=jsonl)
        service.build_from_normalized_output()

        key = EntityKey(entity_type="user", entity_id="svc-iis")
        new_events = make_hospital_batch(5)
        success = service.update_from_new_events(new_events, key)
        assert success is True

    def test_service_update_returns_false_for_unknown_entity(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path)
        service = BaselineService(baseline_dir=tmp_path / "baseline", input_file=jsonl)
        service.build_from_normalized_output()

        ghost_key = EntityKey(entity_type="user", entity_id="ghost-user")
        result = service.update_from_new_events(make_hospital_batch(3), ghost_key)
        assert result is False


# ===========================================================================
# BaselineReader integration (Feature Engine perspective)
# ===========================================================================

class TestBaselineReaderIntegration:

    def _prepare_reader(self, tmp_path: Path) -> BaselineReader:
        jsonl = _make_jsonl(tmp_path)
        baseline_dir = tmp_path / "baseline"
        store = BaselineStore(baseline_dir=baseline_dir)
        profile = BaselineBuilder(input_file=jsonl).build_from_file()
        store.save(profile)
        return BaselineReader(baseline_dir=baseline_dir)

    def test_reader_is_ready_after_build(self, tmp_path: Path) -> None:
        reader = self._prepare_reader(tmp_path)
        assert reader.is_ready

    def test_reader_gets_hospital_entity(self, tmp_path: Path) -> None:
        reader = self._prepare_reader(tmp_path)
        eb = reader.get_entity(EntityKey(entity_type="source", entity_id="hospital_server"))
        assert eb is not None
        assert eb.observation_count == 30

    def test_reader_gets_ot_entity(self, tmp_path: Path) -> None:
        reader = self._prepare_reader(tmp_path)
        eb = reader.get_entity(EntityKey(entity_type="source", entity_id="ot_node"))
        assert eb is not None
        assert eb.modbus is not None

    def test_reader_gets_dc_entity(self, tmp_path: Path) -> None:
        reader = self._prepare_reader(tmp_path)
        eb = reader.get_entity(EntityKey(entity_type="source", entity_id="domain_controller"))
        assert eb is not None
        assert eb.auth is not None

    def test_reader_known_process_seen(self, tmp_path: Path) -> None:
        reader = self._prepare_reader(tmp_path)
        result = reader.process_was_seen("user", "svc-iis", "w3wp.exe")
        assert result is True

    def test_reader_unknown_process_not_seen(self, tmp_path: Path) -> None:
        reader = self._prepare_reader(tmp_path)
        result = reader.process_was_seen("user", "svc-iis", "evil.exe")
        assert result is False

    def test_reader_known_dst_ip_seen(self, tmp_path: Path) -> None:
        reader = self._prepare_reader(tmp_path)
        result = reader.dst_ip_was_seen("user", "svc-iis", "10.0.1.20")
        assert result is True

    def test_reader_modbus_register_in_range(self, tmp_path: Path) -> None:
        reader = self._prepare_reader(tmp_path)
        # OT events use register_start=10 in make_ot_batch, 15 events → registers 10–24
        result = reader.modbus_register_in_range("source", "ot_node", 15)
        assert result is True

    def test_reader_modbus_register_out_of_range(self, tmp_path: Path) -> None:
        reader = self._prepare_reader(tmp_path)
        result = reader.modbus_register_in_range("source", "ot_node", 9999)
        assert result is False


# ===========================================================================
# Incremental update integration
# ===========================================================================

class TestIncrementalUpdateIntegration:

    def test_update_increases_observation_count(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path, n_hospital=20, n_dc=0, n_ot=0, n_att=0)
        baseline_dir = tmp_path / "baseline"
        store = BaselineStore(baseline_dir=baseline_dir)
        profile = BaselineBuilder(input_file=jsonl, dimensions={"user"}).build_from_file()
        store.save(profile)
        store.save_profile_entities(profile)

        key = EntityKey(entity_type="user", entity_id="svc-iis")
        existing = store.load_entity(key)
        assert existing.observation_count == 20

        updater = BaselineUpdater()
        updated = updater.update(existing, make_hospital_batch(10))
        store.save_entity(key, updated)

        reloaded = store.load_entity(key)
        assert reloaded.observation_count == 30

    def test_update_adds_new_process_to_baseline(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path, n_hospital=10, n_dc=0, n_ot=0, n_att=0)
        baseline_dir = tmp_path / "baseline"
        store = BaselineStore(baseline_dir=baseline_dir)
        profile = BaselineBuilder(input_file=jsonl, dimensions={"user"}).build_from_file()
        store.save(profile)
        store.save_profile_entities(profile)

        key = EntityKey(entity_type="user", entity_id="svc-iis")
        existing = store.load_entity(key)
        assert existing.process is not None
        assert "powershell.exe" not in existing.process.unique_processes

        updater = BaselineUpdater()
        new_events = [make_hospital_event({"process": "powershell.exe"})]
        updated = updater.update(existing, new_events)
        store.save_entity(key, updated)

        reloaded = store.load_entity(key)
        assert reloaded.process is not None
        assert "powershell.exe" in reloaded.process.unique_processes

    def test_update_adds_new_modbus_supervisory_host(self, tmp_path: Path) -> None:
        jsonl = _make_jsonl(tmp_path, n_hospital=0, n_dc=0, n_ot=10, n_att=0)
        baseline_dir = tmp_path / "baseline"
        store = BaselineStore(baseline_dir=baseline_dir)
        profile = BaselineBuilder(input_file=jsonl, dimensions={"host"}).build_from_file()
        store.save(profile)
        store.save_profile_entities(profile)

        key = EntityKey(entity_type="host", entity_id="ot-node-01")
        existing = store.load_entity(key)
        assert existing.modbus is not None
        original_hosts = set(existing.modbus.known_supervisory_hosts)

        updater = BaselineUpdater()
        new_events = [make_ot_event({"supervisory_host": "10.99.99.99"})]
        updated = updater.update(existing, new_events)
        store.save_entity(key, updated)

        reloaded = store.load_entity(key)
        assert "10.99.99.99" in reloaded.modbus.known_supervisory_hosts
        # Original hosts still present
        for host in original_hosts:
            assert host in reloaded.modbus.known_supervisory_hosts
