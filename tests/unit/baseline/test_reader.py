"""
tests/unit/baseline/test_reader.py
====================================
Unit tests for NormalizedEventReader and BaselineReader.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.baseline.builder import BaselineBuilder
from backend.baseline.exceptions import BaselineInputError
from backend.baseline.models import EntityKey
from backend.baseline.reader import NormalizedEventReader
from backend.baseline.reader_api import BaselineReader
from backend.baseline.storage import BaselineStore
from backend.normalization.models import CanonicalEvent
from tests.unit.baseline.conftest import (
    make_hospital_batch,
    make_hospital_event,
    make_ot_batch,
    normalized_jsonl,
    write_events_jsonl,
)


# ===========================================================================
# NormalizedEventReader
# ===========================================================================

class TestNormalizedEventReader:

    def test_stream_yields_canonical_events(self, normalized_jsonl: Path) -> None:
        reader = NormalizedEventReader(input_file=normalized_jsonl)
        events = list(reader.stream())
        assert all(isinstance(e, CanonicalEvent) for e in events)

    def test_load_all_returns_correct_count(self, normalized_jsonl: Path) -> None:
        reader = NormalizedEventReader(input_file=normalized_jsonl)
        events = reader.load_all()
        assert len(events) == 30

    def test_missing_file_raises_baseline_input_error(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.jsonl"
        reader = NormalizedEventReader(input_file=missing)
        with pytest.raises(BaselineInputError, match="not found"):
            reader.load_all()

    def test_empty_file_raises_baseline_input_error(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        reader = NormalizedEventReader(input_file=empty)
        with pytest.raises(BaselineInputError, match="empty"):
            reader.load_all()

    def test_malformed_json_lines_skipped(self, tmp_path: Path) -> None:
        events_file = tmp_path / "events.jsonl"
        valid = make_hospital_event()
        events_file.write_text(
            valid.model_dump_json() + "\n"
            + "NOT_VALID_JSON\n"
            + valid.model_dump_json() + "\n",
            encoding="utf-8",
        )
        reader = NormalizedEventReader(input_file=events_file)
        events = reader.load_all()
        assert len(events) == 2
        assert reader.parse_errors == 1

    def test_blank_lines_skipped(self, tmp_path: Path) -> None:
        events_file = tmp_path / "events.jsonl"
        valid = make_hospital_event()
        events_file.write_text(
            valid.model_dump_json() + "\n\n" + valid.model_dump_json() + "\n",
            encoding="utf-8",
        )
        reader = NormalizedEventReader(input_file=events_file)
        events = reader.load_all()
        assert len(events) == 2

    def test_counters_updated_after_stream(self, normalized_jsonl: Path) -> None:
        reader = NormalizedEventReader(input_file=normalized_jsonl)
        reader.load_all()
        assert reader.lines_read == 30
        assert reader.events_yielded == 30
        assert reader.parse_errors == 0

    def test_input_file_property(self, normalized_jsonl: Path) -> None:
        reader = NormalizedEventReader(input_file=normalized_jsonl)
        assert reader.input_file == normalized_jsonl

    def test_file_size_bytes_returns_positive(self, normalized_jsonl: Path) -> None:
        reader = NormalizedEventReader(input_file=normalized_jsonl)
        assert reader.file_size_bytes > 0

    def test_non_dict_json_lines_skipped(self, tmp_path: Path) -> None:
        events_file = tmp_path / "events.jsonl"
        valid = make_hospital_event()
        events_file.write_text(
            valid.model_dump_json() + "\n"
            + '"just_a_string"\n'
            + "[1, 2, 3]\n",
            encoding="utf-8",
        )
        reader = NormalizedEventReader(input_file=events_file)
        events = reader.load_all()
        assert len(events) == 1


# ===========================================================================
# BaselineReader — Feature Engine interface
# ===========================================================================

class TestBaselineReaderColdStart:
    """Tests for BaselineReader when no baseline has been built."""

    def test_is_ready_false_when_no_baseline(self, tmp_path: Path) -> None:
        reader = BaselineReader(baseline_dir=tmp_path)
        assert not reader.is_ready

    def test_profile_id_none_when_no_baseline(self, tmp_path: Path) -> None:
        reader = BaselineReader(baseline_dir=tmp_path)
        assert reader.profile_id is None

    def test_get_entity_returns_none_cold_start(self, tmp_path: Path) -> None:
        reader = BaselineReader(baseline_dir=tmp_path)
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        assert reader.get_entity(key) is None

    def test_get_network_returns_none_cold_start(self, tmp_path: Path) -> None:
        reader = BaselineReader(baseline_dir=tmp_path)
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        assert reader.get_network(key) is None

    def test_process_was_seen_returns_none_cold_start(self, tmp_path: Path) -> None:
        reader = BaselineReader(baseline_dir=tmp_path)
        assert reader.process_was_seen("user", "svc-iis", "w3wp.exe") is None

    def test_list_all_entity_keys_empty_cold_start(self, tmp_path: Path) -> None:
        reader = BaselineReader(baseline_dir=tmp_path)
        assert reader.list_all_entity_keys() == []

    def test_require_baseline_raises_when_no_baseline(self, tmp_path: Path) -> None:
        from backend.baseline.exceptions import BaselineNotFoundError
        with pytest.raises(BaselineNotFoundError):
            BaselineReader(baseline_dir=tmp_path, require_baseline=True)


class TestBaselineReaderWithBaseline:
    """Tests for BaselineReader when a baseline exists."""

    def _build_and_save(self, tmp_path: Path) -> "BaselineStore":
        store = BaselineStore(baseline_dir=tmp_path)
        profile = BaselineBuilder(dimensions={"user", "host", "source"}).build_from_events(
            make_hospital_batch(20)
        )
        store.save(profile)
        return store

    def test_is_ready_true_after_build(self, tmp_path: Path) -> None:
        self._build_and_save(tmp_path)
        reader = BaselineReader(baseline_dir=tmp_path)
        assert reader.is_ready

    def test_get_entity_returns_entity_baseline(self, tmp_path: Path) -> None:
        self._build_and_save(tmp_path)
        reader = BaselineReader(baseline_dir=tmp_path)
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        eb = reader.get_entity(key)
        assert eb is not None
        assert eb.observation_count == 20

    def test_get_entity_by_ids(self, tmp_path: Path) -> None:
        self._build_and_save(tmp_path)
        reader = BaselineReader(baseline_dir=tmp_path)
        eb = reader.get_entity_by_ids("user", "svc-iis")
        assert eb is not None

    def test_get_entity_by_ids_invalid_type_returns_none(self, tmp_path: Path) -> None:
        self._build_and_save(tmp_path)
        reader = BaselineReader(baseline_dir=tmp_path)
        result = reader.get_entity_by_ids("INVALID_TYPE", "svc-iis")
        assert result is None

    def test_get_entity_missing_returns_none(self, tmp_path: Path) -> None:
        self._build_and_save(tmp_path)
        reader = BaselineReader(baseline_dir=tmp_path)
        key = EntityKey(entity_type="user", entity_id="ghost-user")
        assert reader.get_entity(key) is None

    def test_process_was_seen_returns_true(self, tmp_path: Path) -> None:
        self._build_and_save(tmp_path)
        reader = BaselineReader(baseline_dir=tmp_path)
        result = reader.process_was_seen("user", "svc-iis", "w3wp.exe")
        assert result is True

    def test_process_was_seen_returns_false_for_unknown(self, tmp_path: Path) -> None:
        self._build_and_save(tmp_path)
        reader = BaselineReader(baseline_dir=tmp_path)
        result = reader.process_was_seen("user", "svc-iis", "unknown-malware.exe")
        assert result is False

    def test_dst_ip_was_seen(self, tmp_path: Path) -> None:
        self._build_and_save(tmp_path)
        reader = BaselineReader(baseline_dir=tmp_path)
        result = reader.dst_ip_was_seen("user", "svc-iis", "10.0.1.20")
        assert result is True

    def test_dst_ip_not_seen(self, tmp_path: Path) -> None:
        self._build_and_save(tmp_path)
        reader = BaselineReader(baseline_dir=tmp_path)
        result = reader.dst_ip_was_seen("user", "svc-iis", "192.168.99.99")
        assert result is False

    def test_get_event_type_frequency(self, tmp_path: Path) -> None:
        self._build_and_save(tmp_path)
        reader = BaselineReader(baseline_dir=tmp_path)
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        freq = reader.get_event_type_frequency(key, "ProcessCreate")
        assert freq == 20

    def test_get_event_type_frequency_zero_for_unknown(self, tmp_path: Path) -> None:
        self._build_and_save(tmp_path)
        reader = BaselineReader(baseline_dir=tmp_path)
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        freq = reader.get_event_type_frequency(key, "UnknownEvent")
        assert freq == 0

    def test_list_all_entity_keys_returns_keys(self, tmp_path: Path) -> None:
        self._build_and_save(tmp_path)
        reader = BaselineReader(baseline_dir=tmp_path)
        keys = reader.list_all_entity_keys()
        assert len(keys) > 0

    def test_refresh_picks_up_new_baseline(self, tmp_path: Path) -> None:
        """Reader should reflect updated baseline after refresh()."""
        store = BaselineStore(baseline_dir=tmp_path)
        # Build initial baseline
        p1 = BaselineBuilder(dimensions={"user"}).build_from_events(make_hospital_batch(5))
        store.save(p1)

        reader = BaselineReader(baseline_dir=tmp_path)
        assert reader.profile_id == p1.profile_id

        # Build second baseline
        p2 = BaselineBuilder(dimensions={"user"}).build_from_events(make_hospital_batch(10))
        store.save(p2)

        reader.refresh()
        assert reader.profile_id == p2.profile_id
