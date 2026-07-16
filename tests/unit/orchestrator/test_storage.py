"""tests/unit/orchestrator/test_storage.py — OrchestratorStore persistence tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


import pytest

from backend.orchestrator.exceptions import OrchestratorStorageError
from backend.orchestrator.storage import OrchestratorStore
from tests.unit.orchestrator.conftest import make_record


class TestOrchestratorStore:
    def test_save_and_load_by_id(self, tmp_store_dir: Path) -> None:
        store = OrchestratorStore(tmp_store_dir)
        record = make_record()
        store.save(record)
        loaded = store.load(record.orchestration_id)
        assert loaded.orchestration_id == record.orchestration_id

    def test_load_not_found_raises(self, tmp_store_dir: Path) -> None:
        store = OrchestratorStore(tmp_store_dir)
        with pytest.raises(OrchestratorStorageError):
            store.load("nonexistent-id")

    def test_list_ids_returns_saved(self, tmp_store_dir: Path) -> None:
        store = OrchestratorStore(tmp_store_dir)
        record = make_record()
        store.save(record)
        ids = store.list_ids()
        assert record.orchestration_id in ids

    def test_multiple_records_stored(self, tmp_store_dir: Path) -> None:
        store = OrchestratorStore(tmp_store_dir)
        r1 = make_record()
        r2 = make_record()
        store.save(r1)
        store.save(r2)
        ids = store.list_ids()
        assert r1.orchestration_id in ids
        assert r2.orchestration_id in ids

    def test_load_for_date_returns_records(self, tmp_store_dir: Path) -> None:
        store = OrchestratorStore(tmp_store_dir)
        record = make_record()
        store.save(record)
        records = store.load_for_date()
        assert any(r.orchestration_id == record.orchestration_id for r in records)

    def test_load_for_date_empty_when_no_file(self, tmp_store_dir: Path) -> None:
        from datetime import UTC, datetime

        store = OrchestratorStore(tmp_store_dir)
        # Use a past date that has no partition
        past = datetime(2000, 1, 1, tzinfo=UTC)
        records = store.load_for_date(past)
        assert records == []

    def test_save_overwrites_index(self, tmp_store_dir: Path) -> None:
        """Index should reflect the latest state after a re-save."""
        store = OrchestratorStore(tmp_store_dir)
        record = make_record()
        store.save(record)
        # Update and re-save
        updated = record.model_copy(update={"alert_id": "alert-updated"})
        store.save(updated)
        loaded = store.load(record.orchestration_id)
        assert loaded.alert_id == "alert-updated"

    def test_load_by_alert(self, tmp_store_dir: Path) -> None:
        store = OrchestratorStore(tmp_store_dir)
        record = make_record()
        store.save(record)
        results = store.load_by_alert(record.alert_id)
        assert any(r.orchestration_id == record.orchestration_id for r in results)

    def test_save_batch(self, tmp_store_dir: Path) -> None:
        store = OrchestratorStore(tmp_store_dir)
        records = [make_record() for _ in range(3)]
        store.save_batch(records)
        ids = store.list_ids()
        for r in records:
            assert r.orchestration_id in ids

    def test_list_dates(self, tmp_store_dir: Path) -> None:
        store = OrchestratorStore(tmp_store_dir)
        record = make_record()
        store.save(record)
        dates = store.list_dates()
        assert len(dates) == 1  # one day partition


class TestOrchestratorStoreThreadSafety:
    def test_concurrent_saves(self, tmp_store_dir: Path) -> None:
        """Multiple threads saving simultaneously should not corrupt data."""
        import threading

        store = OrchestratorStore(tmp_store_dir)
        records = [make_record() for _ in range(10)]
        errors: list[Exception] = []

        def save_one(r) -> None:
            try:
                store.save(r)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=save_one, args=(r,)) for r in records]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        ids = store.list_ids()
        for r in records:
            assert r.orchestration_id in ids
