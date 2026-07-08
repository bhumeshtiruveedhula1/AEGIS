"""tests/unit/chain_detection/test_storage.py — ChainStore Tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from backend.chain_detection.exceptions import ChainStorageError
from backend.chain_detection.models import AttackChain, ChainReport
from backend.chain_detection.storage import ChainStore

from tests.unit.chain_detection.conftest import make_chain


@pytest.fixture()
def store(tmp_path: Path) -> ChainStore:
    return ChainStore(store_dir=tmp_path / "chains")


def _make_report(chains=None) -> ChainReport:
    if chains is None:
        chains = [make_chain(f"c{i}") for i in range(3)]
    return ChainReport(graph_id="g-test", chains=chains)


class TestChainStore:
    def test_dirs_created(self, tmp_path: Path) -> None:
        d = tmp_path / "chains"
        ChainStore(store_dir=d)
        assert d.exists()
        assert (d / "reports").exists()

    def test_save_chain_creates_jsonl(self, store: ChainStore) -> None:
        path = store.save_chain(make_chain())
        assert path.exists()
        assert path.suffix == ".jsonl"

    def test_save_chain_appends(self, store: ChainStore) -> None:
        store.save_chain(make_chain("c1"))
        store.save_chain(make_chain("c2"))
        loaded = store.load_chains_for_date()
        assert len(loaded) == 2

    def test_save_batch(self, store: ChainStore) -> None:
        chains = [make_chain(f"c{i}") for i in range(6)]
        paths = store.save_batch(chains)
        assert len(paths) >= 1
        loaded = store.load_chains_for_date()
        assert len(loaded) == 6

    def test_save_report_creates_json(self, store: ChainStore) -> None:
        path = store.save_report(_make_report())
        assert path.exists()
        assert path.suffix == ".json"

    def test_save_report_atomic_no_tmp(self, store: ChainStore) -> None:
        store.save_report(_make_report())
        tmp_files = list((store._dir / "reports").glob("*.tmp"))
        assert len(tmp_files) == 0

    def test_load_report_round_trip(self, store: ChainStore) -> None:
        r = _make_report()
        store.save_report(r)
        loaded = store.load_report(r.report_id)
        assert loaded.report_id == r.report_id
        assert len(loaded.chains) == len(r.chains)

    def test_load_report_not_found_raises(self, store: ChainStore) -> None:
        with pytest.raises(ChainStorageError):
            store.load_report("nonexistent")

    def test_list_reports_empty(self, store: ChainStore) -> None:
        assert store.list_reports() == []

    def test_list_reports_after_saves(self, store: ChainStore) -> None:
        store.save_report(_make_report())
        store.save_report(_make_report())
        assert len(store.list_reports()) == 2

    def test_load_nonexistent_date_returns_empty(self, store: ChainStore) -> None:
        old = datetime(2020, 1, 1, tzinfo=UTC)
        assert store.load_chains_for_date(old) == []

    def test_corrupt_line_skipped(self, store: ChainStore) -> None:
        path = store.save_chain(make_chain())
        with path.open("a", encoding="utf-8") as fh:
            fh.write("{corrupted\n")
        loaded = store.load_chains_for_date()
        assert len(loaded) == 1

    def test_list_chain_dates(self, store: ChainStore) -> None:
        store.save_chain(make_chain())
        dates = store.list_chain_dates()
        assert len(dates) == 1
        assert len(dates[0]) == 10  # YYYY-MM-DD
