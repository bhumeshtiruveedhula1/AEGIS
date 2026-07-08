"""tests/unit/mitre/test_storage.py — MappingStore Tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from backend.mitre.exceptions import MappingStorageError
from backend.mitre.models import MappedAttack, MappingReport, TechniqueMapping
from backend.mitre.storage import MappingStore

from tests.unit.mitre.conftest import make_alert


def _technique():
    from backend.mitre.models import AttackTactic, AttackTechnique
    tac = AttackTactic(tactic_id="TA0006", name="Credential Access", short_name="cred")
    return AttackTechnique(technique_id="T1110", name="Brute Force", tactic=tac)


def _tm(conf: float = 0.75) -> TechniqueMapping:
    return TechniqueMapping(
        technique=_technique(), confidence=conf,
        evidence=["Anomaly score high."],
        matched_features=["auth_failure_rate_baseline"],
        shap_contributors=["auth_failure_rate_baseline"],
        shap_total_contribution=0.4,
    )


def _make_mapping(alert_id: str = "a-001", model_id: str = "m") -> MappedAttack:
    return MappedAttack(
        alert_id=alert_id, model_id=model_id,
        entity_type="user_host", entity_id="e",
        event_id=alert_id, anomaly_score=0.82,
        techniques=[_tm()],
    )


def _make_report(run_id: str = "run-1") -> MappingReport:
    mappings = [_make_mapping(f"a-{i}") for i in range(3)]
    return MappingReport(run_id=run_id, model_id="m", mappings=mappings)


@pytest.fixture()
def store(tmp_path: Path) -> MappingStore:
    return MappingStore(store_dir=tmp_path / "mitre")


class TestMappingStore:
    def test_dirs_created(self, tmp_path: Path) -> None:
        d = tmp_path / "mitre"
        MappingStore(store_dir=d)
        assert d.exists()
        assert (d / "reports").exists()

    def test_save_mapping_creates_jsonl(self, store: MappingStore) -> None:
        path = store.save_mapping(_make_mapping())
        assert path.exists()
        assert path.suffix == ".jsonl"

    def test_save_mapping_appends(self, store: MappingStore) -> None:
        store.save_mapping(_make_mapping("a-001"))
        store.save_mapping(_make_mapping("a-002"))
        loaded = store.load_mappings_for_date()
        assert len(loaded) == 2

    def test_save_batch(self, store: MappingStore) -> None:
        mappings = [_make_mapping(f"a-{i}") for i in range(8)]
        paths = store.save_batch(mappings)
        assert len(paths) >= 1
        loaded = store.load_mappings_for_date()
        assert len(loaded) == 8

    def test_save_report_creates_json(self, store: MappingStore) -> None:
        path = store.save_report(_make_report())
        assert path.exists()
        assert path.suffix == ".json"

    def test_save_report_atomic_no_tmp(self, store: MappingStore) -> None:
        store.save_report(_make_report())
        tmp_files = list((store._dir / "reports").glob("*.tmp"))
        assert len(tmp_files) == 0

    def test_load_report_round_trip(self, store: MappingStore) -> None:
        report = _make_report("run-42")
        store.save_report(report)
        loaded = store.load_report(report.report_id)
        assert loaded.report_id == report.report_id
        assert loaded.run_id == "run-42"
        assert len(loaded.mappings) == 3

    def test_load_report_not_found_raises(self, store: MappingStore) -> None:
        with pytest.raises(MappingStorageError):
            store.load_report("nonexistent-id")

    def test_list_reports_empty(self, store: MappingStore) -> None:
        assert store.list_reports() == []

    def test_list_reports_after_saves(self, store: MappingStore) -> None:
        store.save_report(_make_report("r1"))
        store.save_report(_make_report("r2"))
        assert len(store.list_reports()) == 2

    def test_load_nonexistent_date_returns_empty(self, store: MappingStore) -> None:
        old = datetime(2020, 1, 1, tzinfo=UTC)
        assert store.load_mappings_for_date(old) == []

    def test_corrupt_line_skipped(self, store: MappingStore) -> None:
        path = store.save_mapping(_make_mapping())
        with path.open("a", encoding="utf-8") as fh:
            fh.write("{corrupted\n")
        loaded = store.load_mappings_for_date()
        assert len(loaded) == 1

    def test_list_mapping_dates(self, store: MappingStore) -> None:
        store.save_mapping(_make_mapping())
        dates = store.list_mapping_dates()
        assert len(dates) == 1
        assert len(dates[0]) == 10  # YYYY-MM-DD
