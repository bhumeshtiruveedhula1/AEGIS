"""
tests/unit/explainability/test_storage.py — ExplanationStore Tests
===================================================================
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from backend.explainability.exceptions import ExplanationStorageError
from backend.explainability.models import ExplainabilityReport, ExplanationResult
from backend.explainability.storage import ExplanationStore
from backend.features.models import ALL_FEATURE_NAMES

from tests.unit.explainability.conftest import make_alert, make_feature_record


def _make_result(alert_id: str = "a-001", model_id: str = "m-001") -> ExplanationResult:
    from backend.explainability.models import FeatureContribution
    names = list(ALL_FEATURE_NAMES)[:3]
    contribs = [
        FeatureContribution.build(names[i], 0.0, 0.1 * (3 - i), i + 1, 0.6)
        for i in range(3)
    ]
    return ExplanationResult(
        alert_id=alert_id, model_id=model_id,
        entity_type="user_host", entity_id="e",
        event_id=alert_id, anomaly_score=0.8,
        expected_value=-0.1, total_abs_shap=0.6,
        feature_contributions=contribs,
        top_features=names[:3],
    )


def _make_report(run_id: str = "run-1") -> ExplainabilityReport:
    results = [_make_result(f"a-{i}") for i in range(3)]
    return ExplainabilityReport(run_id=run_id, model_id="m-001", explanations=results)


@pytest.fixture()
def store(tmp_path: Path) -> ExplanationStore:
    return ExplanationStore(store_dir=tmp_path / "explanations")


class TestExplanationStore:
    def test_store_dirs_created(self, tmp_path: Path) -> None:
        store_dir = tmp_path / "expl"
        ExplanationStore(store_dir=store_dir)
        assert store_dir.exists()
        assert (store_dir / "reports").exists()

    def test_save_explanation_creates_jsonl(self, store: ExplanationStore) -> None:
        result = _make_result()
        path = store.save_explanation(result)
        assert path.exists()
        assert path.suffix == ".jsonl"

    def test_save_explanation_appends(self, store: ExplanationStore) -> None:
        r1 = _make_result("a-001")
        r2 = _make_result("a-002")
        store.save_explanation(r1)
        store.save_explanation(r2)
        # Both on same date → same file
        loaded = store.load_explanations_for_date()
        assert len(loaded) == 2

    def test_save_report_creates_json(self, store: ExplanationStore) -> None:
        report = _make_report()
        path = store.save_report(report)
        assert path.exists()
        assert path.suffix == ".json"

    def test_save_report_atomic_no_tmp_remaining(self, store: ExplanationStore) -> None:
        report = _make_report()
        store.save_report(report)
        tmp_files = list((store._dir / "reports").glob("*.tmp"))
        assert len(tmp_files) == 0

    def test_load_report_round_trip(self, store: ExplanationStore) -> None:
        report = _make_report("run-42")
        store.save_report(report)
        loaded = store.load_report(report.report_id)
        assert loaded.report_id == report.report_id
        assert loaded.run_id == "run-42"
        assert len(loaded.explanations) == 3

    def test_load_report_not_found_raises(self, store: ExplanationStore) -> None:
        with pytest.raises(ExplanationStorageError):
            store.load_report("nonexistent-report-id")

    def test_list_reports_empty(self, store: ExplanationStore) -> None:
        assert store.list_reports() == []

    def test_list_reports_after_saves(self, store: ExplanationStore) -> None:
        store.save_report(_make_report("run-1"))
        store.save_report(_make_report("run-2"))
        ids = store.list_reports()
        assert len(ids) == 2

    def test_save_batch_groups_by_date(self, store: ExplanationStore) -> None:
        results = [_make_result(f"a-{i}") for i in range(10)]
        paths = store.save_batch(results)
        assert len(paths) >= 1
        loaded = store.load_explanations_for_date()
        assert len(loaded) == 10

    def test_load_explanations_nonexistent_date_returns_empty(
        self, store: ExplanationStore
    ) -> None:
        old_date = datetime(2020, 1, 1, tzinfo=UTC)
        result = store.load_explanations_for_date(old_date)
        assert result == []

    def test_corrupt_line_skipped_on_load(self, store: ExplanationStore) -> None:
        result = _make_result()
        path = store.save_explanation(result)
        # Append a corrupt line
        with path.open("a", encoding="utf-8") as fh:
            fh.write("{not valid json\n")
        loaded = store.load_explanations_for_date()
        assert len(loaded) == 1  # corrupt line skipped

    def test_list_explanation_dates(self, store: ExplanationStore) -> None:
        store.save_explanation(_make_result())
        dates = store.list_explanation_dates()
        assert len(dates) == 1
        # Date format YYYY-MM-DD
        assert len(dates[0]) == 10
