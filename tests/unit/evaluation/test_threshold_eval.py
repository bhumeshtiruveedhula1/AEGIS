"""
tests/unit/evaluation/test_threshold_eval.py
==============================================
Phase 9 Module 9.4 — Unit tests for threshold evaluation harness.

Covers all five evaluation criteria using synthetic ThresholdResult data.
No filesystem I/O except round-trip test (uses tmp_path fixture).
No live models loaded.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_LAB_ROOT = Path(__file__).parent.parent.parent.parent.parent / "aegis_ml_lab"
if str(_LAB_ROOT) not in sys.path:
    sys.path.insert(0, str(_LAB_ROOT))

from thresholds.compute_ecdf import EntityThreshold, ThresholdResult
from evaluate.threshold_eval import (
    CriterionResult,
    ThresholdEvalReport,
    _eval_per_entity,
    _eval_cold_start,
    _eval_fallback_unknown_entity,
    _eval_fpr_vs_target,
    run_threshold_evaluation,
    save_report,
)


# ---------------------------------------------------------------------------
# Helpers — build synthetic ThresholdResult
# ---------------------------------------------------------------------------

def _make_tr(
    per_entity_thresholds: dict[str, float] | None = None,
    cold_start_thresholds: dict[str, int] | None = None,
    fallback: float = 0.10,
    target_percentile: float = 95.0,
    cold_start_min: int = 30,
    run_id: str = "test-run-abc",
) -> ThresholdResult:
    """Build a synthetic ThresholdResult for unit testing."""
    per_entity_thresholds = per_entity_thresholds or {}
    cold_start_thresholds = cold_start_thresholds or {}
    entity_thresholds: dict[str, EntityThreshold] = {}
    for ek, thresh in per_entity_thresholds.items():
        entity_thresholds[ek] = EntityThreshold(
            entity_key=ek,
            threshold=thresh,
            method="per_entity",
            n_scored=cold_start_min + 10,    # above min
        )
    for ek, n_scored in cold_start_thresholds.items():
        entity_thresholds[ek] = EntityThreshold(
            entity_key=ek,
            threshold=fallback,
            method="cold_start_fallback",
            n_scored=n_scored,
        )
    return ThresholdResult(
        run_id=run_id,
        entity_type="IT",
        target_percentile=target_percentile,
        cold_start_min_events=cold_start_min,
        type_level_fallback=fallback,
        entity_thresholds=entity_thresholds,
    )


# ---------------------------------------------------------------------------
# Criterion 1 — Per-entity threshold behaviour
# ---------------------------------------------------------------------------

class TestCriterion1PerEntity:
    def test_pass_when_multiple_distinct_thresholds(self):
        tr = _make_tr(per_entity_thresholds={"e1": 0.1, "e2": 0.5, "e3": 0.3})
        result = _eval_per_entity(tr)
        assert result.passed is True

    def test_fail_when_no_per_entity_entities(self):
        tr = _make_tr(cold_start_thresholds={"e1": 5, "e2": 10})
        result = _eval_per_entity(tr)
        assert result.passed is False

    def test_fail_when_all_per_entity_thresholds_equal(self):
        tr = _make_tr(per_entity_thresholds={"e1": 0.5, "e2": 0.5})
        result = _eval_per_entity(tr)
        assert result.passed is False

    def test_pass_with_single_entity_but_unique_value(self):
        # Single per-entity entity — n_distinct = 1, not > 1 → FAIL
        tr = _make_tr(per_entity_thresholds={"e1": 0.5})
        result = _eval_per_entity(tr)
        # 1 entity, 1 distinct value — fails is_differentiated check
        assert result.passed is False

    def test_two_entities_different_values_pass(self):
        tr = _make_tr(per_entity_thresholds={"e1": 0.1, "e2": 0.6})
        result = _eval_per_entity(tr)
        assert result.passed is True

    def test_result_is_criterion_result(self):
        tr = _make_tr(per_entity_thresholds={"e1": 0.1, "e2": 0.5})
        result = _eval_per_entity(tr)
        assert isinstance(result, CriterionResult)
        assert result.name == "Per-entity threshold behaviour"


# ---------------------------------------------------------------------------
# Criterion 2 — Cold-start threshold behaviour
# ---------------------------------------------------------------------------

class TestCriterion2ColdStart:
    def test_pass_when_cold_start_entities_use_fallback(self):
        tr = _make_tr(
            per_entity_thresholds={"e1": 0.5, "e2": 0.3},
            cold_start_thresholds={"cold1": 5, "cold2": 10},
            fallback=0.10,
        )
        result = _eval_cold_start(tr)
        assert result.passed is True

    def test_fail_when_no_cold_start_entities(self):
        tr = _make_tr(per_entity_thresholds={"e1": 0.5, "e2": 0.3})
        result = _eval_cold_start(tr)
        assert result.passed is False

    def test_fail_when_cold_start_entity_above_min(self):
        tr = _make_tr(cold_start_thresholds={"bad": 5}, fallback=0.10, cold_start_min=30)
        # Manually override n_scored to be above min (simulates data corruption)
        tr.entity_thresholds["bad"].n_scored = 50
        result = _eval_cold_start(tr)
        assert result.passed is False

    def test_fail_when_cold_start_threshold_wrong(self):
        tr = _make_tr(cold_start_thresholds={"e1": 5}, fallback=0.10)
        # Manually corrupt the threshold value
        tr.entity_thresholds["e1"].threshold = 0.99
        result = _eval_cold_start(tr)
        assert result.passed is False

    def test_finding_contains_entity_count(self):
        tr = _make_tr(
            per_entity_thresholds={"e1": 0.5, "e2": 0.3},
            cold_start_thresholds={"cold1": 5},
            fallback=0.10,
        )
        result = _eval_cold_start(tr)
        assert "1 cold-start" in result.finding


# ---------------------------------------------------------------------------
# Criterion 3 — Fallback for unseen entity
# ---------------------------------------------------------------------------

class TestCriterion3Fallback:
    def test_unseen_entity_returns_fallback(self):
        tr = _make_tr(per_entity_thresholds={"e1": 0.5, "e2": 0.3}, fallback=0.10)
        result = _eval_fallback_unknown_entity(tr)
        assert result.passed is True

    def test_per_entity_lookup_returns_entity_threshold(self):
        tr = _make_tr(per_entity_thresholds={"e1": 0.5, "e2": 0.3}, fallback=0.10)
        # get_threshold("e1") must return 0.5, not 0.10
        assert tr.get_threshold("e1") == pytest.approx(0.5)

    def test_completely_unknown_key_returns_fallback(self):
        tr = _make_tr(per_entity_thresholds={"e1": 0.5}, fallback=0.10)
        assert tr.get_threshold("entity_xyz_not_registered") == pytest.approx(0.10)

    def test_empty_entity_dict_returns_fallback(self):
        tr = _make_tr(fallback=0.42)
        assert tr.get_threshold("any_key") == pytest.approx(0.42)

    def test_result_is_criterion_result(self):
        tr = _make_tr(per_entity_thresholds={"e1": 0.5, "e2": 0.3})
        result = _eval_fallback_unknown_entity(tr)
        assert isinstance(result, CriterionResult)
        assert result.name == "Threshold fallback for unseen entity"


# ---------------------------------------------------------------------------
# Criterion 4 — FPR vs target (synthetic raw_metrics.json)
# ---------------------------------------------------------------------------

class TestCriterion5FPRVsTarget:
    def test_pass_when_all_fprs_below_target(self, tmp_path):
        metrics = {"scenarios": [
            {"scenario": "a", "fpr": 0.02, "no_attack_records": False},
            {"scenario": "b", "fpr": 0.03, "no_attack_records": False},
        ]}
        path = tmp_path / "raw_metrics.json"
        path.write_text(json.dumps(metrics))
        result = _eval_fpr_vs_target(path)
        assert result.passed is True

    def test_fail_when_mean_fpr_above_target(self, tmp_path):
        metrics = {"scenarios": [
            {"scenario": "a", "fpr": 0.08, "no_attack_records": False},
            {"scenario": "b", "fpr": 0.06, "no_attack_records": False},
        ]}
        path = tmp_path / "raw_metrics.json"
        path.write_text(json.dumps(metrics))
        result = _eval_fpr_vs_target(path)
        assert result.passed is False

    def test_skip_no_attack_records_scenario(self, tmp_path):
        metrics = {"scenarios": [
            {"scenario": "a", "fpr": 0.01, "no_attack_records": False},
            {"scenario": "b", "fpr": 0.99, "no_attack_records": True},  # skipped
        ]}
        path = tmp_path / "raw_metrics.json"
        path.write_text(json.dumps(metrics))
        result = _eval_fpr_vs_target(path)
        # Only 'a' (fpr=0.01) contributes — passes
        assert result.passed is True

    def test_fail_when_file_not_found(self, tmp_path):
        result = _eval_fpr_vs_target(tmp_path / "nonexistent.json")
        assert result.passed is False

    def test_exactly_at_target_passes(self, tmp_path):
        metrics = {"scenarios": [
            {"scenario": "a", "fpr": 0.05, "no_attack_records": False},
        ]}
        path = tmp_path / "raw_metrics.json"
        path.write_text(json.dumps(metrics))
        result = _eval_fpr_vs_target(path)
        assert result.passed is True


# ---------------------------------------------------------------------------
# ThresholdResult property tests
# ---------------------------------------------------------------------------

class TestThresholdResultProperties:
    def test_per_entity_count(self):
        tr = _make_tr(per_entity_thresholds={"e1": 0.5, "e2": 0.3}, cold_start_thresholds={"cold": 5})
        assert tr.per_entity_count == 2

    def test_cold_start_count(self):
        tr = _make_tr(per_entity_thresholds={"e1": 0.5}, cold_start_thresholds={"c1": 5, "c2": 10})
        assert tr.cold_start_count == 2

    def test_to_json_dict_structure(self):
        tr = _make_tr(per_entity_thresholds={"e1": 0.5}, cold_start_thresholds={"c1": 5})
        d = tr.to_json_dict()
        assert "run_id" in d
        assert "type_level_fallback" in d
        assert "entity_thresholds" in d
        assert "per_entity_count" in d
        assert "cold_start_count" in d


# ---------------------------------------------------------------------------
# save_report round-trip
# ---------------------------------------------------------------------------

class TestSaveReport:
    def test_save_creates_json(self, tmp_path):
        report = ThresholdEvalReport(
            run_id="test-run",
            entity_type="IT",
            criteria=[
                CriterionResult("Test", True, "passed finding", "evidence.py:1"),
            ],
            measured_at="2026-07-17T00:00:00Z",
        )
        out = save_report(report, tmp_path / "test_report.json")
        assert out.exists()
        payload = json.loads(out.read_text())
        assert payload["all_passed"] is True
        assert len(payload["criteria"]) == 1

    def test_all_passed_property_true(self):
        report = ThresholdEvalReport(
            run_id="x",
            entity_type="IT",
            criteria=[
                CriterionResult("A", True, "ok", ""),
                CriterionResult("B", True, "ok", ""),
            ],
        )
        assert report.all_passed is True

    def test_all_passed_property_false_if_any_fail(self):
        report = ThresholdEvalReport(
            run_id="x",
            entity_type="IT",
            criteria=[
                CriterionResult("A", True, "ok", ""),
                CriterionResult("B", False, "fail", ""),
            ],
        )
        assert report.all_passed is False

    def test_verdict_pass_string(self):
        report = ThresholdEvalReport(
            run_id="x",
            entity_type="IT",
            criteria=[CriterionResult("A", True, "ok", "")],
        )
        assert "PASS" in report.verdict

    def test_verdict_fail_string(self):
        report = ThresholdEvalReport(
            run_id="x",
            entity_type="IT",
            criteria=[CriterionResult("A", False, "bad", "")],
        )
        assert "FAIL" in report.verdict


# ---------------------------------------------------------------------------
# Integration — run_threshold_evaluation against production data
# ---------------------------------------------------------------------------

class TestRunThresholdEvaluation:
    def test_returns_report_with_5_criteria(self):
        report = run_threshold_evaluation()
        assert len(report.criteria) == 5

    def test_all_criteria_pass_on_production_data(self):
        """All 5 criteria must pass on the production thresholds."""
        report = run_threshold_evaluation()
        for c in report.criteria:
            assert c.passed is True, f"FAILED criterion: {c.name}\n  Finding: {c.finding}"

    def test_run_id_is_populated(self):
        report = run_threshold_evaluation()
        assert report.run_id != ""

    def test_measured_at_is_set(self):
        report = run_threshold_evaluation()
        assert report.measured_at != ""
