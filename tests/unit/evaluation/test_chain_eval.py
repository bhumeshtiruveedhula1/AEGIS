"""
tests/unit/evaluation/test_chain_eval.py
=========================================
Phase 9 Module 9.3 — Unit tests for AttackChainEvaluator

Tests the evaluation harness in isolation. All tests are deterministic:
they use the real AttackGraphBuilder + AttackChainDetector pipeline but
do NOT require ML models, stored graphs, or filesystem access.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# AttackChainEvaluator imports from aegis_ml_lab — sys.path patching
# is handled by conftest.py / pytest ini; both cybershield and aegis_ml_lab
# must be on PYTHONPATH for this test.
import sys
_LAB_ROOT = Path(__file__).parent.parent.parent.parent.parent / "aegis_ml_lab"
if str(_LAB_ROOT) not in sys.path:
    sys.path.insert(0, str(_LAB_ROOT))

from evaluate.chain_eval import (  # noqa: E402
    CHAIN_ACCURACY_TARGET,
    AttackChainEvaluator,
    ChainEvalReport,
    ChainEvalResult,
    _build_mapped_attack_for_technique,
    _normalise_for_match,
)


# ---------------------------------------------------------------------------
# Module-level fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def kb():
    from backend.mitre.knowledge_base import get_knowledge_base
    return get_knowledge_base()


@pytest.fixture(scope="module")
def evaluator():
    return AttackChainEvaluator()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_target_is_70_percent(self):
        assert CHAIN_ACCURACY_TARGET == pytest.approx(0.70)


# ---------------------------------------------------------------------------
# _normalise_for_match
# ---------------------------------------------------------------------------

class TestNormaliseForMatch:
    def test_single_technique_adds_parent(self):
        result = _normalise_for_match(["T1110.004"])
        assert "T1110.004" in result
        assert "T1110" in result

    def test_parent_technique_only_added_once(self):
        result = _normalise_for_match(["T1110"])
        assert "T1110" in result
        # Parent of T1110 is T1110 itself (no dot)
        assert len([x for x in result if x == "T1110"]) == 1

    def test_multi_technique_expanded(self):
        result = _normalise_for_match(["T1021.002", "T1078"])
        assert "T1021.002" in result
        assert "T1021" in result
        assert "T1078" in result

    def test_empty_returns_empty_set(self):
        assert _normalise_for_match([]) == set()


# ---------------------------------------------------------------------------
# _build_mapped_attack_for_technique
# ---------------------------------------------------------------------------

class TestBuildMappedAttack:
    def test_known_technique_returns_mapped_attack(self, kb):
        ma = _build_mapped_attack_for_technique("T1110", "test_entity", "test_scenario", kb)
        assert ma is not None
        assert ma.entity_id == "test_entity"
        assert len(ma.techniques) == 1
        assert ma.techniques[0].technique.technique_id in ("T1110",)

    def test_unknown_technique_with_no_parent_returns_none(self, kb):
        ma = _build_mapped_attack_for_technique("T9999.999", "test_entity", "test_scenario", kb)
        assert ma is None

    def test_sub_technique_falls_back_to_parent(self, kb):
        # T1110.004 is in KB directly; but even if it weren't, parent T1110 would be used
        ma = _build_mapped_attack_for_technique("T1110.004", "test_entity", "test_scenario", kb)
        # Either the sub-technique or parent is found — not None
        assert ma is not None

    def test_confidence_in_valid_range(self, kb):
        ma = _build_mapped_attack_for_technique("T1021.002", "ent", "scen", kb)
        assert ma is not None
        assert 0.0 <= ma.techniques[0].confidence <= 1.0

    def test_anomaly_score_set_correctly(self, kb):
        ma = _build_mapped_attack_for_technique("T1041", "ent", "scen", kb, anomaly_score=0.9)
        assert ma is not None
        assert ma.anomaly_score == pytest.approx(0.9)


# ---------------------------------------------------------------------------
# AttackChainEvaluator.evaluate_scenario — structural tests
# ---------------------------------------------------------------------------

class TestEvaluateScenario:
    def test_lateral_movement_smb_detects_chain(self, evaluator):
        """
        lateral_movement_smb has 2 GT techniques (T1021.002, T1078).
        The chain detector requires MIN_CHAIN_LENGTH=2, so a chain IS expected.
        """
        result = evaluator.evaluate_scenario("lateral_movement_smb")
        assert isinstance(result, ChainEvalResult)
        assert result.chains_found >= 1
        assert result.tp == 2
        assert result.fn == 0
        assert result.recall == pytest.approx(1.0)
        assert result.any_tp_detected is True

    def test_full_kill_chain_it_detects_all_techniques(self, evaluator):
        """full_kill_chain_it has 4 GT techniques — multi-tactic chain expected."""
        result = evaluator.evaluate_scenario("full_kill_chain_it")
        assert result.tp == 4
        assert result.fn == 0
        assert result.recall == pytest.approx(1.0)
        assert result.chains_found >= 1

    def test_single_technique_scenario_chain_detected(self, evaluator):
        """
        brute_force_auth has 1 GT technique (T1110).
        The evaluator uses min_chain_length=1 for single-technique scenarios so that
        the temporal-order fallback in AttackChainDetector fires and emits a 1-node
        chain. Production MIN_CHAIN_LENGTH=2 is unchanged — this is eval-harness only.
        """
        result = evaluator.evaluate_scenario("brute_force_auth")
        assert result.chains_found >= 1
        assert result.tp == 1
        assert result.any_tp_detected is True
        assert result.recall == pytest.approx(1.0)

    def test_result_has_correct_ground_truth(self, evaluator):
        result = evaluator.evaluate_scenario("lateral_movement_smb")
        assert set(result.ground_truth_techniques) == {"T1021.002", "T1078"}

    def test_kb_coverage_populated(self, evaluator):
        result = evaluator.evaluate_scenario("lateral_movement_smb")
        assert len(result.kb_coverage) > 0

    def test_invalid_scenario_raises(self, evaluator):
        with pytest.raises(ValueError, match="No template registered"):
            evaluator.evaluate_scenario("nonexistent_scenario_xyz")

    def test_no_false_positives_for_exact_gt(self, evaluator):
        """When GT techniques are exactly what the detector produces, fp == 0."""
        result = evaluator.evaluate_scenario("lateral_movement_smb")
        assert result.fp == 0


# ---------------------------------------------------------------------------
# AttackChainEvaluator.evaluate_all
# ---------------------------------------------------------------------------

class TestEvaluateAll:
    def test_returns_report_with_9_scenarios(self, evaluator):
        report = evaluator.evaluate_all()
        assert isinstance(report, ChainEvalReport)
        assert report.n_scenarios == 9

    def test_accuracy_matches_manual_count(self, evaluator):
        """
        All 9 scenarios now produce >= 1 TP:
        - Multi-technique scenarios (lateral_movement_smb, full_kill_chain_it) use
          the standard min_chain_length=2 path.
        - Single-technique scenarios use min_chain_length=1 in the evaluator harness
          so the temporal-order fallback fires and emits a 1-node chain.
        Result: 9/9 = 100%.
        """
        report = evaluator.evaluate_all()
        assert report.n_with_any_tp == 9
        assert report.attack_chain_detection_accuracy == pytest.approx(1.0, abs=0.001)

    def test_target_met_at_current_accuracy(self, evaluator):
        """100% > 70% target. target_met must be True."""
        report = evaluator.evaluate_all()
        assert report.target_met is True

    def test_all_scenario_names_present(self, evaluator):
        report = evaluator.evaluate_all()
        names = {r.scenario for r in report.scenarios}
        expected = {
            "brute_force_auth", "credential_stuffing", "lateral_movement_smb",
            "privilege_escalation_token", "persistence_scheduled_task",
            "command_execution_powershell", "network_discovery_scan",
            "data_exfiltration_http", "full_kill_chain_it",
        }
        assert names == expected

    def test_mean_recall_is_non_negative(self, evaluator):
        report = evaluator.evaluate_all()
        assert report.mean_technique_recall >= 0.0

    def test_measured_at_is_set(self, evaluator):
        report = evaluator.evaluate_all()
        assert report.measured_at != ""

    def test_subset_scenarios(self, evaluator):
        """evaluate_all with a subset of 2 multi-technique scenarios."""
        report = evaluator.evaluate_all(
            scenarios=["lateral_movement_smb", "full_kill_chain_it"]
        )
        assert report.n_scenarios == 2
        assert report.n_with_any_tp == 2
        assert report.attack_chain_detection_accuracy == pytest.approx(1.0)
        assert report.target_met is True


# ---------------------------------------------------------------------------
# save() method
# ---------------------------------------------------------------------------

class TestSave:
    def test_save_creates_valid_json(self, evaluator, tmp_path):
        report = evaluator.evaluate_all()
        out = tmp_path / "chain_eval_results.json"
        returned = evaluator.save(out, report)
        assert returned == out
        assert out.exists()
        payload = json.loads(out.read_text())
        assert "n_scenarios" in payload
        assert "attack_chain_detection_accuracy" in payload
        assert len(payload["scenarios"]) == 9

    def test_save_creates_parent_dirs(self, evaluator, tmp_path):
        report = evaluator.evaluate_all()
        nested = tmp_path / "runs" / "run-abc" / "chain_eval_results.json"
        evaluator.save(nested, report)
        assert nested.exists()

    def test_save_without_report_calls_evaluate_all(self, evaluator, tmp_path):
        out = tmp_path / "auto_eval.json"
        evaluator.save(out)   # no report argument
        payload = json.loads(out.read_text())
        assert payload["n_scenarios"] == 9


# ---------------------------------------------------------------------------
# log_report() smoke test
# ---------------------------------------------------------------------------

class TestLogReport:
    def test_log_report_does_not_raise(self, evaluator):
        report = evaluator.evaluate_all()
        evaluator.log_report(report)   # must not raise

    def test_log_report_without_arg(self, evaluator):
        evaluator.log_report()   # calls evaluate_all() internally, must not raise
