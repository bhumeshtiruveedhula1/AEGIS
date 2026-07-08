"""
tests/unit/explainability/test_models.py — Explainability Model Tests
======================================================================
"""

from __future__ import annotations

import pytest

from backend.explainability.models import (
    EXPLAINABILITY_SCHEMA_VERSION,
    ExplainabilityReport,
    ExplanationResult,
    FeatureContribution,
)
from backend.features.models import ALL_FEATURE_NAMES


class TestFeatureContribution:
    def test_build_normal_direction(self) -> None:
        fc = FeatureContribution.build(
            feature_name="proc_count",
            raw_value=3.0,
            shap_value=-0.4,
            rank=1,
            total_abs_shap=1.0,
        )
        assert fc.direction == "normal"
        assert fc.abs_shap_value == pytest.approx(0.4, abs=1e-6)
        assert fc.contribution_pct == pytest.approx(40.0, abs=1e-3)

    def test_build_anomaly_direction(self) -> None:
        fc = FeatureContribution.build(
            feature_name="rare_process",
            raw_value=1.0,
            shap_value=0.6,
            rank=2,
            total_abs_shap=1.0,
        )
        assert fc.direction == "anomaly"
        assert fc.contribution_rank == 2

    def test_nan_shap_becomes_zero(self) -> None:
        fc = FeatureContribution.build(
            feature_name="f",
            raw_value=0.0,
            shap_value=float("nan"),
            rank=1,
            total_abs_shap=1.0,
        )
        assert fc.shap_value == 0.0
        assert fc.abs_shap_value == 0.0

    def test_total_abs_zero_no_division_error(self) -> None:
        fc = FeatureContribution.build(
            feature_name="f",
            raw_value=0.0,
            shap_value=0.0,
            rank=1,
            total_abs_shap=0.0,
        )
        assert fc.contribution_pct == 0.0

    def test_pct_capped_at_100(self) -> None:
        fc = FeatureContribution.build(
            feature_name="f",
            raw_value=0.0,
            shap_value=2.0,
            rank=1,
            total_abs_shap=1.0,  # pct = 200 → capped at 100
        )
        assert fc.contribution_pct <= 100.0

    def test_json_round_trip(self) -> None:
        fc = FeatureContribution.build("f", 1.0, 0.3, 1, 1.0)
        reloaded = FeatureContribution.model_validate_json(fc.model_dump_json())
        assert reloaded.feature_name == "f"
        assert reloaded.direction == "anomaly"


class TestExplanationResult:
    def _make_contributions(self, n: int = 3) -> list[FeatureContribution]:
        names = list(ALL_FEATURE_NAMES)[:n]
        total = float(n)
        return [
            FeatureContribution.build(names[i], float(i), 0.1 * (n - i), i + 1, total * 0.1)
            for i in range(n)
        ]

    def test_construction_minimal(self) -> None:
        result = ExplanationResult(
            alert_id="alert-001",
            model_id="m-001",
            entity_type="user_host",
            entity_id="alice::ws",
            event_id="evt-001",
            anomaly_score=0.8,
            expected_value=-0.1,
            total_abs_shap=1.5,
        )
        assert result.explanation_id.startswith("expl-")
        assert result.schema_version == EXPLAINABILITY_SCHEMA_VERSION
        assert result.explainer_type == "TreeSHAP"

    def test_explanation_id_unique(self) -> None:
        a = ExplanationResult(
            alert_id="a", model_id="m", entity_type="t", entity_id="e",
            event_id="ev1", anomaly_score=0.7, expected_value=0.0, total_abs_shap=1.0
        )
        b = ExplanationResult(
            alert_id="a", model_id="m", entity_type="t", entity_id="e",
            event_id="ev2", anomaly_score=0.7, expected_value=0.0, total_abs_shap=1.0
        )
        assert a.explanation_id != b.explanation_id

    def test_contributions_sorted_by_rank(self) -> None:
        contribs = self._make_contributions(5)
        import random
        random.shuffle(contribs)
        result = ExplanationResult(
            alert_id="a", model_id="m", entity_type="t", entity_id="e",
            event_id="ev", anomaly_score=0.7, expected_value=0.0,
            total_abs_shap=1.0, feature_contributions=contribs,
        )
        ranks = [c.contribution_rank for c in result.feature_contributions]
        assert ranks == sorted(ranks)

    def test_top_n_contributions(self) -> None:
        contribs = self._make_contributions(10)
        result = ExplanationResult(
            alert_id="a", model_id="m", entity_type="t", entity_id="e",
            event_id="ev", anomaly_score=0.7, expected_value=0.0,
            total_abs_shap=1.0, feature_contributions=contribs,
        )
        top3 = result.top_n_contributions(3)
        assert len(top3) == 3
        assert top3[0].contribution_rank == 1

    def test_to_summary_keys(self) -> None:
        result = ExplanationResult(
            alert_id="a", model_id="m", entity_type="t", entity_id="e",
            event_id="ev", anomaly_score=0.7, expected_value=0.0, total_abs_shap=1.0
        )
        summary = result.to_summary()
        for key in ("explanation_id", "alert_id", "model_id", "anomaly_score",
                    "top_features", "total_abs_shap"):
            assert key in summary

    def test_json_round_trip_with_contributions(self) -> None:
        contribs = self._make_contributions(3)
        result = ExplanationResult(
            alert_id="a", model_id="m", entity_type="t", entity_id="e",
            event_id="ev", anomaly_score=0.7, expected_value=0.0,
            total_abs_shap=1.0, feature_contributions=contribs,
        )
        reloaded = ExplanationResult.model_validate_json(result.model_dump_json())
        assert len(reloaded.feature_contributions) == 3
        assert reloaded.explanation_id == result.explanation_id


class TestExplainabilityReport:
    def _make_result(self, alert_id: str = "a", model_id: str = "m") -> ExplanationResult:
        names = list(ALL_FEATURE_NAMES)[:3]
        contribs = [
            FeatureContribution.build(names[i], 0.0, 0.1 * (3 - i), i + 1, 0.6)
            for i in range(3)
        ]
        return ExplanationResult(
            alert_id=alert_id, model_id=model_id, entity_type="user_host",
            entity_id="e", event_id=alert_id,
            anomaly_score=0.8, expected_value=0.0, total_abs_shap=0.6,
            feature_contributions=contribs,
            top_features=names[:3],
        )

    def test_empty_report(self) -> None:
        report = ExplainabilityReport(
            run_id="run-1", model_id="m", explanations=[]
        )
        assert report.alerts_explained == 0
        assert report.avg_total_abs_shap == 0.0
        assert report.top_global_features == []

    def test_aggregates_computed(self) -> None:
        results = [self._make_result(f"alert-{i}") for i in range(5)]
        report = ExplainabilityReport(
            run_id="run-1", model_id="m", explanations=results
        )
        assert report.alerts_explained == 5
        assert report.avg_total_abs_shap > 0.0
        assert len(report.top_global_features) > 0

    def test_top_global_features_from_top_5(self) -> None:
        results = [self._make_result(f"a-{i}") for i in range(3)]
        report = ExplainabilityReport(
            run_id="r", model_id="m", explanations=results
        )
        # top_global_features should contain the names used in top_features
        for feat in report.top_global_features:
            assert feat in list(ALL_FEATURE_NAMES)

    def test_to_summary_structure(self) -> None:
        results = [self._make_result()]
        report = ExplainabilityReport(run_id="r", model_id="m", explanations=results)
        summary = report.to_summary()
        for key in ("report_id", "run_id", "alerts_explained", "errors",
                    "avg_total_abs_shap", "generated_at"):
            assert key in summary

    def test_json_round_trip(self) -> None:
        results = [self._make_result("a1"), self._make_result("a2")]
        report = ExplainabilityReport(run_id="r", model_id="m", explanations=results)
        reloaded = ExplainabilityReport.model_validate_json(report.model_dump_json())
        assert reloaded.report_id == report.report_id
        assert len(reloaded.explanations) == 2

    def test_errors_field(self) -> None:
        report = ExplainabilityReport(run_id="r", model_id="m", explanations=[], errors=3)
        assert report.errors == 3
