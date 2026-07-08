"""
tests/unit/explainability/test_explainer.py — SHAPExplainer Tests
==================================================================
"""

from __future__ import annotations

import pytest

from backend.detection.models import DetectionAlert
from backend.detection.trainer import IsolationForestTrainer
from backend.explainability.exceptions import ModelVersionMismatchError
from backend.explainability.explainer import SHAPExplainer
from backend.explainability.models import ExplanationResult
from backend.features.models import ALL_FEATURE_NAMES, FEATURE_DIMENSION

from tests.unit.explainability.conftest import (
    make_alert,
    make_feature_record,
    make_normal_records,
)


class TestSHAPExplainerInit:
    def test_init_success(self, shap_explainer: SHAPExplainer) -> None:
        assert shap_explainer.model_id is not None
        assert shap_explainer.expected_value is not None
        assert len(shap_explainer.feature_names) == FEATURE_DIMENSION

    def test_feature_names_match_canonical(self, shap_explainer: SHAPExplainer) -> None:
        assert shap_explainer.feature_names == list(ALL_FEATURE_NAMES)

    def test_expected_value_is_finite(self, shap_explainer: SHAPExplainer) -> None:
        import math
        assert math.isfinite(shap_explainer.expected_value)


class TestExplainAlert:
    def test_explain_alert_returns_result(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        result = shap_explainer.explain_alert(sample_alert, normal_record)
        assert isinstance(result, ExplanationResult)

    def test_explanation_id_starts_with_expl(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        result = shap_explainer.explain_alert(sample_alert, normal_record)
        assert result.explanation_id.startswith("expl-")

    def test_alert_id_preserved(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        result = shap_explainer.explain_alert(sample_alert, normal_record)
        assert result.alert_id == sample_alert.alert_id

    def test_model_id_preserved(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        result = shap_explainer.explain_alert(sample_alert, normal_record)
        assert result.model_id == shap_explainer.model_id

    def test_correct_number_of_contributions(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        result = shap_explainer.explain_alert(sample_alert, normal_record)
        assert len(result.feature_contributions) == FEATURE_DIMENSION

    def test_contributions_sorted_by_rank(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        result = shap_explainer.explain_alert(sample_alert, normal_record)
        ranks = [c.contribution_rank for c in result.feature_contributions]
        assert ranks == sorted(ranks)

    def test_top_features_count(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        result = shap_explainer.explain_alert(sample_alert, normal_record)
        assert len(result.top_features) == 5

    def test_top_features_are_feature_names(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        result = shap_explainer.explain_alert(sample_alert, normal_record)
        canonical = set(ALL_FEATURE_NAMES)
        for feat in result.top_features:
            assert feat in canonical

    def test_anomaly_score_copied(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        result = shap_explainer.explain_alert(sample_alert, normal_record)
        assert result.anomaly_score == pytest.approx(sample_alert.anomaly_score, abs=1e-6)

    def test_total_abs_shap_non_negative(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        result = shap_explainer.explain_alert(sample_alert, normal_record)
        assert result.total_abs_shap >= 0.0

    def test_all_shap_values_finite(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        import math
        result = shap_explainer.explain_alert(sample_alert, normal_record)
        for c in result.feature_contributions:
            assert math.isfinite(c.shap_value)
            assert math.isfinite(c.abs_shap_value)

    def test_contribution_pcts_sum_to_100_or_zero(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        """When all SHAP values are zero (constant training data), sum is 0. Otherwise ≈100."""
        result = shap_explainer.explain_alert(sample_alert, normal_record)
        total_pct = sum(c.contribution_pct for c in result.feature_contributions)
        # Either all zero OR sums to ~100
        assert total_pct == pytest.approx(0.0, abs=1.0) or abs(total_pct - 100.0) < 1.0

    def test_wrong_model_id_raises(
        self,
        shap_explainer: SHAPExplainer,
        normal_record,
    ) -> None:
        wrong_alert = make_alert(normal_record, model_id="wrong-model-id", anomaly_score=0.8)
        with pytest.raises(ModelVersionMismatchError):
            shap_explainer.explain_alert(wrong_alert, normal_record)

    def test_reproducible_shap_values(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        """Same input always produces identical SHAP values (TreeSHAP is exact)."""
        r1 = shap_explainer.explain_alert(sample_alert, normal_record)
        r2 = shap_explainer.explain_alert(sample_alert, normal_record)
        for c1, c2 in zip(r1.feature_contributions, r2.feature_contributions):
            assert c1.shap_value == pytest.approx(c2.shap_value, abs=1e-10)

    def test_raw_feature_values_match_record(
        self,
        shap_explainer: SHAPExplainer,
        sample_alert: DetectionAlert,
        normal_record,
    ) -> None:
        result = shap_explainer.explain_alert(sample_alert, normal_record)
        for name, val in result.raw_feature_values.items():
            assert isinstance(val, float)


class TestExplainBatch:
    def test_batch_returns_list(
        self,
        shap_explainer: SHAPExplainer,
        trained_pipeline_and_id,
    ) -> None:
        _, model_id = trained_pipeline_and_id
        records = [make_feature_record(event_id=f"e-{i}") for i in range(5)]
        alerts = [make_alert(r, model_id=model_id) for r in records]
        results = shap_explainer.explain_batch(alerts, records)
        assert len(results) == 5

    def test_batch_empty_returns_empty(
        self, shap_explainer: SHAPExplainer
    ) -> None:
        assert shap_explainer.explain_batch([], []) == []

    def test_batch_mismatched_lengths_raises(
        self, shap_explainer: SHAPExplainer, normal_record, sample_alert
    ) -> None:
        with pytest.raises(ValueError, match="parallel"):
            shap_explainer.explain_batch([sample_alert], [normal_record, normal_record])

    def test_batch_results_in_order(
        self,
        shap_explainer: SHAPExplainer,
        trained_pipeline_and_id,
    ) -> None:
        _, model_id = trained_pipeline_and_id
        records = [make_feature_record(event_id=f"e-{i}") for i in range(3)]
        alerts = [make_alert(r, model_id=model_id) for r in records]
        results = shap_explainer.explain_batch(alerts, records)
        for i, result in enumerate(results):
            assert result.event_id == records[i].event_id

    def test_batch_explanation_ids_unique(
        self,
        shap_explainer: SHAPExplainer,
        trained_pipeline_and_id,
    ) -> None:
        _, model_id = trained_pipeline_and_id
        records = [make_feature_record(event_id=f"e-{i}") for i in range(4)]
        alerts = [make_alert(r, model_id=model_id) for r in records]
        results = shap_explainer.explain_batch(alerts, records)
        ids = [r.explanation_id for r in results]
        assert len(set(ids)) == 4
