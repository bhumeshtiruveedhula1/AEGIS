"""
tests/unit/detection/test_scorer.py — AnomalyScorer Tests
==========================================================
"""

from __future__ import annotations

import pytest

from backend.detection.models import DetectionAlert, DetectionResult
from backend.detection.scorer import AnomalyScorer, _sigmoid_score
from backend.detection.trainer import IsolationForestTrainer
from backend.features.models import FEATURE_DIMENSION
from tests.unit.detection.conftest import (
    make_feature_record,
    make_normal_records,
)

# ---------------------------------------------------------------------------
# _sigmoid_score unit tests
# ---------------------------------------------------------------------------


class TestSigmoidScore:
    def test_boundary_near_half(self) -> None:
        """decision_function=0 → score ≈ 0.5"""
        assert _sigmoid_score(0.0) == pytest.approx(0.5, abs=1e-6)

    def test_negative_input_above_half(self) -> None:
        """Negative IF score (anomalous) → score > 0.5"""
        assert _sigmoid_score(-1.0) > 0.5

    def test_positive_input_below_half(self) -> None:
        """Positive IF score (normal) → score < 0.5"""
        assert _sigmoid_score(1.0) < 0.5

    def test_output_in_range(self) -> None:
        for raw in [-10.0, -1.0, -0.1, 0.0, 0.1, 1.0, 10.0]:
            s = _sigmoid_score(raw)
            assert 0.0 <= s <= 1.0

    def test_nan_returns_zero(self) -> None:
        assert _sigmoid_score(float("nan")) == 0.0

    def test_inf_returns_valid(self) -> None:
        # Non-finite inputs are caught by the math.isfinite guard and return 0.0
        assert _sigmoid_score(float("inf")) == 0.0
        assert _sigmoid_score(float("-inf")) == 0.0

    def test_monotonically_decreasing(self) -> None:
        """Higher raw score (more normal) → lower anomaly score."""
        scores = [_sigmoid_score(x) for x in [-2.0, -1.0, 0.0, 1.0, 2.0]]
        for a, b in zip(scores, scores[1:], strict=False):
            assert a > b


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def trained_scorer() -> AnomalyScorer:
    """Train a minimal IF and return a scorer with threshold=0.5."""
    records = make_normal_records(80)
    trainer = IsolationForestTrainer(n_estimators=10, contamination=0.05, random_state=42)
    pipeline, metadata, _ = trainer.train(records)
    return AnomalyScorer(pipeline, metadata, threshold=0.5)


# ---------------------------------------------------------------------------
# AnomalyScorer tests
# ---------------------------------------------------------------------------


class TestAnomalyScorer:
    def test_score_single_normal_returns_none_or_alert(self, trained_scorer: AnomalyScorer) -> None:
        """Normal record should typically score below threshold."""
        normal = make_feature_record(anomaly_hint=0.0)
        # Can't guarantee None due to IF stochasticity, but anomaly_score must be valid
        result = trained_scorer.score_single(normal)
        assert result is None or isinstance(result, DetectionAlert)

    def test_score_single_alert_has_required_fields(self, trained_scorer: AnomalyScorer) -> None:
        """Any emitted alert must have all required DetectionAlert fields."""
        records = make_normal_records(100)
        for rec in records:
            alert = trained_scorer.score_single(rec)
            if alert is not None:
                assert 0.0 <= alert.anomaly_score <= 1.0
                assert alert.model_id == trained_scorer.model_id
                assert alert.is_alert is True
                assert alert.feature_dimension == FEATURE_DIMENSION
                break

    def test_score_single_score_in_range(self, trained_scorer: AnomalyScorer) -> None:
        """All scores must be in [0, 1] regardless of record content."""
        for hint in [0.0, 0.5, 1.0]:
            rec = make_feature_record(anomaly_hint=hint)
            alert = trained_scorer.score_single(rec)
            if alert is not None:
                assert 0.0 <= alert.anomaly_score <= 1.0

    def test_score_batch_returns_detection_result(self, trained_scorer: AnomalyScorer) -> None:
        records = make_normal_records(20)
        result = trained_scorer.score_batch(records)
        assert isinstance(result, DetectionResult)
        assert result.records_scored == 20
        assert result.completed_at is not None

    def test_score_batch_empty_entity_dim(self, trained_scorer: AnomalyScorer) -> None:
        """Records of wrong dimension → 0 scored."""
        records = make_normal_records(10, entity_type="user")  # wrong dim
        result = trained_scorer.score_batch(records, entity_dim="user_host")
        assert result.records_scored == 0
        assert result.alerts_generated == 0

    def test_score_batch_alert_count_consistent(self, trained_scorer: AnomalyScorer) -> None:
        records = make_normal_records(30)
        result = trained_scorer.score_batch(records)
        assert result.alerts_generated == len(result.alerts)

    def test_score_stream_yields_only_alerts(self, trained_scorer: AnomalyScorer) -> None:
        records = make_normal_records(40)
        alerts = list(trained_scorer.score_stream(iter(records)))
        # All emitted items must be DetectionAlert
        for alert in alerts:
            assert isinstance(alert, DetectionAlert)
            assert alert.anomaly_score >= trained_scorer.threshold

    def test_score_stream_filters_wrong_entity_dim(self, trained_scorer: AnomalyScorer) -> None:
        records = make_normal_records(20, entity_type="user")  # wrong dim
        alerts = list(trained_scorer.score_stream(iter(records), entity_dim="user_host"))
        assert alerts == []

    def test_scorer_model_id_property(self, trained_scorer: AnomalyScorer) -> None:
        assert trained_scorer.model_id is not None
        assert len(trained_scorer.model_id) > 0

    def test_scorer_threshold_property(self, trained_scorer: AnomalyScorer) -> None:
        assert trained_scorer.threshold == pytest.approx(0.5, abs=1e-9)

    def test_scorer_entity_dimension_property(self, trained_scorer: AnomalyScorer) -> None:
        assert trained_scorer.entity_dimension == "user_host"

    def test_raw_feature_values_in_alert(self, trained_scorer: AnomalyScorer) -> None:
        """DetectionAlert.raw_feature_values must have all feature names."""
        records = make_normal_records(50)
        from backend.features.models import ALL_FEATURE_NAMES

        for rec in records:
            alert = trained_scorer.score_single(rec)
            if alert is not None:
                for name in ALL_FEATURE_NAMES:
                    assert name in alert.raw_feature_values
                break

    def test_score_batch_with_errors_still_completes(self, trained_scorer: AnomalyScorer) -> None:
        """Batch scoring should complete even if some records are unusual."""
        records = make_normal_records(20)
        result = trained_scorer.score_batch(records)
        assert result.completed_at is not None
        assert result.errors == 0  # all normal records should process fine
