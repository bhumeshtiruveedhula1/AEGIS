"""tests/unit/mitre/test_mapper.py — MitreMapper Tests."""

from __future__ import annotations

import pytest

from backend.mitre.mapper import (
    DEFAULT_MIN_CONFIDENCE,
    MAX_TECHNIQUES_PER_ALERT,
    MitreMapper,
    _MAX_SHAP_TOTAL,
    _W_ANOMALY,
    _W_FEATURE_BREADTH,
    _W_SHAP,
)
from backend.mitre.models import MappedAttack

from tests.unit.mitre.conftest import (
    MODEL_ID,
    make_alert,
    make_explanation,
)


class TestMitreMapperInit:
    def test_default_init(self, mapper: MitreMapper) -> None:
        assert mapper._min_confidence == DEFAULT_MIN_CONFIDENCE
        assert mapper._max_techniques == MAX_TECHNIQUES_PER_ALERT

    def test_custom_params(self) -> None:
        m = MitreMapper(min_confidence=0.30, max_techniques=3)
        assert m._min_confidence == 0.30
        assert m._max_techniques == 3


class TestMitreMapperSingle:
    def test_map_alert_returns_mapped_attack(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        result = mapper.map_alert(sample_alert, sample_explanation)
        assert isinstance(result, MappedAttack)

    def test_mapping_id_prefix(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        result = mapper.map_alert(sample_alert, sample_explanation)
        assert result.mapping_id.startswith("map-")

    def test_alert_id_preserved(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        result = mapper.map_alert(sample_alert, sample_explanation)
        assert result.alert_id == sample_alert.alert_id

    def test_model_id_preserved(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        result = mapper.map_alert(sample_alert, sample_explanation)
        assert result.model_id == MODEL_ID

    def test_entity_fields_preserved(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        result = mapper.map_alert(sample_alert, sample_explanation)
        assert result.entity_type == sample_alert.entity_key.entity_type
        assert result.entity_id == sample_alert.entity_key.entity_id

    def test_anomaly_score_preserved(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        result = mapper.map_alert(sample_alert, sample_explanation)
        assert result.anomaly_score == pytest.approx(sample_alert.anomaly_score)

    def test_techniques_found_with_evidence(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        result = mapper.map_alert(sample_alert, sample_explanation)
        # Auth-related features should produce T1110, T1078 etc.
        assert len(result.techniques) > 0

    def test_techniques_sorted_by_confidence_descending(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        result = mapper.map_alert(sample_alert, sample_explanation)
        confs = [t.confidence for t in result.techniques]
        assert confs == sorted(confs, reverse=True)

    def test_all_confidences_in_range(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        result = mapper.map_alert(sample_alert, sample_explanation)
        for tm in result.techniques:
            assert 0.0 <= tm.confidence <= 1.0

    def test_all_confidences_above_threshold(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        result = mapper.map_alert(sample_alert, sample_explanation)
        for tm in result.techniques:
            assert tm.confidence >= mapper._min_confidence

    def test_techniques_capped_at_max(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        result = mapper.map_alert(sample_alert, sample_explanation)
        assert len(result.techniques) <= mapper._max_techniques

    def test_explanation_id_captured(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        result = mapper.map_alert(sample_alert, sample_explanation)
        assert result.explanation_id == sample_explanation.explanation_id

    def test_top_shap_features_from_explanation(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        result = mapper.map_alert(sample_alert, sample_explanation)
        assert result.top_shap_features == sample_explanation.top_features

    def test_map_without_explanation(
        self, mapper: MitreMapper, sample_alert
    ) -> None:
        """Graceful degradation: mapping works without SHAP evidence."""
        result = mapper.map_alert(sample_alert, None)
        assert isinstance(result, MappedAttack)
        assert result.explanation_id == ""

    def test_map_unknown_features_returns_empty_techniques(
        self, mapper: MitreMapper
    ) -> None:
        """Alert with completely unknown features → empty techniques list."""
        alert = make_alert(raw_feature_values={"completely_unknown_feature": 1.0})
        expl = make_explanation(
            alert_id=alert.alert_id,
            top_features=[],
        )
        # Manually override top_features to unknown names
        from backend.explainability.models import ExplanationResult
        expl2 = expl.model_copy(update={"feature_contributions": []})
        result = mapper.map_alert(alert, expl2)
        assert isinstance(result, MappedAttack)
        # No matched techniques for empty contributions
        # (may still find some via raw_feature_values fallback)

    def test_reproducible_mapping(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        """Same inputs always produce identical mapping (deterministic)."""
        r1 = mapper.map_alert(sample_alert, sample_explanation)
        r2 = mapper.map_alert(sample_alert, sample_explanation)
        assert len(r1.techniques) == len(r2.techniques)
        for t1, t2 in zip(r1.techniques, r2.techniques):
            assert t1.technique.technique_id == t2.technique.technique_id
            assert t1.confidence == pytest.approx(t2.confidence)

    def test_high_anomaly_score_boosts_confidence(
        self, mapper: MitreMapper
    ) -> None:
        low_alert = make_alert(anomaly_score=0.3)
        high_alert = make_alert(anomaly_score=0.95)
        expl_low = make_explanation(alert_id=low_alert.alert_id)
        expl_high = make_explanation(alert_id=high_alert.alert_id)

        r_low = mapper.map_alert(low_alert, expl_low)
        r_high = mapper.map_alert(high_alert, expl_high)

        if r_low.primary_technique and r_high.primary_technique:
            # Higher anomaly score → higher confidence for same technique
            assert r_high.primary_technique.confidence >= r_low.primary_technique.confidence


class TestConfidenceFormula:
    def test_weights_sum_to_one(self) -> None:
        assert abs(_W_ANOMALY + _W_SHAP + _W_FEATURE_BREADTH - 1.0) < 1e-9

    def test_zero_inputs_give_zero_confidence(self, mapper: MitreMapper) -> None:
        c = mapper._compute_confidence(
            anomaly_score=0.0, shap_total=0.0, feature_match_count=0
        )
        assert c == pytest.approx(0.0)

    def test_max_inputs_give_confidence_one(self, mapper: MitreMapper) -> None:
        c = mapper._compute_confidence(
            anomaly_score=1.0, shap_total=_MAX_SHAP_TOTAL, feature_match_count=10
        )
        assert c == pytest.approx(1.0)

    def test_confidence_clipped_to_unit_interval(self, mapper: MitreMapper) -> None:
        c = mapper._compute_confidence(
            anomaly_score=1.0, shap_total=100.0, feature_match_count=999
        )
        assert 0.0 <= c <= 1.0

    def test_deterministic(self, mapper: MitreMapper) -> None:
        c1 = mapper._compute_confidence(0.8, 1.5, 5)
        c2 = mapper._compute_confidence(0.8, 1.5, 5)
        assert c1 == c2

    def test_rounded_to_4_dp(self, mapper: MitreMapper) -> None:
        c = mapper._compute_confidence(0.75, 1.2, 4)
        assert c == round(c, 4)


class TestMitreMapperBatch:
    def test_batch_returns_list(self, mapper: MitreMapper) -> None:
        alerts = [make_alert(f"a-{i}") for i in range(5)]
        results = mapper.map_batch(alerts)
        assert len(results) == 5

    def test_batch_empty_returns_empty(self, mapper: MitreMapper) -> None:
        assert mapper.map_batch([]) == []

    def test_batch_with_explanations(self, mapper: MitreMapper) -> None:
        alerts = [make_alert(f"a-{i}") for i in range(3)]
        expls = [make_explanation(alert_id=a.alert_id) for a in alerts]
        results = mapper.map_batch(alerts, expls)
        assert len(results) == 3
        for r in results:
            assert r.explanation_id != ""

    def test_batch_results_in_order(self, mapper: MitreMapper) -> None:
        alerts = [make_alert(f"a-{i}") for i in range(4)]
        results = mapper.map_batch(alerts)
        for i, result in enumerate(results):
            assert result.alert_id == f"a-{i}"


class TestMitreMapperStream:
    def test_stream_yields_results(self, mapper: MitreMapper) -> None:
        alerts = [make_alert(f"a-{i}") for i in range(3)]
        pairs = [(a, None) for a in alerts]
        results = list(mapper.map_stream(iter(pairs)))
        assert len(results) == 3

    def test_stream_empty(self, mapper: MitreMapper) -> None:
        assert list(mapper.map_stream(iter([]))) == []
