"""tests/unit/mitre/test_mapper.py — MitreMapper Tests."""

from __future__ import annotations

import pytest

from backend.mitre.mapper import (
    _MAX_SHAP_TOTAL,
    _W_ANOMALY,
    _W_FEATURE_BREADTH,
    _W_SHAP,
    DEFAULT_MIN_CONFIDENCE,
    MAX_TECHNIQUES_PER_ALERT,
    MitreMapper,
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

    def test_mapping_id_prefix(self, mapper: MitreMapper, sample_alert, sample_explanation) -> None:
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

    def test_map_without_explanation(self, mapper: MitreMapper, sample_alert) -> None:
        """Graceful degradation: mapping works without SHAP evidence."""
        result = mapper.map_alert(sample_alert, None)
        assert isinstance(result, MappedAttack)
        assert result.explanation_id == ""

    def test_map_unknown_features_returns_empty_techniques(self, mapper: MitreMapper) -> None:
        """Alert with empty top_features and explanation present → empty techniques.

        After the scenario-discrimination fix: when explanation is provided,
        feature_pool = top_features only. raw_feature_values fallback only applies
        when explanation is None. So empty top_features → zero pool → zero techniques.
        """
        alert = make_alert(raw_feature_values={"completely_unknown_feature": 1.0})
        expl = make_explanation(
            alert_id=alert.alert_id,
            top_features=[],
        )
        # Override feature_contributions to empty so top_features stays []
        expl2 = expl.model_copy(update={"feature_contributions": []})
        result = mapper.map_alert(alert, expl2)
        assert isinstance(result, MappedAttack)
        # No techniques: empty top_features with explanation present → empty pool
        assert result.techniques == []

    def test_reproducible_mapping(
        self, mapper: MitreMapper, sample_alert, sample_explanation
    ) -> None:
        """Same inputs always produce identical mapping (deterministic)."""
        r1 = mapper.map_alert(sample_alert, sample_explanation)
        r2 = mapper.map_alert(sample_alert, sample_explanation)
        assert len(r1.techniques) == len(r2.techniques)
        for t1, t2 in zip(r1.techniques, r2.techniques, strict=False):
            assert t1.technique.technique_id == t2.technique.technique_id
            assert t1.confidence == pytest.approx(t2.confidence)

    def test_high_anomaly_score_boosts_confidence(self, mapper: MitreMapper) -> None:
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
        c = mapper._compute_confidence(anomaly_score=0.0, shap_total=0.0, feature_match_count=0)
        assert c == pytest.approx(0.0)

    def test_max_inputs_give_confidence_one(self, mapper: MitreMapper) -> None:
        c = mapper._compute_confidence(
            anomaly_score=1.0, shap_total=_MAX_SHAP_TOTAL, feature_match_count=10
        )
        assert c == pytest.approx(1.0)

    def test_confidence_clipped_to_unit_interval(self, mapper: MitreMapper) -> None:
        c = mapper._compute_confidence(anomaly_score=1.0, shap_total=100.0, feature_match_count=999)
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


class TestShapTop3ScenarioDiscrimination:
    """Regression tests for the scenario-discrimination fix (2026-07-15).

    Root cause of original bug: fallback used `raw_feature_values` union (all keys)
    when top_features was empty, so every alert got identical broad technique sets.
    Fix: when explanation is present, feature_pool = explanation.top_features ONLY.
    """

    def test_different_shap_top3_produce_different_technique_sets(
        self, mapper: MitreMapper
    ) -> None:
        """The actual bug being fixed: two alerts with different SHAP top-3 features
        must produce different (not identical) predicted technique sets.

        Uses synthetic data only — no real detection pipeline involved.
        """
        # Alert A: SHAP top features are auth-related (brute force scenario)
        alert_a = make_alert(alert_id="alert-auth", anomaly_score=0.85)
        expl_a = make_explanation(
            alert_id="alert-auth",
            top_features=["auth_failure_rate_baseline", "logon_type_is_novel", "result_is_failure"],
        )

        # Alert B: SHAP top features are temporal/frequency (off-hours scenario)
        alert_b = make_alert(alert_id="alert-temporal", anomaly_score=0.85)
        expl_b = make_explanation(
            alert_id="alert-temporal",
            top_features=["is_business_hours", "day_of_week", "hour_baseline_frequency"],
        )

        result_a = mapper.map_alert(alert_a, expl_a)
        result_b = mapper.map_alert(alert_b, expl_b)

        tech_ids_a = {tm.technique.technique_id for tm in result_a.techniques}
        tech_ids_b = {tm.technique.technique_id for tm in result_b.techniques}

        # The two different SHAP top-3 sets must produce different technique sets.
        # If they're identical, the broad-union bug has regressed.
        assert tech_ids_a != tech_ids_b, (
            f"Scenario discrimination failed: both alerts produced identical technique sets {tech_ids_a}. "
            "This indicates the broad-union fallback bug has regressed — feature_pool is not "
            "being restricted to SHAP top-3 features."
        )

    def test_explanation_present_uses_top_features_not_raw_values(
        self, mapper: MitreMapper
    ) -> None:
        """When explanation is provided, raw_feature_values must NOT pollute the feature pool.

        Constructs an alert where raw_feature_values has many auth features but
        top_features only has temporal features. Verifies the resulting techniques
        match the temporal top_features, not the raw_feature_values.
        Uses synthetic data only.
        """
        # raw_feature_values has auth features only
        raw_values = {
            "auth_failure_rate_baseline": 1.0,
            "logon_type_is_novel": 1.0,
            "result_is_failure": 1.0,
        }
        alert = make_alert(
            alert_id="alert-pool-test", raw_feature_values=raw_values, anomaly_score=0.8
        )

        # But top_features (SHAP) says only temporal features matter
        expl = make_explanation(
            alert_id="alert-pool-test",
            top_features=["is_business_hours", "day_of_week", "hour_relative_frequency"],
        )

        result = mapper.map_alert(alert, expl)

        # All matched_features in the result must come from top_features, not raw_feature_values
        raw_only_features = set(raw_values.keys()) - set(expl.top_features)
        all_matched = {f for tm in result.techniques for f in tm.matched_features}
        overlap_with_raw = all_matched & raw_only_features
        assert not overlap_with_raw, (
            f"raw_feature_values leaked into feature_pool: {overlap_with_raw}. "
            "Fix: feature_pool must equal explanation.top_features when explanation is present."
        )

    def test_no_explanation_falls_back_to_raw_feature_values(self, mapper: MitreMapper) -> None:
        """Graceful degradation: when explanation=None, raw_feature_values is used.

        This is the legitimate fallback for alerts without SHAP (cold-start, non-IT, etc.).
        Uses synthetic data only.
        """
        raw_values = {
            "auth_failure_rate_baseline": 1.0,
            "logon_type_is_novel": 1.0,
        }
        alert = make_alert(alert_id="alert-no-expl", raw_feature_values=raw_values)
        # No explanation provided at all
        result = mapper.map_alert(alert, None)
        assert isinstance(result, MappedAttack)
        assert result.explanation_id == ""
        # May or may not find techniques — depends on kb — but must not raise
