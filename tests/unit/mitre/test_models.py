"""tests/unit/mitre/test_models.py — MITRE Data Model Tests."""

from __future__ import annotations

import pytest
from datetime import UTC, datetime

from backend.mitre.models import (
    MITRE_SCHEMA_VERSION,
    AttackTactic,
    AttackTechnique,
    MappedAttack,
    MappingReport,
    MappingStatistics,
    TechniqueMapping,
)


def _tactic(tid: str = "TA0006") -> AttackTactic:
    return AttackTactic(tactic_id=tid, name="Credential Access", short_name="cred")


def _technique(tid: str = "T1110") -> AttackTechnique:
    return AttackTechnique(technique_id=tid, name="Brute Force", tactic=_tactic())


def _tm(confidence: float = 0.75) -> TechniqueMapping:
    return TechniqueMapping(
        technique=_technique(),
        confidence=confidence,
        evidence=["Anomaly score above threshold."],
        matched_features=["auth_failure_rate_baseline"],
        shap_contributors=["auth_failure_rate_baseline"],
        shap_total_contribution=0.4,
    )


class TestAttackTactic:
    def test_construction(self) -> None:
        t = _tactic()
        assert t.tactic_id == "TA0006"
        assert t.name == "Credential Access"

    def test_str(self) -> None:
        assert "TA0006" in str(_tactic())

    def test_json_round_trip(self) -> None:
        t = _tactic()
        assert AttackTactic.model_validate_json(t.model_dump_json()).tactic_id == "TA0006"


class TestAttackTechnique:
    def test_subtechnique_flag_set(self) -> None:
        t = _technique("T1110.001")
        assert t.is_subtechnique is True

    def test_parent_technique_not_subtechnique(self) -> None:
        t = _technique("T1110")
        assert t.is_subtechnique is False

    def test_str(self) -> None:
        assert "T1110" in str(_technique())

    def test_json_round_trip(self) -> None:
        t = _technique()
        reloaded = AttackTechnique.model_validate_json(t.model_dump_json())
        assert reloaded.technique_id == "T1110"
        assert reloaded.tactic.tactic_id == "TA0006"


class TestTechniqueMapping:
    def test_confidence_bounds(self) -> None:
        with pytest.raises(Exception):
            TechniqueMapping(
                technique=_technique(), confidence=1.5,
                evidence=[], matched_features=[], shap_contributors=[],
                shap_total_contribution=0.0,
            )

    def test_to_summary_keys(self) -> None:
        tm = _tm()
        s = tm.to_summary()
        for k in ("technique_id", "technique_name", "tactic", "confidence"):
            assert k in s

    def test_json_round_trip(self) -> None:
        tm = _tm()
        reloaded = TechniqueMapping.model_validate_json(tm.model_dump_json())
        assert reloaded.confidence == pytest.approx(0.75)


class TestMappedAttack:
    def test_unique_mapping_id(self) -> None:
        a = MappedAttack(alert_id="a", model_id="m", entity_type="t",
                         entity_id="e", event_id="ev", anomaly_score=0.8)
        b = MappedAttack(alert_id="a", model_id="m", entity_type="t",
                         entity_id="e", event_id="ev", anomaly_score=0.8)
        assert a.mapping_id != b.mapping_id

    def test_mapping_id_prefix(self) -> None:
        m = MappedAttack(alert_id="a", model_id="m", entity_type="t",
                         entity_id="e", event_id="ev", anomaly_score=0.8)
        assert m.mapping_id.startswith("map-")

    def test_techniques_sorted_by_confidence(self) -> None:
        t1 = _tm(confidence=0.4)
        t2 = _tm(confidence=0.9)
        t3 = _tm(confidence=0.6)
        m = MappedAttack(
            alert_id="a", model_id="m", entity_type="t",
            entity_id="e", event_id="ev", anomaly_score=0.8,
            techniques=[t1, t2, t3],
        )
        confs = [t.confidence for t in m.techniques]
        assert confs == sorted(confs, reverse=True)

    def test_primary_technique_is_highest_confidence(self) -> None:
        t1 = _tm(0.4)
        t2 = _tm(0.9)
        m = MappedAttack(
            alert_id="a", model_id="m", entity_type="t",
            entity_id="e", event_id="ev", anomaly_score=0.8,
            techniques=[t1, t2],
        )
        assert m.primary_technique.confidence == pytest.approx(0.9)

    def test_primary_technique_none_when_empty(self) -> None:
        m = MappedAttack(alert_id="a", model_id="m", entity_type="t",
                         entity_id="e", event_id="ev", anomaly_score=0.8)
        assert m.primary_technique is None

    def test_mapped_tactics_unique(self) -> None:
        # Two techniques with same tactic
        t1 = _tm(0.8)
        t2 = _tm(0.7)
        m = MappedAttack(
            alert_id="a", model_id="m", entity_type="t",
            entity_id="e", event_id="ev", anomaly_score=0.8,
            techniques=[t1, t2],
        )
        assert len(m.mapped_tactics) == len(set(m.mapped_tactics))

    def test_to_summary_keys(self) -> None:
        m = MappedAttack(alert_id="a", model_id="m", entity_type="t",
                         entity_id="e", event_id="ev", anomaly_score=0.8,
                         techniques=[_tm()])
        s = m.to_summary()
        for k in ("mapping_id", "alert_id", "entity_id", "primary_technique",
                  "primary_tactic", "technique_count", "top_confidence"):
            assert k in s

    def test_schema_version(self) -> None:
        m = MappedAttack(alert_id="a", model_id="m", entity_type="t",
                         entity_id="e", event_id="ev", anomaly_score=0.8)
        assert m.schema_version == MITRE_SCHEMA_VERSION

    def test_json_round_trip(self) -> None:
        m = MappedAttack(
            alert_id="a", model_id="m", entity_type="t",
            entity_id="e", event_id="ev", anomaly_score=0.8,
            techniques=[_tm()],
        )
        reloaded = MappedAttack.model_validate_json(m.model_dump_json())
        assert reloaded.mapping_id == m.mapping_id
        assert len(reloaded.techniques) == 1


class TestMappingReport:
    def _make_mapping(self, alert_id: str = "a") -> MappedAttack:
        return MappedAttack(
            alert_id=alert_id, model_id="m", entity_type="t",
            entity_id="e", event_id=alert_id, anomaly_score=0.8,
            techniques=[_tm(0.8)],
        )

    def test_report_id_prefix(self) -> None:
        r = MappingReport(run_id="r", model_id="m")
        assert r.report_id.startswith("mrpt-")

    def test_empty_report_statistics(self) -> None:
        r = MappingReport(run_id="r", model_id="m", mappings=[])
        assert r.statistics.total_alerts == 0
        assert r.statistics.mapping_rate == 0.0

    def test_statistics_computed(self) -> None:
        mappings = [self._make_mapping(f"a-{i}") for i in range(4)]
        r = MappingReport(run_id="r", model_id="m", mappings=mappings)
        assert r.statistics.total_alerts == 4
        assert r.statistics.total_mapped == 4
        assert r.statistics.mapping_rate == pytest.approx(1.0)
        assert r.statistics.avg_confidence > 0.0

    def test_tactic_distribution_populated(self) -> None:
        mappings = [self._make_mapping(f"a-{i}") for i in range(3)]
        r = MappingReport(run_id="r", model_id="m", mappings=mappings)
        assert len(r.statistics.tactic_distribution) > 0

    def test_errors_counted_in_unmapped(self) -> None:
        r = MappingReport(run_id="r", model_id="m", mappings=[], errors=2)
        assert r.statistics.total_unmapped == 2

    def test_to_summary_keys(self) -> None:
        mappings = [self._make_mapping()]
        r = MappingReport(run_id="r-test", model_id="m", mappings=mappings)
        s = r.to_summary()
        for k in ("report_id", "run_id", "total_alerts", "mapping_rate"):
            assert k in s

    def test_json_round_trip(self) -> None:
        mappings = [self._make_mapping("a1"), self._make_mapping("a2")]
        r = MappingReport(run_id="r", model_id="m", mappings=mappings)
        reloaded = MappingReport.model_validate_json(r.model_dump_json())
        assert reloaded.report_id == r.report_id
        assert len(reloaded.mappings) == 2
