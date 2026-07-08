"""tests/unit/context/test_context.py — Comprehensive Attack Context Tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from backend.context.builder import AttackContextBuilder
from backend.context.exceptions import (
    ContextSchemaError,
    ContextStorageError,
    InsufficientInputError,
)
from backend.context.models import (
    CONTEXT_SCHEMA_VERSION,
    AttackContext,
    BehavioralSummary,
    ChainSummary,
    ContextCompleteness,
    ContextIdentity,
    DetectionSummary,
    FeatureSummaryItem,
    GraphSummary,
    MitreSummary,
    ShapSummary,
    SupportingEvidence,
    TimelineEvent,
)
from backend.context.service import AttackContextService
from backend.context.storage import ContextStore
from backend.context.summarizer import (
    BehavioralSummarizer,
    ChainSummarizer,
    CompletenessSummarizer,
    DetectionSummarizer,
    EvidenceSummarizer,
    GraphSummarizer,
    MitreSummarizer,
    ShapSummarizer,
    StatisticalSummarizer,
)
from backend.context.timeline import TimelineBuilder
from backend.detection.models import DetectionAlert, EntityKey

from tests.unit.context.conftest import (
    make_alert,
    make_canonical_event,
    make_chain,
    make_explanation,
    make_graph,
    BASE_TS,
)


# ─────────────────────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackContextModels:
    def test_context_id_prefix(self) -> None:
        alert = make_alert()
        detection = DetectionSummarizer.build(alert)
        identity = ContextIdentity(
            alert_id="a1", entity_type="user", entity_id="alice"
        )
        ctx = AttackContext(identity=identity, detection=detection)
        assert ctx.context_id.startswith("ctx-")

    def test_schema_version(self) -> None:
        alert = make_alert()
        detection = DetectionSummarizer.build(alert)
        identity = ContextIdentity(
            alert_id="a1", entity_type="user", entity_id="alice"
        )
        ctx = AttackContext(identity=identity, detection=detection)
        assert ctx.schema_version == CONTEXT_SCHEMA_VERSION

    def test_json_round_trip(self, alert) -> None:
        detection = DetectionSummarizer.build(alert)
        identity = ContextIdentity(
            alert_id=alert.alert_id, entity_type="user", entity_id="alice"
        )
        ctx = AttackContext(identity=identity, detection=detection)
        reloaded = AttackContext.model_validate_json(ctx.model_dump_json())
        assert reloaded.context_id == ctx.context_id

    def test_to_summary_keys(self, alert) -> None:
        detection = DetectionSummarizer.build(alert)
        identity = ContextIdentity(
            alert_id=alert.alert_id, entity_type="user", entity_id="alice"
        )
        ctx = AttackContext(identity=identity, detection=detection)
        s = ctx.to_summary()
        for key in ("context_id", "alert_id", "anomaly_score", "completeness_pct"):
            assert key in s

    def test_context_identity_fields(self) -> None:
        identity = ContextIdentity(
            alert_id="a1",
            chain_id="c1",
            graph_id="g1",
            entity_type="host",
            entity_id="server01",
            host="server01",
            user="sysadmin",
        )
        assert identity.entity_type == "host"
        assert identity.entity_id == "server01"


# ─────────────────────────────────────────────────────────────────────────────
# Summarizers
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectionSummarizer:
    def test_builds_from_alert(self, alert) -> None:
        det = DetectionSummarizer.build(alert)
        assert det.anomaly_score == alert.anomaly_score
        assert det.model_id == alert.model_id
        assert det.feature_dimension == alert.feature_dimension
        assert det.baseline_available is True

    def test_detection_timestamp_set(self, alert) -> None:
        det = DetectionSummarizer.build(alert)
        assert isinstance(det.detection_timestamp, datetime)


class TestShapSummarizer:
    def test_builds_from_explanation(self, alert, explanation) -> None:
        shap = ShapSummarizer.build(explanation)
        assert shap.explanation_id == explanation.explanation_id
        assert shap.total_abs_shap == explanation.total_abs_shap
        assert shap.feature_count == 1

    def test_positive_contributors(self, explanation) -> None:
        shap = ShapSummarizer.build(explanation)
        # direction='anomaly' maps to positive_contributors in our model
        assert "failed_logins" in shap.positive_contributors

    def test_empty_shap(self) -> None:
        shap = ShapSummarizer.build_empty()
        assert shap.feature_count == 0
        assert shap.top_features == []

    def test_direction_segregation(self, explanation) -> None:
        shap = ShapSummarizer.build(explanation)
        # fixture uses direction='anomaly' → goes to positive_contributors
        assert len(shap.positive_contributors) >= 1
        assert len(shap.negative_contributors) == 0


class TestMitreSummarizer:
    def test_empty_mapped_attack(self) -> None:
        mitre = MitreSummarizer.build_empty()
        assert mitre.technique_count == 0

    def test_empty_techniques_in_mapped(self) -> None:
        from backend.mitre.models import MappedAttack
        mapped = MappedAttack(
            alert_id="a1",
            model_id="iso-v1",
            entity_type="user",
            entity_id="alice",
            event_id="e1",
            anomaly_score=0.9,
            techniques=[],
            top_shap_features=[],
        )
        mitre = MitreSummarizer.build(mapped)
        assert mitre.technique_count == 0


class TestGraphSummarizer:
    def test_builds_from_graph(self, graph) -> None:
        gs = GraphSummarizer.build(graph)
        assert gs.node_count == 5
        assert gs.edge_count == 4
        assert gs.is_dag is True

    def test_tactic_distribution_preserved(self, graph) -> None:
        gs = GraphSummarizer.build(graph)
        assert "TA0006" in gs.tactic_distribution

    def test_empty_graph_returns_none(self) -> None:
        assert GraphSummarizer.build_empty() is None


class TestChainSummarizer:
    def test_builds_from_chain(self, chain) -> None:
        cs = ChainSummarizer.build(chain)
        assert cs.chain_id == chain.chain_id
        assert cs.chain_length == 2
        assert cs.is_multi_tactic is True

    def test_tactic_sequence(self, chain) -> None:
        cs = ChainSummarizer.build(chain)
        assert "Credential Access" in cs.tactic_sequence

    def test_duration_non_negative(self, chain) -> None:
        cs = ChainSummarizer.build(chain)
        assert cs.duration_seconds >= 0.0

    def test_empty_chain_returns_none(self) -> None:
        assert ChainSummarizer.build_empty() is None


class TestEvidenceSummarizer:
    def test_extracts_hosts(self, events) -> None:
        ev = EvidenceSummarizer.build(events)
        assert "ws01" in ev.affected_hosts
        assert "ws02" in ev.affected_hosts

    def test_extracts_network_indicators(self, events) -> None:
        ev = EvidenceSummarizer.build(events)
        assert ev.has_network_indicators  # ws01 has src_ip

    def test_extracts_auth_indicators(self, events) -> None:
        ev = EvidenceSummarizer.build(events)
        assert ev.has_auth_indicators  # logon_type set

    def test_empty_events(self) -> None:
        ev = EvidenceSummarizer.build([])
        assert ev.affected_hosts == []
        assert not ev.has_ot_indicators

    def test_ot_event_detection(self) -> None:
        from backend.normalization.models import CanonicalEvent
        ot_event = CanonicalEvent(
            event_id="ot-1",
            timestamp=BASE_TS,
            source="ot",
            event_type="ot_modbus",
            host="plc01",
            user="attacker",
            resource="register_40001",
            action="write_register",
            result="success",
            raw_log="raw",
            modbus_register=40001,
            modbus_value=9999,
        )
        ev = EvidenceSummarizer.build([ot_event])
        assert ev.has_ot_indicators
        assert 40001 in ev.modbus_registers

    def test_sorted_output(self, events) -> None:
        ev = EvidenceSummarizer.build(events)
        assert ev.affected_hosts == sorted(ev.affected_hosts)

    def test_deduplication(self) -> None:
        e1 = make_canonical_event("ws01")
        e2 = make_canonical_event("ws01")
        ev = EvidenceSummarizer.build([e1, e2])
        assert ev.affected_hosts.count("ws01") == 1


class TestBehavioralSummarizer:
    def test_builds_from_alert(self, alert) -> None:
        beh = BehavioralSummarizer.build(alert, None)
        assert beh.novelty_count == alert.novelty_count
        assert beh.feature_dimension == alert.feature_dimension
        assert beh.baseline_available is True

    def test_entity_key_string(self, alert) -> None:
        beh = BehavioralSummarizer.build(alert, None)
        assert "user" in beh.entity_key
        assert "alice" in beh.entity_key


class TestStatisticalSummarizer:
    def test_builds_from_alert(self, alert) -> None:
        stat = StatisticalSummarizer.build(alert)
        assert stat.anomaly_score == alert.anomaly_score
        assert stat.feature_count == alert.feature_dimension


class TestCompletenessSummarizer:
    def test_full_completeness(self) -> None:
        c = CompletenessSummarizer.build(
            has_detection=True, has_shap=True, has_mitre=True,
            has_graph=True, has_chain=True, has_timeline=True,
            has_evidence=True, has_behavioral=True, has_statistical=True,
        )
        assert c.completeness_pct == 100.0
        assert len(c.missing) == 0

    def test_minimal_completeness(self) -> None:
        c = CompletenessSummarizer.build(
            has_detection=True, has_shap=False, has_mitre=False,
            has_graph=False, has_chain=False, has_timeline=False,
            has_evidence=False, has_behavioral=False, has_statistical=False,
        )
        assert c.completeness_pct < 30.0
        assert len(c.missing) == 8

    def test_missing_components_named(self) -> None:
        c = CompletenessSummarizer.build(
            has_detection=True, has_shap=False, has_mitre=True,
            has_graph=False, has_chain=True, has_timeline=True,
            has_evidence=True, has_behavioral=True, has_statistical=True,
        )
        missing_names = [m.component for m in c.missing]
        assert "shap" in missing_names
        assert "graph" in missing_names
        assert "detection" not in missing_names


# ─────────────────────────────────────────────────────────────────────────────
# Timeline
# ─────────────────────────────────────────────────────────────────────────────

class TestTimelineBuilder:
    def test_builds_from_chain(self, chain) -> None:
        tl = TimelineBuilder().build(chain)
        assert len(tl) == 2

    def test_ordered_by_step_index(self, chain) -> None:
        tl = TimelineBuilder().build(chain)
        for i, event in enumerate(tl):
            assert event.step_index == i

    def test_technique_ids_correct(self, chain) -> None:
        tl = TimelineBuilder().build(chain)
        assert tl[0].technique_id == "T1110"
        assert tl[1].technique_id == "T1021"

    def test_confidence_populated(self, chain) -> None:
        tl = TimelineBuilder().build(chain)
        assert all(0.0 <= e.confidence <= 1.0 for e in tl)

    def test_empty_build(self) -> None:
        tl = TimelineBuilder().build_empty()
        assert tl == []


# ─────────────────────────────────────────────────────────────────────────────
# Builder
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackContextBuilder:
    def test_minimal_build(self, alert) -> None:
        ctx = AttackContextBuilder().build(alert=alert)
        assert ctx.context_id.startswith("ctx-")
        assert ctx.identity.alert_id == alert.alert_id

    def test_none_alert_raises(self) -> None:
        with pytest.raises(InsufficientInputError):
            AttackContextBuilder().build(alert=None)

    def test_full_build(self, alert, explanation, graph, chain, events) -> None:
        ctx = AttackContextBuilder().build(
            alert=alert,
            explanation=explanation,
            graph=graph,
            chain=chain,
            events=events,
        )
        assert ctx.completeness.has_detection
        assert ctx.completeness.has_shap
        assert ctx.completeness.has_graph
        assert ctx.completeness.has_chain
        assert ctx.completeness.has_evidence

    def test_identity_entity_type(self, alert) -> None:
        ctx = AttackContextBuilder().build(alert=alert)
        assert ctx.identity.entity_type == "user"
        assert ctx.identity.entity_id == "alice"

    def test_shap_populated_when_explanation_provided(self, alert, explanation) -> None:
        ctx = AttackContextBuilder().build(alert=alert, explanation=explanation)
        assert ctx.shap.total_abs_shap == explanation.total_abs_shap

    def test_shap_empty_when_not_provided(self, alert) -> None:
        ctx = AttackContextBuilder().build(alert=alert)
        assert ctx.shap.feature_count == 0

    def test_chain_summary_populated(self, alert, chain) -> None:
        ctx = AttackContextBuilder().build(alert=alert, chain=chain)
        assert ctx.chain is not None
        assert ctx.chain.chain_length == 2

    def test_timeline_built_when_chain_provided(self, alert, chain) -> None:
        ctx = AttackContextBuilder().build(alert=alert, chain=chain)
        assert len(ctx.timeline) == 2

    def test_timeline_empty_without_chain(self, alert) -> None:
        ctx = AttackContextBuilder().build(alert=alert)
        assert ctx.timeline == []

    def test_evidence_populated(self, alert, events) -> None:
        ctx = AttackContextBuilder().build(alert=alert, events=events)
        assert "ws01" in ctx.evidence.affected_hosts

    def test_graph_summary_populated(self, alert, graph) -> None:
        ctx = AttackContextBuilder().build(alert=alert, graph=graph)
        assert ctx.graph is not None
        assert ctx.graph.node_count == 5

    def test_deterministic_output(self, alert, explanation, chain) -> None:
        """Same inputs → same context structure (different IDs)."""
        ctx1 = AttackContextBuilder().build(alert=alert, explanation=explanation, chain=chain)
        ctx2 = AttackContextBuilder().build(alert=alert, explanation=explanation, chain=chain)
        assert ctx1.detection.anomaly_score == ctx2.detection.anomaly_score
        assert ctx1.shap.total_abs_shap == ctx2.shap.total_abs_shap

    def test_behavioral_always_present(self, alert) -> None:
        ctx = AttackContextBuilder().build(alert=alert)
        assert ctx.behavioral is not None

    def test_statistical_always_present(self, alert) -> None:
        ctx = AttackContextBuilder().build(alert=alert)
        assert ctx.statistical is not None


# ─────────────────────────────────────────────────────────────────────────────
# Storage
# ─────────────────────────────────────────────────────────────────────────────

class TestContextStore:
    def _make_ctx(self, alert) -> AttackContext:
        return AttackContextBuilder().build(alert=alert)

    def test_dirs_created(self, tmp_path: Path) -> None:
        d = tmp_path / "ctx"
        ContextStore(store_dir=d)
        assert d.exists()
        assert (d / "index").exists()

    def test_save_and_load_by_id(self, store: ContextStore, alert) -> None:
        ctx = self._make_ctx(alert)
        store.save(ctx)
        loaded = store.load(ctx.context_id)
        assert loaded.context_id == ctx.context_id

    def test_save_appends_to_jsonl(self, store: ContextStore, alert) -> None:
        ctx1 = self._make_ctx(alert)
        ctx2 = self._make_ctx(alert)
        store.save(ctx1)
        store.save(ctx2)
        records = store.load_for_date()
        ids = {r.context_id for r in records}
        assert ctx1.context_id in ids
        assert ctx2.context_id in ids

    def test_load_unknown_id_raises(self, store: ContextStore) -> None:
        with pytest.raises(ContextStorageError):
            store.load("nonexistent-id")

    def test_no_tmp_files_after_write(self, store: ContextStore, alert) -> None:
        ctx = self._make_ctx(alert)
        store.save(ctx)
        tmp_files = list((store._index_dir).glob("*.tmp"))
        assert len(tmp_files) == 0

    def test_batch_save(self, store: ContextStore, alert) -> None:
        contexts = [self._make_ctx(alert) for _ in range(3)]
        store.save_batch(contexts)
        loaded = store.load_for_date()
        assert len(loaded) == 3

    def test_load_by_alert(self, store: ContextStore, alert) -> None:
        ctx = self._make_ctx(alert)
        store.save(ctx)
        results = store.load_by_alert(alert.alert_id)
        assert any(c.context_id == ctx.context_id for c in results)

    def test_list_context_ids(self, store: ContextStore, alert) -> None:
        ctx = self._make_ctx(alert)
        store.save(ctx)
        ids = store.list_context_ids()
        assert ctx.context_id in ids

    def test_empty_date_returns_empty(self, store: ContextStore) -> None:
        old = datetime(2020, 1, 1, tzinfo=UTC)
        assert store.load_for_date(old) == []

    def test_list_dates(self, store: ContextStore, alert) -> None:
        ctx = self._make_ctx(alert)
        store.save(ctx)
        dates = store.list_dates()
        assert len(dates) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Service
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackContextService:
    def test_get_status(self, svc: AttackContextService) -> None:
        s = svc.get_status()
        assert "persist" in s
        assert "stored_contexts" in s

    def test_build_context_minimal(self, svc: AttackContextService, alert) -> None:
        ctx = svc.build_context(alert=alert)
        assert isinstance(ctx, AttackContext)

    def test_build_context_full(
        self, svc: AttackContextService, alert, explanation, graph, chain, events
    ) -> None:
        ctx = svc.build_context(
            alert=alert, explanation=explanation, graph=graph, chain=chain, events=events
        )
        assert ctx.completeness.completeness_pct > 70.0

    def test_no_persist_no_storage(
        self, svc: AttackContextService, alert
    ) -> None:
        svc.build_context(alert=alert)
        assert svc.list_context_ids() == []

    def test_persist_saves_context(
        self, svc_persist: AttackContextService, alert
    ) -> None:
        ctx = svc_persist.build_context(alert=alert)
        assert ctx.context_id in svc_persist.list_context_ids()

    def test_load_after_persist(
        self, svc_persist: AttackContextService, alert
    ) -> None:
        ctx = svc_persist.build_context(alert=alert)
        loaded = svc_persist.load_context(ctx.context_id)
        assert loaded.context_id == ctx.context_id

    def test_build_batch(
        self, svc: AttackContextService, alert
    ) -> None:
        items = [{"alert": alert}, {"alert": alert}]
        contexts = svc.build_batch(items)
        assert len(contexts) == 2

    def test_build_stream(self, svc: AttackContextService, alert) -> None:
        alerts = [alert, alert]
        resolver = lambda a: {}
        results = list(svc.build_contexts_stream(alerts, resolver))
        assert len(results) == 2
        for ctx in results:
            assert isinstance(ctx, AttackContext)

    def test_filter_high_confidence(
        self, svc: AttackContextService, alert, chain
    ) -> None:
        ctx = svc.build_context(alert=alert, chain=chain)
        high = AttackContextService.filter_high_confidence([ctx], threshold=0.5)
        assert ctx in high

    def test_filter_multi_tactic(
        self, svc: AttackContextService, alert, chain
    ) -> None:
        ctx = svc.build_context(alert=alert, chain=chain)
        multi = AttackContextService.filter_multi_tactic([ctx])
        assert ctx in multi  # chain fixture has is_multi_tactic=True

    def test_filter_ot_contexts(
        self, svc: AttackContextService
    ) -> None:
        from backend.normalization.models import CanonicalEvent
        alert = make_alert()
        ot_event = CanonicalEvent(
            event_id="ot-1",
            timestamp=BASE_TS,
            source="ot",
            event_type="ot_modbus",
            host="plc01",
            user="attacker",
            resource="r",
            action="write",
            result="success",
            raw_log="raw",
            modbus_register=40001,
            modbus_value=9999,
        )
        ctx = svc.build_context(alert=alert, events=[ot_event])
        ot_ctxs = AttackContextService.filter_ot_contexts([ctx])
        assert ctx in ot_ctxs

    def test_filter_complete(
        self, svc: AttackContextService, alert, explanation, graph, chain, events
    ) -> None:
        ctx = svc.build_context(
            alert=alert, explanation=explanation, graph=graph, chain=chain, events=events
        )
        complete = AttackContextService.filter_complete([ctx], min_pct=70.0)
        assert ctx in complete

    def test_list_dates(self, svc_persist: AttackContextService, alert) -> None:
        svc_persist.build_context(alert=alert)
        dates = svc_persist.list_dates()
        assert len(dates) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Cold-start / Contract / Regression
# ─────────────────────────────────────────────────────────────────────────────

class TestColdStartAndContracts:
    def test_service_starts_without_data(self, tmp_path: Path) -> None:
        svc = AttackContextService(store_dir=tmp_path / "fresh", persist=False)
        assert svc.list_context_ids() == []

    def test_context_has_all_required_fields(self, alert) -> None:
        ctx = AttackContextBuilder().build(alert=alert)
        assert ctx.context_id
        assert ctx.schema_version == CONTEXT_SCHEMA_VERSION
        assert ctx.assembled_at is not None
        assert ctx.identity is not None
        assert ctx.detection is not None
        assert ctx.completeness is not None

    def test_context_is_immutable_model(self, alert) -> None:
        ctx = AttackContextBuilder().build(alert=alert)
        # Pydantic models can be dict-serialised and validated
        data = ctx.model_dump()
        assert isinstance(data["context_id"], str)

    def test_schema_version_constant(self) -> None:
        assert CONTEXT_SCHEMA_VERSION == "1.0.0"

    def test_multiple_contexts_unique_ids(self, alert) -> None:
        builder = AttackContextBuilder()
        ids = {builder.build(alert=alert).context_id for _ in range(10)}
        assert len(ids) == 10

    def test_load_for_date_empty_returns_empty(
        self, svc: AttackContextService
    ) -> None:
        old = datetime(2020, 1, 1, tzinfo=UTC)
        assert svc.load_for_date(old) == []

    def test_context_with_all_optionals_none(self, alert) -> None:
        ctx = AttackContextBuilder().build(
            alert=alert,
            explanation=None,
            mapped=None,
            graph=None,
            chain=None,
            events=None,
            feature_record=None,
        )
        assert ctx.graph is None
        assert ctx.chain is None
        assert ctx.timeline == []
