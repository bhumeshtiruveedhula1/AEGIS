"""
backend.context.summarizer — Deterministic Summary Builders
============================================================
Module 4.1 — Attack Context Generation

All methods are pure functions.
No LLM, no heuristics, no inference, no prediction.
Every value comes directly from existing module outputs.

One class per summary domain — single responsibility throughout.
"""

from __future__ import annotations

from datetime import UTC

from backend.attack_graph.models import AttackGraph, GraphSnapshot
from backend.chain_detection.models import AttackChain
from backend.context.models import (
    BehavioralSummary,
    ChainSummary,
    ContextCompleteness,
    DetectionSummary,
    FeatureSummaryItem,
    GraphSummary,
    MissingComponent,
    MitreSummary,
    ShapSummary,
    StatisticalSummary,
    SupportingEvidence,
    TechniqueSummary,
)
from backend.detection.models import DetectionAlert
from backend.explainability.models import ExplanationResult
from backend.features.models import FeatureRecord
from backend.mitre.models import MappedAttack
from backend.normalization.models import CanonicalEvent


# ─────────────────────────────────────────────────────────────────────────────
# Detection
# ─────────────────────────────────────────────────────────────────────────────

class DetectionSummarizer:
    @staticmethod
    def build(alert: DetectionAlert) -> DetectionSummary:
        return DetectionSummary(
            model_id=alert.model_id,
            anomaly_score=alert.anomaly_score,
            threshold_used=alert.threshold_used,
            raw_if_score=alert.raw_if_score,
            feature_dimension=alert.feature_dimension,
            novelty_count=alert.novelty_count,
            baseline_available=alert.baseline_available,
            detection_timestamp=alert.triggered_at,
        )


# ─────────────────────────────────────────────────────────────────────────────
# SHAP
# ─────────────────────────────────────────────────────────────────────────────

class ShapSummarizer:
    @staticmethod
    def build(explanation: ExplanationResult) -> ShapSummary:
        top = [
            FeatureSummaryItem(
                feature_name=fc.feature_name,
                raw_value=float(fc.raw_value) if fc.raw_value is not None else 0.0,
                shap_value=fc.shap_value,
                direction=fc.direction,
                contribution_pct=fc.contribution_pct,
            )
            for fc in explanation.feature_contributions
        ]
        positive = [f.feature_name for f in top if f.direction == "anomaly"]
        negative = [f.feature_name for f in top if f.direction == "normal"]
        return ShapSummary(
            explanation_id=explanation.explanation_id,
            total_abs_shap=explanation.total_abs_shap,
            expected_value=explanation.expected_value,
            top_features=top,
            positive_contributors=positive,
            negative_contributors=negative,
            feature_count=len(explanation.feature_contributions),
        )

    @staticmethod
    def build_empty() -> ShapSummary:
        return ShapSummary()


# ─────────────────────────────────────────────────────────────────────────────
# MITRE
# ─────────────────────────────────────────────────────────────────────────────

class MitreSummarizer:
    @staticmethod
    def build(mapped: MappedAttack) -> MitreSummary:
        if not mapped.techniques:
            return MitreSummary(mapping_id=mapped.mapping_id)

        primary = mapped.techniques[0]
        p_tac = primary.technique.tactic
        primary_summary = TechniqueSummary(
            technique_id=primary.technique.technique_id,
            technique_name=primary.technique.name,
            tactic_id=p_tac.tactic_id,
            tactic_name=p_tac.name,
            confidence=primary.confidence,
        )

        supporting = []
        for tm in mapped.techniques[1:]:
            tac = tm.technique.tactic
            supporting.append(TechniqueSummary(
                technique_id=tm.technique.technique_id,
                technique_name=tm.technique.name,
                tactic_id=tac.tactic_id,
                tactic_name=tac.name,
                confidence=tm.confidence,
            ))

        all_tech_ids = [tm.technique.technique_id for tm in mapped.techniques]
        all_tac_ids = list(dict.fromkeys(
            tm.technique.tactic.tactic_id for tm in mapped.techniques
        ))

        return MitreSummary(
            mapping_id=mapped.mapping_id,
            primary_technique=primary_summary,
            supporting_techniques=supporting,
            all_technique_ids=all_tech_ids,
            all_tactic_ids=all_tac_ids,
            technique_count=len(all_tech_ids),
            tactic_count=len(all_tac_ids),
            mapping_confidence=primary.confidence,
        )

    @staticmethod
    def build_empty() -> MitreSummary:
        return MitreSummary()


# ─────────────────────────────────────────────────────────────────────────────
# Graph
# ─────────────────────────────────────────────────────────────────────────────

class GraphSummarizer:
    @staticmethod
    def build(graph: AttackGraph) -> GraphSummary:
        stats = graph.statistics
        return GraphSummary(
            graph_id=graph.graph_id,
            node_count=stats.node_count,
            edge_count=stats.edge_count,
            technique_count=stats.technique_count,
            tactic_count=stats.tactic_count,
            alert_count=stats.alert_count,
            entity_count=stats.entity_count,
            is_dag=stats.is_dag,
            tactic_distribution=dict(stats.tactic_distribution),
            technique_distribution=dict(stats.technique_distribution),
        )

    @staticmethod
    def build_empty() -> None:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Chain
# ─────────────────────────────────────────────────────────────────────────────

class ChainSummarizer:
    @staticmethod
    def build(chain: AttackChain) -> ChainSummary:
        ev = chain.evaluation
        evidence = chain.evidence

        # Compute duration from first/last node timestamps
        first_ts = chain.nodes[0].first_seen if chain.nodes else None
        last_ts = chain.nodes[-1].last_seen if chain.nodes else None
        duration = 0.0
        if first_ts and last_ts:
            duration = max(0.0, (last_ts - first_ts).total_seconds())

        return ChainSummary(
            chain_id=chain.chain_id,
            chain_length=ev.chain_length,
            confidence=ev.confidence,
            tactic_sequence=list(dict.fromkeys(evidence.tactic_sequence)),
            technique_sequence=list(evidence.technique_ids),
            tactic_count=ev.tactic_count,
            is_multi_tactic=ev.is_multi_tactic,
            is_temporally_ordered=ev.is_temporally_ordered,
            observation_strength=ev.observation_strength,
            matched_alert_ids=list(evidence.alert_ids),
            matched_features=list(evidence.matched_features),
            total_observations=evidence.total_observations,
            first_event_time=first_ts,
            last_event_time=last_ts,
            duration_seconds=duration,
        )

    @staticmethod
    def build_empty() -> None:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Supporting Evidence
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceSummarizer:
    @staticmethod
    def build(events: list[CanonicalEvent]) -> SupportingEvidence:
        """Extract all indicators from a set of CanonicalEvents. No inference."""
        hosts: set[str] = set()
        users: set[str] = set()
        processes: set[str] = set()
        commands: set[str] = set()
        src_ips: set[str] = set()
        dst_ips: set[str] = set()
        ports: set[int] = set()
        protocols: set[str] = set()
        logon_types: set[str] = set()
        auth_packages: set[str] = set()
        file_paths: set[str] = set()
        modbus_registers: set[int] = set()
        modbus_values: set[int] = set()
        supervisory_hosts: set[str] = set()

        for e in events:
            if e.host:
                hosts.add(e.host)
            if e.user:
                users.add(e.user)
            if e.process:
                processes.add(e.process)
            if e.command_line:
                commands.add(e.command_line)
            if e.src_ip:
                src_ips.add(e.src_ip)
            if e.dst_ip:
                dst_ips.add(e.dst_ip)
            if e.port is not None:
                ports.add(e.port)
            if e.protocol:
                protocols.add(e.protocol)
            if e.logon_type:
                logon_types.add(e.logon_type)
            if e.auth_package:
                auth_packages.add(e.auth_package)
            if e.file_path:
                file_paths.add(e.file_path)
            if e.modbus_register is not None:
                modbus_registers.add(e.modbus_register)
            if e.modbus_value is not None:
                modbus_values.add(e.modbus_value)
            if e.supervisory_host:
                supervisory_hosts.add(e.supervisory_host)

        return SupportingEvidence(
            affected_hosts=sorted(hosts),
            affected_users=sorted(users),
            processes=sorted(processes),
            command_lines=sorted(commands),
            src_ips=sorted(src_ips),
            dst_ips=sorted(dst_ips),
            ports=sorted(ports),
            protocols=sorted(protocols),
            logon_types=sorted(logon_types),
            auth_packages=sorted(auth_packages),
            file_paths=sorted(file_paths),
            modbus_registers=sorted(modbus_registers),
            modbus_values=sorted(modbus_values),
            supervisory_hosts=sorted(supervisory_hosts),
            has_ot_indicators=bool(modbus_registers),
            has_auth_indicators=bool(logon_types or auth_packages),
            has_network_indicators=bool(src_ips or dst_ips or ports),
            has_process_indicators=bool(processes or commands),
        )

    @staticmethod
    def build_empty() -> SupportingEvidence:
        return SupportingEvidence()


# ─────────────────────────────────────────────────────────────────────────────
# Behavioral
# ─────────────────────────────────────────────────────────────────────────────

class BehavioralSummarizer:
    @staticmethod
    def build(alert: DetectionAlert, feature_record: FeatureRecord | None) -> BehavioralSummary:
        """Extract behavioral novelty from DetectionAlert and optional FeatureRecord."""
        raw_features: dict[str, float] = {}
        if feature_record:
            raw_features = {k: float(v) for k, v in feature_record.feature_vector.values.items()}

        ek = alert.entity_key
        entity_key_str = f"{ek.entity_type}::{ek.entity_id}" if hasattr(ek, "entity_type") else str(ek)

        return BehavioralSummary(
            entity_key=entity_key_str,
            baseline_available=alert.baseline_available,
            novel_features=list(alert.raw_feature_values.keys())[:alert.novelty_count],
            novelty_count=alert.novelty_count,
            feature_dimension=alert.feature_dimension,
            raw_feature_snapshot=raw_features,
        )

    @staticmethod
    def build_empty() -> None:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Statistical
# ─────────────────────────────────────────────────────────────────────────────

class StatisticalSummarizer:
    @staticmethod
    def build(alert: DetectionAlert) -> StatisticalSummary:
        return StatisticalSummary(
            anomaly_score=alert.anomaly_score,
            feature_count=alert.feature_dimension,
            baseline_coverage=1.0 if alert.baseline_available else 0.0,
            entity_observations=0,  # extended by service if EntityBaseline available
        )


# ─────────────────────────────────────────────────────────────────────────────
# Completeness
# ─────────────────────────────────────────────────────────────────────────────

class CompletenessSummarizer:
    """
    Computes deterministic context completeness.
    Reports exactly what is present and what is absent — no guessing.
    """

    # 9 scored components, each worth 1/9 of 100%
    _TOTAL = 9

    @staticmethod
    def build(
        *,
        has_detection: bool,
        has_shap: bool,
        has_mitre: bool,
        has_graph: bool,
        has_chain: bool,
        has_timeline: bool,
        has_evidence: bool,
        has_behavioral: bool,
        has_statistical: bool,
    ) -> ContextCompleteness:
        flags = {
            "detection": has_detection,
            "shap": has_shap,
            "mitre": has_mitre,
            "graph": has_graph,
            "chain": has_chain,
            "timeline": has_timeline,
            "evidence": has_evidence,
            "behavioral": has_behavioral,
            "statistical": has_statistical,
        }
        present = sum(1 for v in flags.values() if v)
        pct = round((present / CompletenessSummarizer._TOTAL) * 100, 1)

        missing = [
            MissingComponent(component=k, reason=f"{k} data not provided")
            for k, v in flags.items()
            if not v
        ]

        return ContextCompleteness(
            completeness_pct=pct,
            has_detection=has_detection,
            has_shap=has_shap,
            has_mitre=has_mitre,
            has_graph=has_graph,
            has_chain=has_chain,
            has_timeline=has_timeline,
            has_evidence=has_evidence,
            has_behavioral=has_behavioral,
            has_statistical=has_statistical,
            missing=missing,
        )
