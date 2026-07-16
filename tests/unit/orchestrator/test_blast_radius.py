"""tests/unit/orchestrator/test_blast_radius.py — Blast radius extraction tests."""

from __future__ import annotations

from backend.orchestrator.blast_radius import compute_blast_radius
from tests.unit.orchestrator.conftest import make_context


class TestBlastRadiusCompute:
    def test_primary_host_always_included(self) -> None:
        ctx = make_context(host="primary-host")
        report = compute_blast_radius(ctx)
        assert "primary-host" in report.affected_hosts

    def test_primary_user_always_included(self) -> None:
        ctx = make_context(user="alice")
        report = compute_blast_radius(ctx)
        assert "alice" in report.affected_users

    def test_primary_entity_always_in_entity_ids(self) -> None:
        ctx = make_context(entity_id="alice")
        report = compute_blast_radius(ctx)
        assert "alice" in report.affected_entity_ids

    def test_source_alert_always_in_scope(self) -> None:
        ctx = make_context()
        report = compute_blast_radius(ctx)
        assert ctx.identity.alert_id in report.alert_ids_in_scope

    def test_chain_alerts_included(self) -> None:
        ctx = make_context(has_chain=True)
        report = compute_blast_radius(ctx)
        # chain has matched_alert_ids = ["alert-001", "alert-002"]
        assert "alert-001" in report.alert_ids_in_scope
        assert "alert-002" in report.alert_ids_in_scope

    def test_ot_scope_when_has_ot(self) -> None:
        ctx = make_context(has_ot=True)
        report = compute_blast_radius(ctx)
        assert report.estimated_scope == "OT"

    def test_lateral_scope_when_multiple_hosts(self) -> None:
        ctx = make_context(has_graph=True)  # graph has node_count=4 ≥ 3
        report = compute_blast_radius(ctx)
        assert report.estimated_scope in ("LATERAL", "MULTI_ENTITY")

    def test_single_host_scope_without_graph(self) -> None:
        ctx = make_context(has_graph=False, has_chain=False)
        # 1 host, no graph, no chain
        report = compute_blast_radius(ctx)
        assert report.estimated_scope == "SINGLE_HOST"

    def test_evidence_sources_listed(self) -> None:
        ctx = make_context()
        report = compute_blast_radius(ctx)
        assert "context.evidence" in report.evidence_sources
        assert "context.identity" in report.evidence_sources

    def test_graph_added_to_evidence_sources(self) -> None:
        ctx = make_context(has_graph=True)
        report = compute_blast_radius(ctx)
        assert "context.graph" in report.evidence_sources

    def test_chain_added_to_evidence_sources(self) -> None:
        ctx = make_context(has_chain=True)
        report = compute_blast_radius(ctx)
        assert "context.chain" in report.evidence_sources

    def test_baseline_available_propagated(self) -> None:
        ctx = make_context(baseline_available=False)
        report = compute_blast_radius(ctx)
        assert report.baseline_available is False

    def test_node_count_from_graph(self) -> None:
        ctx = make_context(has_graph=True)
        report = compute_blast_radius(ctx)
        assert report.estimated_node_count == 4  # from make_context graph fixture

    def test_no_duplicate_alert_ids(self) -> None:
        ctx = make_context(has_chain=True)
        # chain already contains alert-001; identity also references alert-001
        report = compute_blast_radius(ctx)
        assert report.alert_ids_in_scope.count("alert-001") == 1
