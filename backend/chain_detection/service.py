"""
backend.chain_detection.service — Attack Chain Service
=======================================================
Module 3.5 — Attack Chain Detection Engine

AttackChainService is the single public entry point for all chain operations.
Orchestrates AttackChainDetector + ChainEvaluator + ChainStore.

Usage
-----
    from backend.chain_detection.service import AttackChainService
    from backend.attack_graph.models import GraphSnapshot

    svc = AttackChainService()
    report = svc.detect_from_snapshot(snapshot)

    # Query
    chains = svc.load_chains_for_date()
    report  = svc.load_report(report_id)
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import structlog

from backend.attack_graph.models import GraphSnapshot
from backend.attack_graph.service import AttackGraphService
from backend.chain_detection.detector import AttackChainDetector
from backend.chain_detection.evaluator import ChainEvaluator
from backend.chain_detection.models import (
    AttackChain,
    ChainReport,
    ChainStatistics,
)
from backend.chain_detection.storage import ChainStore
from backend.core.config import get_settings

logger = structlog.get_logger(__name__)


class AttackChainService:
    """
    Orchestrates attack chain detection, evaluation, storage, and queries.

    Parameters
    ----------
    store_dir        : Override storage root (default: settings.data_dir / "chain_detection").
    persist          : Auto-persist chains and report after detection.
    min_chain_length : Minimum technique steps per chain.
    min_confidence   : Discard steps below this confidence.
    """

    def __init__(
        self,
        *,
        store_dir: Path | None = None,
        persist: bool = True,
        min_chain_length: int = 2,
        min_confidence: float = 0.05,
    ) -> None:
        settings = get_settings()
        resolved = store_dir or (settings.data_dir / "chain_detection")
        self._store = ChainStore(store_dir=resolved)
        self._detector = AttackChainDetector(
            min_chain_length=min_chain_length,
            min_confidence=min_confidence,
        )
        self._evaluator = ChainEvaluator()
        self._persist = persist
        logger.info(
            "attack_chain_service_initialized",
            persist=persist,
            min_chain_length=min_chain_length,
            store_dir=str(resolved),
        )

    # ── Status ────────────────────────────────────────────────────────────────

    def get_status(self) -> dict:
        return {
            "persist": self._persist,
            "min_chain_length": self._detector._min_length,
            "stored_reports": len(self._store.list_reports()),
        }

    # ── Primary API ───────────────────────────────────────────────────────────

    def detect_from_snapshot(
        self,
        snapshot: GraphSnapshot,
        *,
        persist: bool | None = None,
    ) -> ChainReport:
        """
        Detect all attack chains from a GraphSnapshot.

        Parameters
        ----------
        snapshot : GraphSnapshot from AttackGraphService.build_graph().
        persist  : Override service-level persist flag.

        Returns
        -------
        ChainReport — always returned, may contain zero chains.
        """
        chains = self._detector.detect(snapshot)

        should_persist = persist if persist is not None else self._persist
        if should_persist and chains:
            self._store.save_batch(chains)

        report = ChainReport(
            graph_id=snapshot.graph_id,
            chains=chains,
        )
        if should_persist:
            self._store.save_report(report)

        logger.info(
            "chains_detected_and_reported",
            report_id=report.report_id,
            graph_id=snapshot.graph_id,
            total_chains=report.statistics.total_chains,
            multi_tactic=report.statistics.multi_tactic_chains,
        )
        return report

    def detect_from_graph_id(
        self,
        graph_id: str,
        graph_service: AttackGraphService,
        *,
        persist: bool | None = None,
    ) -> ChainReport:
        """
        Load a stored graph by ID and run detection.

        Parameters
        ----------
        graph_id      : AttackGraph.graph_id to load.
        graph_service : AttackGraphService used to load the graph.
        persist       : Override persist flag.
        """
        snapshot = graph_service.load_graph(graph_id)
        return self.detect_from_snapshot(snapshot, persist=persist)

    def detect_from_snapshots_stream(
        self,
        snapshots: Iterable[GraphSnapshot],
        *,
        persist: bool | None = None,
    ) -> Iterable[ChainReport]:
        """
        Detect chains from a stream of GraphSnapshot objects.
        Yields one ChainReport per snapshot.
        """
        for snapshot in snapshots:
            yield self.detect_from_snapshot(snapshot, persist=persist)

    # ── Re-evaluation ─────────────────────────────────────────────────────────

    def re_evaluate_chains(
        self, chains: list[AttackChain]
    ) -> list[AttackChain]:
        """
        Re-run evaluation on a list of existing chains.
        Returns chains with updated ChainEvaluation.
        Useful after tuning evaluator weights.
        """
        updated: list[AttackChain] = []
        for chain in chains:
            if not chain.nodes:
                updated.append(chain)
                continue
            new_eval = self._evaluator.evaluate(chain)
            updated.append(chain.model_copy(update={"evaluation": new_eval}))
        return updated

    # ── Query API ─────────────────────────────────────────────────────────────

    def load_chains_for_date(self, date=None) -> list[AttackChain]:
        return self._store.load_chains_for_date(date)

    def load_report(self, report_id: str) -> ChainReport:
        return self._store.load_report(report_id)

    def list_reports(self) -> list[str]:
        return self._store.list_reports()

    def get_chains_by_entity(
        self, report: ChainReport, entity_id: str
    ) -> list[AttackChain]:
        """Filter chains from a report by entity_id."""
        return [c for c in report.chains if c.entity_id == entity_id]

    def get_high_confidence_chains(
        self, report: ChainReport, threshold: float = 0.5
    ) -> list[AttackChain]:
        """Return chains with confidence ≥ threshold, sorted descending."""
        return sorted(
            [c for c in report.chains if c.evaluation.confidence >= threshold],
            key=lambda c: c.evaluation.confidence,
            reverse=True,
        )

    def get_multi_tactic_chains(
        self, report: ChainReport
    ) -> list[AttackChain]:
        """Return chains that span more than one tactic."""
        return [c for c in report.chains if c.evaluation.is_multi_tactic]
