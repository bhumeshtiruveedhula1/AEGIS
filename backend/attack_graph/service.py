"""
backend.attack_graph.service — Attack Graph Service
=====================================================
Module 3.4 — Attack Graph Engine

AttackGraphService is the single public entry point for all graph operations.
Orchestrates AttackGraphBuilder + GraphStore + traversal utilities.

Usage
-----
    from backend.attack_graph.service import AttackGraphService
    from backend.mitre.models import MappedAttack

    svc = AttackGraphService()
    graph, snapshot = svc.build_graph(mapped_attacks)

    # Queries (require snapshot to be loaded)
    result = svc.query_neighbors(graph.graph_id, node_id)
    result = svc.query_techniques_for_entity(graph.graph_id, entity_node_id)
    stats  = svc.get_graph_statistics(graph.graph_id)
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import structlog

from backend.attack_graph import traversal as tv
from backend.attack_graph.exceptions import GraphStorageError
from backend.attack_graph.graph_builder import AttackGraphBuilder
from backend.attack_graph.graph_store import GraphStore
from backend.attack_graph.models import (
    AttackGraph,
    EdgeType,
    GraphNode,
    GraphSnapshot,
    GraphStatistics,
    GraphTraversalResult,
    NodeType,
)
from backend.core.config import get_settings
from backend.mitre.models import MappedAttack

logger = structlog.get_logger(__name__)


class AttackGraphService:
    """
    Orchestrates attack graph creation, incremental update, storage, and queries.

    Parameters
    ----------
    store_dir : Override storage root (default: settings.data_dir / "attack_graph").
    persist   : Auto-persist graph and snapshot after build / update.
    """

    def __init__(
        self,
        *,
        store_dir: Path | None = None,
        persist: bool = True,
    ) -> None:
        settings = get_settings()
        resolved = store_dir or (settings.data_dir / "attack_graph")
        self._store = GraphStore(store_dir=resolved)
        self._persist = persist
        # In-memory cache: graph_id → (nx_graph, node_map, snapshot)
        self._cache: dict[str, tuple] = {}
        logger.info(
            "attack_graph_service_initialized",
            persist=persist,
            store_dir=str(resolved),
        )

    # ── Status ────────────────────────────────────────────────────────────────

    def get_status(self) -> dict:
        return {
            "persist": self._persist,
            "cached_graphs": len(self._cache),
            "stored_graphs": len(self._store.list_graph_ids()),
        }

    # ── Graph construction ────────────────────────────────────────────────────

    def build_graph(
        self,
        mappings: list[MappedAttack],
        *,
        graph_id: str | None = None,
        persist: bool | None = None,
    ) -> tuple[AttackGraph, GraphSnapshot]:
        """
        Build a new AttackGraph from a list of MappedAttack objects.

        Parameters
        ----------
        mappings  : List from MitreService output.
        graph_id  : Optional stable ID (default: auto-generated).
        persist   : Override service-level persist flag.

        Returns
        -------
        (AttackGraph, GraphSnapshot) — both always returned.
        """
        builder = AttackGraphBuilder(graph_id=graph_id)
        builder.add_batch(mappings)
        graph, snapshot = builder.build()

        self._cache[graph.graph_id] = (
            builder.nx_graph,
            builder._nodes,
            snapshot,
        )

        should_persist = persist if persist is not None else self._persist
        if should_persist:
            self._store.save_snapshot(snapshot)
            self._store.save_graph_meta(graph)

        logger.info(
            "graph_built",
            graph_id=graph.graph_id,
            nodes=graph.statistics.node_count,
            edges=graph.statistics.edge_count,
            mappings_ingested=len(mappings),
        )
        return graph, snapshot

    def build_graph_from_stream(
        self,
        mappings: Iterable[MappedAttack],
        *,
        graph_id: str | None = None,
        persist: bool | None = None,
    ) -> tuple[AttackGraph, GraphSnapshot]:
        """
        Incrementally build an AttackGraph from a streaming iterable of MappedAttack.
        Suitable for large pipelines where all alerts may not fit in memory.
        """
        builder = AttackGraphBuilder(graph_id=graph_id)
        count = 0
        for mapped in mappings:
            builder.add_mapped_attack(mapped)
            count += 1

        graph, snapshot = builder.build()
        self._cache[graph.graph_id] = (builder.nx_graph, builder._nodes, snapshot)

        should_persist = persist if persist is not None else self._persist
        if should_persist:
            self._store.save_snapshot(snapshot)
            self._store.save_graph_meta(graph)

        logger.info(
            "stream_graph_built",
            graph_id=graph.graph_id,
            ingested=count,
            nodes=graph.statistics.node_count,
        )
        return graph, snapshot

    # ── Loading ───────────────────────────────────────────────────────────────

    def load_graph(self, graph_id: str) -> GraphSnapshot:
        """Load a stored GraphSnapshot into the in-memory cache and return it."""
        if graph_id in self._cache:
            return self._cache[graph_id][2]  # cached snapshot

        snapshot = self._store.load_snapshot(graph_id)
        nx_graph = GraphStore.snapshot_to_nx(snapshot)
        node_map = GraphStore.snapshot_to_node_map(snapshot)
        self._cache[graph_id] = (nx_graph, node_map, snapshot)
        return snapshot

    def list_graphs(self) -> list[str]:
        return self._store.list_graph_ids()

    # ── Graph statistics ──────────────────────────────────────────────────────

    def get_graph_statistics(self, graph_id: str) -> GraphStatistics:
        """Return statistics for a cached or stored graph."""
        snap = self.load_graph(graph_id)
        return snap.statistics

    # ── Traversal queries ─────────────────────────────────────────────────────

    def _get_cached(self, graph_id: str) -> tuple:
        if graph_id not in self._cache:
            self.load_graph(graph_id)
        return self._cache[graph_id]  # (nx_graph, node_map, snapshot)

    def query_node(self, graph_id: str, node_id: str) -> GraphNode:
        _, nodes, _ = self._get_cached(graph_id)
        return tv.get_node(None, nodes, node_id)  # type: ignore[arg-type]

    def query_nodes_by_type(
        self, graph_id: str, node_type: NodeType
    ) -> list[GraphNode]:
        _, nodes, _ = self._get_cached(graph_id)
        return tv.get_nodes_by_type(nodes, node_type)

    def query_neighbors(
        self,
        graph_id: str,
        node_id: str,
        edge_type: EdgeType | None = None,
    ) -> GraphTraversalResult:
        nx_graph, nodes, _ = self._get_cached(graph_id)
        return tv.get_neighbors(nx_graph, nodes, node_id, edge_type)

    def query_predecessors(
        self,
        graph_id: str,
        node_id: str,
        edge_type: EdgeType | None = None,
    ) -> GraphTraversalResult:
        nx_graph, nodes, _ = self._get_cached(graph_id)
        return tv.get_predecessors(nx_graph, nodes, node_id, edge_type)

    def query_descendants(
        self, graph_id: str, node_id: str, max_depth: int = 10
    ) -> GraphTraversalResult:
        nx_graph, nodes, _ = self._get_cached(graph_id)
        return tv.get_descendants(nx_graph, nodes, node_id, max_depth)

    def query_ancestors(
        self, graph_id: str, node_id: str, max_depth: int = 10
    ) -> GraphTraversalResult:
        nx_graph, nodes, _ = self._get_cached(graph_id)
        return tv.get_ancestors(nx_graph, nodes, node_id, max_depth)

    def query_paths(
        self,
        graph_id: str,
        source_id: str,
        target_id: str,
        cutoff: int = 8,
    ) -> GraphTraversalResult:
        nx_graph, nodes, _ = self._get_cached(graph_id)
        return tv.find_paths(nx_graph, nodes, source_id, target_id, cutoff)

    def query_techniques_for_entity(
        self, graph_id: str, entity_node_id: str
    ) -> list[GraphNode]:
        _, nodes, _ = self._get_cached(graph_id)
        return tv.techniques_for_entity(nodes, entity_node_id)

    def query_alerts_for_entity(
        self, graph_id: str, entity_node_id: str
    ) -> list[GraphNode]:
        nx_graph, nodes, _ = self._get_cached(graph_id)
        return tv.alerts_for_entity(nx_graph, nodes, entity_node_id)

    def query_techniques_by_tactic(
        self, graph_id: str, tactic_id: str
    ) -> list[GraphNode]:
        _, nodes, _ = self._get_cached(graph_id)
        return tv.techniques_by_tactic(nodes, tactic_id)

    def query_temporal_order(
        self, graph_id: str, node_type: NodeType | None = None
    ) -> list[GraphNode]:
        _, nodes, _ = self._get_cached(graph_id)
        return tv.get_nodes_in_temporal_order(nodes, node_type)

    def query_connected_components(
        self, graph_id: str
    ) -> list[list[GraphNode]]:
        nx_graph, nodes, _ = self._get_cached(graph_id)
        return tv.get_weakly_connected_components(nx_graph, nodes)
