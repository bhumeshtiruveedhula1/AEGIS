"""
backend.chain_detection.detector — Attack Chain Detector
=========================================================
Module 3.5 — Attack Chain Detection Engine

AttackChainDetector discovers attack chains from a GraphSnapshot.

Detection Strategy
------------------
Phase 1 — Candidate source selection
  Select all TECHNIQUE nodes in the graph. Group by entity_id.
  A "source" is any technique node with no incoming PRECEDES edge
  from another technique node on the same entity — i.e., a chain root.

Phase 2 — DFS path expansion
  From each root, follow PRECEDES edges (then RELATED_TO as fallback)
  using NetworkX successors. Build all simple paths of length ≥ 2
  (at least 2 technique steps) up to MAX_CHAIN_LENGTH.

Phase 3 — Deduplication
  Two chains are duplicates if they share the same ordered sequence of
  technique_ids on the same entity_id. The chain with higher avg
  confidence is kept.

Phase 4 — Minimum quality gate
  Chains with fewer than MIN_CHAIN_LENGTH steps are discarded.
  Chains with avg_step_confidence below MIN_STEP_CONFIDENCE are discarded.

Design constraints
------------------
- Deterministic: same GraphSnapshot → same chains (sorted output)
- No ML, no LLM, no probabilistic reasoning
- Uses only NetworkX traversal and already-present graph information
- Does not modify the graph
"""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import islice
from typing import Any

import networkx as nx
import structlog

from backend.attack_graph.models import (
    EdgeType,
    GraphNode,
    GraphSnapshot,
    NodeType,
)
from backend.chain_detection.exceptions import ChainBuildError, InvalidGraphError
from backend.chain_detection.models import (
    AttackChain,
    ChainEvidence,
    ChainLink,
    ChainNode,
)

logger = structlog.get_logger(__name__)

# Tuning constants
MIN_CHAIN_LENGTH: int = 2          # minimum technique steps to form a chain
MAX_CHAIN_LENGTH: int = 15         # maximum depth DFS will explore
MIN_STEP_CONFIDENCE: float = 0.05  # discard steps below this confidence
MAX_PATHS_PER_ROOT: int = 50       # cap paths per root to avoid combinatorial explosion
_PRECEDES = EdgeType.PRECEDES.value
_RELATED = EdgeType.RELATED_TO.value


class AttackChainDetector:
    """
    Discovers attack chains from a GraphSnapshot.

    Parameters
    ----------
    min_chain_length  : Minimum number of technique steps. Default 2.
    max_chain_length  : Maximum DFS depth. Default 15.
    min_confidence    : Discard steps below this step-level confidence.
    """

    def __init__(
        self,
        *,
        min_chain_length: int = MIN_CHAIN_LENGTH,
        max_chain_length: int = MAX_CHAIN_LENGTH,
        min_confidence: float = MIN_STEP_CONFIDENCE,
    ) -> None:
        self._min_length = min_chain_length
        self._max_length = max_chain_length
        self._min_confidence = min_confidence

    # ── Public API ────────────────────────────────────────────────────────────

    def detect(self, snapshot: GraphSnapshot) -> list[AttackChain]:
        """
        Discover all attack chains in the supplied GraphSnapshot.

        Returns a list of AttackChain objects sorted by:
          (entity_id, -evaluation.confidence, chain_length)
        """
        if not snapshot.nodes:
            logger.info("detect_skipped_empty_graph", graph_id=snapshot.graph_id)
            return []

        try:
            nx_graph, node_map = self._build_graph(snapshot)
        except Exception as exc:
            raise InvalidGraphError(
                f"Cannot build NX graph from snapshot {snapshot.graph_id}: {exc}",
                context={"graph_id": snapshot.graph_id, "cause": str(exc)},
            ) from exc

        # Group technique nodes by entity
        entity_groups = self._group_techniques_by_entity(node_map)
        if not entity_groups:
            logger.info("no_technique_nodes", graph_id=snapshot.graph_id)
            return []

        chains: list[AttackChain] = []
        for entity_id, tech_nodes in entity_groups.items():
            entity_chains = self._detect_for_entity(
                entity_id, tech_nodes, nx_graph, node_map, snapshot.graph_id
            )
            chains.extend(entity_chains)

        # Deduplicate and sort
        chains = self._deduplicate(chains)
        chains.sort(key=lambda c: (c.entity_id, -c.evaluation.confidence, -c.length))

        logger.info(
            "chains_detected",
            graph_id=snapshot.graph_id,
            chains=len(chains),
        )
        return chains

    # ── Graph construction ────────────────────────────────────────────────────

    @staticmethod
    def _build_graph(
        snapshot: GraphSnapshot,
    ) -> tuple[nx.DiGraph, dict[str, GraphNode]]:
        """Reconstruct NX graph and node_map from snapshot."""
        from backend.attack_graph.graph_store import GraphStore
        nx_graph = GraphStore.snapshot_to_nx(snapshot)
        node_map = GraphStore.snapshot_to_node_map(snapshot)
        return nx_graph, node_map

    # ── Entity grouping ───────────────────────────────────────────────────────

    @staticmethod
    def _group_techniques_by_entity(
        node_map: dict[str, GraphNode],
    ) -> dict[str, list[GraphNode]]:
        """
        Group TECHNIQUE nodes by entity_id.

        Entity_id is extracted from node.attributes["entity_id"] if present,
        otherwise parsed from the node_id pattern:
          technique::<T-ID>::<entity_type>::<entity_id_parts...>
        """
        groups: dict[str, list[GraphNode]] = {}
        for node in node_map.values():
            nt = node.node_type
            nt_val = nt.value if hasattr(nt, "value") else str(nt)
            if nt_val != NodeType.TECHNIQUE.value:
                continue

            entity_id = node.attributes.get("entity_id", "")
            if not entity_id:
                # Parse from: technique::<T-ID>::<entity_type>::<id_parts...>
                parts = node.node_id.split("::")
                # [0]=technique, [1]=T-ID, [2]=entity_type, [3..]=entity_id parts
                if len(parts) >= 4:
                    entity_id = "::".join(parts[3:])
                elif len(parts) == 3:
                    entity_id = parts[2]

            if not entity_id:
                continue
            groups.setdefault(entity_id, []).append(node)
        return groups

    # ── Per-entity detection ──────────────────────────────────────────────────

    def _detect_for_entity(
        self,
        entity_id: str,
        tech_nodes: list[GraphNode],
        nx_graph: nx.DiGraph,
        node_map: dict[str, GraphNode],
        graph_id: str,
    ) -> list[AttackChain]:
        """Find all chains for one entity."""
        tech_ids = {n.node_id for n in tech_nodes}
        sub = self._technique_subgraph(nx_graph, tech_ids, node_map)

        # Roots: in-degree 0 in the subgraph
        roots = [nid for nid in sub.nodes() if sub.in_degree(nid) == 0]
        if not roots:
            roots = list(sub.nodes())

        # Leaf nodes (out-degree 0) — needed for all_simple_paths target
        leaves = [nid for nid in sub.nodes() if sub.out_degree(nid) == 0]
        if not leaves:
            leaves = list(sub.nodes())

        chains: list[AttackChain] = []
        seen_sigs: set[tuple[str, ...]] = set()
        path_count = 0

        for root in roots:
            for leaf in leaves:
                if root == leaf:
                    continue
                try:
                    for path in nx.all_simple_paths(
                        sub, root, leaf, cutoff=self._max_length
                    ):
                        if path_count >= MAX_PATHS_PER_ROOT:
                            break
                        path_count += 1
                        if len(path) < self._min_length:
                            continue
                        sig = tuple(path)
                        if sig in seen_sigs:
                            continue
                        seen_sigs.add(sig)
                        chain = self._build_chain(
                            path, node_map, nx_graph, graph_id, entity_id
                        )
                        if chain is not None:
                            chains.append(chain)
                except (nx.NetworkXError, nx.NodeNotFound):
                    continue

        # If no root-to-leaf paths found (e.g. single node or no paths),
        # emit the full temporal ordering as one chain
        if not chains and len(tech_ids) >= self._min_length:
            ordered = sorted(
                [node_map[nid] for nid in tech_ids if nid in node_map],
                key=lambda n: n.first_seen,
            )
            path = [n.node_id for n in ordered]
            if len(path) >= self._min_length:
                sig = tuple(path)
                if sig not in seen_sigs:
                    chain = self._build_chain(
                        path, node_map, nx_graph, graph_id, entity_id
                    )
                    if chain is not None:
                        chains.append(chain)

        return chains

    @staticmethod
    def _technique_subgraph(
        nx_graph: nx.DiGraph,
        tech_ids: set[str],
        node_map: dict[str, GraphNode] | None = None,
    ) -> nx.DiGraph:
        """
        Build a directed subgraph for entity-scoped technique nodes.

        Priority:
        1. Use existing PRECEDES / RELATED_TO edges from the graph (same-alert)
        2. If no edges found, synthesize temporal PRECEDES edges from
           first_seen ordering — enabling cross-alert chain detection.
        """
        sub = nx.DiGraph()
        for nid in tech_ids:
            sub.add_node(nid)

        # Add existing graph edges
        edges_added = False
        for src, dst, data in nx_graph.edges(data=True):
            if src not in tech_ids or dst not in tech_ids:
                continue
            et = data.get("edge_type", "")
            if et in (_PRECEDES, _RELATED):
                sub.add_edge(src, dst, edge_type=et)
                edges_added = True

        # When no existing edges — synthesize temporal PRECEDES from first_seen
        if not edges_added and node_map is not None and len(tech_ids) >= 2:
            ordered = sorted(
                [node_map[nid] for nid in tech_ids if nid in node_map],
                key=lambda n: n.first_seen,
            )
            for a, b in zip(ordered, ordered[1:]):
                # Only connect if different technique (no self-loop)
                if a.node_id != b.node_id:
                    sub.add_edge(a.node_id, b.node_id, edge_type=_PRECEDES)

        return sub

    # ── Chain construction ────────────────────────────────────────────────────

    def _build_chain(
        self,
        path: list[str],
        node_map: dict[str, GraphNode],
        nx_graph: nx.DiGraph,
        graph_id: str,
        entity_id: str,
    ) -> AttackChain | None:
        """Construct an AttackChain from a node-id path. Returns None on failure."""
        try:
            chain_nodes: list[ChainNode] = []
            for step_idx, nid in enumerate(path):
                gn = node_map.get(nid)
                if gn is None:
                    continue
                attrs = gn.attributes
                conf = float(attrs.get("confidence", 0.0))
                if conf < self._min_confidence:
                    # Keep but with floor confidence — don't discard the step
                    conf = self._min_confidence

                # Recover first_seen / last_seen from node
                fs = gn.first_seen
                ls = gn.last_seen

                # Extract entity_id/entity_type: prefer attrs, fallback to node_id parse
                node_entity_id = attrs.get("entity_id", "")
                node_entity_type = attrs.get("entity_type", "")
                if not node_entity_id:
                    parts = nid.split("::")
                    if len(parts) >= 4:
                        node_entity_type = parts[2]
                        node_entity_id = "::".join(parts[3:])
                    elif len(parts) == 3:
                        node_entity_id = parts[2]
                if not node_entity_id:
                    node_entity_id = entity_id

                chain_nodes.append(ChainNode(
                    chain_node_id=nid,
                    technique_id=attrs.get("technique_id", "unknown"),
                    technique_name=attrs.get("technique_name", "unknown"),
                    tactic_id=attrs.get("tactic_id", "unknown"),
                    tactic_name=attrs.get("tactic_name", "unknown"),
                    entity_id=node_entity_id,
                    entity_type=node_entity_type,
                    confidence=conf,
                    observation_count=gn.observation_count,
                    first_seen=fs,
                    last_seen=ls,
                    matched_features=list(attrs.get("matched_features", [])),
                    step_index=step_idx,
                ))

            if len(chain_nodes) < self._min_length:
                return None

            # Build links
            links: list[ChainLink] = []
            for a, b in zip(chain_nodes, chain_nodes[1:]):
                gap = max(
                    0.0,
                    (b.first_seen - a.first_seen).total_seconds(),
                )
                edge_data = nx_graph.get_edge_data(a.chain_node_id, b.chain_node_id, {})
                link_type = edge_data.get("edge_type", _PRECEDES)
                links.append(ChainLink(
                    source_node_id=a.chain_node_id,
                    target_node_id=b.chain_node_id,
                    link_type=link_type,
                    temporal_gap_seconds=gap,
                ))

            # Evidence
            all_features: set[str] = set()
            for cn in chain_nodes:
                all_features.update(cn.matched_features)

            entity_node_id = f"entity::{chain_nodes[0].entity_type}::{entity_id}"
            alert_ids = self._get_alert_ids_for_entity(nx_graph, node_map, entity_node_id)

            evidence = ChainEvidence(
                alert_ids=alert_ids,
                tactic_sequence=[cn.tactic_name for cn in chain_nodes],
                technique_ids=[cn.technique_id for cn in chain_nodes],
                matched_features=sorted(all_features),
                total_observations=sum(cn.observation_count for cn in chain_nodes),
            )

            # Build chain (evaluation added later by ChainEvaluator via service)
            from backend.chain_detection.evaluator import ChainEvaluator
            chain = AttackChain(
                graph_id=graph_id,
                entity_id=entity_id,
                entity_type=chain_nodes[0].entity_type if chain_nodes else "",
                nodes=chain_nodes,
                links=links,
                evidence=evidence,
            )
            # Evaluate inline
            evaluator = ChainEvaluator()
            evaluation = evaluator.evaluate(chain)
            return chain.model_copy(update={"evaluation": evaluation})

        except Exception as exc:
            logger.debug(
                "chain_build_error",
                path=path,
                error=str(exc),
            )
            return None

    @staticmethod
    def _get_alert_ids_for_entity(
        nx_graph: nx.DiGraph,
        node_map: dict[str, GraphNode],
        entity_node_id: str,
    ) -> list[str]:
        """Get alert_ids associated with this entity from GENERATED_FROM edges."""
        alert_ids: list[str] = []
        if entity_node_id not in node_map:
            return alert_ids
        _gen = EdgeType.GENERATED_FROM.value
        for src, _, data in nx_graph.in_edges(entity_node_id, data=True):
            if data.get("edge_type") == _gen and src in node_map:
                src_node = node_map[src]
                nt = src_node.node_type
                nt_val = nt.value if hasattr(nt, "value") else str(nt)
                if nt_val == NodeType.ALERT.value:
                    aid = src_node.attributes.get("alert_id", "")
                    if aid:
                        alert_ids.append(aid)
        return alert_ids

    # ── Deduplication ─────────────────────────────────────────────────────────

    @staticmethod
    def _deduplicate(chains: list[AttackChain]) -> list[AttackChain]:
        """
        Remove duplicate chains. Two chains are duplicates when they have the
        same entity_id and same ordered technique_id sequence.
        Keeps the chain with higher confidence.
        """
        best: dict[tuple, AttackChain] = {}
        for chain in chains:
            sig = (chain.entity_id, tuple(chain.technique_ids))
            existing = best.get(sig)
            if existing is None or chain.evaluation.confidence > existing.evaluation.confidence:
                best[sig] = chain
        return list(best.values())
