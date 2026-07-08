"""
backend.attack_graph.graph_builder — Attack Graph Builder
==========================================================
Module 3.4 — Attack Graph Engine

AttackGraphBuilder translates MappedAttack objects into a NetworkX DiGraph.

Graph Construction Strategy
-----------------------------
For each MappedAttack ingested:

1. ALERT node         — one node per MappedAttack (mapping_id)
2. ENTITY node        — entity_type::entity_id
3. HOST node          — host::event_host  (if present in alert)
4. USER node          — user::event_user  (if present in alert)
5. TACTIC nodes       — one per unique tactic across all techniques
6. TECHNIQUE nodes    — one per technique mapping

Edges added:
  ALERT → ENTITY        (generated_from)
  ALERT → HOST          (generated_from)
  ALERT → USER          (generated_from)
  TECHNIQUE → ALERT     (observed_on)
  TECHNIQUE → ENTITY    (executed_by)
  TECHNIQUE → TACTIC    (belongs_to)
  TECHNIQUE → TECHNIQUE (precedes — if same entity, earlier timestamp < later)
  TECHNIQUE → TECHNIQUE (related_to — same tactic, same entity, same timestamp)

Merge semantics
---------------
Repeated observations of the same (type, value) pair collapse into a single
node. The builder calls GraphNode.merge() to aggregate attributes and update
observation_count. NetworkX node attributes are kept in sync via
nx.DiGraph.nodes[node_id].update(attrs).

Determinism
-----------
Given the same list of MappedAttack objects in the same order, the builder
always produces the same graph structure.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import networkx as nx
import structlog

from backend.attack_graph.exceptions import GraphBuildError, GraphIntegrityError
from backend.attack_graph.models import (
    AttackGraph,
    EdgeType,
    GraphEdge,
    GraphNode,
    GraphSnapshot,
    GraphStatistics,
    NodeType,
)
from backend.mitre.models import MappedAttack

logger = structlog.get_logger(__name__)


class AttackGraphBuilder:
    """
    Builds and incrementally updates a NetworkX DiGraph from MappedAttack objects.

    Usage
    -----
        builder = AttackGraphBuilder()
        for mapped in mappings:
            builder.add_mapped_attack(mapped)
        graph, snapshot = builder.build()

    Thread safety: Not thread-safe. Use one builder per graph session.
    """

    def __init__(self, graph_id: str | None = None) -> None:
        self._nx: nx.DiGraph = nx.DiGraph()
        self._nodes: dict[str, GraphNode] = {}       # node_id → GraphNode
        self._edges: dict[tuple, GraphEdge] = {}     # edge_key → GraphEdge
        self._mapped_attack_ids: list[str] = []
        self._source_model_id: str = ""
        self._graph_id: str = graph_id or f"ag-{self._short_id()}"
        self._created_at: datetime = datetime.now(UTC)
        logger.debug("attack_graph_builder_initialized", graph_id=self._graph_id)

    # ── Public API ────────────────────────────────────────────────────────────

    def add_mapped_attack(self, mapped: MappedAttack) -> None:
        """
        Ingest one MappedAttack into the graph.
        Idempotent: repeated calls with the same mapping merge observations.
        """
        if not mapped.techniques:
            logger.debug(
                "mapped_attack_skipped_no_techniques",
                mapping_id=mapped.mapping_id,
            )
            return

        try:
            self._ingest(mapped)
        except Exception as exc:
            raise GraphBuildError(
                f"Failed to add MappedAttack {mapped.mapping_id}: {exc}",
                context={"mapping_id": mapped.mapping_id, "cause": str(exc)},
            ) from exc

        if mapped.mapping_id not in self._mapped_attack_ids:
            self._mapped_attack_ids.append(mapped.mapping_id)
        if mapped.model_id and not self._source_model_id:
            self._source_model_id = mapped.model_id

    def add_batch(self, mappings: list[MappedAttack]) -> None:
        """Ingest a list of MappedAttack objects."""
        for mapped in mappings:
            self.add_mapped_attack(mapped)
        logger.info(
            "batch_ingested",
            graph_id=self._graph_id,
            count=len(mappings),
            nodes=self._nx.number_of_nodes(),
            edges=self._nx.number_of_edges(),
        )

    def build(self) -> tuple[AttackGraph, GraphSnapshot]:
        """
        Finalise and return (AttackGraph, GraphSnapshot).

        Validates graph integrity before returning.
        Safe to call multiple times — each call returns the current state.
        """
        self._validate()
        stats = self._compute_statistics()
        now = datetime.now(UTC)

        graph = AttackGraph(
            graph_id=self._graph_id,
            created_at=self._created_at,
            updated_at=now,
            source_model_id=self._source_model_id,
            mapped_attack_ids=list(self._mapped_attack_ids),
            statistics=stats,
        )
        snapshot = GraphSnapshot(
            graph_id=self._graph_id,
            created_at=now,
            nodes=list(self._nodes.values()),
            edges=list(self._edges.values()),
            statistics=stats,
            metadata={"source_model_id": self._source_model_id},
        )
        logger.info(
            "attack_graph_built",
            graph_id=self._graph_id,
            nodes=stats.node_count,
            edges=stats.edge_count,
            techniques=stats.technique_count,
        )
        return graph, snapshot

    @property
    def nx_graph(self) -> nx.DiGraph:
        """Direct access to the underlying NetworkX DiGraph (read-only intent)."""
        return self._nx

    @property
    def node_count(self) -> int:
        return self._nx.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._nx.number_of_edges()

    # ── Internal ingestion ────────────────────────────────────────────────────

    def _ingest(self, mapped: MappedAttack) -> None:
        ts = mapped.mapped_at

        # 1. ALERT node
        alert_id = GraphNode.make_id(NodeType.ALERT, mapped.mapping_id)
        alert_node = GraphNode(
            node_id=alert_id,
            node_type=NodeType.ALERT,
            label=f"Alert {mapped.alert_id[:12]}",
            attributes={
                "alert_id": mapped.alert_id,
                "mapping_id": mapped.mapping_id,
                "model_id": mapped.model_id,
                "anomaly_score": mapped.anomaly_score,
                "event_id": mapped.event_id,
            },
            first_seen=ts,
            last_seen=ts,
        )
        self._upsert_node(alert_node)

        # 2. ENTITY node
        entity_val = f"{mapped.entity_type}::{mapped.entity_id}"
        entity_id = GraphNode.make_id(NodeType.ENTITY, entity_val)
        entity_node = GraphNode(
            node_id=entity_id,
            node_type=NodeType.ENTITY,
            label=entity_val,
            attributes={
                "entity_type": mapped.entity_type,
                "entity_id": mapped.entity_id,
            },
            first_seen=ts,
            last_seen=ts,
        )
        self._upsert_node(entity_node)
        self._upsert_edge(alert_id, entity_id, EdgeType.GENERATED_FROM, {}, ts)

        # 3. HOST / USER nodes (derived from entity_id convention "user::host")
        if "::" in mapped.entity_id:
            parts = mapped.entity_id.split("::", 1)
            user_val, host_val = parts[0], parts[1]
            if user_val:
                user_id = GraphNode.make_id(NodeType.USER, user_val)
                self._upsert_node(GraphNode(
                    node_id=user_id, node_type=NodeType.USER,
                    label=user_val,
                    attributes={"username": user_val},
                    first_seen=ts, last_seen=ts,
                ))
                self._upsert_edge(entity_id, user_id, EdgeType.GENERATED_FROM, {}, ts)
            if host_val:
                host_id = GraphNode.make_id(NodeType.HOST, host_val)
                self._upsert_node(GraphNode(
                    node_id=host_id, node_type=NodeType.HOST,
                    label=host_val,
                    attributes={"hostname": host_val},
                    first_seen=ts, last_seen=ts,
                ))
                self._upsert_edge(entity_id, host_id, EdgeType.TARGETS, {}, ts)

        # 4. Techniques + Tactics
        technique_node_ids: list[str] = []
        for tm in mapped.techniques:
            tactic = tm.technique.tactic
            technique = tm.technique

            # TACTIC node
            tac_id = GraphNode.make_id(NodeType.TACTIC, tactic.tactic_id)
            self._upsert_node(GraphNode(
                node_id=tac_id, node_type=NodeType.TACTIC,
                label=tactic.name,
                attributes={"tactic_id": tactic.tactic_id, "short_name": tactic.short_name},
                first_seen=ts, last_seen=ts,
            ))

            # TECHNIQUE node
            tec_val = f"{technique.technique_id}::{entity_val}"
            tec_id = GraphNode.make_id(NodeType.TECHNIQUE, tec_val)
            self._upsert_node(GraphNode(
                node_id=tec_id, node_type=NodeType.TECHNIQUE,
                label=f"{technique.technique_id} {technique.name}",
                attributes={
                    "technique_id": technique.technique_id,
                    "technique_name": technique.name,
                    "tactic_id": tactic.tactic_id,
                    "tactic_name": tactic.name,
                    "confidence": tm.confidence,
                    "shap_total": tm.shap_total_contribution,
                    "matched_features": tm.matched_features,
                },
                first_seen=ts, last_seen=ts,
            ))

            # Edges: technique → alert, technique → entity, technique → tactic
            self._upsert_edge(tec_id, alert_id, EdgeType.OBSERVED_ON,
                              {"confidence": tm.confidence}, ts)
            self._upsert_edge(tec_id, entity_id, EdgeType.EXECUTED_BY,
                              {"confidence": tm.confidence}, ts)
            self._upsert_edge(tec_id, tac_id, EdgeType.BELONGS_TO, {}, ts)

            technique_node_ids.append(tec_id)

        # 5. PRECEDES / RELATED_TO edges between techniques of the same alert
        for i, src_id in enumerate(technique_node_ids):
            for j, dst_id in enumerate(technique_node_ids):
                if i == j or src_id == dst_id:
                    continue
                src_attrs = self._nx.nodes[src_id]
                dst_attrs = self._nx.nodes[dst_id]
                if src_attrs.get("tactic_id") == dst_attrs.get("tactic_id"):
                    # Same tactic → related_to
                    self._upsert_edge(src_id, dst_id, EdgeType.RELATED_TO, {}, ts)
                else:
                    # Different tactic — only precedes if i < j (ordering by confidence rank)
                    if i < j:
                        self._upsert_edge(src_id, dst_id, EdgeType.PRECEDES, {}, ts)

    def _upsert_node(self, node: GraphNode) -> None:
        """Insert or merge a GraphNode."""
        nid = node.node_id
        if nid in self._nodes:
            self._nodes[nid] = self._nodes[nid].merge(node)
        else:
            self._nodes[nid] = node
        # Keep NX attributes in sync
        self._nx.add_node(nid, **self._node_to_nx_attrs(self._nodes[nid]))

    def _upsert_edge(
        self,
        src: str,
        dst: str,
        etype: EdgeType,
        attrs: dict[str, Any],
        ts: datetime,
    ) -> None:
        """Insert or merge a directed edge."""
        key = (src, dst, etype.value)
        if key in self._edges:
            existing = self._edges[key]
            self._edges[key] = existing.model_copy(update={
                "last_seen": max(existing.last_seen, ts),
                "observation_count": existing.observation_count + 1,
                "attributes": {**existing.attributes, **attrs},
            })
        else:
            self._edges[key] = GraphEdge(
                source_id=src, target_id=dst, edge_type=etype,
                attributes=attrs, first_seen=ts, last_seen=ts,
            )
        self._nx.add_edge(src, dst, edge_type=etype.value, **attrs)

    # ── Statistics & Validation ───────────────────────────────────────────────

    @staticmethod
    def _node_type_str(node) -> str:
        """Return node_type as a plain string, regardless of enum vs str."""
        nt = node.node_type
        return nt.value if hasattr(nt, 'value') else str(nt)

    def _compute_statistics(self) -> GraphStatistics:
        from collections import Counter
        type_counts: Counter[str] = Counter(
            self._node_type_str(n) for n in self._nodes.values()
        )
        tac_dist: Counter[str] = Counter()
        tec_dist: Counter[str] = Counter()
        for node in self._nodes.values():
            if self._node_type_str(node) == NodeType.TECHNIQUE.value:
                tid = node.attributes.get("technique_id", "unknown")
                tac = node.attributes.get("tactic_name", "unknown")
                tec_dist[tid] += node.observation_count
                tac_dist[tac] += 1

        return GraphStatistics(
            node_count=self._nx.number_of_nodes(),
            edge_count=self._nx.number_of_edges(),
            technique_count=type_counts[NodeType.TECHNIQUE],
            tactic_count=type_counts[NodeType.TACTIC],
            alert_count=type_counts[NodeType.ALERT],
            entity_count=type_counts[NodeType.ENTITY],
            host_count=type_counts[NodeType.HOST],
            user_count=type_counts[NodeType.USER],
            tactic_distribution=dict(tac_dist),
            technique_distribution=dict(tec_dist),
            is_dag=nx.is_directed_acyclic_graph(self._nx),
        )

    def _validate(self) -> None:
        """Basic integrity checks. Raises GraphIntegrityError on violation."""
        # All edge endpoints must exist as nodes
        for src, dst in self._nx.edges():
            if src not in self._nodes:
                raise GraphIntegrityError(
                    f"Edge references missing source node: {src}",
                    context={"source": src, "target": dst},
                )
            if dst not in self._nodes:
                raise GraphIntegrityError(
                    f"Edge references missing target node: {dst}",
                    context={"source": src, "target": dst},
                )

    @staticmethod
    def _node_to_nx_attrs(node: GraphNode) -> dict[str, Any]:
        node_type_val = (
            node.node_type.value
            if isinstance(node.node_type, NodeType)
            else node.node_type
        )
        return {
            "node_type": node_type_val,
            "label": node.label,
            "first_seen": node.first_seen.isoformat(),
            "last_seen": node.last_seen.isoformat(),
            "observation_count": node.observation_count,
            **node.attributes,
        }

    @staticmethod
    def _short_id() -> str:
        import uuid
        return str(uuid.uuid4())[:8]
