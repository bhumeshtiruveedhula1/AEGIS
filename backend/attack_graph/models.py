"""
backend.attack_graph.models — Attack Graph Data Models
=======================================================
Module 3.4 — Attack Graph Engine

Pure data models — no graph logic. All graph operations live in
graph_builder.py and traversal.py.

Node Types
----------
TECHNIQUE   — an ATT&CK technique observed in a MappedAttack
TACTIC      — an ATT&CK tactic (parent of technique nodes)
ALERT       — the source DetectionAlert
ENTITY      — user_host / host / user composite
HOST        — a specific host machine
USER        — a specific user account

Edge Types
----------
OBSERVED_ON         — technique → alert
GENERATED_FROM      — alert → entity
EXECUTED_BY         — technique → entity
TARGETS             — technique → host | entity
BELONGS_TO          — technique → tactic
PRECEDES            — technique → technique (temporal ordering, same entity)
RELATED_TO          — technique → technique (same tactic, same entity)

Schema Version: 1.0.0
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import ConfigDict, Field

from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

GRAPH_SCHEMA_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class NodeType(str, Enum):
    TECHNIQUE = "technique"
    TACTIC = "tactic"
    ALERT = "alert"
    ENTITY = "entity"
    HOST = "host"
    USER = "user"


class EdgeType(str, Enum):
    OBSERVED_ON = "observed_on"
    GENERATED_FROM = "generated_from"
    EXECUTED_BY = "executed_by"
    TARGETS = "targets"
    BELONGS_TO = "belongs_to"
    PRECEDES = "precedes"
    RELATED_TO = "related_to"


# ---------------------------------------------------------------------------
# GraphNode — vertex in the attack graph
# ---------------------------------------------------------------------------

class GraphNode(CyberShieldBaseModel):
    """
    A typed vertex in the attack graph.

    node_id is the stable key used as the NetworkX node identifier.
    It is deterministically derived from node_type + the primary identifier
    so that merging repeated observations of the same technique/entity is
    automatic (same node_id → same NX node, attributes merged).
    """

    model_config = ConfigDict(protected_namespaces=())

    node_id: str = Field(..., description="Stable unique key (type::value)")
    node_type: NodeType
    label: str = Field(..., description="Human-readable display label")
    attributes: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    observation_count: int = Field(default=1, ge=1)

    @staticmethod
    def make_id(node_type: NodeType, value: str) -> str:
        """Derive deterministic node_id: '<type>::<value>'."""
        return f"{node_type.value}::{value}"

    def merge(self, other: "GraphNode") -> "GraphNode":
        """Merge another observation of the same node (idempotent union)."""
        merged_attrs = {**self.attributes, **other.attributes}
        return self.model_copy(update={
            "attributes": merged_attrs,
            "last_seen": max(self.last_seen, other.last_seen),
            "first_seen": min(self.first_seen, other.first_seen),
            "observation_count": self.observation_count + 1,
        })


# ---------------------------------------------------------------------------
# GraphEdge — directed edge in the attack graph
# ---------------------------------------------------------------------------

class GraphEdge(CyberShieldBaseModel):
    """A typed directed edge between two GraphNodes."""

    model_config = ConfigDict(protected_namespaces=())

    source_id: str
    target_id: str
    edge_type: EdgeType
    attributes: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    observation_count: int = Field(default=1, ge=1)

    @property
    def edge_key(self) -> tuple[str, str, str]:
        """Stable key for deduplication: (source_id, target_id, edge_type)."""
        et = self.edge_type
        et_val = et.value if hasattr(et, 'value') else str(et)
        return (self.source_id, self.target_id, et_val)


# ---------------------------------------------------------------------------
# GraphStatistics — aggregate metrics for an AttackGraph
# ---------------------------------------------------------------------------

class GraphStatistics(CyberShieldBaseModel):
    model_config = ConfigDict(protected_namespaces=())

    node_count: int = Field(default=0, ge=0)
    edge_count: int = Field(default=0, ge=0)
    technique_count: int = Field(default=0, ge=0)
    tactic_count: int = Field(default=0, ge=0)
    alert_count: int = Field(default=0, ge=0)
    entity_count: int = Field(default=0, ge=0)
    host_count: int = Field(default=0, ge=0)
    user_count: int = Field(default=0, ge=0)
    tactic_distribution: dict[str, int] = Field(default_factory=dict)
    technique_distribution: dict[str, int] = Field(default_factory=dict)
    is_dag: bool = Field(default=True, description="True if graph is acyclic")


# ---------------------------------------------------------------------------
# GraphSnapshot — serialisable snapshot of the full graph
# ---------------------------------------------------------------------------

class GraphSnapshot(CyberShieldBaseModel):
    """
    A versioned, serialisable snapshot of an AttackGraph.
    Serialises nodes and edges (NetworkX graph is reconstructed on load).
    """

    model_config = ConfigDict(protected_namespaces=())

    snapshot_id: str = Field(default_factory=lambda: f"snap-{generate_id()}")
    graph_id: str = Field(...)
    schema_version: str = Field(default=GRAPH_SCHEMA_VERSION)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    statistics: GraphStatistics = Field(default_factory=GraphStatistics)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# AttackGraph — the core domain object (metadata + snapshot reference)
# ---------------------------------------------------------------------------

class AttackGraph(CyberShieldBaseModel):
    """
    Domain representation of a complete attack graph for one session/batch.

    The underlying NetworkX DiGraph is NOT stored here — it lives in
    AttackGraphBuilder which returns an AttackGraph after build().
    Serialisation uses GraphSnapshot.
    """

    model_config = ConfigDict(protected_namespaces=())

    graph_id: str = Field(default_factory=lambda: f"ag-{generate_id()}")
    schema_version: str = Field(default=GRAPH_SCHEMA_VERSION)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_model_id: str = Field(default="", description="Detection model that produced input alerts")
    mapped_attack_ids: list[str] = Field(default_factory=list, description="MappedAttack.mapping_ids ingested")
    statistics: GraphStatistics = Field(default_factory=GraphStatistics)

    def to_summary(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "nodes": self.statistics.node_count,
            "edges": self.statistics.edge_count,
            "techniques": self.statistics.technique_count,
            "alerts": self.statistics.alert_count,
            "entities": self.statistics.entity_count,
            "is_dag": self.statistics.is_dag,
            "updated_at": self.updated_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# GraphTraversalResult
# ---------------------------------------------------------------------------

class GraphTraversalResult(CyberShieldBaseModel):
    """Result of a graph traversal query."""

    model_config = ConfigDict(protected_namespaces=())

    query_type: str = Field(..., description="e.g. 'neighbors', 'ancestors', 'paths'")
    root_node_id: str
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    depth: int = Field(default=0)
    metadata: dict[str, Any] = Field(default_factory=dict)
