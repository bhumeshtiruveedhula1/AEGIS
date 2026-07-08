"""
backend.attack_graph.traversal — Graph Traversal Utilities
===========================================================
Module 3.4 — Attack Graph Engine

Provides all read-only traversal operations over the NetworkX DiGraph.

Design principles
-----------------
- Stateless functions that take nx.DiGraph + typed inputs
- Never mutate the graph
- Return typed GraphNode / GraphEdge / GraphTraversalResult objects
- No attack-chain reasoning — purely structural traversal
- O(1) node lookup, O(k) neighbor lookup where k = degree
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import networkx as nx

from backend.attack_graph.exceptions import NodeNotFoundError
from backend.attack_graph.models import (
    EdgeType,
    GraphEdge,
    GraphNode,
    GraphStatistics,
    GraphTraversalResult,
    NodeType,
)


def _require_node(
    graph: nx.DiGraph,
    nodes: dict[str, GraphNode],
    node_id: str,
) -> GraphNode:
    if node_id not in nodes:
        raise NodeNotFoundError(
            f"Node {node_id!r} not found in graph.",
            context={"node_id": node_id},
        )
    return nodes[node_id]


# ---------------------------------------------------------------------------
# Node lookups
# ---------------------------------------------------------------------------

def get_node(
    graph: nx.DiGraph,
    nodes: dict[str, GraphNode],
    node_id: str,
) -> GraphNode:
    """Return a single node by ID. Raises NodeNotFoundError if absent."""
    return _require_node(graph, nodes, node_id)


def get_nodes_by_type(
    nodes: dict[str, GraphNode],
    node_type: NodeType,
) -> list[GraphNode]:
    """Return all nodes of a given type."""
    return [n for n in nodes.values() if n.node_type == node_type]


def find_nodes_by_attribute(
    nodes: dict[str, GraphNode],
    attr_key: str,
    attr_value: Any,
) -> list[GraphNode]:
    """Return nodes where node.attributes[attr_key] == attr_value."""
    return [
        n for n in nodes.values()
        if n.attributes.get(attr_key) == attr_value
    ]


# ---------------------------------------------------------------------------
# Neighbourhood
# ---------------------------------------------------------------------------

def get_neighbors(
    graph: nx.DiGraph,
    nodes: dict[str, GraphNode],
    node_id: str,
    edge_type: EdgeType | None = None,
) -> GraphTraversalResult:
    """
    Return direct successors (outgoing neighbours) of a node.
    Optionally filter by edge_type.
    """
    _require_node(graph, nodes, node_id)
    result_nodes: list[GraphNode] = []
    result_edges: list[GraphEdge] = []

    for _, dst, data in graph.out_edges(node_id, data=True):
        et = data.get("edge_type", "")
        if edge_type and et != edge_type.value:
            continue
        if dst in nodes:
            result_nodes.append(nodes[dst])
            result_edges.append(GraphEdge(
                source_id=node_id, target_id=dst,
                edge_type=EdgeType(et) if et else EdgeType.RELATED_TO,
                attributes={k: v for k, v in data.items() if k != "edge_type"},
            ))

    return GraphTraversalResult(
        query_type="neighbors",
        root_node_id=node_id,
        nodes=result_nodes,
        edges=result_edges,
        depth=1,
    )


def get_predecessors(
    graph: nx.DiGraph,
    nodes: dict[str, GraphNode],
    node_id: str,
    edge_type: EdgeType | None = None,
) -> GraphTraversalResult:
    """Return direct predecessors (incoming neighbours) of a node."""
    _require_node(graph, nodes, node_id)
    result_nodes: list[GraphNode] = []
    result_edges: list[GraphEdge] = []

    for src, _, data in graph.in_edges(node_id, data=True):
        et = data.get("edge_type", "")
        if edge_type and et != edge_type.value:
            continue
        if src in nodes:
            result_nodes.append(nodes[src])
            result_edges.append(GraphEdge(
                source_id=src, target_id=node_id,
                edge_type=EdgeType(et) if et else EdgeType.RELATED_TO,
                attributes={k: v for k, v in data.items() if k != "edge_type"},
            ))

    return GraphTraversalResult(
        query_type="predecessors",
        root_node_id=node_id,
        nodes=result_nodes,
        edges=result_edges,
        depth=1,
    )


# ---------------------------------------------------------------------------
# Descendants / Ancestors (BFS, bounded depth)
# ---------------------------------------------------------------------------

def get_descendants(
    graph: nx.DiGraph,
    nodes: dict[str, GraphNode],
    node_id: str,
    max_depth: int = 10,
) -> GraphTraversalResult:
    """Return all descendants of a node up to max_depth (BFS)."""
    _require_node(graph, nodes, node_id)
    try:
        desc_ids = nx.descendants(graph, node_id)
    except nx.NetworkXError:
        desc_ids = set()

    result_nodes = [nodes[nid] for nid in desc_ids if nid in nodes]
    return GraphTraversalResult(
        query_type="descendants",
        root_node_id=node_id,
        nodes=result_nodes,
        edges=[],
        depth=max_depth,
        metadata={"count": len(result_nodes)},
    )


def get_ancestors(
    graph: nx.DiGraph,
    nodes: dict[str, GraphNode],
    node_id: str,
    max_depth: int = 10,
) -> GraphTraversalResult:
    """Return all ancestors of a node up to max_depth (BFS)."""
    _require_node(graph, nodes, node_id)
    try:
        anc_ids = nx.ancestors(graph, node_id)
    except nx.NetworkXError:
        anc_ids = set()

    result_nodes = [nodes[nid] for nid in anc_ids if nid in nodes]
    return GraphTraversalResult(
        query_type="ancestors",
        root_node_id=node_id,
        nodes=result_nodes,
        edges=[],
        depth=max_depth,
        metadata={"count": len(result_nodes)},
    )


# ---------------------------------------------------------------------------
# Path queries
# ---------------------------------------------------------------------------

def find_paths(
    graph: nx.DiGraph,
    nodes: dict[str, GraphNode],
    source_id: str,
    target_id: str,
    cutoff: int = 8,
) -> GraphTraversalResult:
    """
    Find all simple paths from source to target with length ≤ cutoff.
    Returns a GraphTraversalResult with all intermediate nodes.
    """
    _require_node(graph, nodes, source_id)
    _require_node(graph, nodes, target_id)

    try:
        all_paths = list(nx.all_simple_paths(graph, source_id, target_id, cutoff=cutoff))
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        all_paths = []

    path_nodes: set[str] = set()
    for path in all_paths:
        path_nodes.update(path)

    result_nodes = [nodes[nid] for nid in path_nodes if nid in nodes]
    return GraphTraversalResult(
        query_type="paths",
        root_node_id=source_id,
        nodes=result_nodes,
        edges=[],
        depth=cutoff,
        metadata={
            "target_id": target_id,
            "path_count": len(all_paths),
            "paths": all_paths,
        },
    )


# ---------------------------------------------------------------------------
# Temporal ordering
# ---------------------------------------------------------------------------

def get_nodes_in_temporal_order(
    nodes: dict[str, GraphNode],
    node_type: NodeType | None = None,
) -> list[GraphNode]:
    """
    Return nodes sorted by first_seen ascending (oldest first).
    Optionally filter by node_type.
    """
    candidates = (
        get_nodes_by_type(nodes, node_type)
        if node_type
        else list(nodes.values())
    )
    return sorted(candidates, key=lambda n: n.first_seen)


def get_nodes_in_window(
    nodes: dict[str, GraphNode],
    start: datetime,
    end: datetime,
    node_type: NodeType | None = None,
) -> list[GraphNode]:
    """Return nodes whose first_seen falls within [start, end]."""
    candidates = (
        get_nodes_by_type(nodes, node_type)
        if node_type
        else list(nodes.values())
    )
    return [
        n for n in candidates
        if start <= n.first_seen <= end
    ]


# ---------------------------------------------------------------------------
# Connected components
# ---------------------------------------------------------------------------

def get_weakly_connected_components(
    graph: nx.DiGraph,
    nodes: dict[str, GraphNode],
) -> list[list[GraphNode]]:
    """Return weakly connected components as lists of GraphNode."""
    components = []
    for comp_ids in nx.weakly_connected_components(graph):
        components.append([nodes[nid] for nid in comp_ids if nid in nodes])
    return sorted(components, key=len, reverse=True)


def is_connected(graph: nx.DiGraph) -> bool:
    """True if the graph has exactly one weakly connected component."""
    return nx.is_weakly_connected(graph) if graph.number_of_nodes() > 0 else True


# ---------------------------------------------------------------------------
# Technique / Entity specific helpers
# ---------------------------------------------------------------------------

def techniques_for_entity(
    nodes: dict[str, GraphNode],
    entity_node_id: str,
) -> list[GraphNode]:
    """
    Return TECHNIQUE nodes associated with a given ENTITY node_id.
    Uses the entity_id embedded in the technique node_id convention:
    node_id = 'technique::<technique_id>::<entity_type>::<entity_id>'
    """
    entity_suffix = entity_node_id.removeprefix("entity::")
    return [
        n for n in nodes.values()
        if n.node_type == NodeType.TECHNIQUE
        and entity_suffix in n.node_id
    ]


def alerts_for_entity(
    graph: nx.DiGraph,
    nodes: dict[str, GraphNode],
    entity_node_id: str,
) -> list[GraphNode]:
    """Return ALERT nodes that have a generated_from edge to this entity."""
    result = []
    for src, dst, data in graph.in_edges(entity_node_id, data=True):
        if (data.get("edge_type") == EdgeType.GENERATED_FROM.value
                and src in nodes
                and nodes[src].node_type == NodeType.ALERT):
            result.append(nodes[src])
    return result


def techniques_by_tactic(
    nodes: dict[str, GraphNode],
    tactic_id: str,
) -> list[GraphNode]:
    """Return TECHNIQUE nodes belonging to a specific tactic."""
    return [
        n for n in nodes.values()
        if n.node_type == NodeType.TECHNIQUE
        and n.attributes.get("tactic_id") == tactic_id
    ]
