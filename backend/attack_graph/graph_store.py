"""
backend.attack_graph.graph_store — Attack Graph Persistence
============================================================
Module 3.4 — Attack Graph Engine

Persists GraphSnapshot (JSON) and AttackGraph metadata (JSON).
Follows the same atomic-write philosophy as ExplanationStore and MappingStore.

File layout
-----------
graphs/
├── graph_<graph_id>.json       ← GraphSnapshot (full, with nodes/edges)
└── meta/
    └── meta_<graph_id>.json    ← AttackGraph metadata (lightweight)
"""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import structlog

from backend.attack_graph.exceptions import GraphSchemaError, GraphStorageError
from backend.attack_graph.models import (
    GRAPH_SCHEMA_VERSION,
    AttackGraph,
    GraphEdge,
    GraphNode,
    GraphSnapshot,
)

logger = structlog.get_logger(__name__)


class GraphStore:
    """
    Versioned persistence for attack graph artifacts.

    Parameters
    ----------
    store_dir : Root directory for graph files.
    """

    def __init__(self, store_dir: Path) -> None:
        self._dir: Path = store_dir / "graphs"
        self._meta_dir: Path = self._dir / "meta"
        self._dir.mkdir(parents=True, exist_ok=True)
        self._meta_dir.mkdir(parents=True, exist_ok=True)
        logger.debug("graph_store_initialized", store_dir=str(store_dir))

    # ── Write ─────────────────────────────────────────────────────────────────

    def save_snapshot(self, snapshot: GraphSnapshot) -> Path:
        """Atomically persist a GraphSnapshot (full nodes + edges). Returns path."""
        path = self._snapshot_path(snapshot.graph_id)
        self._atomic_write(path, snapshot.model_dump_json(indent=2))
        logger.info(
            "graph_snapshot_saved",
            graph_id=snapshot.graph_id,
            nodes=len(snapshot.nodes),
            edges=len(snapshot.edges),
        )
        return path

    def save_graph_meta(self, graph: AttackGraph) -> Path:
        """Atomically persist lightweight AttackGraph metadata."""
        path = self._meta_path(graph.graph_id)
        self._atomic_write(path, graph.model_dump_json(indent=2))
        return path

    # ── Read ──────────────────────────────────────────────────────────────────

    def load_snapshot(self, graph_id: str) -> GraphSnapshot:
        """Load a GraphSnapshot by graph_id."""
        path = self._snapshot_path(graph_id)
        if not path.exists():
            raise GraphStorageError(
                f"Snapshot for graph {graph_id!r} not found.",
                context={"graph_id": graph_id},
            )
        try:
            raw = path.read_text(encoding="utf-8")
            snap = GraphSnapshot.model_validate_json(raw)
        except Exception as exc:
            raise GraphStorageError(
                f"Failed to parse snapshot for {graph_id}: {exc}",
                context={"graph_id": graph_id, "cause": str(exc)},
            ) from exc

        if snap.schema_version != GRAPH_SCHEMA_VERSION:
            raise GraphSchemaError(
                f"Schema mismatch: stored={snap.schema_version!r} "
                f"current={GRAPH_SCHEMA_VERSION!r}",
                context={"graph_id": graph_id},
            )
        return snap

    def load_graph_meta(self, graph_id: str) -> AttackGraph:
        """Load lightweight AttackGraph metadata."""
        path = self._meta_path(graph_id)
        if not path.exists():
            raise GraphStorageError(
                f"Graph meta for {graph_id!r} not found.",
                context={"graph_id": graph_id},
            )
        try:
            return AttackGraph.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise GraphStorageError(
                f"Failed to parse graph meta {graph_id}: {exc}",
                context={"graph_id": graph_id, "cause": str(exc)},
            ) from exc

    def list_graph_ids(self) -> list[str]:
        """Return all stored graph IDs, newest first (by filename mtime)."""
        files = sorted(
            self._dir.glob("graph_*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return [f.stem.removeprefix("graph_") for f in files]

    # ── NetworkX serialisation helpers ────────────────────────────────────────

    @staticmethod
    def snapshot_to_nx(snapshot: GraphSnapshot) -> nx.DiGraph:
        """
        Reconstruct a NetworkX DiGraph from a GraphSnapshot.
        Useful for loading a persisted graph back into memory for traversal.
        """
        g = nx.DiGraph()
        for node in snapshot.nodes:
            nt = node.node_type
            nt_val = nt.value if hasattr(nt, 'value') else str(nt)
            g.add_node(
                node.node_id,
                node_type=nt_val,
                label=node.label,
                first_seen=node.first_seen.isoformat(),
                last_seen=node.last_seen.isoformat(),
                observation_count=node.observation_count,
                **node.attributes,
            )
        for edge in snapshot.edges:
            et = edge.edge_type
            et_val = et.value if hasattr(et, 'value') else str(et)
            g.add_edge(
                edge.source_id,
                edge.target_id,
                edge_type=et_val,
                **edge.attributes,
            )
        return g

    @staticmethod
    def snapshot_to_node_map(snapshot: GraphSnapshot) -> dict[str, GraphNode]:
        """Reconstruct node_id → GraphNode dict from a snapshot."""
        return {n.node_id: n for n in snapshot.nodes}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _snapshot_path(self, graph_id: str) -> Path:
        return self._dir / f"graph_{graph_id}.json"

    def _meta_path(self, graph_id: str) -> Path:
        return self._meta_dir / f"meta_{graph_id}.json"

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(path)
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            raise GraphStorageError(
                f"Atomic write failed for {path.name}: {exc}",
                context={"path": str(path), "cause": str(exc)},
            ) from exc
