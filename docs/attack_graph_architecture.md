# Attack Graph — Architecture

**Module:** 3.4  
**Version:** 1.0.0  
**NetworkX Version:** 3.3  
**Branch:** `phase-3-behavioral-detection`

---

## 1. Architecture Overview

```
MappedAttack (Module 3.3)
        │
        ▼
┌───────────────────────────────────────────────────────┐
│               AttackGraphService                      │
│  ┌─────────────────────────────────────────────────┐  │
│  │          AttackGraphBuilder                     │  │
│  │  nx.DiGraph — directed, attributed              │  │
│  │  Merge semantics: same node_id → merged attrs   │  │
│  │  Deterministic, ordered, no randomness          │  │
│  └─────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────┐  │
│  │          traversal.py (stateless)               │  │
│  │  get_node / get_neighbors / get_ancestors       │  │
│  │  find_paths / temporal ordering / components    │  │
│  └─────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────┐  │
│  │               GraphStore                        │  │
│  │  graphs/graph_<id>.json  (atomic, full)         │  │
│  │  graphs/meta/meta_<id>.json  (lightweight)      │  │
│  └─────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────┘
        │
        ▼
AttackGraph + GraphSnapshot (output → Module 3.5)
```

---

## 2. Node Types

| NodeType    | node_id Pattern                              | Description |
|-------------|----------------------------------------------|-------------|
| `TECHNIQUE` | `technique::<T-ID>::<entity_type>::<entity_id>` | ATT&CK technique observed for a specific entity |
| `TACTIC`    | `tactic::<TA-ID>`                            | ATT&CK tactic (parent of techniques) |
| `ALERT`     | `alert::<mapping_id>`                        | Source MappedAttack |
| `ENTITY`    | `entity::<entity_type>::<entity_id>`         | User-host composite |
| `HOST`      | `host::<hostname>`                           | Specific host |
| `USER`      | `user::<username>`                           | Specific user account |

### Merge Semantics

Nodes with the same `node_id` are merged — their attributes are unioned, `last_seen` is updated, `observation_count` incremented. This ensures repeated observations of the same technique on the same entity collapse to a single node.

---

## 3. Edge Types

| EdgeType         | Source → Target           | Meaning |
|------------------|---------------------------|---------|
| `OBSERVED_ON`    | TECHNIQUE → ALERT         | This technique was observed in this alert |
| `GENERATED_FROM` | ALERT → ENTITY            | Alert was generated from this entity |
| `GENERATED_FROM` | ENTITY → USER             | Entity includes this user |
| `EXECUTED_BY`    | TECHNIQUE → ENTITY        | Technique was executed by this entity |
| `BELONGS_TO`     | TECHNIQUE → TACTIC        | Technique is a child of this tactic |
| `TARGETS`        | ENTITY → HOST             | Entity operates on this host |
| `PRECEDES`       | TECHNIQUE → TECHNIQUE     | Technique i came before technique j (confidence-rank order, same alert) |
| `RELATED_TO`     | TECHNIQUE → TECHNIQUE     | Same tactic, same alert — laterally related |

---

## 4. Data Flow

### `build_graph(mappings)`

```
for each MappedAttack:
  1. Upsert ALERT node          ← mapping_id
  2. Upsert ENTITY node         ← entity_type + entity_id
  3. Upsert USER node           ← left side of 'user::host' entity_id
  4. Upsert HOST node           ← right side of 'user::host' entity_id
  5. For each TechniqueMapping:
     a. Upsert TACTIC node
     b. Upsert TECHNIQUE node   ← scoped to entity_id (not global)
     c. Add OBSERVED_ON edge    (technique → alert)
     d. Add EXECUTED_BY edge    (technique → entity)
     e. Add BELONGS_TO edge     (technique → tactic)
  6. Add PRECEDES edges between techniques of different tactics
  7. Add RELATED_TO edges between techniques of the same tactic
→ call build() → returns (AttackGraph, GraphSnapshot)
```

### Why technique nodes are entity-scoped

Technique node_id = `technique::<T-ID>::<entity_type>::<entity_id>`

This ensures T1110 observed on `alice::ws01` and T1110 observed on `bob::ws02` are distinct nodes. If the same technique is observed on the same entity across multiple alerts, they merge into one node with increasing `observation_count`. This is the correct behaviour for attack graph analysis.

---

## 5. Graph Construction Properties

| Property | Value |
|---|---|
| Graph type | `nx.DiGraph` (directed) |
| Node attributes | node_type, label, first_seen, last_seen, observation_count, + domain-specific |
| Edge attributes | edge_type, confidence (on technique edges), + domain-specific |
| Determinism | Same list of MappedAttack → same graph |
| Thread safety | Builder is NOT thread-safe (one per session) |
| DAG check | `nx.is_directed_acyclic_graph()` — reported in statistics |
| Cycle risk | RELATED_TO between two co-occurring techniques in the same tactic creates a cycle |

---

## 6. Traversal API

All traversal functions are stateless utilities in `traversal.py`.
They take `(nx.DiGraph, dict[str, GraphNode])` — the live graph + node map.

| Function | Description |
|---|---|
| `get_node(g, nodes, node_id)` | Single node lookup — O(1) |
| `get_nodes_by_type(nodes, NodeType)` | All nodes of a type |
| `find_nodes_by_attribute(nodes, key, value)` | Attribute scan |
| `get_neighbors(g, nodes, node_id, edge_type?)` | Direct successors |
| `get_predecessors(g, nodes, node_id, edge_type?)` | Direct predecessors |
| `get_descendants(g, nodes, node_id, max_depth)` | BFS descendants |
| `get_ancestors(g, nodes, node_id, max_depth)` | BFS ancestors |
| `find_paths(g, nodes, source, target, cutoff)` | All simple paths |
| `get_nodes_in_temporal_order(nodes, type?)` | Sorted by first_seen |
| `get_nodes_in_window(nodes, start, end, type?)` | Temporal window filter |
| `get_weakly_connected_components(g, nodes)` | Component analysis |
| `techniques_for_entity(nodes, entity_id)` | Entity technique lookup |
| `alerts_for_entity(g, nodes, entity_id)` | Entity alert lookup |
| `techniques_by_tactic(nodes, tactic_id)` | Tactic scoped techniques |

All traversal functions return `GraphTraversalResult` or `list[GraphNode]`.
None mutate the graph.

---

## 7. Storage Strategy

Same atomic-write philosophy as ExplanationStore and MappingStore.

```
data/attack_graph/
└── graphs/
    ├── graph_<graph_id>.json     ← Full GraphSnapshot (nodes + edges)
    └── meta/
        └── meta_<graph_id>.json ← Lightweight AttackGraph metadata
```

- `save_snapshot` / `save_graph_meta`: write to `.tmp` then atomic `Path.replace()`
- `load_snapshot`: validates schema version before returning
- `snapshot_to_nx(snapshot)`: reconstructs `nx.DiGraph` from persisted nodes/edges
- `snapshot_to_node_map(snapshot)`: reconstructs `{node_id: GraphNode}` dict

### Schema versioning

`GraphSnapshot.schema_version` = `"1.0.0"`.  
`load_snapshot` raises `GraphSchemaError` if stored version ≠ current.

---

## 8. In-Memory Cache

`AttackGraphService` maintains a dict cache:

```python
_cache: dict[str, tuple[nx.DiGraph, dict[str, GraphNode], GraphSnapshot]]
```

- Built graphs are automatically cached after `build_graph()` / `build_graph_from_stream()`
- Loaded graphs are cached after `load_graph()`
- All traversal queries check cache first before loading from disk
- Cache is per-service-instance (not global)

---

## 9. Integration Points

### Upstream (consumed by this module)

| Source | Object | Fields used |
|---|---|---|
| Module 3.3 (MITRE) | `MappedAttack` | `mapping_id`, `alert_id`, `model_id`, `entity_type`, `entity_id`, `anomaly_score`, `techniques`, `mapped_at` |
| Module 3.3 (MITRE) | `TechniqueMapping` | `technique`, `confidence`, `matched_features`, `shap_total_contribution` |
| Module 3.3 (MITRE) | `AttackTechnique` | `technique_id`, `name`, `tactic` |
| Module 3.3 (MITRE) | `AttackTactic` | `tactic_id`, `name`, `short_name` |

### Downstream (produced for Module 3.5)

```python
from backend.attack_graph.service import AttackGraphService
from backend.mitre.models import MappedAttack

svc = AttackGraphService()

# Build
graph, snapshot = svc.build_graph(mapped_attacks)

# Query
techs = svc.query_nodes_by_type(graph.graph_id, NodeType.TECHNIQUE)
alerts = svc.query_nodes_by_type(graph.graph_id, NodeType.ALERT)
ordered = svc.query_temporal_order(graph.graph_id, NodeType.ALERT)

# Traversal
predecessors = svc.query_predecessors(graph.graph_id, alert_node_id)
ancestors = svc.query_ancestors(graph.graph_id, node_id)
comps = svc.query_connected_components(graph.graph_id)

# Entity analysis
entity_techniques = svc.query_techniques_for_entity(graph.graph_id, entity_node_id)
entity_alerts = svc.query_alerts_for_entity(graph.graph_id, entity_node_id)
tactic_techniques = svc.query_techniques_by_tactic(graph.graph_id, "TA0006")
```

---

## 10. Engineering Constraints

- **No attack chain reasoning** — this module only builds and traverses graphs
- **No prediction, scoring, or LLMs**
- **No correlation across sessions** — each `AttackGraphService.build_graph()` call creates an isolated graph
- **No architectural redesign** — only `backend/attack_graph/` and `tests/unit/attack_graph/` created
- **NetworkX 3.3** — fixed version, no upgrade without regression testing

---

## 11. Future Consumer: Module 3.5 (Attack Chain Detection)

Module 3.5 will:
1. Call `AttackGraphService.build_graph(mapped_attacks)` to get the graph
2. Use traversal APIs (`get_descendants`, `find_paths`, `get_nodes_in_temporal_order`) to identify kill-chain sequences
3. Detect multi-hop attack paths: Initial Access → Execution → Lateral Movement → Exfiltration
4. Produce `AttackChain` objects with supporting evidence from the graph nodes/edges

Module 3.5 must NOT modify `backend/attack_graph/` — it consumes only the public API.
