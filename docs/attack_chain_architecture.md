# Attack Chain Detection — Architecture

**Module:** 3.5  
**Version:** 1.0.0  
**Depends on:** Module 3.4 — Attack Graph Engine

---

## 1. Architecture Overview

```
GraphSnapshot (Module 3.4)
        │
        ▼
┌──────────────────────────────────────────────────────┐
│              AttackChainService                      │
│  ┌────────────────────────────────────────────────┐  │
│  │          AttackChainDetector                   │  │
│  │  Phase 1: Group TECHNIQUE nodes by entity      │  │
│  │  Phase 2: Build entity-scoped subgraph         │  │
│  │     └─ PRECEDES/RELATED edges (same-alert)     │  │
│  │     └─ Synthesised temporal edges (cross-alert)│  │
│  │  Phase 3: DFS root-to-leaf path enumeration    │  │
│  │  Phase 4: Deduplication by (entity, techniques)│  │
│  └────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────┐  │
│  │          ChainEvaluator (inline)               │  │
│  │  4-component deterministic confidence score    │  │
│  └────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────┐  │
│  │               ChainStore                       │  │
│  │  chains_YYYY-MM-DD.jsonl  (append, date-part.) │  │
│  │  reports/report_<id>.json (atomic)             │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
        │
        ▼
ChainReport + AttackChain[] → Module 3.6 (Attack Context)
```

---

## 2. Chain Model

### AttackChain

The primary output. An ordered sequence of ATT&CK technique observations for a specific entity.

| Field | Type | Description |
|---|---|---|
| `chain_id` | str | `chain-<uuid>` |
| `graph_id` | str | Source `AttackGraph.graph_id` |
| `entity_id` | str | e.g. `alice::ws01` |
| `entity_type` | str | e.g. `user_host` |
| `nodes` | `list[ChainNode]` | Steps sorted by `step_index` |
| `links` | `list[ChainLink]` | Directed connections |
| `evidence` | `ChainEvidence` | Supporting evidence |
| `evaluation` | `ChainEvaluation` | Deterministic quality score |

### ChainNode

One technique step in the chain. Maps 1:1 to a TECHNIQUE `GraphNode`.

| Field | Type | Description |
|---|---|---|
| `chain_node_id` | str | Mirrors `GraphNode.node_id` |
| `technique_id` | str | ATT&CK technique ID |
| `tactic_id` / `tactic_name` | str | Parent tactic |
| `confidence` | float | Technique-level confidence [0,1] |
| `observation_count` | int | Times observed in graph |
| `step_index` | int | Zero-based position in chain |

### ChainLink

Directed relationship between consecutive chain steps.

```
ChainLink(source_node_id, target_node_id, link_type, temporal_gap_seconds)
```

`link_type` is one of: `precedes`, `related_to`

---

## 3. Detection Strategy

### Phase 1 — Entity Grouping

All `TECHNIQUE` nodes from the `GraphSnapshot` are grouped by `entity_id`.  
`entity_id` is parsed from `node.attributes["entity_id"]` when available, otherwise extracted from the node_id pattern:

```
technique::<T-ID>::<entity_type>::<entity_id_parts...>
```

### Phase 2 — Entity-Scoped Subgraph

For each entity, build a directed subgraph over its technique nodes.

**Priority:**
1. Use existing `PRECEDES` / `RELATED_TO` edges (from same-alert multi-technique observations in the Attack Graph)
2. If no structural edges exist (one technique per alert is common), synthesise temporal `PRECEDES` edges by sorting technique nodes by `first_seen`

This enables **cross-alert chain detection** — the most common real-world scenario.

### Phase 3 — Path Enumeration

For each (root, leaf) pair in the entity subgraph:

```
nx.all_simple_paths(subgraph, root, leaf, cutoff=MAX_CHAIN_LENGTH)
```

- Root = node with `in_degree == 0`  
- Leaf = node with `out_degree == 0`  
- Capped at `MAX_PATHS_PER_ROOT = 50` to prevent combinatorial explosion
- If no root-to-leaf paths found, fall back to full temporal ordering as one chain

### Phase 4 — Filtering & Deduplication

- `MIN_CHAIN_LENGTH = 2` — paths shorter than this are discarded
- `MIN_STEP_CONFIDENCE = 0.05` — steps below this get floored (not discarded)
- Deduplication key: `(entity_id, tuple(technique_ids))` — higher-confidence duplicate wins

---

## 4. Evaluation Strategy

`ChainEvaluator` computes a deterministic confidence score. No ML, no LLMs.

### Confidence Formula

```
confidence = (0.40 × avg_step_confidence)
           + (0.25 × tactic_coverage_ratio)
           + (0.20 × temporal_consistency_score)
           + (0.15 × observation_strength)
```

Clipped to [0, 1], rounded to 4 decimal places.

| Component | Description |
|---|---|
| `avg_step_confidence` | Mean confidence across chain steps |
| `tactic_coverage_ratio` | Distinct tactics / 14 (full ATT&CK kill-chain) |
| `temporal_consistency_score` | Fraction of consecutive pairs that are temporally ordered |
| `observation_strength` | Total observations / 20 (normalisation cap) |

### Derived Fields

| Field | Derivation |
|---|---|
| `is_multi_tactic` | distinct `tactic_id` count > 1 |
| `is_temporally_ordered` | `temporal_consistency_score == 1.0` |
| `chain_length` | `len(nodes)` |
| `tactic_count` | distinct tactics |

---

## 5. Storage

Same atomic-write philosophy as earlier modules.

```
chain_detection/
├── chains_<YYYY-MM-DD>.jsonl     ← one AttackChain per line, append-only
└── reports/
    └── report_<report_id>.json   ← ChainReport (atomic tmp → rename)
```

- **Thread-safe**: per-file locks for JSONL append
- **Date-partitioned**: one JSONL file per day — `chains_2024-06-10.jsonl`
- **Schema versioning**: `schema_version = "1.0.0"` — mismatches raise `ChainSchemaError`
- **Batch save**: groups chains by date partition for efficient writes

---

## 6. Service API

```python
from backend.chain_detection.service import AttackChainService
from backend.attack_graph.models import GraphSnapshot

svc = AttackChainService(persist=True)

# Primary input: GraphSnapshot from AttackGraphService.build_graph()
report: ChainReport = svc.detect_from_snapshot(snapshot)

# Stream processing
for report in svc.detect_from_snapshots_stream(snapshot_iter):
    ...

# Graph ID shorthand (loads from disk via AttackGraphService)
report = svc.detect_from_graph_id(graph_id, graph_service)

# Query helpers
high_conf = svc.get_high_confidence_chains(report, threshold=0.5)
multi     = svc.get_multi_tactic_chains(report)
by_entity = svc.get_chains_by_entity(report, "alice::ws01")

# Persistence
chains = svc.load_chains_for_date()
report = svc.load_report(report_id)
ids    = svc.list_reports()
```

---

## 7. Integration Points

### Upstream (consumed by this module)

| Source | Object | Fields used |
|---|---|---|
| Module 3.4 (Attack Graph) | `GraphSnapshot` | `graph_id`, `nodes`, `edges` |
| Module 3.4 (Attack Graph) | `GraphNode` | `node_id`, `node_type`, `attributes`, `first_seen`, `last_seen`, `observation_count` |
| Module 3.4 (Attack Graph) | `GraphStore` | `snapshot_to_nx()`, `snapshot_to_node_map()` |

### Downstream (produced for Module 3.6)

```python
from backend.chain_detection.service import AttackChainService
from backend.chain_detection.models import AttackChain, ChainReport

svc = AttackChainService()
report = svc.detect_from_snapshot(snapshot)

# Module 3.6 consumes:
report.chains          # list[AttackChain]
report.statistics      # ChainStatistics
chain.evaluation       # ChainEvaluation
chain.nodes            # list[ChainNode]
chain.evidence         # ChainEvidence
chain.tactic_sequence  # list[str]
chain.technique_ids    # list[str]
```

Module 3.6 must NOT modify `backend/chain_detection/` — it consumes only the public API.

---

## 8. Engineering Constraints

- **No LLMs, no ML** — fully deterministic
- **No narrative generation** — that's Module 3.6
- **No response orchestration** — that's Module 3.7+
- **No graph modification** — detector is read-only
- **No cross-module imports** — only imports from `backend.attack_graph` and `backend.core`
- **Deterministic**: same `GraphSnapshot` → same `ChainReport`

---

## 9. Tuning Constants

| Constant | Default | Description |
|---|---|---|
| `MIN_CHAIN_LENGTH` | 2 | Minimum technique steps |
| `MAX_CHAIN_LENGTH` | 15 | DFS depth cap |
| `MIN_STEP_CONFIDENCE` | 0.05 | Floor for step confidence |
| `MAX_PATHS_PER_ROOT` | 50 | Path cap per root node |
| `_FULL_KILL_CHAIN_SIZE` | 14 | ATT&CK Enterprise tactic count |
| `_MAX_OBSERVATIONS` | 20 | Observation normalisation cap |
