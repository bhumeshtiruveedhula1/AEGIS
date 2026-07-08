# Attack Context Generation — Architecture

**Module:** 4.1  
**Phase:** Phase 4 — Context Assembly  
**Version:** 1.0.0  
**Produces:** `AttackContext` → consumed by Phase 5 LLM Reasoning Agent

---

## 1. Architecture Overview

```
Modules 1.x–3.x (Existing pipeline outputs)
         │
         │  DetectionAlert     ← required
         │  ExplanationResult  ← optional
         │  MappedAttack       ← optional
         │  AttackGraph        ← optional
         │  AttackChain        ← optional
         │  CanonicalEvent[]   ← optional
         │  FeatureRecord      ← optional
         ▼
┌─────────────────────────────────────────────────────────────┐
│                 AttackContextService                        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              AttackContextBuilder                     │  │
│  │  DetectionSummarizer  → DetectionSummary              │  │
│  │  ShapSummarizer       → ShapSummary                   │  │
│  │  MitreSummarizer      → MitreSummary                  │  │
│  │  GraphSummarizer      → GraphSummary                  │  │
│  │  ChainSummarizer      → ChainSummary                  │  │
│  │  EvidenceSummarizer   → SupportingEvidence            │  │
│  │  BehavioralSummarizer → BehavioralSummary             │  │
│  │  StatisticalSummarizer→ StatisticalSummary            │  │
│  │  TimelineBuilder      → list[TimelineEvent]           │  │
│  │  CompletenessSummarizer→ ContextCompleteness          │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                 ContextStore                          │  │
│  │  contexts_YYYY-MM-DD.jsonl  (append, date-part.)      │  │
│  │  index/<context_id>.json    (atomic full copy)        │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
   AttackContext  →  Phase 5 LLM Reasoning Agent
```

---

## 2. AttackContext Object

The single output of this module. Immutable. Fully typed.

```
AttackContext
├── context_id         "ctx-<uuid>"
├── schema_version     "1.0.0"
├── assembled_at       UTC datetime
│
├── identity           ContextIdentity
│   ├── alert_id
│   ├── chain_id
│   ├── graph_id
│   ├── entity_type
│   ├── entity_id
│   ├── host / user / source
│   └── event_id
│
├── detection          DetectionSummary
│   ├── model_id
│   ├── anomaly_score
│   ├── threshold_used / raw_if_score
│   ├── feature_dimension / novelty_count
│   ├── baseline_available
│   └── detection_timestamp
│
├── shap               ShapSummary
│   ├── explanation_id
│   ├── total_abs_shap / expected_value
│   ├── top_features: [FeatureSummaryItem]
│   ├── positive_contributors: [str]  ← direction='anomaly'
│   ├── negative_contributors: [str]  ← direction='normal'
│   └── feature_count
│
├── mitre              MitreSummary
│   ├── primary_technique: TechniqueSummary
│   ├── supporting_techniques: [TechniqueSummary]
│   ├── all_technique_ids / all_tactic_ids
│   ├── technique_count / tactic_count
│   └── mapping_confidence
│
├── graph              GraphSummary | None
│   ├── node_count / edge_count
│   ├── technique_count / tactic_count
│   ├── alert_count / entity_count
│   ├── is_dag
│   └── tactic_distribution / technique_distribution
│
├── chain              ChainSummary | None
│   ├── chain_id / chain_length / confidence
│   ├── tactic_sequence / technique_sequence
│   ├── is_multi_tactic / is_temporally_ordered
│   ├── matched_alert_ids / matched_features
│   ├── first_event_time / last_event_time
│   └── duration_seconds
│
├── timeline           list[TimelineEvent]  ← ordered by step_index
│   └── step_index, timestamp, technique_id, tactic_name,
│       action, host, user, source, result, confidence
│
├── evidence           SupportingEvidence
│   ├── affected_hosts / affected_users
│   ├── processes / command_lines
│   ├── src_ips / dst_ips / ports / protocols
│   ├── logon_types / auth_packages / file_paths
│   ├── modbus_registers / modbus_values / supervisory_hosts
│   └── has_ot_indicators / has_auth_indicators /
│       has_network_indicators / has_process_indicators
│
├── behavioral         BehavioralSummary | None
│   ├── entity_key / baseline_available
│   ├── novel_features / novelty_count
│   └── feature_dimension / raw_feature_snapshot
│
├── statistical        StatisticalSummary | None
│   ├── anomaly_score / feature_count
│   └── baseline_coverage / entity_observations
│
└── completeness       ContextCompleteness
    ├── completeness_pct (0.0–100.0)
    ├── has_detection / has_shap / has_mitre / ...
    └── missing: [MissingComponent]
```

---

## 3. Layer Responsibilities

| File | Responsibility | Pattern |
|---|---|---|
| `models.py` | Pure immutable Pydantic models | No logic |
| `exceptions.py` | Exception hierarchy | Inherits `CyberShieldError` |
| `timeline.py` | `TimelineBuilder` — ChainNode → TimelineEvent | Single responsibility |
| `summarizer.py` | 9 domain summarizer classes | Pure static methods |
| `builder.py` | `AttackContextBuilder` — calls summarizers | Assembly only |
| `storage.py` | `ContextStore` — JSONL + atomic index | Thread-safe |
| `service.py` | `AttackContextService` — public API | Orchestration only |
| `__init__.py` | Full public `__all__` export | |

---

## 4. Summarizer Responsibilities

Each summarizer is a **separate class** with **static methods only**. No shared state.

```
DetectionSummarizer   reads DetectionAlert
ShapSummarizer        reads ExplanationResult
MitreSummarizer       reads MappedAttack
GraphSummarizer       reads AttackGraph
ChainSummarizer       reads AttackChain
EvidenceSummarizer    reads list[CanonicalEvent]
BehavioralSummarizer  reads DetectionAlert + FeatureRecord
StatisticalSummarizer reads DetectionAlert
CompletenessSummarizer computes presence flags
```

**None of these summarizers modify, re-run, or re-compute upstream module logic.**

---

## 5. Storage Strategy

Identical to existing modules (BaselineStore, MetricStore, GraphStore, ChainStore).

```
context/
├── contexts_2024-06-10.jsonl    ← append-only, date-partitioned
└── index/
    └── ctx-<uuid>.json          ← atomic tmp → rename full copy
```

- **JSONL**: one `AttackContext` per line — fast streaming reads by date
- **Index**: random access by `context_id` — fast single-context loads
- **Thread-safe**: per-file locks for JSONL, atomic replace for index
- **Schema versioning**: `schema_version = "1.0.0"` — mismatch raises `ContextSchemaError`

---

## 6. Completeness Scoring

`ContextCompleteness` scores exactly 9 binary presence components:

| Component | Source | Weight |
|---|---|---|
| detection | DetectionAlert (always) | 1/9 |
| shap | ExplanationResult | 1/9 |
| mitre | MappedAttack | 1/9 |
| graph | AttackGraph | 1/9 |
| chain | AttackChain | 1/9 |
| timeline | chain.nodes | 1/9 |
| evidence | CanonicalEvent[] | 1/9 |
| behavioral | DetectionAlert (always) | 1/9 |
| statistical | DetectionAlert (always) | 1/9 |

`completeness_pct = (present_count / 9) × 100`

Minimum guaranteed completeness (alert only): **3/9 = 33.3%**  
Full completeness (all inputs): **9/9 = 100%**

---

## 7. Service API

```python
from backend.context.service import AttackContextService

svc = AttackContextService()

# Single — minimal (alert only)
ctx = svc.build_context(alert=alert)

# Single — full enrichment
ctx = svc.build_context(
    alert=alert,
    explanation=explanation,
    mapped=mapped_attack,
    graph=graph,
    chain=chain,
    events=canonical_events,
    feature_record=feature_record,
)

# Batch
contexts = svc.build_batch([{"alert": a1}, {"alert": a2}])

# Stream
for ctx in svc.build_contexts_stream(alert_iter, resolver_fn):
    ...

# Query
ctx = svc.load_context(context_id)
contexts = svc.load_for_date()
ids = svc.list_context_ids()

# Filters (static helpers)
high  = svc.filter_high_confidence(contexts, threshold=0.7)
multi = svc.filter_multi_tactic(contexts)
ot    = svc.filter_ot_contexts(contexts)
full  = svc.filter_complete(contexts, min_pct=80.0)
```

---

## 8. Engineering Constraints

- **No LLM** — zero language model calls
- **No inference** — no predicted values, no heuristics
- **No re-computation** — all values read from existing module outputs
- **No upstream modification** — zero changes to Modules 1.x–3.x
- **Deterministic** — same inputs → same `AttackContext` structure
- **Thread-safe** — per-file locks on JSONL, atomic writes on index
- **Cold-start safe** — no global state, no singleton dependencies

---

## 9. Integration Guide — Phase 5 LLM Reasoning Agent

The LLM Reasoning Agent (Phase 5) receives one `AttackContext` object as its sole input.

```python
from backend.context.models import AttackContext

def llm_reason(ctx: AttackContext) -> str:
    # Everything the LLM needs is in ctx:

    # Who / what
    entity = ctx.identity.entity_id
    host = ctx.identity.host

    # How anomalous
    score = ctx.detection.anomaly_score

    # Why anomalous (SHAP)
    top_features = ctx.shap.top_features

    # Kill chain
    techniques = ctx.chain.technique_sequence if ctx.chain else []
    tactics = ctx.chain.tactic_sequence if ctx.chain else []

    # Timeline of events
    for step in ctx.timeline:
        t = step.timestamp
        tech = step.technique_id

    # Evidence
    hosts = ctx.evidence.affected_hosts
    is_ot = ctx.evidence.has_ot_indicators

    # Quality gate
    if ctx.completeness.completeness_pct < 50.0:
        # Warn the LLM about incomplete context
        ...
```

**The LLM agent MUST NOT call any upstream module** — all data is in `AttackContext`.

---

## 10. Extension Guide

To add a new summary component:

1. Add a new model class to `models.py` (inherit `CyberShieldBaseModel`)
2. Add a new field to `AttackContext`
3. Add a new summarizer class to `summarizer.py`
4. Call the summarizer in `AttackContextBuilder.build()`
5. Add the presence flag to `CompletenessSummarizer.build()`
6. Export from `__init__.py`
7. Add tests to `tests/unit/context/`

No other files need changing.
