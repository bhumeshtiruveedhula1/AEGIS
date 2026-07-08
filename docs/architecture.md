# CyberShield — System Architecture

**Operation AEGIS · AI-Driven Cyber Resilience Platform for Critical National Infrastructure**

**Status:** Phases 1–4.1 Complete | **Tests:** 1541 passed / 0 failures
**Branch:** `phase-3-behavioral-detection`

---

## 1. System Pipeline Overview

```
┌────────────────────────────────────────────────────────────────┐
│              PHASE 1 — INPUT & NORMALISATION                   │
│                                                                │
│  DigitalTwin (Module 1.2)         SyntheticAttackService (3.X) │
│  IT containers, OT simulator  OR  10 built-in attack templates │
│           │                                │                   │
│           └──────────────┬─────────────────┘                   │
│                          │                                     │
│              backend.normalization (Module 1.3)                │
│              raw events → CanonicalEvent                       │
│              [event_id, timestamp(UTC), source, event_type,    │
│               host, user, action, result, raw_log, ...]        │
└──────────────────────────┬─────────────────────────────────────┘
                           │  CanonicalEvent[]
┌──────────────────────────▼─────────────────────────────────────┐
│              PHASE 2 — BEHAVIORAL INTELLIGENCE                  │
│                                                                │
│  backend.baseline (Module 2.1)                                 │
│  EntityBaseline — per-entity behavioral profile                │
│           │                                                     │
│  backend.features (Module 2.2)                                  │
│  CanonicalEvent + EntityBaseline → FeatureRecord               │
│  56-dimensional numerical feature vector per entity            │
│           │                                                     │
│  backend.metrics (Module 2.3)                                   │
│  Platform-wide observability metrics (MTTD, FPR, throughput)   │
│           │                                                     │
│  backend.detection (Module 2.4)                                 │
│  IsolationForest — anomaly_score ∈ [0,1]                       │
│  is_alert = True when anomaly_score > threshold (default 0.5)  │
│  Output: DetectionAlert                                        │
└──────────────────────────┬─────────────────────────────────────┘
                           │  DetectionAlert
┌──────────────────────────▼─────────────────────────────────────┐
│              PHASE 3 — THREAT INTELLIGENCE                      │
│                                                                │
│  backend.explainability (Module 3.2)                           │
│  SHAP TreeExplainer — per-feature attribution                  │
│  Output: ExplanationResult (feature_contributions ranked)      │
│           │                                                     │
│  backend.mitre (Module 3.3)                                     │
│  ATT&CK v15 Knowledge Base — 36 techniques, 16 tactics         │
│  top SHAP features → TechniqueMapping → MappedAttack           │
│           │                                                     │
│  backend.attack_graph (Module 3.4)                              │
│  NetworkX DiGraph — TECHNIQUE + ENTITY nodes                   │
│  PRECEDES / RELATED_TO edges across alerts                     │
│  Output: AttackGraph, GraphStatistics                          │
│           │                                                     │
│  backend.chain_detection (Module 3.5)                           │
│  DFS path-finding on entity-scoped subgraph                    │
│  Minimum chain length: 2 techniques                            │
│  Output: AttackChain (tactic_sequence, technique_sequence)     │
└──────────────────────────┬─────────────────────────────────────┘
                           │  AttackChain + all upstream outputs
┌──────────────────────────▼─────────────────────────────────────┐
│              PHASE 4 — CONTEXT ASSEMBLY                         │
│                                                                │
│  backend.context (Module 4.1)                                   │
│  Deterministic AttackContext assembly — NO inference, NO LLM   │
│  9-component completeness scoring (33.3% min → 100% full)      │
│  Output: AttackContext (sole input to Phase 5)                 │
└──────────────────────────┬─────────────────────────────────────┘
                           │  AttackContext
┌──────────────────────────▼─────────────────────────────────────┐
│              PHASE 5 — REASONING & RESPONSE [⏳ NOT BUILT]      │
│                                                                │
│  backend.llm       LLM Reasoning Agent                         │
│  backend.response  Response Orchestrator                       │
│  (Human Approval Gate)                                         │
│  backend.dashboard Metrics Dashboard API                       │
│  (Audit Ledger, SOAR Integration)                              │
└────────────────────────────────────────────────────────────────┘
```

---

## 2. Module Registry

| Phase | Module | Package | Key Output | Status |
|---|---|---|---|---|
| 1.2 | Digital Twin | `backend/digital_twin/` | Simulated events | ✅ |
| 1.3 | Normalization | `backend/normalization/` | `CanonicalEvent` | ✅ |
| 2.1 | Baseline Generator | `backend/baseline/` | `EntityBaseline` | ✅ |
| 2.2 | Feature Engine | `backend/features/` | `FeatureRecord` (56-dim) | ✅ |
| 2.3 | Metrics Engine | `backend/metrics/` | `MetricSnapshot` | ✅ |
| 2.4 | Isolation Forest | `backend/detection/` | `DetectionAlert` | ✅ 97 tests |
| 3.2 | SHAP Explainability | `backend/explainability/` | `ExplanationResult` | ✅ 73 tests |
| 3.3 | MITRE ATT&CK Mapper | `backend/mitre/` | `MappedAttack` | ✅ 88 tests |
| 3.4 | Attack Graph Builder | `backend/attack_graph/` | `AttackGraph` | ✅ |
| 3.5 | Attack Chain Detection | `backend/chain_detection/` | `AttackChain` | ✅ 106 tests |
| 3.X | Synthetic Attack Gen | `backend/synthetic_attack/` | `SyntheticExecution` | ✅ 68 tests |
| 4.1 | Attack Context | `backend/context/` | `AttackContext` | ✅ 82 tests |
| 5.1 | LLM Reasoning Agent | `backend/llm/` | — | ⏳ |
| 5.2 | Response Orchestrator | `backend/response/` | — | ⏳ |
| 5.3 | Dashboard | `backend/dashboard/` | — | ⏳ |

**Total tests: 1541 passed / 0 failures**

---

## 3. Core Data Contracts

### 3.1 CanonicalEvent — Module 1.3 (Foundation Schema)

Every event in the system is a `CanonicalEvent`. All modules consume it.

```python
# backend.normalization.models.CanonicalEvent
{
  "event_id":            "evt-uuid-v4",
  "timestamp":           "2024-06-10T14:30:00.000000+00:00",  # UTC-aware
  "source":              "windows",          # "windows"|"linux"|"ot"|"network"
  "event_type":          "authentication",   # "authentication"|"process"|"network"|"ot_modbus"|"file"
  "host":                "ws01",
  "user":                "alice",
  "resource":            "ws01",
  "action":              "logon_failure",
  "result":              "failure",
  "raw_log":             "EventID=4625 ...",
  "schema_version":      "1.0.0",
  # Optional IT fields:
  "src_ip":              "10.0.0.1",
  "dst_ip":              "10.0.0.2",
  "port":                445,
  "protocol":            "SMB",
  "process":             "lsass.exe",
  "command_line":        "...",
  "logon_type":          "network",
  "auth_package":        "NTLM",
  "windows_event_id":    4625,
  # Optional OT fields:
  "modbus_register":     40001,
  "modbus_value":        9999,
  "modbus_function_code": "6"               # string, not int
}
```

### 3.2 EntityKey — Module 2.4 (Identity Type)

```python
# backend.detection.models.EntityKey
# NOT a string — it is a Pydantic model
EntityKey(entity_type="user", entity_id="alice")
# Access: ek.entity_type, ek.entity_id
```

### 3.3 DetectionAlert — Module 2.4 (Detection Output)

```python
# backend.detection.models.DetectionAlert
{
  "alert_id":            "alert-uuid",
  "entity_key":          {"entity_type": "user", "entity_id": "alice"},
  "anomaly_score":       0.85,              # sigmoid-normalised ∈ [0.0, 1.0]
  "raw_if_score":        -0.12,             # raw IsolationForest score
  "threshold_used":      0.5,
  "is_alert":            true,              # anomaly_score > threshold_used
  "feature_dimension":   56,
  "novelty_count":       3,                 # features with no baseline value
  "baseline_available":  true,
  "schema_version":      "1.0.0"
}
```

### 3.4 ExplanationResult — Module 3.2 (SHAP Output)

```python
# backend.explainability.models.ExplanationResult
{
  "explanation_id":   "exp-uuid",
  "alert_id":         "alert-uuid",
  "total_abs_shap":   1.23,
  "expected_value":   0.12,
  "feature_contributions": [
    {
      "feature_name":       "failed_logins",
      "raw_value":          20.0,
      "shap_value":         0.45,
      "abs_shap_value":     0.45,
      "contribution_rank":  1,
      "contribution_pct":   80.0,
      "direction":          "anomaly"       # "anomaly" | "normal" — NOT "positive"/"negative"
    }
  ]
}
```

### 3.5 MappedAttack — Module 3.3 (MITRE Output)

```python
# backend.mitre.models.MappedAttack
{
  "mapping_id":        "map-uuid",
  "alert_id":          "alert-uuid",
  "primary_technique": {
    "technique_id":    "T1110",
    "technique_name":  "Brute Force",
    "tactic_id":       "TA0006",
    "tactic_name":     "Credential Access",
    "confidence":      0.87,
    "triggered_by":    ["failed_logon_rate", "failed_logon_count"]
  },
  "all_techniques":    [...],
  "mapping_confidence": 0.87,
  "knowledge_version": "ATT&CK v15 (2024-10-01)"
}
```

### 3.6 AttackChain — Module 3.5 (Kill-Chain Output)

```python
# backend.chain_detection.models.AttackChain
{
  "chain_id":           "chain-uuid",
  "entity_key":         {"entity_type": "user", "entity_id": "alice"},
  "chain_length":       3,
  "tactic_sequence":    ["Credential Access", "Lateral Movement", "Execution"],
  "technique_sequence": ["T1110", "T1021.002", "T1059.001"],
  "is_multi_tactic":    true,
  "is_temporally_ordered": true,
  "confidence":         0.78,
  "duration_seconds":   1800.0
}
```

### 3.7 AttackContext — Module 4.1 (LLM Input Package)

The sole input to the Phase 5 LLM Reasoning Agent.

```python
# backend.context.models.AttackContext
{
  "context_id":        "ctx-uuid",
  "schema_version":    "1.0.0",
  "assembled_at":      "UTC datetime",
  "identity":          { "alert_id", "chain_id", "entity_type", "entity_id", "host", "user" },
  "detection":         { "model_id", "anomaly_score", "threshold_used", "feature_dimension" },
  "shap":              { "total_abs_shap", "top_features", "positive_contributors", "negative_contributors" },
  "mitre":             { "primary_technique", "all_technique_ids", "all_tactic_ids", "confidence" },
  "graph":             { "node_count", "edge_count", "tactic_distribution" },    # optional
  "chain":             { "chain_length", "tactic_sequence", "technique_sequence", "duration_seconds" },  # optional
  "timeline":          [ { "step_index", "timestamp", "technique_id", "tactic_name" } ],
  "evidence":          { "affected_hosts", "affected_users", "src_ips", "modbus_registers",
                         "has_ot_indicators", "has_auth_indicators", "has_network_indicators" },
  "behavioral":        { "entity_key", "novel_features", "novelty_count" },
  "statistical":       { "anomaly_score", "feature_count" },
  "completeness":      { "completeness_pct": 33.3–100.0, "missing": [...] }
}
```

---

## 4. Storage Architecture

All modules use the **identical** flat-file storage pattern. No database required.

```
data/                              ← gitignored, auto-created
├── normalized/
│   └── events_YYYY-MM-DD.jsonl   ← CanonicalEvent, append-only
├── baseline/
│   └── <entity_key>.json         ← EntityBaseline per entity
├── features/
│   └── features_YYYY-MM-DD.jsonl ← FeatureRecord, append-only
├── metrics/
│   └── metrics_YYYY-MM-DD.jsonl  ← MetricSnapshot, append-only
├── detection/
│   ├── model_v<N>.pkl             ← Trained IsolationForest pipeline
│   └── model_v<N>.json           ← ModelMetadata
├── explanations/
│   ├── explanations_YYYY-MM-DD.jsonl
│   └── index/<explanation_id>.json
├── mitre/
│   ├── mappings_YYYY-MM-DD.jsonl
│   └── index/<mapping_id>.json
├── attack_graph/
│   ├── graphs_YYYY-MM-DD.jsonl
│   └── index/<graph_id>.json
├── chain_detection/
│   ├── chains_YYYY-MM-DD.jsonl
│   └── index/<chain_id>.json
├── synthetic/
│   ├── executions_YYYY-MM-DD.jsonl
│   └── index/<execution_id>.json
└── context/
    ├── contexts_YYYY-MM-DD.jsonl
    └── index/<context_id>.json
```

**Atomic write pattern** (all modules):
```python
tmp = final_path.with_suffix(".tmp")
tmp.write_text(json_content, encoding="utf-8")
tmp.replace(final_path)  # atomic on all platforms
```

---

## 5. Module Dependency Rules

```
backend.core          ← zero dependencies on backend.*
backend.shared        ← only imports from backend.core
backend.[module]      ← imports from backend.core + backend.shared only
                         NEVER imports from another backend.[module]
backend.context       ← reads (never writes) all upstream module outputs
backend.api           ← imports from any backend.*
```

**Cross-module data flow:** Data is passed between modules as function arguments or via the storage layer. Modules do not import from each other at the module level.

---

## 6. Exception Hierarchy

```
CyberShieldError (backend.core.exceptions)
├── ContextError       → ContextBuildError, ContextStorageError, ContextSchemaError, InsufficientInputError
├── DetectionError     → ModelNotTrainedError, SchemaCompatibilityError
├── ExplainabilityError → ExplainerNotInitializedError, ExplanationComputationError
├── MitreError         → TechniqueNotFoundError, MappingError
├── GraphError         → GraphBuildError, GraphStorageError
├── ChainError         → ChainBuildError, ChainStorageError
└── SyntheticAttackError → TemplateNotFoundError, GenerationError
```

---

## 7. Key Design Decisions

### 7.1 Unsupervised Training — Zero Labeled Attack Samples
Training uses ONLY normal baseline data. This enables zero-day attack detection without any labeled attack samples required.

### 7.2 Deterministic Context Assembly — No Inference in Phase 4
`AttackContext` (Module 4.1) performs no inference, no LLM calls, no heuristics. It is a pure assembly layer: same inputs always produce the same output. Only the Phase 5 LLM Reasoning Agent introduces non-determinism.

### 7.3 Single Responsibility Per Module
Each module has one and only one job. No module detects AND explains AND maps. This makes the system debuggable, testable, and replaceable.

### 7.4 Identical Storage Pattern Across All Modules
Every module uses the same JSONL + atomic index pattern. There are no module-specific database schemas, no ORM, no migrations. The `data/` directory can be deleted entirely to reset state.

### 7.5 Embedded ATT&CK Knowledge Base — No Internet Required
The MITRE ATT&CK v15 knowledge base is fully embedded in `backend/mitre/knowledge_base.py`. The mapper works offline with O(1) lookups. No API calls, no network dependencies.

### 7.6 Entity-Scoped Kill Chains — No Cross-Entity Contamination
Attack chains are always scoped to a single entity (user or host). Chains never mix activity from different entities. This prevents false chain correlation from unrelated coincident alerts.

### 7.7 Human Gate Mandatory (Phase 5 Design)
All autonomous response actions will require SOC analyst approval before execution. Auto-execution is never enabled.

---

## 8. Synthetic Attack Templates

Module 3.X provides 10 built-in templates for pipeline testing without live attack traffic:

| Template ID | Domain | Events | Kill Chain Stage(s) |
|---|---|---|---|
| `brute_force_auth` | IT | 21 | Credential Access |
| `credential_stuffing` | IT | 31 | Credential Access |
| `lateral_movement_smb` | IT | 9 | Lateral Movement |
| `privilege_escalation_token` | IT | 3 | Privilege Escalation |
| `persistence_scheduled_task` | IT | 2 | Persistence |
| `command_execution_powershell` | IT | 4 | Execution |
| `network_discovery_scan` | IT | 50 | Discovery |
| `data_exfiltration_http` | IT | 15 | Exfiltration |
| `ot_register_manipulation` | OT | 17 | ICS: Impair + Impact |
| `full_kill_chain_it` | IT | 26 | All: Credential→Lateral→Exec→Exfil |

---

## 9. Success Criteria (Current Scope)

| Metric | Target | Current |
|--------|--------|---------|
| Test suite pass rate | 100% | ✅ 1541/1541 |
| Normal event false positive rate | < 5% | Validated via synthetic baseline |
| Brute-force detection rate | > 90% | Validated via `brute_force_auth` template |
| MITRE technique coverage | 36 techniques, 16 tactics | ✅ ATT&CK v15 |
| Context completeness (full input) | 100% | ✅ 9/9 components |
| Context completeness (alert only) | 33.3% | ✅ 3/9 guaranteed |
| Feature extraction dimensionality | 56 features | ✅ Stable |
| Pipeline cold-start | No crash on empty data/ | ✅ Verified |
| JSON round-trip fidelity | 100% | ✅ All models tested |
| MTTD (Mean Time to Detection) | < 2 minutes | Validated in pipeline tests |
| False Positive Rate | < 5% | Measured via metrics engine |

---

## 10. What Is NOT Yet Implemented (Phase 5+)

| Component | Package | Description |
|-----------|---------|-------------|
| LLM Reasoning Agent | `backend/llm/` | Receives `AttackContext`, generates threat narrative |
| Response Orchestrator | `backend/response/` | Generates and queues response actions |
| Human Approval Gate | TBD | SOC analyst approval before execution |
| Dashboard API | `backend/dashboard/` | MTTD, FPR, alert metrics over time |
| Audit Ledger | TBD | Immutable INSERT-ONLY forensic trail |
| SOAR Integration | TBD | Integration with existing SOAR platforms |

**Do not instantiate or reference these packages** — they do not exist yet.
