# MITRE ATT&CK Mapper — Architecture

**Module:** 3.3  
**Version:** 1.0.0  
**ATT&CK Knowledge Base:** v15 (2024-10-01)  
**Branch:** `phase-3-behavioral-detection`

---

## 1. Architecture Overview

```
DetectionAlert (Module 2.4)
        │
        │  anomaly_score, entity, event_id, raw_feature_values
        ▼
SHAP ExplanationResult (Module 3.2)
        │
        │  feature_contributions (sorted by |SHAP| desc), top_features
        ▼
┌─────────────────────────────────────────────────────┐
│                   MitreService                      │
│  ┌─────────────────────────────────────────────┐    │
│  │               MitreMapper                   │    │
│  │  ┌─────────────────────────────────────┐    │    │
│  │  │      MitreKnowledgeBase             │    │    │
│  │  │  feature → [technique_id]  O(1)     │    │    │
│  │  │  36 techniques, 16 tactics          │    │    │
│  │  └─────────────────────────────────────┘    │    │
│  │  Confidence = 0.4×anomaly + 0.4×SHAP +     │    │
│  │              0.2×feature_breadth            │    │
│  └─────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────┐    │
│  │             MappingStore                    │    │
│  │  mappings_YYYY-MM-DD.jsonl (append)         │    │
│  │  reports/report_<id>.json (atomic)          │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
        │
        ▼
MappedAttack (output of this module)
        │
        ▼
[Future] Attack Graph / Response Module (3.4)
```

---

## 2. Data Flow

### Single Alert Mapping

```
1. MitreService.map_alert(alert, explanation)
2. → MitreMapper.map_alert(alert, explanation)
3.   → iterate explanation.feature_contributions (sorted by |SHAP| desc)
4.   → for each feature: kb.technique_ids_for_feature(feature_name) → [T1110, T1078, ...]
5.   → accumulate: matched_features, shap_contributors, shap_total per technique_id
6.   → compute_confidence(anomaly_score, shap_total, feature_match_count)
7.   → filter by min_confidence (default 0.10), cap at max_techniques (8)
8.   → sort by confidence descending
9.   → return MappedAttack
10. ← (persist if flag=True) MappingStore.save_mapping()
11. ← return MappedAttack to caller
```

### Batch (DetectionResult)

```
1. MitreService.map_detection_result(detection_result, explanations)
2. → index explanations by alert_id for O(1) lookup
3. → for each alert in detection_result.alerts:
4.     expl = index.get(alert.alert_id)  # None = graceful degradation
5.     MitreMapper.map_alert(alert, expl)
6. → collect MappedAttack list
7. → MappingStore.save_batch(mappings)
8. → MappingReport(mappings=...) → auto-computes MappingStatistics
9. → MappingStore.save_report(report)
10. ← return MappingReport
```

### Streaming

```
1. MitreService.map_stream(pairs: Iterable[(alert, explanation_or_None)])
2. → MitreMapper.map_stream(pairs)
3. → for each pair: map_alert() → yield MappedAttack
4. → (optional persist per item)
```

---

## 3. Mapping Strategy

### Feature → Technique Lookup

All 56 behavioral features (from `backend.features.models.ALL_FEATURE_NAMES`) are pre-mapped in `knowledge_base.py` to ATT&CK technique IDs.

Each feature maps to 1–4 technique IDs. Example:

| Feature | Techniques |
|---|---|
| `auth_failure_rate_baseline` | T1110, T1110.001, T1110.003 |
| `logon_type_is_novel` | T1078, T1021.001, T1021.002 |
| `process_is_novel` | T1059, T1055, T1036 |
| `dst_ip_is_novel` | T1021, T1071, T1041, T1571 |
| `modbus_function_code_is_novel` | T0855, T0836 |
| `bytes_out_z_score` | T1041, T1048 |

### Behavioral Indicator Groups

Higher-level patterns (not used in primary mapping path but available for indicator-level queries):

| Indicator | Techniques |
|---|---|
| `credential_brute_force` | T1110, T1110.001, T1110.003 |
| `lateral_movement_smb` | T1021.002, T1021 |
| `ot_command_injection` | T0855, T0836 |
| `data_exfiltration` | T1041, T1048 |
| `network_scan` | T1046, T1087 |

### Graceful Degradation

When no ExplanationResult is available:
- Mapper falls back to `alert.raw_feature_values` keys as the feature pool
- SHAP component of confidence = 0 (no shap_total)
- Mapping still occurs via feature breadth + anomaly score

---

## 4. Confidence Strategy

### Formula (deterministic, no ML, no LLMs)

```
confidence = (
    0.40 × alert.anomaly_score
  + 0.40 × min(shap_total / MAX_SHAP_TOTAL, 1.0)
  + 0.20 × min(feature_match_count / MAX_FEATURE_MATCH, 1.0)
)
clipped to [0.0, 1.0], rounded to 4 decimal places.
```

### Weight rationale

| Component | Weight | Rationale |
|---|---|---|
| `anomaly_score` | 0.40 | IsolationForest confidence — the primary detection signal |
| `shap_total` | 0.40 | SHAP evidence strength — how much this technique's features contributed |
| `feature_breadth` | 0.20 | How many distinct features support this hypothesis |

### Calibration constants

| Constant | Value | Notes |
|---|---|---|
| `MAX_SHAP_TOTAL` | 3.0 | Max observed |SHAP| sum for IsolationForest on 56 features |
| `MAX_FEATURE_MATCH` | 10 | Max expected feature matches per technique |
| `min_confidence` | 0.10 | Techniques below this are discarded as noise |
| `max_techniques` | 8 | Maximum techniques per MappedAttack |

---

## 5. Storage Design

Same atomic-write / date-partitioned philosophy as `ExplanationStore`.

```
data/mitre/
├── mappings_2024-06-10.jsonl     ← one MappedAttack per line, append-only
├── mappings_2024-06-11.jsonl
└── reports/
    └── report_mrpt-<id>.json    ← atomic (tmp→rename), full MappingReport
```

### Thread safety
- Per-file `threading.Lock` in a lock-map (LRU-style keyed by path string)
- `save_report`: write to `.tmp` then `Path.replace()` (atomic on all OS)

### Schema versioning
- `MappedAttack.schema_version` and `MappingReport.schema_version` carry `MITRE_SCHEMA_VERSION`
- `load_mappings_for_date` checks schema version per-line and raises `SchemaCompatibilityError` on mismatch

---

## 6. Integration Points

### Upstream (consumed by this module)

| Source | Object | Field used |
|---|---|---|
| Module 2.4 | `DetectionAlert` | `alert_id`, `anomaly_score`, `entity_key`, `model_id`, `raw_feature_values` |
| Module 3.2 | `ExplanationResult` | `feature_contributions`, `top_features`, `explanation_id` |

### Downstream (produced by this module → consumed by future modules)

| Consumer | Object | Primary fields |
|---|---|---|
| Module 3.4 (Attack Graph) | `MappedAttack` | `techniques`, `primary_technique`, `primary_tactic`, `mapped_tactics` |

### API contract (for Module 3.4)

```python
from backend.mitre.service import MitreService
from backend.mitre.models import MappedAttack, MappingReport

svc = MitreService()

# One-shot
mapped: MappedAttack = svc.map_alert(alert, explanation)

# Batch from DetectionResult
report: MappingReport = svc.map_detection_result(detection_result, explanations)

# Stream
for mapped in svc.map_stream(zip(alerts, explanations)):
    attack_graph.ingest(mapped)

# Access primary technique
pt = mapped.primary_technique        # TechniqueMapping or None
pt.technique.technique_id            # "T1110"
pt.technique.tactic.name             # "Credential Access"
pt.confidence                        # 0.7240

# All tactics represented
mapped.mapped_tactics                # ["Credential Access", "Initial Access"]
```

---

## 7. ATT&CK Coverage

### Tactics covered (16)

| ID | Name |
|---|---|
| TA0001 | Initial Access |
| TA0002 | Execution |
| TA0003 | Persistence |
| TA0004 | Privilege Escalation |
| TA0005 | Defense Evasion |
| TA0006 | Credential Access |
| TA0007 | Discovery |
| TA0008 | Lateral Movement |
| TA0009 | Collection |
| TA0010 | Exfiltration |
| TA0011 | Command and Control |
| TA0040 | Impact |
| TA0042 | Resource Development |
| TA0100 | Inhibit Response Function (ICS) |
| TA0104 | Impair Process Control (ICS) |
| TA0108 | ICS Discovery |

### Key techniques (36 total, includes ICS ATT&CK)

T1110, T1110.001, T1110.003, T1078, T1552, T1087, T1083, T1046, T1057, T1082,
T1059, T1059.001, T1059.003, T1204, T1021, T1021.001, T1021.002, T1210,
T1071, T1095, T1571, T1041, T1048, T1053, T1547, T1068, T1134, T1055, T1036,
T1005, T1499, **T0855, T0836, T0861, T0846, T0800**

---

## 8. Future Consumers

- **Module 3.4 — Attack Graph**: Consumes `MappedAttack.techniques` and `MappedAttack.mapped_tactics` to build causal attack chains with NetworkX (NOT implemented in this module)
- **Module 3.5 — Response Orchestrator**: Uses `MappingReport.statistics.tactic_distribution` for triage priority
- **Dashboard API**: Surfaces `TechniqueMapping.to_summary()` for per-alert ATT&CK overlays

---

## 9. Engineering Constraints

- **No NetworkX** — attack graph is not in scope here
- **No LLMs** — confidence is purely arithmetic
- **No internet** — knowledge base is embedded Python, version-pinned to ATT&CK v15
- **No architecture changes** — only `backend/mitre/` and `tests/unit/mitre/` created
- **Stateless mapper** — `MitreMapper` is safe for concurrent use
