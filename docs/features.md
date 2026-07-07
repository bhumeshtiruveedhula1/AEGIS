# Module 2.2 — Behavioral Feature Engine

## Overview

The Behavioral Feature Engine transforms normalized telemetry events
(`CanonicalEvent` from Module 1.3) and learned behavioral baselines
(`EntityBaseline` from Module 2.1) into **deterministic behavioral feature
vectors** suitable for downstream unsupervised anomaly detection.

> **This module does NOT detect anomalies. It does NOT score behavior.
> It does NOT generate alerts. It represents behavior numerically.**

---

## Feature Generation Workflow

```
CanonicalEvent (Module 1.3)
         │
         ▼
  FeaturePipeline
    │
    ├─ Resolve entity keys (user, host, source, user_host)
    ├─ Query BaselineReader (Module 2.1) for each dimension
    ├─ Inject BaselinePresenceExtractor context
    ├─ Select primary baseline (user_host > user > host > source)
    │
    ├─ TemporalExtractor       → 8  features
    ├─ FrequencyExtractor      → 8  features
    ├─ NetworkExtractor        → 10 features
    ├─ ProcessExtractor        → 8  features
    ├─ AuthExtractor           → 7  features
    ├─ OTExtractor             → 7  features
    ├─ BaselinePresenceExtractor → 4 features
    └─ EntityActivityExtractor  → 4 features
         │
         ▼
  FeatureVector (56 floats, canonical order)
         │
         ▼
  FeatureRecord (vector + event provenance)
         │
         ▼
  FeatureVectorWriter → features_<run_id>.jsonl
```

---

## Feature Vector Schema

**Version:** `1.0.0`  
**Dimension:** 56 features  
**Type:** All `float`, all finite (NaN/Inf replaced with `0.0`)  
**Binary features:** Exactly `{0.0, 1.0}`

### Group 1 — Temporal (8 features)

| Feature | Description |
|---------|-------------|
| `hour_of_day` | UTC hour (0–23) |
| `day_of_week` | Weekday (0=Monday, 6=Sunday) |
| `is_business_hours` | 1.0 if 08:00–18:00 Mon–Fri UTC |
| `hour_baseline_frequency` | Fraction of baseline events at this hour |
| `hour_relative_frequency` | Current hour freq / peak hour freq |
| `day_baseline_frequency` | Fraction of baseline events on this weekday |
| `is_peak_hour` | 1.0 if event hour == baseline peak hour |
| `time_since_last_seen_hours` | Hours since entity last_seen (capped at 8760) |

### Group 2 — Frequency (8 features)

| Feature | Description |
|---------|-------------|
| `event_type_frequency` | Count of this event_type in baseline |
| `event_type_frequency_rank` | Rank by frequency (0=most common) |
| `action_frequency` | Count of this action in baseline |
| `result_failure_rate_baseline` | Baseline proportion of failure results |
| `result_is_failure` | 1.0 if current event result == "failure" |
| `source_frequency` | Count of this source in baseline |
| `entity_observation_count` | Total events in baseline for this entity |
| `baseline_window_days` | Duration of baseline window in days |

### Group 3 — Network (10 features)

| Feature | Description |
|---------|-------------|
| `dst_ip_is_novel` | 1.0 if dst_ip not seen in baseline |
| `src_ip_is_novel` | 1.0 if src_ip not seen in baseline |
| `port_is_novel` | 1.0 if port not seen in baseline |
| `protocol_is_novel` | 1.0 if protocol not in baseline distribution |
| `port_baseline_frequency` | Baseline count for this port |
| `protocol_baseline_frequency` | Baseline count for this protocol |
| `bytes_out_z_score` | Z-score of bytes_out vs baseline |
| `bytes_out_percentile_rank` | Percentile rank of bytes_out (0–4) |
| `unique_dst_ips_baseline` | Unique destination IPs in baseline |
| `connection_count_baseline` | Total network events in baseline |

### Group 4 — Process (8 features)

| Feature | Description |
|---------|-------------|
| `process_is_novel` | 1.0 if process not in baseline |
| `parent_process_is_novel` | 1.0 if parent process not in baseline |
| `parent_child_pair_is_novel` | 1.0 if parent__child pair not in baseline |
| `process_frequency_rank` | Rank of process by frequency |
| `unique_processes_baseline` | Unique processes in baseline |
| `process_event_count_baseline` | Total process events in baseline |
| `pid_z_score` | Z-score of PID vs baseline |
| `has_command_line` | 1.0 if command_line is not None |

### Group 5 — Authentication (7 features)

| Feature | Description |
|---------|-------------|
| `logon_type_is_novel` | 1.0 if logon type not in baseline |
| `auth_package_is_novel` | 1.0 if auth package not in baseline |
| `logon_type_baseline_frequency` | Baseline count for this logon type |
| `auth_package_baseline_frequency` | Baseline count for this auth package |
| `auth_failure_rate_baseline` | Baseline authentication failure rate |
| `auth_event_count_baseline` | Total auth events in baseline |
| `windows_event_id_is_novel` | 1.0 if Windows event ID not in baseline |

### Group 6 — OT/Modbus (7 features)

| Feature | Description |
|---------|-------------|
| `modbus_register_z_score` | Z-score of register address vs baseline |
| `modbus_value_z_score` | Z-score of register value vs baseline |
| `modbus_register_is_in_range` | 1.0 if register within baseline [min, max] |
| `modbus_value_is_in_range` | 1.0 if value within baseline [min, max] |
| `modbus_function_code_is_novel` | 1.0 if function code not in baseline |
| `supervisory_host_is_novel` | 1.0 if supervisory host not in baseline |
| `modbus_event_count_baseline` | Total OT events in baseline |

### Group 7 — Baseline Presence (4 features)

| Feature | Description |
|---------|-------------|
| `has_user_baseline` | 1.0 if user-dimension baseline exists |
| `has_host_baseline` | 1.0 if host-dimension baseline exists |
| `has_source_baseline` | 1.0 if source-dimension baseline exists |
| `has_user_host_baseline` | 1.0 if user_host-dimension baseline exists |

### Group 8 — Entity Activity (4 features)

| Feature | Description |
|---------|-------------|
| `entity_unique_dst_ips` | Unique destination IPs across baseline |
| `entity_unique_processes` | Unique process names across baseline |
| `entity_auth_failure_count` | Cumulative auth failures in baseline |
| `entity_modbus_event_count` | Cumulative OT events in baseline |

---

## Baseline Interaction

The Feature Engine consumes baselines **exclusively via `BaselineReader`**.

```python
from backend.baseline.reader_api import BaselineReader
from backend.features.pipeline import FeaturePipeline

reader = BaselineReader()           # loads latest baseline from disk
pipeline = FeaturePipeline(baseline_reader=reader)
records = pipeline.process_event(event)
```

### Entity Dimension Priority

For each event, the pipeline resolves baselines for all four entity dimensions
and selects the **most specific available** baseline for feature computation:

```
user_host  (e.g., "svc-iis::hospital-server-01")  ← highest priority
user       (e.g., "svc-iis")
host       (e.g., "hospital-server-01")
source     (e.g., "hospital_server")               ← lowest priority
```

### Cold-Start Safety

When no baseline exists for any dimension, **all features default to `0.0`**.
No exception is raised. The `has_*_baseline` flags will all be `0.0`,
letting downstream models condition on baseline availability.

---

## Downstream Integration

### Consuming FeatureRecords

```python
from backend.features.models import FeatureRecord, FEATURE_DIMENSION

# Read JSONL output
import json
with open("data/features/features_<run_id>.jsonl") as f:
    for line in f:
        record = FeatureRecord.model_validate_json(line)

        # Get ordered array (numpy-compatible)
        arr = record.feature_vector.to_array()   # list of 56 floats

        # Get group subset
        temporal = record.feature_vector.group("temporal")

        # Check novelty summary
        count = record.feature_vector.novelty_count()
```

### Schema Versioning

Always check `schema_version` before consuming stored feature vectors:

```python
from backend.features.models import FEATURE_SCHEMA_VERSION

assert record.schema_version == FEATURE_SCHEMA_VERSION, (
    f"Schema mismatch: stored={record.schema_version}, "
    f"current={FEATURE_SCHEMA_VERSION}"
)
```

---

## Design Rationale

| Decision | Rationale |
|----------|-----------|
| All features are `float` | Homogeneous type required by ML frameworks |
| Missing → `0.0` (not `NaN`) | Prevents NaN propagation in downstream models |
| Binary novelty features `{0.0, 1.0}` | Clean, explainable encoding for analysts |
| Per-extractor isolation (`safe_extract`) | One extractor failure does not abort the event |
| Most-specific entity priority | User_host baseline is most precise predictor |
| Parent__child pair key | Stronger signal than individual process novelty |
| Z-scores return `0.0` when `std=0` | "Equal to mean" is the safest default |
| Context dict for BaselinePresenceExtractor | Decouples dimension lookup from extraction |
| Emit up to 4 records per event | Preserves all entity dimension perspectives |

---

## Extension Guidelines

### Adding a New Feature Group

1. Create `backend/features/extractors/<group>.py`
2. Subclass `BaseExtractor`, implement `group_name`, `feature_names`, `extract()`
3. Add feature names to `FEATURE_GROUPS` in `backend/features/models.py`
4. Register the extractor in `_build_registry()` in `backend/features/extractors/__init__.py`
5. Add tests in `tests/unit/features/test_extractors.py`

### Adding Features to an Existing Group

1. Add the feature to `FEATURE_GROUPS[group]` in `models.py`
2. Compute and return it in the extractor's `extract()` method
3. **Bump `FEATURE_SCHEMA_VERSION`** (breaking change — downstream consumers must reload)
4. Add test cases verifying cold-start safety and correct computation

### Adding a New Entity Dimension

1. Add the new entity type to `ENTITY_TYPES` in `backend/baseline/models.py` (Module 2.1)
2. Add key resolution helper in `backend/features/pipeline.py`
3. Add presence flag to `BaselinePresenceExtractor`
4. Update `_select_primary()` priority list

---

## File Structure

```
backend/features/
├── __init__.py              # Public API surface
├── exceptions.py            # FeatureEngineError hierarchy
├── models.py                # FeatureVector, FeatureRecord, FeatureSchema
├── pipeline.py              # FeaturePipeline — orchestrator
├── writer.py                # FeatureVectorWriter — JSONL output
├── service.py               # FeatureService — application entry point
└── extractors/
    ├── __init__.py          # BaseExtractor ABC + numeric helpers + registry
    ├── temporal.py          # Temporal features (8)
    ├── frequency.py         # Frequency features (8)
    ├── network.py           # Network features (10)
    ├── process.py           # Process features (8)
    ├── auth.py              # Authentication features (7)
    ├── ot.py                # OT/Modbus features (7)
    ├── baseline.py          # Baseline presence flags (4)
    └── entity_activity.py   # Entity activity summaries (4)

tests/unit/features/
├── __init__.py
├── conftest.py              # Shared factories and fixtures
├── test_models.py           # FeatureVector/Record/Schema tests
├── test_extractors.py       # Per-extractor unit tests
└── test_pipeline.py         # FeaturePipeline unit tests

tests/integration/
└── test_feature_pipeline.py # End-to-end integration tests

docs/
└── features.md              # This file
```
