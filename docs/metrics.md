# Module 2.3 — Metrics Collection & Evaluation Engine

## Overview

Module 2.3 is the permanent observability and evaluation subsystem for the
Operation AEGIS AI-Driven Cyber Resilience Platform. It collects, computes,
persists, and exposes engineering metrics across all platform modules.

**This module measures the platform. It does not detect, classify or respond.**

---

## Architecture

```
                      ┌─────────────────────────────────────────────┐
                      │             MetricService                    │
                      │  (orchestrator — wires data to collectors)   │
                      └──────────────┬──────────────────────────────┘
                                     │  collect_all(**kwargs)
                    ┌────────────────┼─────────────────────┐
                    ▼                ▼                       ▼
           ┌────────────┐  ┌────────────────┐  ┌──────────────────┐
           │ Pipeline   │  │   Baseline     │  │   Feature        │
           │ Collector  │  │   Collector    │  │   Collector      │
           └────────────┘  └────────────────┘  └──────────────────┘
                    │       ┌──────────────┐     ┌──────────────────┐
                    │       │  Detection   │     │   Response       │
                    │       │  Collector   │     │   Collector      │
                    │       │ (UNAVAILABLE)│     │  (UNAVAILABLE)   │
                    │       └──────────────┘     └──────────────────┘
                    │       ┌─────────────────────────────────┐
                    │       │       Health Collector           │
                    │       │  (schema versions + components)  │
                    │       └─────────────────────────────────┘
                    │
                    ▼
           ┌────────────────────────────────────────────┐
           │              MetricSnapshot                 │
           │     (6 domain models, all 57+ metrics)     │
           └───────────────────┬────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │     MetricStore      │
                    │  data/metrics/       │
                    │  ├── history.jsonl   │
                    │  ├── manifest.json   │
                    │  └── snapshots/      │
                    │      └── <id>.json   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │     MetricReader     │
                    │  trend() / compare() │
                    │  get_metric()        │
                    └─────────────────────┘
```

---

## Metric Domain Taxonomy

| Domain | Model | Available Now | Data Source |
|--------|-------|---------------|-------------|
| `pipeline` | `PipelineMetrics` | ✅ Yes | Module 1.3 + Module 2.2 reports |
| `baseline` | `BaselineMetrics` | ✅ Yes | Module 2.1 `BaselineProfile` |
| `feature` | `FeatureMetrics` | ✅ Yes | Module 2.2 `FeaturePipelineReport` |
| `detection` | `DetectionMetrics` | ✅ Module 2.4 | Isolation Forest — `DetectionAlert` |
| `response` | `ResponseMetrics` | ⏳ Phase 5 | Response Orchestrator (not yet implemented) |
| `platform_health` | `PlatformHealthMetrics` | ✅ Yes | Runtime state + file system |

---

## Metric Models

### MetricValue — core container

Every metric is a `MetricValue[T]` with:

```python
class MetricValue(CyberShieldBaseModel, Generic[T]):
    value: T | None          # None when unavailable
    availability: MetricAvailability   # COMPUTED | UNAVAILABLE | INSUFFICIENT_DATA
    unit: str | None         # "seconds", "ratio", "count/s"
    description: str | None  # human-readable explanation
    computed_at: datetime    # UTC timestamp
```

**Availability contract**:
- `COMPUTED` — real value, safe to consume
- `UNAVAILABLE` — producing module not yet implemented (Phase 5 modules)
- `INSUFFICIENT_DATA` — module active, but no data for this run

Constructors:
```python
MetricValue.computed(1000, unit="count")      # COMPUTED
MetricValue.unavailable("Requires Module 2.4")  # UNAVAILABLE
MetricValue.insufficient("No events found")   # INSUFFICIENT_DATA
```

Safe access:
```python
val = mv.safe_float(default=0.0)  # never raises, never returns NaN/Inf
```

### PipelineMetrics (11 fields)

| Metric | Unit | Description |
|--------|------|-------------|
| `events_normalized` | count | Events successfully normalized |
| `events_failed` | count | Events that failed normalization |
| `normalization_error_rate` | ratio | `failed / (normalized + failed)` |
| `sources_processed` | count | Distinct telemetry sources |
| `normalization_duration_seconds` | seconds | Normalization wall-clock time |
| `event_processing_rate` | events/second | Throughput |
| `feature_records_produced` | count | FeatureRecords written |
| `feature_extraction_errors` | count | Extraction-level errors |
| `feature_generation_rate` | records/second | Feature throughput |
| `feature_extraction_duration_seconds` | seconds | Feature run wall-clock |
| `pipeline_end_to_end_latency_seconds` | seconds | norm + feature total time |

### BaselineMetrics (14 fields)

| Metric | Unit | Description |
|--------|------|-------------|
| `entity_count` | count | Total entities with a baseline |
| `entity_type_breakdown` | dict | Count per entity dimension |
| `baseline_coverage_ratio` | ratio | Entities / events processed |
| `total_events_in_baseline` | count | Events that built this baseline |
| `mean_observations_per_entity` | count | Mean observation count |
| `min_observations_per_entity` | count | Minimum observation count |
| `max_observations_per_entity` | count | Maximum observation count |
| `mean_baseline_window_days` | days | Mean observation window |
| `baseline_age_hours` | hours | Time since baseline was built |
| `baseline_profile_id` | string | Active profile identifier |
| `entities_with_network_baseline` | count | Entities with NetworkBaseline |
| `entities_with_process_baseline` | count | Entities with ProcessBaseline |
| `entities_with_auth_baseline` | count | Entities with AuthBaseline |
| `entities_with_modbus_baseline` | count | Entities with ModbusBaseline |

### FeatureMetrics (11 fields)

| Metric | Unit | Description |
|--------|------|-------------|
| `feature_schema_version` | string | Schema version constant |
| `feature_dimension` | count | 56 (number of features per vector) |
| `total_feature_records` | count | FeatureRecords produced |
| `unique_entities_extracted` | count | Distinct entity dimensions |
| `baseline_available_fraction` | ratio | Records with a baseline |
| `cold_start_fraction` | ratio | Records without a baseline |
| `mean_novelty_count` | count | Avg novelty flags per record |
| `max_novelty_count` | count | Max novelty flags in any record |
| `novelty_rate` | ratio | Fraction with ≥1 novelty flag |
| `extraction_error_rate` | ratio | Records with errors |
| `extraction_warning_rate` | ratio | Records with warnings |

### DetectionMetrics (8 fields) — UNAVAILABLE

All UNAVAILABLE until Module 2.4 (Behavioral Detection Core).
MTTD, detection rate, FP rate, TP/FP counts, alerts, anomaly score stats.

### ResponseMetrics (6 fields) — UNAVAILABLE

All UNAVAILABLE until Module 3.x (Response Orchestration).
MTTR, automation coverage, audit coverage, action counts.

### PlatformHealthMetrics

Schema versions for all 4 modules, per-component health status, enabled
feature flags, deployment environment, collection timestamp.

---

## Storage Strategy

```
data/metrics/
├── history.jsonl        # Append-only log — one MetricRecord per line
├── manifest.json        # Lightweight index for fast snapshot discovery
└── snapshots/
    └── <snapshot_id>.json   # Per-snapshot JSON for O(1) random access
```

**Append-only**: `history.jsonl` is never mutated (except by `purge_before()`).
**Atomic writes**: All file writes use `tmp → rename` to prevent partial writes.
**Zero contention**: Concurrent readers never block (no locks on JSONL appends).

### MetricRecord — atomic JSONL unit

```python
MetricRecord(
    record_id: str,           # UUID v4
    snapshot: MetricSnapshot, # complete 6-domain snapshot
    written_at: datetime,     # UTC timestamp
)
```

### MetricHistoryManifest

Maintains a reverse-chronological list of `ManifestEntry` objects.
Written atomically after every `save()` call.
`MetricReader` uses the manifest for `list_snapshots()` and snapshot discovery.

---

## Query Interface

```python
from backend.metrics import MetricService, MetricDomain

service = MetricService()
reader = service.reader

# Latest snapshot
snap = reader.latest_snapshot()

# Specific metric value
events = reader.get_value(snap, MetricDomain.PIPELINE, "events_normalized")

# Time-series trend (last 30 runs)
points = reader.trend(MetricDomain.PIPELINE, "events_normalized", limit=30)
# → [(datetime, float), ...]

# Statistical summary
summary = reader.trend_summary(MetricDomain.BASELINE, "entity_count")
# → {"count": 10, "mean": 48.5, "min": 40, "max": 60, "latest": 55}

# Run-over-run comparison
comparison = reader.compare_last_two()
regressions = comparison.regressions()
improvements = comparison.improvements()
changes = comparison.significant_changes(threshold_pct=5.0)

# Manifest browsing
entries = reader.list_snapshots(limit=20)
count = reader.snapshot_count()
```

---

## Computation Strategy

### Incremental vs. full recompute

| Strategy | Used for |
|----------|---------|
| Per-report extraction | Pipeline/Feature metrics (read from report fields) |
| Aggregate over entity list | Baseline statistics (mean/min/max from `EntityBaseline`) |
| Probe-based | Platform health (lightweight file-system + reader state checks) |
| Timestamp arithmetic | Baseline staleness (age_hours), latency sums |
| Honest UNAVAILABLE | Response metrics (Phase 5 — not yet implemented) |

All computation is deterministic — same inputs always produce identical outputs.

### Novelty statistics

`mean_novelty_count`, `max_novelty_count`, and `novelty_rate` are computed
by iterating `FeatureRecord.feature_vector.novelty_count()` over all records
in the feature_records list. These are O(N) in the number of records.

---

## Integration Points

### Consuming existing module outputs

| Module | Input object | Kwarg name |
|--------|-------------|-----------|
| Module 1.3 | `NormalizationPipelineReport` | `norm_report` |
| Module 2.1 | `BaselineProfile` | `baseline_profile` |
| Module 2.1 | `BaselineReader` | `baseline_reader` |
| Module 2.2 | `FeaturePipelineReport` | `feature_report` |
| Module 2.2 | `list[FeatureRecord]` | `feature_records` |

### Phase 5 module integration (no architecture changes required)

| Module | New kwargs to add |
|--------|------------------|
| Module 5.1 (LLM Agent) | `llm_results`, `reasoning_records` |
| Module 5.2 (Response) | `response_actions`, `approval_records` |

---

## Extension Mechanism

### Adding a new metric to an existing domain

1. Add the field to the domain model (e.g. `PipelineMetrics`) with a `MetricValue` type
2. Add the computation helper in the corresponding collector
3. Populate the new field in `collect()`
4. Add a test for the new metric
5. Bump `METRICS_SCHEMA_VERSION` if the change is breaking

### Adding a new collector domain

1. Create `backend/metrics/collectors/<domain>.py`
2. Subclass `BaseCollector`, implement `domain`, `name`, `collect()`
3. Decorate with `@register_collector`
4. Add the module path to `_bootstrap()` in `collectors/__init__.py`
5. Add the new domain model to `MetricSnapshot`
6. Add a fallback in `service.py`

---

## Configuration

Metrics-related settings in `Settings`:

| Setting | Default | Description |
|---------|---------|-------------|
| `metrics_interval_seconds` | 3600 | Interval for scheduled metric collection |
| `data_dir` | `./data` | Root for `data/metrics/` storage |

The `MetricStore` default directory is `settings.data_dir / "metrics"`.

---

## Versioning

`METRICS_SCHEMA_VERSION = "1.0.0"` — stored in every `MetricSnapshot`.

**Bump rules:**
- Patch (1.0.x): Adding new optional fields, changing descriptions
- Minor (1.x.0): Adding required fields with defaults
- Major (x.0.0): Removing fields, changing field types (breaking)

When loading stored snapshots, check `snapshot.schema_version` before consuming.

---

## Files Delivered

```
backend/metrics/
├── __init__.py                    Public API (all exports)
├── exceptions.py                  5 exception types
├── models.py                      All metric models (58 classes/types)
├── service.py                     MetricService orchestrator
├── store.py                       MetricStore persistence
├── reader.py                      MetricReader query interface
└── collectors/
    ├── __init__.py                BaseCollector ABC + registry + bootstrap
    ├── pipeline.py                PipelineMetricsCollector (11 metrics)
    ├── baseline.py                BaselineMetricsCollector (14 metrics)
    ├── feature.py                 FeatureMetricsCollector (11 metrics)
    ├── detection.py               DetectionMetricsCollector (8, UNAVAILABLE)
    ├── response.py                ResponseMetricsCollector (6, UNAVAILABLE)
    └── health.py                  PlatformHealthCollector (8 + component list)

tests/unit/metrics/
├── __init__.py
├── conftest.py                    Factories + pytest fixtures
├── test_models.py                 Model unit tests
├── test_collectors.py             Collector unit tests
├── test_store_reader.py           Store + reader unit tests
└── test_service.py                Service unit tests

tests/integration/
└── test_metrics_pipeline.py       End-to-end integration tests

docs/metrics.md                    This document
```
