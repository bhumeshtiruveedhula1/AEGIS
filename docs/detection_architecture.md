# Detection Architecture — Module 2.4
## CyberShield / Operation AEGIS

---

## Overview

Module 2.4 implements the **Behavioral Detection Core** — the first AI component of the CyberShield platform. It trains an Isolation Forest model exclusively on normal behavioral feature vectors and scores live events for anomalous behavior.

**Key invariant:** The model never trains on attack-labelled data. Anomalies are inferred purely from deviation from the learned normal behavior distribution.

---

## Architecture

```
DetectionService          ← public entry point (orchestration only)
  ├── IsolationForestTrainer  ← training only
  │     └── FeaturePreprocessor  ← StandardScaler fit + transform
  ├── AnomalyScorer            ← inference only (sigmoid normalisation)
  └── ModelStore               ← versioned persistence (atomic pkl + JSON)
```

**Strict layer separation:**
- Training logic never enters scorer
- Scoring logic never enters trainer
- Persistence logic never enters either
- Application code only calls `DetectionService`

---

## File Map

```
backend/detection/
├── __init__.py         Public API re-exports
├── models.py           ModelMetadata, TrainingResult, DetectionAlert, DetectionResult
├── exceptions.py       DetectionError, ModelNotTrainedError, SchemaCompatibilityError
├── storage.py          ModelStore — atomic versioned model persistence
├── preprocessor.py     FeaturePreprocessor — StandardScaler lifecycle + schema validation
├── trainer.py          IsolationForestTrainer — full train + incremental retrain
├── scorer.py           AnomalyScorer — sigmoid score normalisation, single/batch/stream
└── service.py          DetectionService — orchestrates all layers
```

---

## Model Lifecycle

### 1. Training

```python
from backend.detection.service import DetectionService

service = DetectionService()
result = service.train_from_features()
# Reads all JSONL files from settings.data_dir / "features"
# Filters to entity_dim="user_host" (configurable)
# Fits StandardScaler on training data
# Trains IsolationForest on scaled vectors
# Saves pkl + metadata JSON atomically
# Reloads model into memory immediately
# Returns TrainingResult
```

After training:
- `settings.models_dir/isolation_forest_<model_id>.pkl`
- `settings.models_dir/isolation_forest_<model_id>_meta.json`

### 2. Inference — Single Event

```python
alert = service.score_event(feature_record)
# Returns DetectionAlert | None
# None = below threshold (normal)
# DetectionAlert = anomaly_score >= threshold
```

### 3. Inference — Batch

```python
result = service.score_batch_from_features()
# Returns DetectionResult with all alerts and statistics
```

### 4. Inference — Streaming

```python
for alert in service.score_stream(record_iterable):
    # Process each alert as it arrives
    # Normal records are silently consumed
```

### 5. Incremental Retraining

```python
result = service.retrain_incremental(
    new_records,
    existing_records=existing_records  # optional; reads from disk if None
)
```

IsolationForest has no online learning API. Retraining is always a full refit on all available data. This is the correct approach.

---

## Score Normalisation

Raw IsolationForest `decision_function()` values:
- Negative → anomalous (further from 0 = more anomalous)
- Positive → normal

Mapped to `[0, 1]` via sigmoid inversion:

```
anomaly_score = 1 / (1 + exp(raw_if_score))
```

| Raw IF Score | Anomaly Score | Interpretation |
|---|---|---|
| −3.0 | ~0.95 | Highly anomalous |
| −1.0 | ~0.73 | Anomalous |
| 0.0 | ~0.50 | Decision boundary |
| +1.0 | ~0.27 | Normal |
| +3.0 | ~0.05 | Highly normal |

---

## Model Persistence

```
models/
├── isolation_forest_iforest-<uuid>.pkl        ← sklearn _DetectionPipeline
└── isolation_forest_iforest-<uuid>_meta.json  ← ModelMetadata (JSON)
```

**Atomic write pattern** (same as MetricStore, BaselineStore):
```python
tmp = target_path.with_suffix(".tmp")
write(tmp)
tmp.replace(target_path)  # atomic rename
```

### ModelMetadata fields
| Field | Purpose |
|---|---|
| `model_id` | Unique version identifier |
| `trained_at` | UTC training timestamp |
| `feature_names` | Ordered feature list at training time |
| `feature_dimension` | Total feature count (56) |
| `contamination` | Expected anomaly fraction |
| `n_estimators` | Number of isolation trees |
| `random_state` | Reproducibility seed |
| `entity_dimension` | Entity type trained on |
| `sample_count` | Training samples |
| `entity_count` | Distinct entities |

---

## Schema Compatibility

Before inference, `ModelStore` validates:
1. `len(model.feature_names) == len(ALL_FEATURE_NAMES)` — dimension match
2. `model.feature_names == ALL_FEATURE_NAMES` — exact name + order match

If either check fails, `SchemaCompatibilityError` is raised. This prevents silent score corruption from feature schema migrations.

---

## Configuration

All tunable parameters come from `backend.core.config.Settings`:

| Setting | Default | Description |
|---|---|---|
| `isolation_forest_contamination` | 0.01 | Expected anomaly fraction |
| `isolation_forest_n_estimators` | 100 | Number of isolation trees |
| `isolation_forest_random_state` | 42 | Random seed |
| `anomaly_score_threshold` | 0.5 | Alert trigger threshold |
| `models_dir` | `./models` | Model artifact directory |

---

## Output Contract

### DetectionAlert
Emitted when `anomaly_score >= threshold`:
```python
alert.alert_id          # "alert-<uuid>"
alert.model_id          # trained model version
alert.entity_key        # EntityKey (type + id)
alert.event_id          # originating event
alert.anomaly_score     # float [0,1]
alert.raw_if_score      # raw decision_function value (for SHAP later)
alert.threshold_used    # threshold active at scoring time
alert.raw_feature_values # {name: float} complete feature snapshot
alert.novelty_count     # count of binary 'is_novel' features that fired
alert.baseline_available # was a baseline available at extraction time
```

### DetectionResult
Aggregate from one scoring pass:
```python
result.records_scored   # int
result.alerts_generated # int
result.alert_rate       # fraction [0,1]
result.alerts           # list[DetectionAlert]
result.duration_seconds # float
```

---

## Integration Points

| Direction | Interface |
|---|---|
| **Input from Module 2.2** | `FeatureRecord` objects read from `data/features/*.jsonl` |
| **Output to Module 3.1** | `DetectionAlert` → `MitreService.map_alert()` |
| **Output to MetricService** | `DetectionResult` → `MetricService.collect_all(detection_result=...)` |
| **Output to Dashboard** | `DetectionService.get_status()` for health endpoints |

---

## Extension Points

The following hooks are designed into the architecture for future modules:

| Extension | Where | Status |
|---|---|---|
| SHAP explainability | `DetectionAlert.raw_feature_values` preserved | Ready (not implemented) |
| MITRE ATT&CK mapping | Consumes `DetectionAlert` | Module 3.1 |
| LLM enrichment | Consumes `DetectionAlert` | Module 3.2 |
| Model calibration (Platt) | Replace sigmoid in `scorer.py` | Future |
| ONNX export | Replace pickle in `storage.py` | Future |
| Multi-dimension scoring | Set `entity_dim` per detection run | Configurable now |

---

## Testing

```bash
# Module tests only
pytest tests/unit/detection/ -v

# Regression check
pytest tests/ --no-cov -q
```

**Coverage: 97 tests** across 6 test files covering:
- All model fields, validators, serialisation
- Atomic storage write/load, schema validation
- Preprocessor fit/transform lifecycle
- Trainer reproducibility, entity dim filtering
- Scorer sigmoid normalisation, single/batch/stream inference
- Service end-to-end: training, inference, JSONL loading, error handling
