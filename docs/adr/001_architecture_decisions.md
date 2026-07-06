# ADR-001: Isolation Forest for Anomaly Detection

**Date:** 2024-01-15  
**Status:** Accepted  
**Deciders:** CyberShield Team

## Context

We need an anomaly detection algorithm that:
1. Requires NO labeled attack data (zero-day scenarios)
2. Can be trained on 7 days of normal behaviour
3. Produces interpretable scores compatible with SHAP
4. Processes events in < 50ms per event at inference time

## Decision

Use **scikit-learn's Isolation Forest** with the following configuration:
- `n_estimators=100` — sufficient accuracy with < 50ms inference
- `contamination=0.01` — expect 1% anomalies in normal training data
- `random_state=42` — reproducible training results

## Alternatives Considered

| Algorithm | Pros | Cons | Decision |
|-----------|------|------|----------|
| Isolation Forest | Fast, no labels, SHAP compatible | Needs baseline period | ✅ Selected |
| One-Class SVM | High accuracy | Slow inference (>100ms) | ❌ Rejected |
| LSTM Autoencoder | Temporal modelling | Needs GPU, complex retraining | ❌ Out of scope |
| Statistical Z-score | Simple, explainable | Too many false positives | ❌ Insufficient |

## Consequences

- **Training:** 7-day baseline window required before first detection
- **Retraining:** Weekly (configurable via cron/scheduled job)
- **Explainability:** SHAP TreeExplainer works natively with Isolation Forest
- **Performance:** < 50ms inference, < 1min training on 100K events

---

# ADR-002: structlog for Structured Logging

**Date:** 2024-01-15  
**Status:** Accepted

## Decision

Use **structlog** (JSON in production, console in development) instead of:
- Python stdlib `logging` — not structured natively
- `loguru` — good but less enterprise tooling support
- `python-json-logger` — less flexible processor pipeline

## Consequences

- All log records are machine-readable JSON in production
- Every record carries `request_id`, `timestamp`, `level`, `logger`
- Easy to ingest into ELK, Grafana Loki, Google Cloud Logging

---

# ADR-003: Single LLM Call Per Alert

**Date:** 2024-01-15  
**Status:** Accepted

## Decision

The LLM (Anthropic Claude) is invoked **exactly once per alert**, not in
a multi-turn reasoning chain.

Rationale:
1. **Cost constraint:** < $0.01 per alert
2. **Latency constraint:** < 2 second total LLM contribution to MTTD
3. **Reliability:** Fail-open on timeout (return medium severity default)
4. **Scope:** Context is already rich (SHAP explanation + attack chain)

## Consequences

- Prompt must be carefully engineered to extract all information in one shot
- Multi-turn enrichment is explicitly out of scope for MVP
- Timeout (2s) returns a sensible default, never blocking the response pipeline
