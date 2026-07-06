# CyberShield — System Architecture

## Pipeline Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Log Ingestion Layer                      │
│  (Windows Event IDs, Sysmon, iptables, DNS, Netflow, OT)    │
└────────────────────┬────────────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
┌───────▼──────────────┐ ┌───────▼──────────────┐
│  IT Container        │ │  OT Container         │
│  Win/Linux/Network   │ │  Modbus Simulator     │
└───────┬──────────────┘ └───────┬──────────────┘
        │                         │
        └────────────┬────────────┘
                     │ backend.normalization
        ┌────────────▼────────────┐
        │   Log Normalisation     │
        │  (unified LogEvent)     │
        └────────────┬────────────┘
                     │ backend.features
        ┌────────────▼────────────┐
        │   Feature Engineering   │
        │  (7 features, hourly)   │
        └────────────┬────────────┘
                     │ backend.detection
        ┌────────────▼────────────────────────────┐
        │   Isolation Forest Anomaly Detector     │
        │  contamination=0.01, n_estimators=100   │
        └────────────┬────────────────────────────┘
                     │ backend.explainability
        ┌────────────▼────────────────────────────┐
        │   SHAP Explainability                   │
        │  (top-3 features per alert)             │
        └────────────┬────────────────────────────┘
                     │ backend.mitre
        ┌────────────▼────────────────────────────┐
        │   MITRE ATT&CK Mapper                  │
        │  (event_type → technique ID)            │
        └────────────┬────────────────────────────┘
                     │ backend.graph
        ┌────────────▼────────────────────────────┐
        │   Attack Graph Reasoner (NetworkX)      │
        │  (top-3 chains, probability ranked)     │
        └────────────┬────────────────────────────┘
                     │ backend.llm
        ┌────────────▼────────────────────────────┐
        │   LLM Alert Enrichment (Claude)         │
        │  (1 call/alert, <2s, <$0.01)            │
        └────────────┬────────────────────────────┘
                     │ backend.response
        ┌────────────▼────────────────────────────┐
        │  Autonomous Response Engine (Gated)     │
        │  generate → queue → human approve →     │
        │  mock-execute → log                     │
        └────────────┬────────────────────────────┘
                     │ backend.audit
        ┌────────────▼────────────────────────────┐
        │  Audit Log + Forensic Replay            │
        │  (every action, immutable records)      │
        └────────────┬────────────────────────────┘
                     │ backend.dashboard
        ┌────────────▼────────────────────────────┐
        │  Metrics Dashboard API                  │
        │  (MTTD, FPR, chain rate, LLM cost)      │
        └────────────────────────────────────────┘
```

---

## Component Responsibilities

| Module | Package | Week | Responsibility |
|--------|---------|------|----------------|
| Foundation | `backend.core`, `backend.shared` | 1 | Config, logging, types, utilities |
| Ingestion | `backend.ingestion` | 1 | Collect raw logs from all sources |
| Normalisation | `backend.normalization` | 1 | Parse to unified LogEvent schema |
| Features | `backend.features` | 1 | Extract 7-dimensional feature vector |
| Detection | `backend.detection` | 2 | Isolation Forest scoring |
| Explainability | `backend.explainability` | 2 | SHAP feature importance |
| MITRE | `backend.mitre` | 2 | Event → ATT&CK technique mapping |
| Graph | `backend.graph` | 2 | Attack chain reasoning (NetworkX) |
| LLM | `backend.llm` | 3 | Alert enrichment (Claude API) |
| Response | `backend.response` | 3 | Action suggestion + approval queue |
| Audit | `backend.audit` | 3 | Immutable audit trail |
| Dashboard | `backend.dashboard` | 4 | Metrics API and time-series data |

---

## Data Contracts

### LogEvent (core data type)
All modules communicate using `backend.shared.models.BaseEvent`:

```python
{
  "event_id":    "uuid-v4",
  "timestamp":   "2024-01-15T10:30:00.000000Z",  # UTC
  "source":      "sysmon",                         # LogSource
  "event_type":  "ProcessCreate",                  # EventType
  "host":        "web-server-01",
  "user":        "CORP\\john.doe",
  "resource":    "cmd.exe",
  "action":      "execute",
  "result":      "success",
  "raw_log":     "..."                             # preserved verbatim
}
```

### AnomalyResult (detection output)
```python
{
  "event_id":       "uuid-v4",
  "anomaly_score":  0.82,       # float ∈ [-1.0, 1.0]
  "is_anomalous":   true,       # score > ANOMALY_SCORE_THRESHOLD
  "detection_time": "UTC datetime"
}
```

### EnrichedAlert (LLM output)
```python
{
  "alert_id":              "uuid-v4",
  "severity":              "critical",
  "justification":         "...",
  "attack_hypothesis":     "Credential Access → Lateral Movement",
  "recommended_action":    "isolate_host",
  "confidence":            0.87,
  "next_stage_prediction": "T1078",
  "llm_latency_ms":        1200,
  "llm_cost_usd":          0.005
}
```

---

## Key Design Decisions

### 1. Unsupervised Training Only
Training uses ONLY normal baseline data (7 days).
This enables zero-day attack detection without labeled attack samples.

### 2. Single LLM Call Per Alert
Claude API is called exactly once per alert.
No multi-turn reasoning. Budget: <$0.01/call, <2s latency.

### 3. Human Gate Mandatory
All response actions require SOC analyst approval before execution.
Auto-execution is never enabled in the MVP.

### 4. Separation of IT and OT
IT and OT environments generate separate log streams.
Both are normalised to the same LogEvent schema.
The same anomaly detector processes both.

### 5. Audit Immutability
Every audit record is INSERT-ONLY. No updates.
Preserves a tamper-evident forensic trail.

---

## Success Criteria

| Metric | Target |
|--------|--------|
| MTTD (Mean Time To Detection) | < 2 minutes |
| MTTR (Mean Time To Response) | < 5 minutes |
| False Positive Rate | < 5% |
| Attack Chain Detection | ≥ 70% of 3+ step chains |
| LLM Cost per Alert | < $0.01 |
| Audit Coverage | 100% of actions |
