"""
backend.dashboard — Metrics Dashboard API Module
=================================================
[Module 4.1 — Week 4, Phase 4]

RESPONSIBILITY
--------------
Expose computed operational metrics and system health as time-series
JSON endpoints, suitable for consumption by Grafana, a custom HTML
dashboard, or the judges' demo interface.

DATA FLOW
---------
Audit Log (from Audit Module)
    → MetricsAggregator (hourly computation)
    → MetricsSnapshot { mttd_p95, fpr, chain_detection_rate, llm_cost, ... }
    → GET /api/v1/metrics/hourly (time-series JSON)
    → Dashboard frontend or Grafana

FUTURE CONTENTS
---------------
- aggregator.py     MetricsAggregator — hourly metric computation
- collector.py      MetricsCollector — in-memory accumulation + SQLite persistence
- models/           MetricsSnapshot, HourlyMetrics
- router.py         GET /api/v1/metrics/hourly?start=...&end=...
                    GET /api/v1/metrics/summary
                    GET /api/v1/metrics/alerts?hours=N

METRICS EXPOSED (hourly JSON)
------------------------------
{
  "hour": "2024-01-15T10:00:00Z",
  "alerts_count": 42,
  "mttd_p95_ms": 45000,        ← 95th percentile detection latency
  "fpr": 0.03,                  ← false positive rate
  "chain_detection_rate": 0.82, ← attack chains identified / total alerts
  "avg_llm_latency_ms": 1200,
  "llm_cost_usd": 0.35,
  "autonomous_actions": 5,
  "human_approvals": 4,
  "human_denials": 1
}

DEMO DASHBOARD COMPONENTS (Week 4)
------------------------------------
- Live alert feed (last 10 alerts with anomaly scores)
- MTTD/MTTR gauges
- False positive rate trend
- Attack chain topology graph (NetworkX → D3.js)
- LLM cost accumulator
- Approval queue status

INTEGRATION CONTRACT
--------------------
Input:  Audit log query results (via AuditModule)
Output: MetricsSnapshot per hour, queryable by time range

DEPENDENCIES
------------
- backend.audit         AuditLogger (data source)
- backend.core.config   Settings (metrics_interval_seconds)
- backend.shared.utils  datetime_utils (hour boundaries)

FEATURE FLAG
------------
settings.feature_dashboard_enabled = True to activate
"""
