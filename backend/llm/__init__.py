"""
backend.llm — LLM Alert Enrichment Module (Anthropic Claude)
=============================================================
[Module 3.1 — Week 3, Phase 3A]

RESPONSIBILITY
--------------
Make a SINGLE Anthropic Claude API call per alert to enrich it with:
  - Severity classification (critical | high | medium | low)
  - Attack hypothesis (e.g., "Credential Access → Lateral Movement")
  - Recommended response action
  - Confidence score
  - Next-stage ATT&CK technique prediction

CONSTRAINT: Exactly one API call per alert. No multi-turn reasoning.
COST TARGET: < $0.01 USD per call.
LATENCY TARGET: < 2 seconds (fail-open on timeout).

DATA FLOW
---------
AnomalyResult + List[AttackChain] (from Graph)
    → LLMAlertEnricher.enrich()
    → Claude API (1 call, JSON response)
    → EnrichedAlert
    → Response Engine

FUTURE CONTENTS
---------------
- enricher.py       AnthropicLLMEnricher — API call + parsing
- prompts.py        Prompt templates (versioned, tested)
- models/           EnrichedAlert, LLMCallRecord
- cost_tracker.py   Per-call cost computation + budget enforcement
- cache.py          Response cache for identical alert signatures
- router.py         POST /api/v1/enrich

PROMPT TEMPLATE (v1)
--------------------
Given an anomaly alert:
- Event type: {event_type}
- Host: {host}, User: {user}
- Anomaly score: {anomaly_score}
- Predicted ATT&CK techniques: {techniques}
- Baseline frequency: {baseline_freq}, Observed: {observed_freq}
- SHAP top features: {shap_explanation}

Respond ONLY with valid JSON (no markdown):
{
  "severity": "critical|high|medium|low",
  "justification": "2-sentence explanation",
  "attack_hypothesis": "attack progression name",
  "recommended_action": "isolate_host|block_ip|disable_account|investigate|none",
  "confidence": 0.0-1.0,
  "next_stage_prediction": "T####"
}

ERROR HANDLING
--------------
- Timeout (> 2s)    → return default: severity=medium, confidence=0.0
- Rate limit        → exponential backoff (tenacity), max 3 retries
- Invalid JSON      → log parse error, return default
- Budget exceeded   → raise LLMBudgetExceededError

INTEGRATION CONTRACT
--------------------
Input:  AlertEnrichmentRequest { anomaly_result, chains, shap_explanation }
Output: EnrichedAlert {
    alert_id, severity, justification, attack_hypothesis,
    recommended_action, confidence, next_stage_prediction,
    llm_latency_ms, llm_cost_usd
}

DEPENDENCIES
------------
- anthropic             Claude API client
- tenacity              Retry logic
- backend.core.config   Settings (api_key, model, timeout, budget)
- backend.core.exceptions  LLMTimeoutError, LLMRateLimitError, LLMBudgetExceededError
- backend.shared.types  SeverityLiteral, ActionTypeLiteral, ConfidenceScore

FEATURE FLAG
------------
settings.feature_llm_enabled = True to activate
"""
