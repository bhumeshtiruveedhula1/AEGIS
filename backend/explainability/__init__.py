"""
backend.explainability — SHAP Explainability Module
====================================================
[Module 2.2 — Week 2, Phase 2A]

RESPONSIBILITY
--------------
For every anomalous event, compute SHAP (SHapley Additive exPlanations)
feature importance values to explain WHY the Isolation Forest flagged
the event as anomalous.

DATA FLOW
---------
AnomalyResult + feature_vector (from Detection)
    → SHAPExplainer.explain()
    → SHAPExplanation {
        feature_importances: dict[str, float]
        top_3_features: list[tuple[str, float]]
        human_readable: str
      }
    → Passed to MITRE Mapping module for technique suggestion

FUTURE CONTENTS
---------------
- explainer.py      SHAPExplainer (wraps shap.TreeExplainer)
- models/           SHAPExplanation schema
- cache.py          Pre-computed SHAP cache for high-volume scenarios

SHAP APPROACH
-------------
Use shap.TreeExplainer (fastest for tree-based models like Isolation Forest).
Compute SHAP values per event: shape (1, 7) matching the 7-feature vector.
Top-3 features by |SHAP value| = primary explanation.

Human-readable template:
  "Event deviates on {feature1} (+{shap1:.2f}), {feature2} ({shap2:.2f}),
   {feature3} ({shap3:.2f})"

COST NOTE
---------
SHAP for Isolation Forest is fast (~10ms per event).
For high-throughput scenarios (>1K events/hour), cache SHAP results
for the top-100 flagged events per hour.

INTEGRATION CONTRACT
--------------------
Input:  feature_vector + trained IsolationForest model
Output: SHAPExplanation { feature_importances, top_3_features, human_readable }

DEPENDENCIES
------------
- shap                      SHAPExplainer (TreeExplainer)
- backend.detection         IsolationForestAnomalyDetector (model reference)
- backend.features          Feature names (for labeling)

FEATURE FLAG
------------
Activated automatically when detection module is enabled.
"""
