"""
backend.detection — Isolation Forest Anomaly Detection Module
=============================================================
[Module 2.1 — Week 2, Phase 2A]

RESPONSIBILITY
--------------
Train an Isolation Forest on 7 days of normalised baseline logs,
then score live events against the trained model to produce anomaly
scores and alert triggers.

DATA FLOW
---------
BaselineStats + normalised baseline LogEvents
    → IsolationForestAnomalyDetector.train()
    → models/isolation_forest.pkl (persisted model)

Live LogEvent
    → FeatureVectorizer.transform()
    → IsolationForestAnomalyDetector.score()
    → AnomalyScore ∈ [-1.0, 1.0]
    → if score > ANOMALY_SCORE_THRESHOLD → Alert generated

FUTURE CONTENTS
---------------
- models/           AnomalyResult, AlertRecord, ModelMetadata
- detector.py       IsolationForestAnomalyDetector
- trainer.py        ModelTrainer — batch training workflow
- scorer.py         EventScorer — real-time scoring pipeline
- router.py         GET /api/v1/anomalies
- health.py         Model loaded? Baseline available?

MODEL CONFIGURATION (from Settings)
------------------------------------
- contamination       : 0.01 (1% expected anomalies in normal data)
- n_estimators        : 100
- random_state        : 42 (reproducible)
- alert_threshold     : 0.5 (anomaly_score > 0.5 → alert)

INTEGRATION CONTRACT
--------------------
Input:  feature_vector numpy.ndarray (from Features module)
Output: AnomalyResult {
    event_id:         str
    anomaly_score:    float ∈ [-1.0, 1.0]
    is_anomalous:     bool
    detection_time:   datetime
}

DEPENDENCIES
------------
- scikit-learn              IsolationForest
- backend.features          FeatureVectorizer, HourlyFeatureVector
- backend.core.config       Settings (contamination, n_estimators, seed)
- backend.core.exceptions   ModelNotTrainedError, BaselineNotFoundError

FEATURE FLAG
------------
settings.feature_detection_enabled = True to activate
"""
