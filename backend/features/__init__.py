"""
backend.features — Feature Engineering & Baseline Module
=========================================================
[Module 1.4 — Week 1, Phase 1B]

RESPONSIBILITY
--------------
Transform normalised LogEvents into numeric feature vectors suitable
for Isolation Forest training. Also computes and stores the 7-day
baseline statistics used for z-score normalisation.

DATA FLOW
---------
LogEvents (7-day baseline window, from Normalization)
    → LogFeatureExtractor
    → HourlyFeatureVector (per host, per hour)
    → BaselineGenerator
    → BaselineStats (baseline_stats.json)

Then at inference time:
LogEvent (live)
    → LogFeatureExtractor
    → feature_vector (z-score normalised using BaselineStats)
    → Anomaly Detection Module

FEATURE SET (7 features, one row = one hourly window per host)
--------------------------------------------------------------
1. event_frequency_per_host_per_type  (z-score of event counts)
2. failed_login_ratio_per_host        (failed / total logins)
3. privilege_escalation_count         (count of UAC/sudo events)
4. unusual_process_count              (processes not in KNOWN_GOOD_PROCESSES)
5. cross_subnet_connection_count      (connections crossing subnet boundary)
6. dns_query_entropy                  (Shannon entropy of unique queried domains)
7. abnormal_time_of_day              (logon events between 22:00–06:00 UTC)

FUTURE CONTENTS
---------------
- models/           HourlyFeatureVector, BaselineStats
- extractor.py      LogFeatureExtractor
- baseline.py       BaselineGenerator — computes 7-day stats
- vectorizer.py     FeatureVectorizer — z-score normalisation

INTEGRATION CONTRACT
--------------------
Input:  List[LogEvent] (7-day window for training, or single event at inference)
Output: numpy.ndarray shape (N, 7) — normalised feature matrix

DEPENDENCIES
------------
- backend.shared.models    BaseEvent (LogEvent source)
- backend.shared.utils     datetime_utils (hour truncation)
- backend.core.constants   KNOWN_GOOD_PROCESSES, BASELINE_WINDOW_DAYS

FEATURE FLAG
------------
Activated implicitly when detection module trains the model.
"""
