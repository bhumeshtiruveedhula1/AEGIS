"""
Diagnostic script for Issue A — Isolation Forest score compression.

Uses the exact same FeatureRecord construction pattern as the test suite.

Run from project root with venv active:
  .venv\\Scripts\\python.exe scripts\\diagnose_if_scores.py
"""
from __future__ import annotations

import math
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from backend.baseline.models import EntityKey
from backend.detection.trainer import IsolationForestTrainer
from backend.features.models import ALL_FEATURE_NAMES, FeatureRecord, FeatureVector


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_record(
    values: dict[str, float],
    entity_id: str = "diag-entity",
    entity_type: str = "user_host",
    baseline_available: bool = True,
) -> FeatureRecord:
    ek = EntityKey(entity_type=entity_type, entity_id=entity_id)
    full_values = {k: 0.0 for k in ALL_FEATURE_NAMES}
    full_values.update(values)
    fv = FeatureVector(entity_key=ek, values=full_values)
    return FeatureRecord(
        event_id=str(uuid.uuid4()),
        event_type="ProcessCreate",
        event_source="domain_controller",
        event_timestamp=datetime(2024, 1, 15, 10, 30, tzinfo=UTC),
        event_host="workstation-01",
        event_user="alice",
        entity_key=ek,
        baseline_available=baseline_available,
        feature_vector=fv,
    )


def _sigmoid(x: float) -> float:
    return round(1.0 / (1.0 + math.exp(x)), 6)


def _linear_rescale(x: float) -> float:
    """Map IF decision_function to [0,1]. Negative (anomalous) → high score."""
    # IF decision_function range is approximately [-0.5, 0.5]
    clamped = max(-0.5, min(0.5, x))
    return round(1.0 - (clamped + 0.5), 6)


# ── Scenarios ─────────────────────────────────────────────────────────────────

SCENARIOS: list[tuple[str, dict[str, float], bool]] = [
    # (label, feature overrides, baseline_available)
    ("Normal baseline", {
        "failed_logon_rate": 0.05,
        "hour_of_day": 10.0,
        "events_per_hour": 25.0,
        "bytes_out_zscore": 0.4,
        "unique_process_count": 6.0,
    }, True),
    ("Brute force (20 failed logins)", {
        "failed_logon_rate": 0.95,
        "hour_of_day": 3.0,
        "events_per_hour": 180.0,
        "bytes_out_zscore": 2.8,
        "unique_process_count": 3.0,
    }, True),
    ("Brute force — NO baseline", {
        "failed_logon_rate": 0.95,
        "hour_of_day": 3.0,
        "events_per_hour": 180.0,
        "bytes_out_zscore": 2.8,
        "unique_process_count": 3.0,
    }, False),
    ("Full kill chain (26 events)", {
        "failed_logon_rate": 0.80,
        "hour_of_day": 2.0,
        "events_per_hour": 250.0,
        "bytes_out_zscore": 4.5,
        "unique_process_count": 20.0,
    }, True),
    ("All-zero vector (empty entity)", {}, True),
]


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 78)
    print("AEGIS Diagnostic — Isolation Forest Score Compression Test")
    print("=" * 78)

    # Build normal-behavior training data (150 records, varied but normal)
    normal_records: list[FeatureRecord] = []
    for i in range(150):
        normal_records.append(_make_record(
            values={
                "failed_logon_rate": 0.03 + (i % 5) * 0.01,
                "hour_of_day": float(9 + (i % 8)),
                "events_per_hour": 20.0 + (i % 20),
                "bytes_out_zscore": 0.2 + (i % 10) * 0.05,
                "unique_process_count": float(5 + i % 8),
            },
            entity_id=f"normal-user-{i}::host-{i % 10}",
        ))

    # Train — entity_dim and contamination are constructor params
    trainer = IsolationForestTrainer(entity_dim="user_host", contamination=0.01)
    pipeline, metadata, _ = trainer.train(normal_records)

    # Score all scenarios — use AnomalyScorer with threshold=0.0 so all events emit a score
    from backend.detection.scorer import AnomalyScorer
    scorer = AnomalyScorer(pipeline, metadata, threshold=0.0)

    print(f"\n{'Scenario':<40} {'Baseline':>8} {'Raw IF':>8} {'Sigmoid':>8} {'Linear':>8}")
    print("-" * 78)

    raw_scores: list[float] = []
    sigs: list[float] = []
    lins: list[float] = []
    labels: list[str] = []
    has_baseline: list[bool] = []

    for label, vals, baseline in SCENARIOS:
        rec = _make_record(vals, entity_id="test-entity", baseline_available=baseline)
        X = scorer._pipeline.preprocessor.transform_single(rec)
        raw = float(scorer._pipeline.isolation_forest.decision_function(X)[0])
        sig = _sigmoid(raw)
        lin = _linear_rescale(raw)

        raw_scores.append(raw)
        sigs.append(sig)
        lins.append(lin)
        labels.append(label)
        has_baseline.append(baseline)

        bflag = "YES" if baseline else "NO"
        print(f"{label:<40} {bflag:>8} {raw:>8.4f} {sig:>8.4f} {lin:>8.4f}")

    print("-" * 78)

    # Analysis
    normal_raw = raw_scores[0]
    attack_idxs = [i for i, (_, _, b) in enumerate(SCENARIOS) if i > 0 and b]
    all_zero_idx = len(SCENARIOS) - 1

    print("\n── SEPARATION ANALYSIS ──")
    for i in attack_idxs:
        sep_raw = normal_raw - raw_scores[i]
        sep_sig = sigs[0] - sigs[i]
        sep_lin = lins[0] - lins[i]
        print(f"  {labels[i]:<42} sep_raw={sep_raw:+.4f}  sep_sig={sep_sig:+.4f}  sep_lin={sep_lin:+.4f}")

    raw_range = max(raw_scores) - min(raw_scores)
    sig_range = max(sigs) - min(sigs)

    print(f"\n  Raw IF range across all scenarios:    {raw_range:.4f}")
    print(f"  Sigmoid range across all scenarios:   {sig_range:.4f}")
    print(f"  Zero vector raw score:                {raw_scores[all_zero_idx]:.4f}")
    print(f"  Zero vector sigmoid score:            {sigs[all_zero_idx]:.4f}")

    print("\n── DIAGNOSIS ──")

    if raw_range < 0.05:
        print("❌ CRITICAL: Raw IF scores are COMPRESSED regardless of input.")
        print("   All feature vectors look identical to the model.")
        print("   → Root cause: Feature vectors are probably all-zero (baseline absent)")
        print("   → Action: Verify EntityBaseline exists before scoring attack entities")
    elif sig_range < 0.05 and raw_range >= 0.1:
        print("❌ CONFIRMED: Sigmoid is COLLAPSING raw score separation.")
        print(f"   Raw range={raw_range:.4f} but sigmoid range={sig_range:.4f}")
        print("   → Root cause: sigmoid(x) on small IF values maps everything near 0.5")
        print("   → Action: Replace sigmoid with linear rescale in scorer.py")
    elif sig_range < 0.1 and raw_range >= 0.05:
        print("⚠️  PARTIAL: Some separation but sigmoid is still compressing scores.")
        print("   → Action: Both linear rescale AND baseline check recommended")
    else:
        print("✅ Scores separate cleanly with sigmoid in this synthetic test.")
        print("   → The real E2E failure is likely caused by missing EntityBaseline")
        print("      for attack entities in the full pipeline (alice, ws01, plc01)")

    if abs(raw_scores[all_zero_idx] - normal_raw) < 0.02:
        print("\n⚠️  All-zero vector scores SAME as normal → empty vectors are invisible to IF")
        print("   This confirms NEG-05: empty feature vectors must be rejected before scoring")


if __name__ == "__main__":
    main()
