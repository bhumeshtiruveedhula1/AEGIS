"""
tests/unit/evaluation/test_mttd_instrument.py
==============================================
Phase 9 Module 9.2 — Unit tests for MTTDInstrumentor

Tests the MTTDInstrumentor in isolation using synthetic DetectionAlert-like
objects. No ML models loaded — pure timestamp arithmetic.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

# ---------------------------------------------------------------------------
# Ensure aegis_ml_lab is on sys.path so we can import mttd_instrument
# ---------------------------------------------------------------------------
_LAB_ROOT = Path(__file__).parent.parent.parent.parent.parent / "aegis_ml_lab"
if str(_LAB_ROOT) not in sys.path:
    sys.path.insert(0, str(_LAB_ROOT))

if not (_LAB_ROOT / "evaluate" / "mttd_instrument.py").exists():
    pytest.skip(
        "aegis_ml_lab not found — clone it as a sibling of cybershield and re-run",
        allow_module_level=True,
    )

from evaluate.mttd_instrument import (  # noqa: E402
    MTTD_TARGET_SECONDS,
    MTTDInstrumentor,
    MTTDSample,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(
    *,
    event_timestamp: datetime,
    extracted_at: datetime,
    triggered_at: datetime,
    score: float = 0.75,
    alert_id: str = "alert-test-001",
    entity_type: str = "user_host",
    entity_id: str = "corp\\nurse01:hospital-server-01",
) -> SimpleNamespace:
    """Build a minimal alert-like namespace for testing."""
    entity_key = SimpleNamespace(entity_type=entity_type, entity_id=entity_id)
    feature_vector = SimpleNamespace(extracted_at=extracted_at)
    return SimpleNamespace(
        alert_id=alert_id,
        entity_key=entity_key,
        event_timestamp=event_timestamp,
        feature_extracted_at=extracted_at,  # optional attr checked by record()
        triggered_at=triggered_at,
        anomaly_score=score,
    )


NOW = datetime(2026, 7, 17, 9, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestMTTDInstrumentorInit:
    def test_empty_on_init(self) -> None:
        inst = MTTDInstrumentor()
        assert len(inst) == 0
        assert inst.samples == []

    def test_target_constant_is_120(self) -> None:
        assert MTTD_TARGET_SECONDS == 120.0


# ---------------------------------------------------------------------------
# record() method — via DetectionAlert object
# ---------------------------------------------------------------------------


class TestMTTDRecord:
    def test_record_returns_sample(self) -> None:
        inst = MTTDInstrumentor()
        event_ts = NOW
        extracted_ts = NOW + timedelta(seconds=1)
        triggered_ts = NOW + timedelta(seconds=2)
        alert = _make_alert(
            event_timestamp=event_ts,
            extracted_at=extracted_ts,
            triggered_at=triggered_ts,
        )
        sample = inst.record(alert, scenario_name="brute_force_auth")
        assert isinstance(sample, MTTDSample)

    def test_record_primary_mttd_computed(self) -> None:
        """Primary MTTD = triggered_at - event_timestamp."""
        inst = MTTDInstrumentor()
        event_ts = NOW
        triggered_ts = NOW + timedelta(seconds=45.5)
        alert = _make_alert(
            event_timestamp=event_ts,
            extracted_at=NOW + timedelta(seconds=1),
            triggered_at=triggered_ts,
        )
        sample = inst.record(alert, scenario_name="brute_force_auth")
        assert abs(sample.mttd_primary_s - 45.5) < 0.001

    def test_record_secondary_mttd_computed(self) -> None:
        """Secondary MTTD = triggered_at - extracted_at."""
        inst = MTTDInstrumentor()
        extracted_ts = NOW + timedelta(seconds=10)
        triggered_ts = NOW + timedelta(seconds=10.25)
        alert = _make_alert(
            event_timestamp=NOW,
            extracted_at=extracted_ts,
            triggered_at=triggered_ts,
        )
        sample = inst.record(alert, scenario_name="brute_force_auth")
        assert abs(sample.mttd_secondary_s - 0.25) < 0.001

    def test_record_increments_count(self) -> None:
        inst = MTTDInstrumentor()
        for i in range(5):
            inst.record(
                _make_alert(
                    event_timestamp=NOW,
                    extracted_at=NOW + timedelta(seconds=1),
                    triggered_at=NOW + timedelta(seconds=i + 2),
                    alert_id=f"alert-{i}",
                ),
                scenario_name="cred_stuff",
            )
        assert len(inst) == 5

    def test_record_stores_scenario_name(self) -> None:
        inst = MTTDInstrumentor()
        alert = _make_alert(
            event_timestamp=NOW,
            extracted_at=NOW + timedelta(seconds=1),
            triggered_at=NOW + timedelta(seconds=5),
        )
        sample = inst.record(alert, scenario_name="lateral_movement_smb")
        assert sample.scenario == "lateral_movement_smb"

    def test_record_naive_datetime_handled(self) -> None:
        """Naive datetimes (no tzinfo) must not raise — they get UTC attached."""
        inst = MTTDInstrumentor()
        naive_event = datetime(2026, 7, 17, 9, 0, 0)  # no tzinfo
        alert = _make_alert(
            event_timestamp=naive_event,
            extracted_at=datetime(2026, 7, 17, 9, 0, 1),
            triggered_at=datetime(2026, 7, 17, 9, 0, 2),
        )
        sample = inst.record(alert, scenario_name="brute_force_auth")
        assert sample.mttd_primary_s == pytest.approx(2.0, abs=0.001)


# ---------------------------------------------------------------------------
# record_from_fields() method — direct field path
# ---------------------------------------------------------------------------


class TestMTTDRecordFromFields:
    def test_record_from_fields_primary_correct(self) -> None:
        inst = MTTDInstrumentor()
        event_ts = NOW
        triggered_ts = NOW + timedelta(seconds=30.0)
        sample = inst.record_from_fields(
            alert_id="alert-fields-001",
            scenario_name="privilege_escalation_token",
            entity_type="IT",
            entity_key_str="user_host:svc-iis:hospital-server-01",
            event_timestamp=event_ts,
            extracted_at=NOW + timedelta(seconds=0.5),
            triggered_at=triggered_ts,
            anomaly_score=0.88,
        )
        assert abs(sample.mttd_primary_s - 30.0) < 0.001
        assert sample.scenario == "privilege_escalation_token"

    def test_record_from_fields_secondary_correct(self) -> None:
        inst = MTTDInstrumentor()
        extracted_ts = NOW + timedelta(seconds=5)
        triggered_ts = NOW + timedelta(seconds=5.1)
        sample = inst.record_from_fields(
            alert_id="alert-fields-002",
            scenario_name="brute_force_auth",
            entity_type="IT",
            entity_key_str="user_host:svc-iis:hospital-server-01",
            event_timestamp=NOW,
            extracted_at=extracted_ts,
            triggered_at=triggered_ts,
            anomaly_score=0.92,
        )
        assert abs(sample.mttd_secondary_s - 0.1) < 0.001


# ---------------------------------------------------------------------------
# summarise() method
# ---------------------------------------------------------------------------


class TestMTTDSummarise:
    def test_empty_summarise(self) -> None:
        inst = MTTDInstrumentor()
        summary = inst.summarise()
        assert summary.n_alerts == 0
        assert summary.primary_mean_s is None
        assert summary.target_met is False
        assert summary.pct_alerts_within_target == 0.0

    def test_single_alert_summary(self) -> None:
        inst = MTTDInstrumentor()
        inst.record_from_fields(
            alert_id="a1",
            scenario_name="brute_force_auth",
            entity_type="IT",
            entity_key_str="user_host:x:y",
            event_timestamp=NOW,
            extracted_at=NOW + timedelta(seconds=1),
            triggered_at=NOW + timedelta(seconds=10),
            anomaly_score=0.8,
        )
        summary = inst.summarise()
        assert summary.n_alerts == 1
        assert summary.primary_mean_s == pytest.approx(10.0, abs=0.001)
        assert summary.primary_min_s == pytest.approx(10.0, abs=0.001)
        assert summary.primary_max_s == pytest.approx(10.0, abs=0.001)

    def test_target_met_when_mean_below_120s(self) -> None:
        inst = MTTDInstrumentor()
        for i, delta_s in enumerate([10.0, 20.0, 30.0]):
            inst.record_from_fields(
                alert_id=f"a{i}",
                scenario_name="brute_force_auth",
                entity_type="IT",
                entity_key_str="user_host:x:y",
                event_timestamp=NOW,
                extracted_at=NOW + timedelta(seconds=1),
                triggered_at=NOW + timedelta(seconds=delta_s),
                anomaly_score=0.8,
            )
        summary = inst.summarise()
        assert summary.target_met is True
        assert summary.primary_mean_s == pytest.approx(20.0, abs=0.001)

    def test_target_not_met_when_mean_above_120s(self) -> None:
        inst = MTTDInstrumentor()
        for i, delta_s in enumerate([150.0, 200.0, 300.0]):
            inst.record_from_fields(
                alert_id=f"a{i}",
                scenario_name="brute_force_auth",
                entity_type="IT",
                entity_key_str="user_host:x:y",
                event_timestamp=NOW,
                extracted_at=NOW + timedelta(seconds=1),
                triggered_at=NOW + timedelta(seconds=delta_s),
                anomaly_score=0.8,
            )
        summary = inst.summarise()
        assert summary.target_met is False

    def test_pct_within_target(self) -> None:
        """4 out of 5 alerts within 120s = 80%."""
        inst = MTTDInstrumentor()
        for i, delta_s in enumerate([10.0, 20.0, 30.0, 50.0, 200.0]):
            inst.record_from_fields(
                alert_id=f"a{i}",
                scenario_name="s",
                entity_type="IT",
                entity_key_str="user_host:x:y",
                event_timestamp=NOW,
                extracted_at=NOW + timedelta(seconds=1),
                triggered_at=NOW + timedelta(seconds=delta_s),
                anomaly_score=0.8,
            )
        summary = inst.summarise()
        assert summary.pct_alerts_within_target == pytest.approx(80.0, abs=0.1)

    def test_per_scenario_breakdown(self) -> None:
        inst = MTTDInstrumentor()
        for sc, delta_s in [("sc_a", 10.0), ("sc_a", 20.0), ("sc_b", 50.0)]:
            inst.record_from_fields(
                alert_id=f"a_{sc}_{delta_s}",
                scenario_name=sc,
                entity_type="IT",
                entity_key_str="user_host:x:y",
                event_timestamp=NOW,
                extracted_at=NOW + timedelta(seconds=1),
                triggered_at=NOW + timedelta(seconds=delta_s),
                anomaly_score=0.8,
            )
        summary = inst.summarise()
        assert "sc_a" in summary.per_scenario
        assert "sc_b" in summary.per_scenario
        assert summary.per_scenario["sc_a"]["n"] == 2
        assert summary.per_scenario["sc_a"]["mean_s"] == pytest.approx(15.0, abs=0.001)
        assert summary.per_scenario["sc_b"]["n"] == 1


# ---------------------------------------------------------------------------
# save() method
# ---------------------------------------------------------------------------


class TestMTTDSave:
    def test_save_creates_json(self, tmp_path: Path) -> None:
        inst = MTTDInstrumentor()
        inst.record_from_fields(
            alert_id="a1",
            scenario_name="brute_force_auth",
            entity_type="IT",
            entity_key_str="user_host:x:y",
            event_timestamp=NOW,
            extracted_at=NOW + timedelta(seconds=1),
            triggered_at=NOW + timedelta(seconds=15),
            anomaly_score=0.9,
        )
        out = tmp_path / "mttd_results.json"
        returned = inst.save(out)
        assert returned == out
        assert out.exists()
        payload = json.loads(out.read_text())
        assert "summary" in payload
        assert "samples" in payload
        assert len(payload["samples"]) == 1
        assert payload["samples"][0]["mttd_primary_s"] == pytest.approx(15.0, abs=0.001)
        assert payload["mttd_target_s"] == 120.0

    def test_save_creates_parent_dirs(self, tmp_path: Path) -> None:
        inst = MTTDInstrumentor()
        inst.record_from_fields(
            alert_id="a1",
            scenario_name="s",
            entity_type="IT",
            entity_key_str="user_host:x:y",
            event_timestamp=NOW,
            extracted_at=NOW + timedelta(seconds=1),
            triggered_at=NOW + timedelta(seconds=5),
            anomaly_score=0.7,
        )
        nested = tmp_path / "runs" / "run-abc" / "mttd_results.json"
        inst.save(nested)
        assert nested.exists()

    def test_empty_instrumentor_save(self, tmp_path: Path) -> None:
        """Empty instrumentor saves with n_alerts=0 without crashing."""
        inst = MTTDInstrumentor()
        out = tmp_path / "empty.json"
        inst.save(out)
        payload = json.loads(out.read_text())
        assert payload["summary"]["n_alerts"] == 0


# ---------------------------------------------------------------------------
# log_report() method — smoke test (should not raise)
# ---------------------------------------------------------------------------


class TestMTTDLogReport:
    def test_log_report_no_samples(self) -> None:
        """log_report() with 0 samples must not raise."""
        inst = MTTDInstrumentor()
        inst.log_report()  # should emit a warning log and return

    def test_log_report_with_samples(self) -> None:
        inst = MTTDInstrumentor()
        inst.record_from_fields(
            alert_id="a1",
            scenario_name="brute_force_auth",
            entity_type="IT",
            entity_key_str="user_host:x:y",
            event_timestamp=NOW,
            extracted_at=NOW + timedelta(seconds=0.5),
            triggered_at=NOW + timedelta(seconds=5),
            anomaly_score=0.85,
        )
        inst.log_report()  # should emit info log and return
