"""tests/unit/audit/test_integrity.py — AuditIntegrityChecker tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from backend.audit.integrity import AuditIntegrityChecker, IntegrityReport
from backend.audit.models import (
    AuditEntry,
    AuditEventType,
    AuditMetadata,
)

if TYPE_CHECKING:
    from backend.audit.storage import AuditStore


def _save(store: AuditStore, *, ts: datetime | None = None, alert_id: str = "a-001") -> AuditEntry:
    now = ts or datetime.now(UTC)
    entry = AuditEntry(
        event_type=AuditEventType.DETECTION_ALERT,
        metadata=AuditMetadata(source_module="detection", alert_id=alert_id),
        timestamp=now,
        recorded_at=now,
    )
    store.save(entry)
    return entry


class TestIntegrityEmptyLedger:
    def test_empty_ledger_passes(self, store: AuditStore) -> None:
        checker = AuditIntegrityChecker(store)
        report = checker.verify()
        assert report.passed is True
        assert report.total_entries == 0


class TestIntegrityCleanLedger:
    def test_clean_ledger_passes(self, store: AuditStore) -> None:
        _save(store)
        _save(store)
        checker = AuditIntegrityChecker(store)
        report = checker.verify()
        assert report.passed is True
        assert report.total_entries == 2
        assert report.error_count == 0

    def test_report_has_correct_partition_count(self, store: AuditStore) -> None:
        now = datetime.now(UTC)
        _save(store, ts=now)
        _save(store, ts=now - timedelta(days=1))
        checker = AuditIntegrityChecker(store)
        report = checker.verify()
        assert report.total_partitions == 2


class TestIntegrityCorruption:
    def test_corrupt_line_detected(self, store: AuditStore) -> None:
        _save(store)
        path = store._daily_jsonl_path(datetime.now(UTC))
        path.open("a").write("CORRUPT_LINE\n")
        checker = AuditIntegrityChecker(store)
        report = checker.verify()
        assert report.error_count >= 1
        assert not report.passed
        struct_violations = [v for v in report.violations if v.check == "structural"]
        assert len(struct_violations) >= 1


class TestIntegrityDuplicateId:
    def test_duplicate_audit_id_detected(self, store: AuditStore) -> None:
        entry = _save(store)
        # Manually write same audit_id twice
        path = store._daily_jsonl_path(datetime.now(UTC))
        path.open("a").write(entry.model_dump_json() + "\n")
        checker = AuditIntegrityChecker(store)
        report = checker.verify()
        dup_violations = [v for v in report.violations if v.check == "duplicate"]
        assert len(dup_violations) >= 1
        assert not report.passed


class TestIntegrityReport:
    def test_passed_property_true_when_no_errors(self) -> None:
        report = IntegrityReport()
        assert report.passed is True

    def test_passed_property_false_when_errors(self) -> None:
        from backend.audit.integrity import IntegrityViolation

        report = IntegrityReport()
        report.add(IntegrityViolation(check="structural", severity="error", detail="broken"))
        assert report.passed is False

    def test_error_count(self) -> None:
        from backend.audit.integrity import IntegrityViolation

        report = IntegrityReport()
        report.add(IntegrityViolation(check="x", severity="error", detail="e"))
        report.add(IntegrityViolation(check="y", severity="warning", detail="w"))
        assert report.error_count == 1
        assert report.warning_count == 1

    def test_summary_includes_pass_fail(self) -> None:
        report = IntegrityReport(total_entries=5, total_partitions=1)
        assert "PASS" in report.summary()
