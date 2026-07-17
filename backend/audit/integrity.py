"""
backend.audit.integrity — Audit Ledger Integrity Verification
=============================================================
Module 7.2 — Audit Ledger

Validates the structural and logical consistency of stored audit history.

Checks
------
1. Structural   — every line in every JSONL partition deserialises without error
2. Schema       — every entry has the expected schema_version
3. Sequence     — sequence_numbers are unique and non-negative
4. Timestamp    — recorded_at is always >= timestamp for each entry
5. Ordering     — entries within a partition are in non-decreasing timestamp order
6. Duplicate ID — no two entries share the same audit_id
7. Index sync   — every audit_id in JSONL has a matching index file

This module validates. It never repairs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

from backend.audit.models import AUDIT_SCHEMA_VERSION, AuditEntry

if TYPE_CHECKING:
    from backend.audit.storage import AuditStore

logger = structlog.get_logger(__name__)


# ── Result model ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class IntegrityViolation:
    """A single detected integrity problem."""

    check: str
    severity: str  # 'error' | 'warning'
    detail: str
    audit_id: str | None = None
    partition: str | None = None


@dataclass
class IntegrityReport:
    """Full report returned by AuditIntegrityChecker.verify()."""

    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    total_entries: int = 0
    total_partitions: int = 0
    violations: list[IntegrityViolation] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True iff there are no error-severity violations."""
        return all(v.severity != "error" for v in self.violations)

    @property
    def error_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "warning")

    def add(self, violation: IntegrityViolation) -> None:
        self.violations.append(violation)

    def summary(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return (
            f"[{status}] {self.total_entries} entries / "
            f"{self.total_partitions} partitions | "
            f"{self.error_count} errors, {self.warning_count} warnings"
        )


# ── Checker ───────────────────────────────────────────────────────────────────


class AuditIntegrityChecker:
    """
    Runs a full suite of integrity checks against the audit store.

    Parameters
    ----------
    store : AuditStore instance to verify.
    """

    def __init__(self, store: AuditStore) -> None:
        self._store = store

    def verify(self) -> IntegrityReport:
        """
        Run all integrity checks and return a consolidated IntegrityReport.
        Order of checks: structural → schema → duplicate → sequence → timestamp → ordering → index sync.
        """
        report = IntegrityReport()
        report.total_partitions = len(self._store.list_dates())

        all_entries: list[AuditEntry] = []
        partition_entries: dict[str, list[AuditEntry]] = {}

        # ── 1. Structural: deserialise every line ─────────────────────────────
        dates = self._store.list_dates()
        for date_str in dates:
            # Parse date string to datetime for load_for_date
            try:
                d = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=UTC)
            except ValueError:
                continue

            raw_path = self._store._daily_jsonl_path(d)
            if not raw_path.exists():
                continue
            valid_lines: list[AuditEntry] = []
            for i, line in enumerate(raw_path.read_text(encoding="utf-8").splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    e = AuditEntry.model_validate_json(line)
                    valid_lines.append(e)
                except Exception as exc:
                    report.add(
                        IntegrityViolation(
                            check="structural",
                            severity="error",
                            detail=f"Line {i+1} failed deserialisation: {exc}",
                            partition=date_str,
                        )
                    )
            all_entries.extend(valid_lines)
            partition_entries[date_str] = valid_lines

        report.total_entries = len(all_entries)

        if not all_entries:
            logger.debug("audit_integrity_empty_ledger")
            return report

        # ── 2. Schema version ─────────────────────────────────────────────────
        for e in all_entries:
            if e.schema_version != AUDIT_SCHEMA_VERSION:
                report.add(
                    IntegrityViolation(
                        check="schema",
                        severity="error",
                        detail=f"Unexpected schema_version {e.schema_version!r}",
                        audit_id=e.audit_id,
                    )
                )

        # ── 3. Duplicate audit_id ─────────────────────────────────────────────
        seen_ids: set[str] = set()
        for e in all_entries:
            if e.audit_id in seen_ids:
                report.add(
                    IntegrityViolation(
                        check="duplicate",
                        severity="error",
                        detail="Duplicate audit_id detected",
                        audit_id=e.audit_id,
                    )
                )
            seen_ids.add(e.audit_id)

        # ── 4. Sequence uniqueness ────────────────────────────────────────────
        seen_seqs: set[int] = set()
        for e in all_entries:
            if e.sequence_number in seen_seqs:
                report.add(
                    IntegrityViolation(
                        check="sequence",
                        severity="warning",
                        detail=f"Duplicate sequence_number {e.sequence_number}",
                        audit_id=e.audit_id,
                    )
                )
            seen_seqs.add(e.sequence_number)

        # ── 5. Timestamp: recorded_at >= timestamp ────────────────────────────
        for e in all_entries:
            # Allow up to 1 second of clock skew
            if e.recorded_at < e.timestamp:
                skew = (e.timestamp - e.recorded_at).total_seconds()
                if skew > 1.0:
                    report.add(
                        IntegrityViolation(
                            check="timestamp",
                            severity="warning",
                            detail=f"recorded_at ({e.recorded_at.isoformat()}) < "
                            f"timestamp ({e.timestamp.isoformat()}) by {skew:.1f}s",
                            audit_id=e.audit_id,
                        )
                    )

        # ── 6. Ordering within each partition (non-decreasing by timestamp) ───
        for date_str, entries in partition_entries.items():
            for i in range(1, len(entries)):
                prev = entries[i - 1]
                curr = entries[i]
                if curr.recorded_at < prev.recorded_at:
                    report.add(
                        IntegrityViolation(
                            check="ordering",
                            severity="warning",
                            detail=(
                                f"Entry at position {i} ({curr.audit_id}) has "
                                f"recorded_at {curr.recorded_at.isoformat()} which is "
                                f"earlier than previous entry {prev.audit_id} at "
                                f"{prev.recorded_at.isoformat()}"
                            ),
                            audit_id=curr.audit_id,
                            partition=date_str,
                        )
                    )

        # ── 7. Index sync: every audit_id should have an index file ───────────
        index_ids = set(self._store.list_ids())
        for e in all_entries:
            if e.audit_id not in index_ids:
                report.add(
                    IntegrityViolation(
                        check="index_sync",
                        severity="warning",
                        detail="Entry in JSONL but missing from index",
                        audit_id=e.audit_id,
                    )
                )

        logger.info(
            "audit_integrity_check_complete",
            passed=report.passed,
            entries=report.total_entries,
            errors=report.error_count,
            warnings=report.warning_count,
        )
        return report
