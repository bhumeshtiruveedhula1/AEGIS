"""tests/unit/audit/test_storage.py — AuditStore JSONL persistence tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from backend.audit.exceptions import AuditRecordNotFoundError
from backend.audit.models import AuditEntry, AuditEventType, AuditMetadata

if TYPE_CHECKING:
    from backend.audit.storage import AuditStore


def _make_entry(
    event_type: AuditEventType = AuditEventType.DETECTION_ALERT,
    source_module: str = "detection",
    alert_id: str = "a-001",
    ts: datetime | None = None,
) -> AuditEntry:
    return AuditEntry(
        event_type=event_type,
        metadata=AuditMetadata(source_module=source_module, alert_id=alert_id),
        recorded_at=ts or datetime.now(UTC),
        timestamp=ts or datetime.now(UTC),
    )


class TestAuditStoreSave:
    def test_save_creates_jsonl(self, store: AuditStore) -> None:
        e = _make_entry()
        path = store.save(e)
        assert path.exists()
        assert path.suffix == ".jsonl"

    def test_save_appends_not_overwrites(self, store: AuditStore) -> None:
        e1 = _make_entry(alert_id="a-001")
        e2 = _make_entry(alert_id="a-002")
        store.save(e1)
        store.save(e2)
        path = store._daily_jsonl_path(datetime.now(UTC))
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) == 2

    def test_save_creates_index(self, store: AuditStore) -> None:
        e = _make_entry()
        store.save(e)
        idx = store._index_dir / f"{e.audit_id}.json"
        assert idx.exists()

    def test_save_batch_groups_by_date(self, store: AuditStore) -> None:
        now = datetime.now(UTC)
        yesterday = now - timedelta(days=1)
        e1 = _make_entry(ts=now)
        e2 = _make_entry(ts=now)
        e3 = _make_entry(ts=yesterday)
        paths = store.save_batch([e1, e2, e3])
        # Two distinct date partitions
        assert len(paths) == 2


class TestAuditStoreLoad:
    def test_load_by_id(self, store: AuditStore) -> None:
        e = _make_entry()
        store.save(e)
        loaded = store.load(e.audit_id)
        assert loaded.audit_id == e.audit_id

    def test_load_missing_raises(self, store: AuditStore) -> None:
        with pytest.raises(AuditRecordNotFoundError):
            store.load("nonexistent-id")

    def test_load_for_date_returns_todays(self, store: AuditStore) -> None:
        e1 = _make_entry(alert_id="a-001")
        e2 = _make_entry(alert_id="a-002")
        store.save(e1)
        store.save(e2)
        results = store.load_for_date(datetime.now(UTC))
        assert len(results) == 2

    def test_load_for_date_empty_when_no_data(self, store: AuditStore) -> None:
        yesterday = datetime.now(UTC) - timedelta(days=1)
        results = store.load_for_date(yesterday)
        assert results == []

    def test_load_all_returns_all_partitions(self, store: AuditStore) -> None:
        now = datetime.now(UTC)
        yesterday = now - timedelta(days=1)
        e1 = _make_entry(ts=now)
        e2 = _make_entry(ts=yesterday)
        store.save_batch([e1, e2])
        all_e = store.load_all()
        assert len(all_e) == 2


class TestAuditStoreListing:
    def test_list_ids(self, store: AuditStore) -> None:
        e1 = _make_entry()
        e2 = _make_entry()
        store.save(e1)
        store.save(e2)
        ids = store.list_ids()
        assert e1.audit_id in ids
        assert e2.audit_id in ids

    def test_list_dates(self, store: AuditStore) -> None:
        store.save(_make_entry())
        dates = store.list_dates()
        assert len(dates) == 1
        today_str = datetime.now(UTC).strftime("%Y-%m-%d")
        assert today_str in dates

    def test_count_all(self, store: AuditStore) -> None:
        for _ in range(5):
            store.save(_make_entry())
        assert store.count_all() == 5


class TestAuditStoreAppendOnly:
    def test_save_does_not_delete_existing(self, store: AuditStore) -> None:
        """Saving a new entry must not erase prior entries — append-only."""
        for _ in range(3):
            store.save(_make_entry())
        path = store._daily_jsonl_path(datetime.now(UTC))
        lines_before = sum(1 for ln in path.read_text().splitlines() if ln.strip())
        store.save(_make_entry())
        lines_after = sum(1 for ln in path.read_text().splitlines() if ln.strip())
        assert lines_after == lines_before + 1

    def test_corrupt_lines_skipped_gracefully(self, store: AuditStore) -> None:
        e = _make_entry()
        store.save(e)
        path = store._daily_jsonl_path(datetime.now(UTC))
        # Inject a corrupt line
        path.open("a").write("NOT_VALID_JSON\n")
        results = store.load_for_date(datetime.now(UTC))
        # The valid entry is still returned; the corrupt line is skipped
        assert len(results) == 1
        assert results[0].audit_id == e.audit_id
