"""tests/unit/orchestrator/test_audit.py — OrchestratorAuditLogger tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from backend.orchestrator.audit import OrchestratorAuditLogger
from backend.orchestrator.models import OrchestratorAuditEvent


class TestOrchestratorAuditLogger:
    def test_log_event_returns_event(self, tmp_path: Path) -> None:
        logger = OrchestratorAuditLogger(tmp_path / "audit")
        evt = logger.log_event(
            orchestration_id="orch-1",
            alert_id="alert-1",
            event_type="playbook_selected",
        )
        assert isinstance(evt, OrchestratorAuditEvent)
        assert evt.event_type == "playbook_selected"

    def test_log_event_writes_jsonl(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        logger = OrchestratorAuditLogger(audit_dir)
        logger.log_event("orch-1", "alert-1", "test_event")
        files = list(audit_dir.glob("audit_*.jsonl"))
        assert len(files) == 1
        content = files[0].read_text()
        assert "test_event" in content

    def test_load_for_orchestration(self, tmp_path: Path) -> None:
        logger = OrchestratorAuditLogger(tmp_path / "audit")
        logger.log_event("orch-1", "alert-1", "event_a")
        logger.log_event("orch-2", "alert-2", "event_b")
        events = logger.load_for_orchestration("orch-1")
        assert len(events) == 1
        assert events[0].orchestration_id == "orch-1"

    def test_load_for_orchestration_returns_all_events(self, tmp_path: Path) -> None:
        logger = OrchestratorAuditLogger(tmp_path / "audit")
        for evt_type in ("playbook_selected", "approval_requested", "approved"):
            logger.log_event("orch-x", "alert-x", evt_type)
        events = logger.load_for_orchestration("orch-x")
        assert len(events) == 3

    def test_load_for_date_returns_all(self, tmp_path: Path) -> None:
        logger = OrchestratorAuditLogger(tmp_path / "audit")
        logger.log_event("orch-1", "alert-1", "evt1")
        logger.log_event("orch-2", "alert-2", "evt2")
        events = logger.load_for_date()
        assert len(events) == 2

    def test_load_for_orchestration_empty_when_not_found(self, tmp_path: Path) -> None:
        logger = OrchestratorAuditLogger(tmp_path / "audit")
        events = logger.load_for_orchestration("nonexistent")
        assert events == []

    def test_actor_set_correctly(self, tmp_path: Path) -> None:
        logger = OrchestratorAuditLogger(tmp_path / "audit")
        evt = logger.log_event("orch-1", "alert-1", "approved", actor="soc@example.com")
        assert evt.actor == "soc@example.com"

    def test_detail_preserved(self, tmp_path: Path) -> None:
        logger = OrchestratorAuditLogger(tmp_path / "audit")
        detail = {"playbook_id": "isolate_host", "score": 0.85}
        evt = logger.log_event("orch-1", "a-1", "playbook_selected", detail=detail)
        assert evt.detail["playbook_id"] == "isolate_host"

    def test_events_ordered_by_timestamp(self, tmp_path: Path) -> None:
        logger = OrchestratorAuditLogger(tmp_path / "audit")
        logger.log_event("orch-1", "a-1", "first")
        logger.log_event("orch-1", "a-1", "second")
        events = logger.load_for_orchestration("orch-1")
        assert events[0].timestamp <= events[1].timestamp

    def test_unique_event_ids(self, tmp_path: Path) -> None:
        logger = OrchestratorAuditLogger(tmp_path / "audit")
        e1 = logger.log_event("o", "a", "e1")
        e2 = logger.log_event("o", "a", "e2")
        assert e1.event_id != e2.event_id
