"""tests/unit/replay/conftest.py — Shared fixtures for replay engine tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from backend.audit.models import AuditEntry, AuditEventType, AuditMetadata
from backend.replay.models import ReplayEventType, ReplayFrame, ReplaySession, ReplayTimeline
from backend.replay.player import ReplayPlayer
from backend.replay.service import ReplayService
from backend.replay.storage import ReplayStore
from backend.replay.timeline import TimelineBuilder

if TYPE_CHECKING:
    from pathlib import Path


# ── Audit helpers ─────────────────────────────────────────────────────────────

def _make_audit_entry(
    *,
    alert_id: str = "a-001",
    context_id: str | None = None,
    orchestration_id: str | None = None,
    source_module: str = "detection",
    event_type: AuditEventType = AuditEventType.DETECTION_ALERT,
    ts: datetime | None = None,
    severity: str = "high",
    outcome: str = "success",
    description: str = "test event",
) -> AuditEntry:
    t = ts or datetime.now(UTC)
    return AuditEntry(
        event_type=event_type,
        timestamp=t,
        recorded_at=t + timedelta(milliseconds=1),
        metadata=AuditMetadata(
            source_module=source_module,
            alert_id=alert_id,
            context_id=context_id,
            orchestration_id=orchestration_id,
        ),
        severity=severity,
        outcome=outcome,
        description=description,
    )


def _make_frame(index: int = 0, *, ts: datetime | None = None) -> ReplayFrame:
    t = ts or datetime.now(UTC)
    return ReplayFrame(
        frame_index=index,
        audit_id=f"aud-test-{index}",
        event_type=ReplayEventType.DETECTION,
        timestamp=t,
        recorded_at=t + timedelta(milliseconds=1),
        source_module="detection",
        description=f"frame {index}",
    )


def _make_timeline(n: int = 3) -> ReplayTimeline:
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    frames = tuple(_make_frame(i, ts=base + timedelta(minutes=i)) for i in range(n))
    return ReplayTimeline(frames=frames, source_query="test")


def _make_session(n: int = 3) -> ReplaySession:
    return ReplaySession(
        name="test session",
        replay_type="alert",
        alert_id="a-001",
        timeline=_make_timeline(n),
    )


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def store_dir(tmp_path: Path) -> Path:
    return tmp_path / "replay"


@pytest.fixture()
def store(store_dir: Path) -> ReplayStore:
    return ReplayStore(store_dir)


@pytest.fixture()
def service(store_dir: Path) -> ReplayService:
    from backend.audit.service import AuditService
    audit = AuditService(store_dir=store_dir / "audit")
    return ReplayService(store_dir=store_dir, audit_service=audit)


@pytest.fixture()
def builder() -> TimelineBuilder:
    return TimelineBuilder()


@pytest.fixture()
def sample_entries() -> list[AuditEntry]:
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    return [
        _make_audit_entry(ts=base, event_type=AuditEventType.DETECTION_ALERT),
        _make_audit_entry(ts=base + timedelta(minutes=1), event_type=AuditEventType.SHAP_EXPLANATION),
        _make_audit_entry(ts=base + timedelta(minutes=2), event_type=AuditEventType.MITRE_MAPPED),
        _make_audit_entry(ts=base + timedelta(minutes=3), event_type=AuditEventType.CONTEXT_CREATED),
        _make_audit_entry(ts=base + timedelta(minutes=4), event_type=AuditEventType.ORCHESTRATION_CREATED),
    ]


@pytest.fixture()
def session_3() -> ReplaySession:
    return _make_session(3)


@pytest.fixture()
def session_1() -> ReplaySession:
    return _make_session(1)


@pytest.fixture()
def empty_session() -> ReplaySession:
    return ReplaySession(
        name="empty",
        replay_type="audit",
        timeline=ReplayTimeline(frames=(), source_query="empty"),
    )


@pytest.fixture()
def player_3(session_3: ReplaySession) -> ReplayPlayer:
    return ReplayPlayer(session_3)


@pytest.fixture()
def started_player(session_3: ReplaySession) -> ReplayPlayer:
    p = ReplayPlayer(session_3)
    p.start()
    return p
