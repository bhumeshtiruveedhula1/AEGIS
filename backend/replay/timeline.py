"""
backend.replay.timeline — Replay Timeline Builder
==================================================
Module 7.3 — Forensic Replay Engine

Constructs deterministic, chronologically ordered ReplayTimeline objects
from stored AuditEntry records.

The builder is read-only — it never regenerates source data.
It only reads from the Audit Ledger.

Responsibilities
----------------
- Accept audit entries and convert them to ReplayFrames
- Sort chronologically (by timestamp, then recorded_at as tie-breaker)
- Assign sequential frame_index values (0-based)
- Map AuditEventType → ReplayEventType
- Build the immutable ReplayTimeline
"""

from __future__ import annotations

import structlog

from backend.audit.models import AuditEntry, AuditEventType
from backend.replay.exceptions import ReplayTimelineError
from backend.replay.models import ReplayEventType, ReplayFrame, ReplayTimeline

logger = structlog.get_logger(__name__)

# ── AuditEventType → ReplayEventType mapping ──────────────────────────────────

_AUDIT_TO_REPLAY: dict[str, ReplayEventType] = {
    AuditEventType.DETECTION_ALERT.value:      ReplayEventType.DETECTION,
    AuditEventType.DETECTION_SCORED.value:     ReplayEventType.DETECTION,
    AuditEventType.SHAP_EXPLANATION.value:     ReplayEventType.EXPLANATION,
    AuditEventType.MITRE_MAPPED.value:         ReplayEventType.MITRE_MAPPING,
    AuditEventType.ATTACK_GRAPH_BUILT.value:   ReplayEventType.ATTACK_GRAPH,
    AuditEventType.ATTACK_CHAIN_DETECTED.value: ReplayEventType.ATTACK_CHAIN,
    AuditEventType.CONTEXT_CREATED.value:      ReplayEventType.CONTEXT,
    AuditEventType.ORCHESTRATION_CREATED.value: ReplayEventType.ORCHESTRATION,
    AuditEventType.APPROVAL_PENDING.value:     ReplayEventType.APPROVAL,
    AuditEventType.APPROVAL_APPROVED.value:    ReplayEventType.APPROVAL,
    AuditEventType.APPROVAL_REJECTED.value:    ReplayEventType.APPROVAL,
    AuditEventType.APPROVAL_EXPIRED.value:     ReplayEventType.APPROVAL,
    AuditEventType.EXECUTION_SIMULATED.value:  ReplayEventType.EXECUTION,
    AuditEventType.DASHBOARD_ACCESSED.value:   ReplayEventType.AUDIT,
    AuditEventType.PLATFORM_STARTED.value:     ReplayEventType.PLATFORM,
    AuditEventType.PLATFORM_STOPPED.value:     ReplayEventType.PLATFORM,
    AuditEventType.METRIC_COLLECTED.value:     ReplayEventType.AUDIT,
    AuditEventType.INTEGRITY_CHECKED.value:    ReplayEventType.AUDIT,
    AuditEventType.CUSTOM.value:               ReplayEventType.AUDIT,
}


def _map_event_type(audit_event_type: str) -> ReplayEventType:
    return _AUDIT_TO_REPLAY.get(audit_event_type, ReplayEventType.UNKNOWN)


def _entry_to_frame(entry: AuditEntry, frame_index: int) -> ReplayFrame:
    """Convert a single AuditEntry into a ReplayFrame."""
    m = entry.metadata
    correlation: dict[str, str | None] = {
        "alert_id": m.alert_id,
        "context_id": m.context_id,
        "orchestration_id": m.orchestration_id,
        "entity_id": m.entity_id,
        "host": m.host,
        "user": m.user,
    }
    return ReplayFrame(
        frame_index=frame_index,
        audit_id=entry.audit_id,
        event_type=_map_event_type(str(entry.event_type)),
        timestamp=entry.timestamp,
        recorded_at=entry.recorded_at,
        source_module=m.source_module,
        description=entry.description,
        severity=entry.severity,
        outcome=entry.outcome,
        actor_id=entry.actor.actor_id,
        correlation=correlation,
        payload=dict(entry.payload),
    )


class TimelineBuilder:
    """
    Builds a deterministic ReplayTimeline from AuditEntry records.

    Usage
    -----
        builder = TimelineBuilder()
        timeline = builder.build(entries, source_query="alert a-001")
    """

    def build(
        self,
        entries: list[AuditEntry],
        *,
        source_query: str = "",
    ) -> ReplayTimeline:
        """
        Build a ReplayTimeline from a list of AuditEntry records.

        Steps:
        1. Sort by (timestamp, recorded_at, sequence_number) — deterministic
        2. Convert each entry to a ReplayFrame with sequential frame_index
        3. Wrap in an immutable ReplayTimeline

        Parameters
        ----------
        entries      : AuditEntry records to include in the timeline.
        source_query : Human-readable description of what was replayed.

        Returns
        -------
        ReplayTimeline : Immutable, ordered timeline.

        Raises
        ------
        ReplayTimelineError : If any entry cannot be converted.
        """
        if not entries:
            logger.debug("replay_timeline_built_empty", source_query=source_query)
            return ReplayTimeline(frames=(), source_query=source_query)

        try:
            sorted_entries = sorted(
                entries,
                key=lambda e: (e.timestamp, e.recorded_at, e.sequence_number),
            )
        except Exception as exc:
            raise ReplayTimelineError(
                f"Failed to sort audit entries for timeline: {exc}",
                context={"source_query": source_query, "count": len(entries)},
            ) from exc

        frames: list[ReplayFrame] = []
        for idx, entry in enumerate(sorted_entries):
            try:
                frames.append(_entry_to_frame(entry, idx))
            except Exception as exc:
                raise ReplayTimelineError(
                    f"Failed to convert entry {entry.audit_id} to ReplayFrame: {exc}",
                    context={"audit_id": entry.audit_id, "index": idx},
                ) from exc

        timeline = ReplayTimeline(
            frames=tuple(frames),
            source_query=source_query,
        )

        logger.debug(
            "replay_timeline_built",
            frames=len(frames),
            source_query=source_query,
            first_at=str(timeline.first_at)[:19] if timeline.first_at else None,
            last_at=str(timeline.last_at)[:19] if timeline.last_at else None,
        )
        return timeline

    def build_for_context(
        self,
        entries: list[AuditEntry],
        context_id: str,
    ) -> ReplayTimeline:
        """Filter to context_id and build timeline."""
        filtered = [e for e in entries if e.metadata.context_id == context_id]
        return self.build(filtered, source_query=f"context:{context_id}")

    def build_for_alert(
        self,
        entries: list[AuditEntry],
        alert_id: str,
    ) -> ReplayTimeline:
        """Filter to alert_id and build timeline."""
        filtered = [e for e in entries if e.metadata.alert_id == alert_id]
        return self.build(filtered, source_query=f"alert:{alert_id}")

    def build_for_orchestration(
        self,
        entries: list[AuditEntry],
        orchestration_id: str,
    ) -> ReplayTimeline:
        """Filter to orchestration_id and build timeline."""
        filtered = [e for e in entries if e.metadata.orchestration_id == orchestration_id]
        return self.build(filtered, source_query=f"orchestration:{orchestration_id}")
