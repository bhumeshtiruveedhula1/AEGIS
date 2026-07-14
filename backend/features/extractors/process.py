"""
backend.features.extractors.process — Process Feature Extractor
===============================================================
Module 2.2 — Behavioral Feature Engine

Computes 8 process behavioral features comparing the current event's
process context against the entity's baseline ProcessBaseline.

Features
--------
process_is_novel           : 1.0 if process not seen in baseline
parent_process_is_novel    : 1.0 if parent_process not seen in baseline
parent_child_pair_is_novel : 1.0 if "parent::child" pair not in baseline
process_frequency_rank     : Rank of this process by frequency (0=most common)
unique_processes_baseline  : Count of unique processes in baseline
process_event_count_baseline: Total process events in baseline
pid_z_score                : Z-score of PID vs baseline PID distribution
has_command_line           : 1.0 if command_line is not None in this event

Design notes
------------
- Parent-child pair novelty encodes the pair "parent::child" as a single
  categorical feature — this is a stronger signal than individual novelty.
- PID z-score: unusual PID values (very high or very low) can indicate
  process injection or staged execution.
- All process features return 0.0 (not applicable) when event has no
  process field (OT/attacker events).

Cold-start novelty default — Architectural Decision (F02, Option A)
--------------------------------------------------------------------
process_is_novel, parent_process_is_novel, parent_child_pair_is_novel
all default to 0.0 when baseline is None.

Rationale: novelty requires a known reference set. On cold-start, no
process set exists to compare against, so novelty is undefined. Setting
0.0 is the conservative choice; the `baseline_presence` feature group
signals cold-start state to the Isolation Forest via has_*_baseline
features, which the model uses as context when all novelty features are 0.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.features.extractors import (
    BaseExtractor,
    binary,
    frequency_rank,
    safe_z_score,
)

if TYPE_CHECKING:
    from backend.baseline.models import EntityBaseline, ProcessBaseline
    from backend.normalization.models import CanonicalEvent


class ProcessExtractor(BaseExtractor):
    """Process behavior novelty and deviation features."""

    @property
    def group_name(self) -> str:
        return "process"

    @property
    def feature_names(self) -> list[str]:
        return [
            "process_is_novel",
            "parent_process_is_novel",
            "parent_child_pair_is_novel",
            "process_frequency_rank",
            "unique_processes_baseline",
            "process_event_count_baseline",
            "pid_z_score",
            "has_command_line",
        ]

    def extract(
        self,
        event: CanonicalEvent,
        baseline: EntityBaseline | None,
    ) -> dict[str, float]:
        proc: ProcessBaseline | None = None
        if baseline is not None:
            proc = baseline.process

        # ── has_command_line — event-level, no baseline needed ────────────
        has_cmd = binary(event.command_line is not None)

        if event.process is None:
            # Non-process event — all process features are not applicable
            return {
                "process_is_novel": 0.0,
                "parent_process_is_novel": 0.0,
                "parent_child_pair_is_novel": 0.0,
                "process_frequency_rank": 0.0,
                "unique_processes_baseline": 0.0,
                "process_event_count_baseline": 0.0,
                "pid_z_score": 0.0,
                "has_command_line": has_cmd,
            }

        proc_lower = event.process.lower()

        # ── Process novelty ────────────────────────────────────────────────
        proc_novel = 0.0
        proc_rank = 0.0
        if proc is not None:
            known = {p.lower() for p in proc.unique_processes}
            proc_novel = binary(proc_lower not in known)
            proc_rank = frequency_rank(event.process, proc.process_frequency)

        # ── Parent process novelty ─────────────────────────────────────────
        parent_novel = 0.0
        if proc is not None and event.parent_process is not None:
            known_parents = {p.lower() for p in proc.unique_parent_processes}
            parent_novel = binary(event.parent_process.lower() not in known_parents)

        # ── Parent-child pair novelty ──────────────────────────────────────
        pair_novel = 0.0
        if proc is not None and event.parent_process is not None:
            pair_key = f"{event.parent_process.lower()}__{proc_lower}"
            pair_novel = binary(pair_key not in proc.parent_child_pairs)

        # ── Summary counts ─────────────────────────────────────────────────
        unique_proc_count = 0.0
        proc_event_count = 0.0
        if proc is not None:
            unique_proc_count = float(len(proc.unique_processes))
            proc_event_count = float(proc.process_event_count)

        # ── PID z-score ────────────────────────────────────────────────────
        pid_z = 0.0
        if proc is not None and event.pid is not None and proc.pid_stats is not None:
            pid_z = safe_z_score(
                float(event.pid),
                proc.pid_stats.mean,
                proc.pid_stats.std,
            )

        return {
            "process_is_novel": proc_novel,
            "parent_process_is_novel": parent_novel,
            "parent_child_pair_is_novel": pair_novel,
            "process_frequency_rank": proc_rank,
            "unique_processes_baseline": unique_proc_count,
            "process_event_count_baseline": proc_event_count,
            "pid_z_score": pid_z,
            "has_command_line": has_cmd,
        }
