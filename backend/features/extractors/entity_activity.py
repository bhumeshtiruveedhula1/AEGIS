"""
backend.features.extractors.entity_activity — Entity Activity Feature Extractor
================================================================================
Module 2.2 — Behavioral Feature Engine

Computes 4 entity activity summary features from the entity baseline,
providing downstream models with aggregate behavioral fingerprint numbers.

Features
--------
entity_unique_dst_ips    : Unique destination IPs seen across all baseline events
entity_unique_processes  : Unique process names seen across all baseline events
entity_auth_failure_count: Cumulative auth failures in baseline
entity_modbus_event_count: Cumulative OT/Modbus events in baseline

Design notes
------------
- These are aggregate statistics from the baseline, not event-level features.
  They characterise the ENTITY, not the current event.
- High entity_unique_dst_ips + novel dst_ip is a compound signal for
  lateral movement (already diverse destinations, still exploring new ones).
- High entity_auth_failure_count establishes a noisy baseline (spray
  activity) vs an entity that normally succeeds.
- These features are safe for all entity types — fields default to 0.0
  when the sub-baseline is None (e.g., no network baseline for OT nodes).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.features.extractors import BaseExtractor

if TYPE_CHECKING:
    from backend.baseline.models import EntityBaseline
    from backend.normalization.models import CanonicalEvent


class EntityActivityExtractor(BaseExtractor):
    """Aggregate entity activity summary features from baseline."""

    @property
    def group_name(self) -> str:
        return "entity_activity"

    @property
    def feature_names(self) -> list[str]:
        return [
            "entity_unique_dst_ips",
            "entity_unique_processes",
            "entity_auth_failure_count",
            "entity_modbus_event_count",
        ]

    def extract(
        self,
        event: "CanonicalEvent",
        baseline: "EntityBaseline | None",
    ) -> dict[str, float]:
        if baseline is None:
            return {name: 0.0 for name in self.feature_names}

        # Unique dst IPs
        unique_dst = 0.0
        if baseline.network is not None:
            unique_dst = float(len(baseline.network.unique_dst_ips))

        # Unique processes
        unique_proc = 0.0
        if baseline.process is not None:
            unique_proc = float(len(baseline.process.unique_processes))

        # Auth failure count
        auth_fail_count = 0.0
        if baseline.auth is not None:
            auth_fail_count = float(baseline.auth.failure_count)

        # Modbus event count
        mb_count = 0.0
        if baseline.modbus is not None:
            mb_count = float(baseline.modbus.modbus_event_count)

        return {
            "entity_unique_dst_ips": unique_dst,
            "entity_unique_processes": unique_proc,
            "entity_auth_failure_count": auth_fail_count,
            "entity_modbus_event_count": mb_count,
        }
