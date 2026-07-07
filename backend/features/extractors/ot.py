"""
backend.features.extractors.ot — OT/Modbus Feature Extractor
=============================================================
Module 2.2 — Behavioral Feature Engine

Computes 7 operational technology (OT) / ICS behavioral features
from Modbus protocol context compared against the entity's baseline
ModbusBaseline.

Features
--------
modbus_register_z_score      : Z-score of register address vs baseline
modbus_value_z_score         : Z-score of register value vs baseline
modbus_register_is_in_range  : 1.0 if register within baseline [min, max]
modbus_value_is_in_range     : 1.0 if value within baseline [min, max]
modbus_function_code_is_novel: 1.0 if function code not in baseline dist
supervisory_host_is_novel    : 1.0 if supervisory IP not in baseline set
modbus_event_count_baseline  : Total OT events tracked in baseline

Design notes
------------
- OT features are only meaningful for OT node events that have modbus_*
  fields populated. All features return 0.0 for non-OT events.
- Range features (is_in_range) are complementary to z-score: an outlier
  register may be within range but still statistically unusual.
- supervisory_host_is_novel is one of the highest-value OT features —
  any new SCADA host contacting an OT device warrants attention.
- modbus_function_code_is_novel catches write commands (FC06) on
  read-only baseline entities.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.features.extractors import BaseExtractor, binary, safe_z_score

if TYPE_CHECKING:
    from backend.baseline.models import EntityBaseline, ModbusBaseline
    from backend.normalization.models import CanonicalEvent


class OTExtractor(BaseExtractor):
    """OT/Modbus behavioral features for industrial control system events."""

    @property
    def group_name(self) -> str:
        return "ot"

    @property
    def feature_names(self) -> list[str]:
        return [
            "modbus_register_z_score",
            "modbus_value_z_score",
            "modbus_register_is_in_range",
            "modbus_value_is_in_range",
            "modbus_function_code_is_novel",
            "supervisory_host_is_novel",
            "modbus_event_count_baseline",
        ]

    def extract(
        self,
        event: "CanonicalEvent",
        baseline: "EntityBaseline | None",
    ) -> dict[str, float]:
        mb: ModbusBaseline | None = None
        if baseline is not None:
            mb = baseline.modbus

        # Check whether this event has any OT context
        has_ot_context = (
            event.modbus_register is not None
            or event.modbus_value is not None
            or event.modbus_function_code is not None
            or event.supervisory_host is not None
        )
        if not has_ot_context:
            return {name: 0.0 for name in self.feature_names}

        # ── Register deviation ─────────────────────────────────────────────
        reg_z = 0.0
        reg_in_range = 0.0
        if event.modbus_register is not None and mb is not None:
            if mb.register_stats is not None:
                reg_z = safe_z_score(
                    float(event.modbus_register),
                    mb.register_stats.mean,
                    mb.register_stats.std,
                )
                # Range check
                mn = mb.register_stats.minimum
                mx = mb.register_stats.maximum
                if mn is not None and mx is not None:
                    reg_in_range = binary(mn <= event.modbus_register <= mx)

        # ── Value deviation ────────────────────────────────────────────────
        val_z = 0.0
        val_in_range = 0.0
        if event.modbus_value is not None and mb is not None:
            if mb.value_stats is not None:
                val_z = safe_z_score(
                    float(event.modbus_value),
                    mb.value_stats.mean,
                    mb.value_stats.std,
                )
                mn = mb.value_stats.minimum
                mx = mb.value_stats.maximum
                if mn is not None and mx is not None:
                    val_in_range = binary(mn <= event.modbus_value <= mx)

        # ── Function code novelty ──────────────────────────────────────────
        fc_novel = 0.0
        if event.modbus_function_code is not None and mb is not None:
            known_fcs = {fc.lower() for fc in mb.function_code_distribution}
            fc_novel = binary(event.modbus_function_code.lower() not in known_fcs)

        # ── Supervisory host novelty ───────────────────────────────────────
        sup_novel = 0.0
        if event.supervisory_host is not None and mb is not None:
            known_hosts = {h.lower() for h in mb.known_supervisory_hosts}
            sup_novel = binary(event.supervisory_host.lower() not in known_hosts)

        # ── Summary count ──────────────────────────────────────────────────
        mb_event_count = 0.0
        if mb is not None:
            mb_event_count = float(mb.modbus_event_count)

        return {
            "modbus_register_z_score": reg_z,
            "modbus_value_z_score": val_z,
            "modbus_register_is_in_range": reg_in_range,
            "modbus_value_is_in_range": val_in_range,
            "modbus_function_code_is_novel": fc_novel,
            "supervisory_host_is_novel": sup_novel,
            "modbus_event_count_baseline": mb_event_count,
        }
