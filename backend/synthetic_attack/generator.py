"""
backend.synthetic_attack.generator — Attack Event Generator
============================================================
Module 3.X — Synthetic Attack Generation

AttackGenerator expands an AttackScenario into a list of CanonicalEvents.

Design
------
- Purely functional core: scenario + template → [CanonicalEvent]
- No I/O, no scheduling, no storage
- Generates deterministic event sequences when a seed is provided
- Produces events accepted by the existing Normalizer without modification
- All field values come from the template stage definitions + scenario entity map
- Timestamps respect the scheduler's pre-computed timeline
"""

from __future__ import annotations

import random
import string
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from backend.normalization.models import CanonicalEvent
from backend.shared.utils.id_utils import generate_id
from backend.synthetic_attack.exceptions import GenerationError
from backend.synthetic_attack.models import (
    AttackExecution,
    AttackScenario,
    AttackStage,
    AttackTemplate,
)

logger = structlog.get_logger(__name__)

# Per-event time jitter window (seconds) — adds realism without breaking ordering
_JITTER_WINDOW_SEC: float = 0.5


class AttackGenerator:
    """
    Expands a scenario + template into concrete CanonicalEvents.

    Parameters
    ----------
    seed : Optional random seed for deterministic output. None = non-deterministic.
    """

    def __init__(self, *, seed: int | None = None) -> None:
        self._rng = random.Random(seed)

    # ── Public API ────────────────────────────────────────────────────────────

    def generate(
        self,
        scenario: AttackScenario,
        template: AttackTemplate,
        stage_start_times: dict[str, datetime],
    ) -> AttackExecution:
        """
        Generate all CanonicalEvents for one scenario.

        Parameters
        ----------
        scenario          : Configured attack scenario with entity bindings.
        template          : The template being executed.
        stage_start_times : Pre-computed start time per stage_id from Scheduler.

        Returns
        -------
        AttackExecution   : Contains all generated events as serialised dicts.
        """
        all_events: list[CanonicalEvent] = []
        stage_counts: dict[str, int] = {}

        try:
            for stage in template.stages:
                # Apply any scenario-level stage overrides
                stage = self._apply_overrides(stage, scenario)

                start = stage_start_times.get(stage.stage_id, scenario.start_time)
                events = self._generate_stage(stage, scenario, start)
                all_events.extend(events)
                stage_counts[stage.stage_id] = len(events)

        except Exception as exc:
            raise GenerationError(
                f"Event generation failed for scenario {scenario.scenario_id}: {exc}",
                context={"scenario_id": scenario.scenario_id, "cause": str(exc)},
            ) from exc

        first_ts = all_events[0].timestamp if all_events else scenario.start_time
        last_ts = all_events[-1].timestamp if all_events else scenario.start_time

        execution = AttackExecution(
            scenario_id=scenario.scenario_id,
            template_id=template.template_id,
            stage_event_counts=stage_counts,
            total_events=len(all_events),
            first_event_time=first_ts,
            last_event_time=last_ts,
            event_payloads=[e.model_dump(mode="json") for e in all_events],
            tags=scenario.tags,
        )

        logger.info(
            "attack_generation_complete",
            scenario_id=scenario.scenario_id,
            template_id=template.template_id,
            total_events=len(all_events),
        )
        return execution

    def events_from_execution(self, execution: AttackExecution) -> list[CanonicalEvent]:
        """Deserialise events stored in an AttackExecution back to CanonicalEvent objects."""
        return [CanonicalEvent.model_validate(p) for p in execution.event_payloads]

    # ── Stage-level generation ────────────────────────────────────────────────

    def _generate_stage(
        self,
        stage: AttackStage,
        scenario: AttackScenario,
        stage_start: datetime,
    ) -> list[CanonicalEvent]:
        """Generate all events for one stage."""
        entity_map = scenario.entity_map
        events: list[CanonicalEvent] = []

        for i in range(stage.event_count):
            # Inter-event spread: events in the same stage are spread across the delay window
            spread = stage.delay_seconds if stage.delay_seconds > 0 else 1.0
            offset = (spread / max(stage.event_count, 1)) * i
            jitter = self._rng.uniform(-_JITTER_WINDOW_SEC, _JITTER_WINDOW_SEC) if not scenario.compress_time else 0.0
            ts = stage_start + timedelta(seconds=offset + jitter)
            ts = ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts

            event = self._build_canonical_event(stage, entity_map, ts, i)
            events.append(event)

        return events

    def _build_canonical_event(
        self,
        stage: AttackStage,
        entity_map: dict[str, str],
        ts: datetime,
        index: int,
    ) -> CanonicalEvent:
        """Build one CanonicalEvent from a stage definition."""
        host = self._render(stage.host_template, entity_map)
        user = self._render(stage.user_template, entity_map)
        resource = self._render(stage.resource_template, entity_map) if stage.resource_template else ""
        src_ip = self._render(stage.src_ip_template, entity_map) if stage.src_ip_template else None
        dst_ip = self._render(stage.dst_ip_template, entity_map) if stage.dst_ip_template else None
        process = self._render(stage.process_template, entity_map) if stage.process_template else None
        cmd = self._render(stage.command_line_template, entity_map) if stage.command_line_template else None

        # Construct a realistic raw_log for the Normalizer
        raw_log = self._build_raw_log(stage, host, user, resource, index)

        extra: dict[str, Any] = {
            "synthetic": True,
            "mitre_technique_hint": stage.mitre_technique_hint,
            "mitre_tactic_hint": stage.mitre_tactic_hint,
            **stage.extra_context,
        }

        return CanonicalEvent(
            event_id=f"syn-{generate_id()}",
            timestamp=ts,
            source=stage.source,
            event_type=stage.event_type,
            host=host,
            user=user,
            resource=resource,
            action=stage.action,
            result=stage.result,
            raw_log=raw_log,
            # Process fields
            process=process,
            command_line=cmd,
            # Network fields
            src_ip=src_ip,
            dst_ip=dst_ip,
            port=stage.port,
            protocol=stage.protocol if stage.protocol else None,
            bytes_out=stage.bytes_out_hint if stage.bytes_out_hint > 0 else None,
            # OT/ICS fields
            modbus_register=stage.modbus_register,
            modbus_value=stage.modbus_value,
            modbus_function_code=str(stage.modbus_function_code) if stage.modbus_function_code is not None else None,
            supervisory_host=self._render(stage.extra_context.get("supervisory_host", ""), entity_map) or None,
            # Windows fields
            logon_type=stage.logon_type_hint or None,
            auth_package=stage.auth_package_hint or None,
            windows_event_id=stage.windows_event_id_hint,
            extra_fields=extra,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _render(template: str, entity_map: dict[str, str]) -> str:
        """Substitute {key} tokens in a template string using the entity map."""
        result = template
        for key, value in entity_map.items():
            result = result.replace(f"{{{key}}}", value)
        return result

    @staticmethod
    def _apply_overrides(stage: AttackStage, scenario: AttackScenario) -> AttackStage:
        """Apply scenario-level stage overrides if defined."""
        overrides = scenario.stage_overrides.get(stage.stage_id, {})
        if overrides:
            return stage.model_copy(update=overrides)
        return stage

    def _build_raw_log(
        self,
        stage: AttackStage,
        host: str,
        user: str,
        resource: str,
        index: int,
    ) -> str:
        """Build a realistic raw_log string for the CanonicalEvent."""
        parts = [
            f"source={stage.source}",
            f"event_type={stage.event_type}",
            f"action={stage.action}",
            f"result={stage.result}",
            f"host={host}",
            f"user={user}",
        ]
        if resource:
            parts.append(f"resource={resource}")
        if stage.windows_event_id_hint:
            parts.append(f"EventID={stage.windows_event_id_hint}")
        if stage.modbus_register is not None:
            parts.append(f"register={stage.modbus_register} value={stage.modbus_value}")
        # Add a sequence suffix to differentiate events within the same stage
        parts.append(f"seq={index}")
        return " ".join(parts)
