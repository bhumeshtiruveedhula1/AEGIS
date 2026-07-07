"""
backend.baseline.reader_api — Baseline Query Interface for Feature Engine
=========================================================================
Module 2.1 — Baseline Generator

BaselineReader is the ONLY sanctioned interface for downstream modules
(Feature Engine, Module 2.2+) to access baseline data.

This is a clean read-only query API. Downstream modules MUST use this
class — they must NOT read from BaselineStore, BaselineProfile, or
EntityBaseline JSON files directly.

Design
------
- Loads the latest BaselineProfile from the BaselineStore on construction
  (or on demand via refresh()).
- Provides typed query methods for common access patterns.
- Returns None when no baseline exists for a requested entity
  (callers must handle cold-start gracefully).
- Never raises BaselineNotFoundError to callers — returns None instead.

Usage (Feature Engine)
----------------------
    reader = BaselineReader()

    # Get full entity baseline (for all fields)
    baseline = reader.get_entity(EntityKey("user", "svc-iis"))
    if baseline is None:
        # Cold-start: no baseline yet, skip scoring
        return

    # Get the time pattern only
    time_pattern = reader.get_time_pattern(EntityKey("host", "hospital-server-01"))

    # Get network baseline
    net = reader.get_network(EntityKey("source", "hospital_server"))

    # Check if a specific value was seen in baseline
    seen = reader.value_was_seen("host", "hospital-server-01", "process", "w3wp.exe")
"""

from __future__ import annotations

from pathlib import Path

import structlog

from backend.baseline.exceptions import (
    BaselineNotFoundError,
    BaselineVersionError,
)
from backend.baseline.models import (
    AuthBaseline,
    EntityBaseline,
    EntityKey,
    ModbusBaseline,
    NetworkBaseline,
    ProcessBaseline,
    TimePattern,
)
from backend.baseline.storage import BaselineStore

logger = structlog.get_logger(__name__)


class BaselineReader:
    """
    Read-only query interface to baseline data.

    Intended exclusively for the Feature Engine and downstream consumers.
    Loads the latest BaselineProfile from disk and provides typed query methods.

    Parameters
    ----------
    baseline_dir:  Root directory of the baseline store.
                   Defaults to data/baseline/.

    Raises
    ------
    BaselineNotFoundError if no baseline has been built yet and
    require_baseline=True (default: False).
    """

    def __init__(
        self,
        baseline_dir: Path | None = None,
        *,
        require_baseline: bool = False,
    ) -> None:
        self._store = BaselineStore(baseline_dir=baseline_dir)
        self._profile = None
        self._load_profile(require_baseline=require_baseline)

    def refresh(self) -> None:
        """
        Reload the latest baseline profile from disk.

        Call this when you know a new baseline has been built and you want
        the Feature Engine to pick up the latest data without restarting.
        """
        self._load_profile(require_baseline=False)
        logger.info("baseline_reader_refreshed")

    @property
    def is_ready(self) -> bool:
        """True if a baseline profile is loaded and available."""
        return self._profile is not None

    @property
    def profile_id(self) -> str | None:
        """ID of the currently loaded profile, or None if not loaded."""
        return self._profile.profile_id if self._profile else None

    # ── Entity access ───────────────────────────────────────────────────────

    def get_entity(self, entity_key: EntityKey) -> EntityBaseline | None:
        """
        Return the full EntityBaseline for a given entity.

        Returns None if:
        - No baseline has been built (cold-start).
        - This specific entity was not in the baseline data.

        Never raises — callers MUST check for None.
        """
        if self._profile is None:
            return None
        return self._profile.get_entity(entity_key)

    def get_entity_by_ids(
        self, entity_type: str, entity_id: str
    ) -> EntityBaseline | None:
        """
        Convenience wrapper using (type, id) strings instead of EntityKey.

        Returns None on any failure (invalid type, entity not found).
        """
        try:
            key = EntityKey(entity_type=entity_type, entity_id=entity_id)
        except Exception:  # noqa: BLE001
            return None
        return self.get_entity(key)

    # ── Sub-baseline access ─────────────────────────────────────────────────

    def get_time_pattern(self, entity_key: EntityKey) -> TimePattern | None:
        """Return the TimePattern for an entity, or None if unavailable."""
        baseline = self.get_entity(entity_key)
        if baseline is None:
            return None
        return baseline.time_pattern

    def get_network(self, entity_key: EntityKey) -> NetworkBaseline | None:
        """Return the NetworkBaseline for an entity, or None."""
        baseline = self.get_entity(entity_key)
        if baseline is None:
            return None
        return baseline.network

    def get_process(self, entity_key: EntityKey) -> ProcessBaseline | None:
        """Return the ProcessBaseline for an entity, or None."""
        baseline = self.get_entity(entity_key)
        if baseline is None:
            return None
        return baseline.process

    def get_modbus(self, entity_key: EntityKey) -> ModbusBaseline | None:
        """Return the ModbusBaseline for an entity, or None."""
        baseline = self.get_entity(entity_key)
        if baseline is None:
            return None
        return baseline.modbus

    def get_auth(self, entity_key: EntityKey) -> AuthBaseline | None:
        """Return the AuthBaseline for an entity, or None."""
        baseline = self.get_entity(entity_key)
        if baseline is None:
            return None
        return baseline.auth

    # ── Value-presence queries ──────────────────────────────────────────────

    def process_was_seen(
        self, entity_type: str, entity_id: str, process_name: str
    ) -> bool | None:
        """
        Return True if this process was seen in the baseline.
        Returns None if no baseline exists for this entity (cold-start).
        Returns False if baseline exists but this process was not seen.
        """
        baseline = self.get_entity_by_ids(entity_type, entity_id)
        if baseline is None:
            return None
        if baseline.process is None:
            return False
        return process_name.lower() in {p.lower() for p in baseline.process.unique_processes}

    def dst_ip_was_seen(
        self, entity_type: str, entity_id: str, ip: str
    ) -> bool | None:
        """
        Return True if this destination IP was seen in baseline network behavior.
        Returns None if no baseline (cold-start). False if IP is new.
        """
        baseline = self.get_entity_by_ids(entity_type, entity_id)
        if baseline is None:
            return None
        if baseline.network is None:
            return False
        return ip in baseline.network.unique_dst_ips

    def port_was_seen(
        self, entity_type: str, entity_id: str, port: int
    ) -> bool | None:
        """
        Return True if this port was seen in baseline network behavior.
        Returns None if no baseline. False if port is new.
        """
        baseline = self.get_entity_by_ids(entity_type, entity_id)
        if baseline is None:
            return None
        if baseline.network is None:
            return False
        return str(port) in baseline.network.port_distribution

    def modbus_register_in_range(
        self, entity_type: str, entity_id: str, register: int
    ) -> bool | None:
        """
        Return True if this Modbus register is within the baseline range.
        Returns None if no baseline. False if register is outside range.
        """
        baseline = self.get_entity_by_ids(entity_type, entity_id)
        if baseline is None:
            return None
        if baseline.modbus is None or baseline.modbus.register_stats is None:
            return False
        stats = baseline.modbus.register_stats
        if stats.minimum is None or stats.maximum is None:
            return False
        return stats.minimum <= register <= stats.maximum

    def get_event_type_frequency(
        self, entity_key: EntityKey, event_type: str
    ) -> int:
        """
        Return how many times this event_type was observed for this entity.
        Returns 0 if no baseline or event_type not seen.
        """
        baseline = self.get_entity(entity_key)
        if baseline is None:
            return 0
        return baseline.event_type_distribution.get(event_type, 0)

    def list_all_entity_keys(self) -> list[EntityKey]:
        """
        Return all EntityKey objects in the loaded profile.
        Returns empty list if no profile is loaded.
        """
        if self._profile is None:
            return []
        return self._profile.all_entity_keys()

    # ── Private ─────────────────────────────────────────────────────────────

    def _load_profile(self, *, require_baseline: bool) -> None:
        """Load latest profile from store, gracefully handling cold-start."""
        try:
            self._profile = self._store.load_latest()
            logger.info(
                "baseline_reader_loaded",
                profile_id=self._profile.profile_id,
                entity_count=self._profile.entity_count,
            )
        except BaselineNotFoundError:
            if require_baseline:
                raise
            logger.info(
                "baseline_reader_no_profile",
                message="No baseline found — cold-start mode. is_ready=False.",
            )
            self._profile = None
        except BaselineVersionError:
            logger.warning(
                "baseline_reader_version_mismatch",
                message="Stored baseline is incompatible. Re-run BaselineBuilder.",
            )
            self._profile = None
