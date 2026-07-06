"""
docker/digital_twin/shared/base_generator.py
=============================================
Abstract base class for all Digital Twin telemetry generators.

Every container's generator.py subclasses BaseGenerator and implements:

  generate_normal_events(tick: int) -> list[TelemetryEvent]

The base class handles:
  - Deterministic timing loop with configurable tick intervals
  - Acceleration mode (compress time for CI baseline generation)
  - Signal handling (SIGTERM/SIGINT → graceful flush + shutdown)
  - Health reporting (writes a health.json file that the HTTP server reads)
  - Error isolation (generator exception does not crash the container)
  - Structured stderr logging

Architecture
------------
                    BaseGenerator
                         |
          +--------------+--------------+
          |              |              |
  HospitalServerGenerator  DCGenerator  OTNodeGenerator
  (hospital_server/)      (domain_ctrl/) (ot_node/)

Subclass Contract
-----------------
Implement:
    generate_normal_events(self, tick: int) -> list[TelemetryEvent]

Optionally override:
    on_start(self) -> None         # setup before loop begins
    on_shutdown(self) -> None      # cleanup when SIGTERM received
    health_extras(self) -> dict    # extra fields in health.json
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shared.event_schema import TelemetryEvent
from shared.writer import EventWriter


def _stderr(level: str, msg: str, **kwargs: Any) -> None:
    """Minimal structured logger to stderr."""
    record = {
        "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "level": level,
        "generator": kwargs.pop("generator", "unknown"),
        "msg": msg,
        **kwargs,
    }
    print(json.dumps(record, separators=(",", ":")), file=sys.stderr, flush=True)


class BaseGenerator(ABC):
    """
    Abstract base class for Digital Twin telemetry generators.

    Configuration is loaded from environment variables.

    Environment Variables
    ---------------------
    DT_LOG_PATH               : str   — Output JSONL path (required)
    DT_ACCELERATED_MODE       : bool  — Enable accelerated generation
    DT_ACCELERATION_FACTOR    : int   — Speed multiplier (default 1440)
    DT_EVENTS_PER_HOUR        : int   — Target events per hour (baseline rate)
    DT_BUFFER_SIZE            : int   — Writer buffer size (default 50)
    DT_HEALTH_FILE_PATH       : str   — Health status JSON file path
    DT_CONTAINER_HOSTNAME     : str   — Hostname embedded in all events
    """

    def __init__(self) -> None:
        # Identify this generator
        self.name: str = self.__class__.__name__
        self.container_hostname: str = os.environ.get(
            "DT_CONTAINER_HOSTNAME", "unknown-host"
        )

        # Output configuration
        log_path = os.environ.get("DT_LOG_PATH", "/logs/events.jsonl")
        self.writer = EventWriter(
            log_path=log_path,
            buffer_size=int(os.environ.get("DT_BUFFER_SIZE", "50")),
        )

        # Timing configuration
        self.accelerated_mode: bool = (
            os.environ.get("DT_ACCELERATED_MODE", "false").lower() == "true"
        )
        self.acceleration_factor: int = int(
            os.environ.get("DT_ACCELERATION_FACTOR", "1440")
        )
        self.events_per_hour: int = int(
            os.environ.get("DT_EVENTS_PER_HOUR", "100")
        )

        # Health file (read by health_server.py)
        self.health_file = Path(
            os.environ.get("DT_HEALTH_FILE_PATH", "/tmp/generator_health.json")
        )

        # State
        self._running = False
        self._tick = 0
        self._started_at: datetime | None = None
        self._shutdown_event = threading.Event()

        # Install signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        _stderr("INFO", "generator_configured",
                generator=self.name,
                hostname=self.container_hostname,
                accelerated=self.accelerated_mode,
                events_per_hour=self.events_per_hour)

    # -----------------------------------------------------------------------
    # Timing
    # -----------------------------------------------------------------------

    @property
    def _tick_interval_seconds(self) -> float:
        """
        Real-world seconds between each generator tick.

        In real-time mode:    3600 / events_per_hour
        In accelerated mode:  real_interval / acceleration_factor
        """
        real_interval = 3600.0 / self.events_per_hour
        if self.accelerated_mode:
            return max(0.001, real_interval / self.acceleration_factor)
        return real_interval

    # -----------------------------------------------------------------------
    # Main Loop
    # -----------------------------------------------------------------------

    def run(self) -> None:
        """
        Start the generator main loop.

        This is a blocking call. The loop runs until:
          - SIGTERM or SIGINT received (graceful shutdown)
          - on_shutdown() is called externally
        """
        self._running = True
        self._started_at = datetime.now(UTC)
        self._write_health(status="starting")

        _stderr("INFO", "generator_starting",
                generator=self.name,
                tick_interval_s=round(self._tick_interval_seconds, 4))

        try:
            self.on_start()
        except Exception as exc:  # noqa: BLE001
            _stderr("ERROR", "generator_on_start_failed",
                    generator=self.name, error=str(exc))

        self._write_health(status="running")

        try:
            while not self._shutdown_event.is_set():
                tick_start = time.monotonic()
                self._tick += 1

                try:
                    events = self.generate_normal_events(self._tick)
                    for event in events:
                        self.writer.write(event)
                except Exception as exc:  # noqa: BLE001
                    _stderr("WARNING", "generator_tick_error",
                            generator=self.name,
                            tick=self._tick,
                            error=str(exc))

                # Update health file periodically (every 10 ticks)
                if self._tick % 10 == 0:
                    self._write_health(status="running")

                # Sleep for the remainder of the tick interval
                elapsed = time.monotonic() - tick_start
                sleep_time = max(0.0, self._tick_interval_seconds - elapsed)
                if sleep_time > 0:
                    self._shutdown_event.wait(timeout=sleep_time)

        finally:
            self._shutdown()

    def stop(self) -> None:
        """Signal the generator to stop gracefully."""
        self._shutdown_event.set()

    # -----------------------------------------------------------------------
    # Abstract Methods (implement in each generator)
    # -----------------------------------------------------------------------

    @abstractmethod
    def generate_normal_events(self, tick: int) -> list[TelemetryEvent]:
        """
        Generate the set of events for one tick of the generator loop.

        Parameters
        ----------
        tick : int
            Monotonically increasing tick counter (1-indexed).

        Returns
        -------
        list[TelemetryEvent]
            Events to emit this tick. May be empty.
        """
        ...

    def on_start(self) -> None:
        """Called once before the main loop begins. Override for setup."""
        pass

    def on_shutdown(self) -> None:
        """Called once after the main loop exits. Override for cleanup."""
        pass

    def health_extras(self) -> dict[str, Any]:
        """Return extra fields to include in health.json. Override in subclasses."""
        return {}

    # -----------------------------------------------------------------------
    # Signal Handling and Shutdown
    # -----------------------------------------------------------------------

    def _handle_signal(self, signum: int, _frame: Any) -> None:
        """Handle SIGTERM/SIGINT — triggers graceful shutdown."""
        _stderr("INFO", "generator_signal_received",
                generator=self.name, signal=signum)
        self.stop()

    def _shutdown(self) -> None:
        """Internal shutdown — flush writer and run on_shutdown."""
        _stderr("INFO", "generator_shutting_down",
                generator=self.name, total_ticks=self._tick)

        try:
            self.on_shutdown()
        except Exception as exc:  # noqa: BLE001
            _stderr("WARNING", "generator_on_shutdown_failed",
                    generator=self.name, error=str(exc))

        self.writer.flush()
        self.writer.close()
        self._write_health(status="stopped")

        _stderr("INFO", "generator_stopped",
                generator=self.name,
                total_written=self.writer.total_written,
                error_count=self.writer.error_count)

    # -----------------------------------------------------------------------
    # Health Reporting
    # -----------------------------------------------------------------------

    def _write_health(self, status: str) -> None:
        """
        Write the generator health status to health.json.
        The HTTP health_server.py reads this file to serve /health.
        """
        try:
            uptime = (
                (datetime.now(UTC) - self._started_at).total_seconds()
                if self._started_at
                else 0.0
            )
            health = {
                "status": status,
                "generator": self.name,
                "hostname": self.container_hostname,
                "total_events_written": self.writer.total_written,
                "error_count": self.writer.error_count,
                "total_ticks": self._tick,
                "uptime_seconds": round(uptime, 2),
                "accelerated_mode": self.accelerated_mode,
                "tick_interval_seconds": round(self._tick_interval_seconds, 4),
                "checked_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
                **self.health_extras(),
            }
            self.health_file.parent.mkdir(parents=True, exist_ok=True)
            self.health_file.write_text(
                json.dumps(health, separators=(",", ":")), encoding="utf-8"
            )
        except Exception as exc:  # noqa: BLE001
            _stderr("WARNING", "health_write_failed",
                    generator=self.name, error=str(exc))
