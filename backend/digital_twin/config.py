"""
backend.digital_twin.config — Digital Twin Configuration
=========================================================
Extends the Module 1.1 Settings singleton with all configuration
required to manage and operate the Digital Twin environment.

All Digital Twin settings are namespaced with the `dt_` prefix to avoid
collision with core application settings.

Usage
-----
    from backend.digital_twin.config import get_digital_twin_settings, DigitalTwinSettings

    dt_settings = get_digital_twin_settings()
    print(dt_settings.dt_hospital_server_ip)   # "172.20.1.10"
    print(dt_settings.dt_log_base_dir)         # Path("./data/digital_twin")

Design Notes
------------
- DigitalTwinSettings is a separate, independently cached singleton.
- It does NOT extend Settings directly to avoid creating a merged god-object.
- Future modules that need DT config import get_digital_twin_settings().
- All IP addresses match the docker-compose.yml network configuration exactly.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class DigitalTwinSettings(BaseSettings):
    """
    Digital Twin environment configuration.

    Loaded from environment variables (with DT_ prefix) and the .env file.
    Override in tests by constructing with explicit field values.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="DT_",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    # -----------------------------------------------------------------------
    # Network Configuration
    # Mirrors docker/docker-compose.yml static IP assignments exactly.
    # -----------------------------------------------------------------------
    hospital_server_ip: str = Field(
        default="172.20.1.10",
        description="Static IP of the hospital server container.",
    )
    hospital_server_port: int = Field(
        default=9002,
        ge=1024,
        le=65535,
        description="Health check HTTP port for the hospital server.",
    )

    domain_controller_ip: str = Field(
        default="172.20.1.20",
        description="Static IP of the domain controller container.",
    )
    domain_controller_port: int = Field(
        default=9001,
        ge=1024,
        le=65535,
        description="Health check HTTP port for the domain controller.",
    )

    ot_node_ip: str = Field(
        default="172.20.2.10",
        description="Static IP of the OT node container.",
    )
    ot_node_port: int = Field(
        default=9003,
        ge=1024,
        le=65535,
        description="Health check HTTP port for the OT node.",
    )

    attacker_ip: str = Field(
        default="172.20.3.10",
        description="Static IP of the attacker container.",
    )
    # Attacker has no health check port (no inbound ports exposed by design)

    # -----------------------------------------------------------------------
    # Log Storage Paths
    # -----------------------------------------------------------------------
    log_base_dir: Path = Field(
        default=Path("./data/digital_twin"),
        description="Root directory for all Digital Twin log outputs.",
    )

    @property
    def hospital_server_log_path(self) -> Path:
        """Absolute path to hospital server JSONL log file."""
        return self.log_base_dir / "hospital_server" / "hospital_server.jsonl"

    @property
    def domain_controller_log_path(self) -> Path:
        """Absolute path to domain controller JSONL log file."""
        return self.log_base_dir / "domain_controller" / "domain_controller.jsonl"

    @property
    def ot_node_log_path(self) -> Path:
        """Absolute path to OT node JSONL log file."""
        return self.log_base_dir / "ot_node" / "ot_node.jsonl"

    @property
    def attacker_log_path(self) -> Path:
        """Absolute path to attacker container JSONL log file."""
        return self.log_base_dir / "attacker" / "attacker.jsonl"

    # -----------------------------------------------------------------------
    # Event Generation Configuration
    # Controls the baseline telemetry generation rates for each container.
    # In CI, set ACCELERATED=true to compress 7 days into minutes.
    # -----------------------------------------------------------------------
    accelerated_mode: bool = Field(
        default=False,
        description=(
            "When True, generators run at maximum speed. "
            "Use for CI baseline generation. "
            "False = real-time for production baseline collection."
        ),
    )
    acceleration_factor: int = Field(
        default=1440,
        ge=1,
        le=100_000,
        description=(
            "Speed multiplier when accelerated_mode=True. "
            "1440 = compress 1 day into 1 minute. "
            "10080 = compress 7 days into 1 minute."
        ),
    )

    # Hospital Server — baseline event rates (events per hour, real-time)
    hospital_process_creates_per_hour: int = Field(
        default=75,
        ge=1,
        description="Baseline process creation events per hour (normal).",
    )
    hospital_network_connects_per_hour: int = Field(
        default=150,
        ge=1,
        description="Baseline network connection events per hour (normal).",
    )
    hospital_file_events_per_hour: int = Field(
        default=50,
        ge=1,
        description="Baseline file I/O events per hour (normal).",
    )
    hospital_auth_events_per_hour: int = Field(
        default=20,
        ge=1,
        description="Baseline authentication events per hour (normal).",
    )

    # Domain Controller — baseline event rates
    dc_successful_logins_per_hour: int = Field(
        default=12,
        ge=1,
        description="Successful logon events per hour (normal).",
    )
    dc_failed_logins_per_hour: int = Field(
        default=5,
        ge=0,
        description="Failed logon events per hour (normal baseline — not zero, just low).",
    )
    dc_privilege_events_per_hour: int = Field(
        default=3,
        ge=0,
        description="Privilege assignment events per hour (normal).",
    )
    dc_user_management_per_hour: int = Field(
        default=2,
        ge=0,
        description="User management events per hour (normal).",
    )

    # OT Node — baseline Modbus simulation rates (in seconds)
    ot_read_interval_seconds: int = Field(
        default=5,
        ge=1,
        description="Modbus register read interval in seconds (normal polling).",
    )
    ot_write_interval_seconds: int = Field(
        default=60,
        ge=1,
        description="Modbus register write interval in seconds (normal control).",
    )
    ot_supervisory_host: str = Field(
        default="192.168.1.100",
        description="Simulated SCADA supervisory host IP for normal Modbus traffic.",
    )
    ot_normal_read_registers_start: int = Field(
        default=10,
        description="Start of normal read register range (inclusive).",
    )
    ot_normal_read_registers_end: int = Field(
        default=20,
        description="End of normal read register range (inclusive).",
    )
    ot_normal_write_registers_start: int = Field(
        default=30,
        description="Start of normal write register range (inclusive).",
    )
    ot_normal_write_registers_end: int = Field(
        default=40,
        description="End of normal write register range (inclusive).",
    )

    # -----------------------------------------------------------------------
    # Health Check Configuration
    # -----------------------------------------------------------------------
    health_check_timeout_seconds: int = Field(
        default=5,
        ge=1,
        le=30,
        description="Timeout in seconds for Digital Twin container health checks.",
    )
    health_check_retry_count: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Number of retries before marking a container as unhealthy.",
    )

    # -----------------------------------------------------------------------
    # Container Identity
    # -----------------------------------------------------------------------
    hospital_server_hostname: str = Field(
        default="hospital-server-01",
        description="Hostname used in generated telemetry events.",
    )
    domain_controller_hostname: str = Field(
        default="dc-01",
        description="Hostname used in generated telemetry events.",
    )
    ot_node_hostname: str = Field(
        default="plc-01",
        description="Hostname used in generated telemetry events.",
    )
    attacker_hostname: str = Field(
        default="attacker-kali",
        description="Hostname used in attacker events (future attack scripts).",
    )

    # -----------------------------------------------------------------------
    # Validators
    # -----------------------------------------------------------------------
    @field_validator("log_base_dir", mode="before")
    @classmethod
    def parse_log_dir(cls, v: str | Path) -> Path:
        """Convert string paths to Path objects."""
        return Path(v)

    def __repr__(self) -> str:
        return (
            f"DigitalTwinSettings("
            f"hospital={self.hospital_server_ip}:{self.hospital_server_port}, "
            f"dc={self.domain_controller_ip}:{self.domain_controller_port}, "
            f"ot={self.ot_node_ip}:{self.ot_node_port}, "
            f"accelerated={self.accelerated_mode})"
        )


@functools.lru_cache(maxsize=1)
def get_digital_twin_settings() -> DigitalTwinSettings:
    """
    Return the Digital Twin settings singleton.

    Uses lru_cache to ensure settings are constructed ONCE and shared
    across the entire application lifetime.

    In tests:
        from backend.digital_twin.config import get_digital_twin_settings
        get_digital_twin_settings.cache_clear()
        # Or construct directly: DigitalTwinSettings(...)
    """
    return DigitalTwinSettings()
