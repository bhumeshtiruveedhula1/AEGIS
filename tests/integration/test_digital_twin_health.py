"""
tests/integration/test_digital_twin_health.py
==============================================
Integration tests for Digital Twin health check integration.

Tests:
  - /health endpoint includes digital_twin component when registered
  - Registry reports correct topology via get_topology()
  - All 3 telemetry sources discoverable
  - Health status transitions correctly after status updates

These tests do NOT require Docker to be running.
They test the registry and health check logic in isolation.
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from backend.digital_twin.config import DigitalTwinSettings
from backend.digital_twin.models import (
    ContainerHealthStatus,
    ContainerRole,
)
from backend.digital_twin.registry import DigitalTwinRegistry


@pytest.fixture()
def dt_settings() -> DigitalTwinSettings:
    return DigitalTwinSettings(
        hospital_server_ip="172.20.1.10",
        hospital_server_port=9002,
        domain_controller_ip="172.20.1.20",
        domain_controller_port=9001,
        ot_node_ip="172.20.2.10",
        ot_node_port=9003,
        attacker_ip="172.20.3.10",
        log_base_dir="./data/digital_twin",
    )


@pytest.fixture()
def registry(dt_settings: DigitalTwinSettings) -> DigitalTwinRegistry:
    return DigitalTwinRegistry(settings=dt_settings)


class TestDigitalTwinHealthIntegration:
    """Integration-level tests for the complete DT health check chain."""

    @pytest.mark.asyncio
    async def test_initial_health_is_starting(
        self, registry: DigitalTwinRegistry
    ) -> None:
        """All containers start in STARTING state."""
        health = await registry.get_digital_twin_health()
        assert health.overall_status == ContainerHealthStatus.STARTING
        assert len(health.containers) == 4

    @pytest.mark.asyncio
    async def test_health_summary_structure(
        self, registry: DigitalTwinRegistry
    ) -> None:
        """The to_summary() method returns all required keys."""
        health = await registry.get_digital_twin_health()
        summary = health.to_summary()
        required_keys = {
            "digital_twin_status",
            "containers_healthy",
            "containers_total",
            "total_events_generated",
            "checked_at",
        }
        assert required_keys.issubset(summary.keys())

    @pytest.mark.asyncio
    async def test_full_healthy_transition(
        self, registry: DigitalTwinRegistry
    ) -> None:
        """Simulates all containers becoming healthy."""
        for role in [
            ContainerRole.HOSPITAL_SERVER,
            ContainerRole.DOMAIN_CONTROLLER,
            ContainerRole.OT_NODE,
            ContainerRole.ATTACKER,
        ]:
            await registry.update_container_status(
                role,
                status=ContainerHealthStatus.HEALTHY,
                events_generated=100,
            )

        health = await registry.get_digital_twin_health()
        assert health.overall_status == ContainerHealthStatus.HEALTHY
        assert health.healthy_count == 4
        assert health.is_fully_operational is True
        assert health.total_events_generated == 400

    @pytest.mark.asyncio
    async def test_partial_failure_gives_unhealthy(
        self, registry: DigitalTwinRegistry
    ) -> None:
        """One container failing should make the overall status unhealthy."""
        await registry.update_container_status(
            ContainerRole.HOSPITAL_SERVER, status=ContainerHealthStatus.HEALTHY
        )
        await registry.update_container_status(
            ContainerRole.DOMAIN_CONTROLLER, status=ContainerHealthStatus.HEALTHY
        )
        await registry.update_container_status(
            ContainerRole.OT_NODE, status=ContainerHealthStatus.UNREACHABLE
        )
        await registry.update_container_status(
            ContainerRole.ATTACKER, status=ContainerHealthStatus.UNKNOWN
        )

        health = await registry.get_digital_twin_health()
        assert health.overall_status == ContainerHealthStatus.UNHEALTHY


class TestDigitalTwinTopologyIntegration:
    """Test network topology is correctly built and queryable."""

    def test_four_segments_in_topology(self, registry: DigitalTwinRegistry) -> None:
        topo = registry.get_topology()
        assert len(topo.subnets) == 4

    def test_hospital_server_in_it_subnet(self, registry: DigitalTwinRegistry) -> None:
        topo = registry.get_topology()
        it = topo.it_subnet
        assert it is not None
        assert "hospital-server" in it.containers

    def test_dc_in_it_subnet(self, registry: DigitalTwinRegistry) -> None:
        topo = registry.get_topology()
        it = topo.it_subnet
        assert it is not None
        assert "domain-controller" in it.containers

    def test_ot_node_in_ot_subnet(self, registry: DigitalTwinRegistry) -> None:
        topo = registry.get_topology()
        ot = topo.ot_subnet
        assert ot is not None
        assert "ot-node" in ot.containers

    def test_attacker_in_attacker_subnet(self, registry: DigitalTwinRegistry) -> None:
        topo = registry.get_topology()
        att = topo.attacker_subnet
        assert att is not None
        assert "attacker" in att.containers


class TestTelemetryDiscoveryIntegration:
    """Validate the telemetry source discovery chain works end-to-end."""

    def test_all_sources_discoverable(self, registry: DigitalTwinRegistry) -> None:
        sources = registry.list_telemetry_sources()
        assert len(sources) == 3

    def test_source_log_paths_contain_digital_twin(
        self, registry: DigitalTwinRegistry
    ) -> None:
        paths = registry.get_all_log_paths()
        for path in paths:
            assert "digital_twin" in path

    def test_hospital_source_has_process_events(
        self, registry: DigitalTwinRegistry
    ) -> None:
        sources = registry.list_telemetry_sources(role=ContainerRole.HOSPITAL_SERVER)
        # TelemetryEventType is a StrEnum — instances compare equal to their string values
        event_type_values = [str(et) for s in sources for et in s.event_types]
        assert "ProcessCreate" in event_type_values

    def test_dc_source_has_logon_events(self, registry: DigitalTwinRegistry) -> None:
        sources = registry.list_telemetry_sources(role=ContainerRole.DOMAIN_CONTROLLER)
        event_type_values = [str(et) for s in sources for et in s.event_types]
        assert "UserLogon" in event_type_values
        assert "UserLogonFailed" in event_type_values
        assert "KerberosTicketRequest" in event_type_values

    def test_ot_source_has_modbus_events(self, registry: DigitalTwinRegistry) -> None:
        sources = registry.list_telemetry_sources(role=ContainerRole.OT_NODE)
        event_type_values = [str(et) for s in sources for et in s.event_types]
        assert "ModbusRead" in event_type_values
        assert "ModbusWrite" in event_type_values
        assert "ModbusHeartbeat" in event_type_values
