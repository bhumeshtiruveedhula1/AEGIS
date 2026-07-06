"""
tests/unit/digital_twin/test_registry.py
=========================================
Unit tests for backend.digital_twin.registry.DigitalTwinRegistry

Tests:
  - Registry initialises with all 4 containers
  - list_telemetry_sources() returns correct sources
  - list_telemetry_sources(role=) filters correctly
  - get_endpoint() returns correct IP / URL
  - get_topology() returns complete topology
  - get_all_log_paths() returns paths for active sources only
  - update_container_status() updates status correctly
  - get_digital_twin_health() computes correct overall status
"""

from __future__ import annotations

import asyncio

import pytest

from backend.digital_twin.config import DigitalTwinSettings
from backend.digital_twin.models import (
    ContainerHealthStatus,
    ContainerRole,
    NetworkSegment,
)
from backend.digital_twin.registry import DigitalTwinRegistry


@pytest.fixture()
def settings() -> DigitalTwinSettings:
    """Construct settings with deterministic test values."""
    return DigitalTwinSettings(
        hospital_server_ip="172.20.1.10",
        hospital_server_port=9002,
        domain_controller_ip="172.20.1.20",
        domain_controller_port=9001,
        ot_node_ip="172.20.2.10",
        ot_node_port=9003,
        attacker_ip="172.20.3.10",
        log_base_dir="./data/digital_twin",
        accelerated_mode=False,
    )


@pytest.fixture()
def registry(settings: DigitalTwinSettings) -> DigitalTwinRegistry:
    """Construct a fresh registry for each test."""
    return DigitalTwinRegistry(settings=settings)


class TestRegistryInitialisation:
    def test_four_containers_registered(self, registry: DigitalTwinRegistry) -> None:
        statuses = registry.list_all_statuses()
        assert len(statuses) == 4

    def test_all_roles_present(self, registry: DigitalTwinRegistry) -> None:
        roles = {s.role for s in registry.list_all_statuses()}
        assert ContainerRole.HOSPITAL_SERVER in roles
        assert ContainerRole.DOMAIN_CONTROLLER in roles
        assert ContainerRole.OT_NODE in roles
        assert ContainerRole.ATTACKER in roles

    def test_initial_status_is_starting(self, registry: DigitalTwinRegistry) -> None:
        for status in registry.list_all_statuses():
            assert status.status == ContainerHealthStatus.STARTING

    def test_three_telemetry_sources(self, registry: DigitalTwinRegistry) -> None:
        # hospital_server + domain_controller + ot_node (no attacker source)
        sources = registry.list_telemetry_sources()
        assert len(sources) == 3


class TestTelemetrySourceDiscovery:
    def test_list_all_sources(self, registry: DigitalTwinRegistry) -> None:
        sources = registry.list_telemetry_sources()
        source_ids = {s.source_id for s in sources}
        assert "hospital_server_main" in source_ids
        assert "domain_controller_auth" in source_ids
        assert "ot_node_modbus" in source_ids

    def test_filter_by_role_hospital(self, registry: DigitalTwinRegistry) -> None:
        sources = registry.list_telemetry_sources(role=ContainerRole.HOSPITAL_SERVER)
        assert len(sources) == 1
        assert sources[0].container_role == ContainerRole.HOSPITAL_SERVER

    def test_filter_by_role_dc(self, registry: DigitalTwinRegistry) -> None:
        sources = registry.list_telemetry_sources(role=ContainerRole.DOMAIN_CONTROLLER)
        assert len(sources) == 1
        # TelemetryEventType is a StrEnum — instances are already strings
        assert "UserLogon" in [str(e) for e in sources[0].event_types]

    def test_filter_by_role_ot(self, registry: DigitalTwinRegistry) -> None:
        sources = registry.list_telemetry_sources(role=ContainerRole.OT_NODE)
        assert len(sources) == 1
        assert "ModbusRead" in [str(e) for e in sources[0].event_types]

    def test_attacker_has_no_telemetry_source(self, registry: DigitalTwinRegistry) -> None:
        sources = registry.list_telemetry_sources(role=ContainerRole.ATTACKER)
        assert len(sources) == 0

    def test_get_all_log_paths(self, registry: DigitalTwinRegistry) -> None:
        paths = registry.get_all_log_paths()
        assert len(paths) == 3  # hospital + dc + ot (all active by default)
        assert all("digital_twin" in p for p in paths)


class TestEndpointDiscovery:
    def test_hospital_server_endpoint(self, registry: DigitalTwinRegistry) -> None:
        ep = registry.get_endpoint(ContainerRole.HOSPITAL_SERVER)
        assert ep is not None
        assert ep.ip_address == "172.20.1.10"
        assert ep.network_segment == NetworkSegment.IT
        assert "9002" in ep.health_check_url

    def test_domain_controller_endpoint(self, registry: DigitalTwinRegistry) -> None:
        ep = registry.get_endpoint(ContainerRole.DOMAIN_CONTROLLER)
        assert ep is not None
        assert ep.ip_address == "172.20.1.20"
        assert "9001" in ep.health_check_url

    def test_ot_node_endpoint(self, registry: DigitalTwinRegistry) -> None:
        ep = registry.get_endpoint(ContainerRole.OT_NODE)
        assert ep is not None
        assert ep.ip_address == "172.20.2.10"
        assert ep.network_segment == NetworkSegment.OT

    def test_attacker_has_no_health_url(self, registry: DigitalTwinRegistry) -> None:
        ep = registry.get_endpoint(ContainerRole.ATTACKER)
        assert ep is not None
        assert ep.health_check_url is None
        assert ep.network_segment == NetworkSegment.ATTACKER


class TestNetworkTopology:
    def test_topology_has_four_subnets(self, registry: DigitalTwinRegistry) -> None:
        topo = registry.get_topology()
        assert len(topo.subnets) == 4

    def test_it_subnet_cidr(self, registry: DigitalTwinRegistry) -> None:
        topo = registry.get_topology()
        it_subnet = topo.it_subnet
        assert it_subnet is not None
        assert it_subnet.cidr == "172.20.1.0/24"

    def test_ot_subnet_cidr(self, registry: DigitalTwinRegistry) -> None:
        topo = registry.get_topology()
        ot_subnet = topo.ot_subnet
        assert ot_subnet is not None
        assert ot_subnet.cidr == "172.20.2.0/24"


class TestStatusUpdates:
    @pytest.mark.asyncio
    async def test_update_status_healthy(self, registry: DigitalTwinRegistry) -> None:
        await registry.update_container_status(
            ContainerRole.HOSPITAL_SERVER,
            status=ContainerHealthStatus.HEALTHY,
            events_generated=500,
        )
        status = registry.get_container_status(ContainerRole.HOSPITAL_SERVER)
        assert status is not None
        assert status.status == ContainerHealthStatus.HEALTHY
        assert status.events_generated == 500

    @pytest.mark.asyncio
    async def test_update_status_unhealthy_with_error(
        self, registry: DigitalTwinRegistry
    ) -> None:
        await registry.update_container_status(
            ContainerRole.OT_NODE,
            status=ContainerHealthStatus.UNREACHABLE,
            error_message="Connection refused",
        )
        status = registry.get_container_status(ContainerRole.OT_NODE)
        assert status is not None
        assert status.status == ContainerHealthStatus.UNREACHABLE
        assert status.error_message == "Connection refused"

    @pytest.mark.asyncio
    async def test_update_unknown_role_does_not_raise(
        self, registry: DigitalTwinRegistry
    ) -> None:
        """Updating an unknown role should log a warning and return gracefully."""
        await registry.update_container_status(
            ContainerRole.API,  # API not registered in DT registry
            status=ContainerHealthStatus.HEALTHY,
        )
        # Should not raise; just log a warning


class TestAggregateHealth:
    @pytest.mark.asyncio
    async def test_all_starting_gives_starting_overall(
        self, registry: DigitalTwinRegistry
    ) -> None:
        health = await registry.get_digital_twin_health()
        assert health.overall_status == ContainerHealthStatus.STARTING

    @pytest.mark.asyncio
    async def test_all_healthy_gives_healthy_overall(
        self, registry: DigitalTwinRegistry
    ) -> None:
        for role in [
            ContainerRole.HOSPITAL_SERVER,
            ContainerRole.DOMAIN_CONTROLLER,
            ContainerRole.OT_NODE,
            ContainerRole.ATTACKER,
        ]:
            await registry.update_container_status(
                role, status=ContainerHealthStatus.HEALTHY
            )
        health = await registry.get_digital_twin_health()
        assert health.overall_status == ContainerHealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_one_unhealthy_gives_unhealthy_overall(
        self, registry: DigitalTwinRegistry
    ) -> None:
        await registry.update_container_status(
            ContainerRole.HOSPITAL_SERVER, status=ContainerHealthStatus.HEALTHY
        )
        await registry.update_container_status(
            ContainerRole.DOMAIN_CONTROLLER, status=ContainerHealthStatus.UNHEALTHY
        )
        await registry.update_container_status(
            ContainerRole.OT_NODE, status=ContainerHealthStatus.HEALTHY
        )
        await registry.update_container_status(
            ContainerRole.ATTACKER, status=ContainerHealthStatus.UNKNOWN
        )
        health = await registry.get_digital_twin_health()
        assert health.overall_status == ContainerHealthStatus.UNHEALTHY

    @pytest.mark.asyncio
    async def test_total_events_aggregated(
        self, registry: DigitalTwinRegistry
    ) -> None:
        await registry.update_container_status(
            ContainerRole.HOSPITAL_SERVER,
            status=ContainerHealthStatus.HEALTHY,
            events_generated=1000,
        )
        await registry.update_container_status(
            ContainerRole.DOMAIN_CONTROLLER,
            status=ContainerHealthStatus.HEALTHY,
            events_generated=200,
        )
        health = await registry.get_digital_twin_health()
        assert health.total_events_generated >= 1200
