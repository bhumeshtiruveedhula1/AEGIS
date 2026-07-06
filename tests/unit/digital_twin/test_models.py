"""
tests/unit/digital_twin/test_models.py
=======================================
Unit tests for backend.digital_twin.models

Covers:
  - Enum correctness and exhaustiveness
  - TelemetrySource construction and field validation
  - ContainerStatus properties (is_healthy, is_generating)
  - NetworkTopology subnet properties
  - DigitalTwinHealth aggregate properties and to_summary()
  - TelemetryVolume error_rate calculation
"""

from __future__ import annotations

import pytest

from backend.digital_twin.models import (
    ContainerHealthStatus,
    ContainerRole,
    ContainerStatus,
    DigitalTwinHealth,
    LogSource,
    NetworkSegment,
    NetworkSubnet,
    NetworkTopology,
    TelemetryEventType,
    TelemetrySource,
    TelemetryVolume,
)


# ---------------------------------------------------------------------------
# Enum Tests
# ---------------------------------------------------------------------------

class TestNetworkSegment:
    def test_all_segments_defined(self) -> None:
        segments = {s.value for s in NetworkSegment}
        assert "management" in segments
        assert "it" in segments
        assert "ot" in segments
        assert "attacker" in segments

    def test_segment_count(self) -> None:
        assert len(NetworkSegment) == 4


class TestContainerRole:
    def test_all_roles_defined(self) -> None:
        roles = {r.value for r in ContainerRole}
        assert "hospital_server" in roles
        assert "domain_controller" in roles
        assert "ot_node" in roles
        assert "attacker" in roles
        assert "api" in roles

    def test_role_count(self) -> None:
        assert len(ContainerRole) == 5


class TestContainerHealthStatus:
    def test_all_statuses_defined(self) -> None:
        statuses = {s.value for s in ContainerHealthStatus}
        assert "healthy" in statuses
        assert "unhealthy" in statuses
        assert "starting" in statuses
        assert "unreachable" in statuses
        assert "unknown" in statuses


class TestTelemetryEventType:
    def test_hospital_events_present(self) -> None:
        assert TelemetryEventType.PROCESS_CREATE == "ProcessCreate"
        assert TelemetryEventType.NETWORK_CONNECT == "NetworkConnect"
        assert TelemetryEventType.FILE_ACCESS == "FileAccess"

    def test_dc_events_present(self) -> None:
        assert TelemetryEventType.USER_LOGON == "UserLogon"
        assert TelemetryEventType.USER_LOGON_FAILED == "UserLogonFailed"
        assert TelemetryEventType.PRIVILEGE_ASSIGNED == "PrivilegeAssigned"
        assert TelemetryEventType.KERBEROS_REQUEST == "KerberosTicketRequest"

    def test_ot_events_present(self) -> None:
        assert TelemetryEventType.MODBUS_READ == "ModbusRead"
        assert TelemetryEventType.MODBUS_WRITE == "ModbusWrite"
        assert TelemetryEventType.MODBUS_HEARTBEAT == "ModbusHeartbeat"
        assert TelemetryEventType.PLC_STATUS == "PLCStatus"


# ---------------------------------------------------------------------------
# TelemetrySource Tests
# ---------------------------------------------------------------------------

class TestTelemetrySource:
    def _make_source(self) -> TelemetrySource:
        return TelemetrySource(
            source_id="hospital_server_main",
            container_role=ContainerRole.HOSPITAL_SERVER,
            log_source=LogSource.HOSPITAL_SERVER,
            event_types=[
                TelemetryEventType.PROCESS_CREATE,
                TelemetryEventType.NETWORK_CONNECT,
            ],
            log_file_path="/logs/hospital_server.jsonl",
            host_log_path="./data/digital_twin/hospital_server/hospital_server.jsonl",
            description="Test hospital server source",
        )

    def test_construction(self) -> None:
        source = self._make_source()
        assert source.source_id == "hospital_server_main"
        assert source.container_role == ContainerRole.HOSPITAL_SERVER
        assert len(source.event_types) == 2
        assert source.is_active is True

    def test_default_active(self) -> None:
        source = self._make_source()
        assert source.is_active is True

    def test_can_deactivate(self) -> None:
        source = self._make_source()
        deactivated = source.model_copy(update={"is_active": False})
        assert deactivated.is_active is False

    def test_event_types_contain_correct_values(self) -> None:
        source = self._make_source()
        assert TelemetryEventType.PROCESS_CREATE in source.event_types
        assert TelemetryEventType.NETWORK_CONNECT in source.event_types


# ---------------------------------------------------------------------------
# ContainerStatus Tests
# ---------------------------------------------------------------------------

class TestContainerStatus:
    def _make_status(
        self,
        status: ContainerHealthStatus = ContainerHealthStatus.HEALTHY,
        events: int = 0,
    ) -> ContainerStatus:
        return ContainerStatus(
            role=ContainerRole.HOSPITAL_SERVER,
            container_name="cybershield-hospital-server",
            status=status,
            ip_address="172.20.1.10",
            network_segment=NetworkSegment.IT,
            events_generated=events,
        )

    def test_is_healthy_when_healthy(self) -> None:
        status = self._make_status(ContainerHealthStatus.HEALTHY)
        assert status.is_healthy is True

    def test_is_not_healthy_when_starting(self) -> None:
        status = self._make_status(ContainerHealthStatus.STARTING)
        assert status.is_healthy is False

    def test_is_not_healthy_when_unreachable(self) -> None:
        status = self._make_status(ContainerHealthStatus.UNREACHABLE)
        assert status.is_healthy is False

    def test_is_generating_when_events_gt_zero(self) -> None:
        status = self._make_status(events=100)
        assert status.is_generating is True

    def test_is_not_generating_when_no_events(self) -> None:
        status = self._make_status(events=0)
        assert status.is_generating is False

    def test_default_status_is_unknown(self) -> None:
        status = ContainerStatus(
            role=ContainerRole.OT_NODE,
            container_name="cybershield-ot-node",
            ip_address="172.20.2.10",
            network_segment=NetworkSegment.OT,
        )
        assert status.status == ContainerHealthStatus.UNKNOWN


# ---------------------------------------------------------------------------
# NetworkTopology Tests
# ---------------------------------------------------------------------------

class TestNetworkTopology:
    def _make_topology(self) -> NetworkTopology:
        return NetworkTopology(
            subnets=[
                NetworkSubnet(
                    name="management",
                    segment=NetworkSegment.MANAGEMENT,
                    cidr="172.20.0.0/24",
                    description="Management",
                    containers=["cybershield-api"],
                ),
                NetworkSubnet(
                    name="it-segment",
                    segment=NetworkSegment.IT,
                    cidr="172.20.1.0/24",
                    description="IT",
                    containers=["hospital-server", "domain-controller"],
                ),
                NetworkSubnet(
                    name="ot-segment",
                    segment=NetworkSegment.OT,
                    cidr="172.20.2.0/24",
                    description="OT",
                    containers=["ot-node"],
                ),
                NetworkSubnet(
                    name="attacker-segment",
                    segment=NetworkSegment.ATTACKER,
                    cidr="172.20.3.0/24",
                    description="Attacker",
                    containers=["attacker"],
                ),
            ]
        )

    def test_it_subnet_property(self) -> None:
        topo = self._make_topology()
        it = topo.it_subnet
        assert it is not None
        assert it.cidr == "172.20.1.0/24"
        assert "hospital-server" in it.containers

    def test_ot_subnet_property(self) -> None:
        topo = self._make_topology()
        ot = topo.ot_subnet
        assert ot is not None
        assert ot.cidr == "172.20.2.0/24"

    def test_attacker_subnet_property(self) -> None:
        topo = self._make_topology()
        att = topo.attacker_subnet
        assert att is not None
        assert att.cidr == "172.20.3.0/24"

    def test_invalid_cidr_raises(self) -> None:
        with pytest.raises(Exception):
            NetworkSubnet(
                name="bad",
                segment=NetworkSegment.IT,
                cidr="not-a-cidr",
                description="Bad",
            )


# ---------------------------------------------------------------------------
# DigitalTwinHealth Tests
# ---------------------------------------------------------------------------

class TestDigitalTwinHealth:
    def _make_health(
        self,
        statuses: list[ContainerHealthStatus],
        overall: ContainerHealthStatus = ContainerHealthStatus.HEALTHY,
    ) -> DigitalTwinHealth:
        containers = [
            ContainerStatus(
                role=ContainerRole.HOSPITAL_SERVER,
                container_name=f"container-{i}",
                status=s,
                ip_address=f"172.20.1.{10 + i}",
                network_segment=NetworkSegment.IT,
                events_generated=i * 10,
            )
            for i, s in enumerate(statuses)
        ]
        return DigitalTwinHealth(
            overall_status=overall,
            containers=containers,
            total_events_generated=sum(i * 10 for i in range(len(statuses))),
        )

    def test_healthy_count(self) -> None:
        health = self._make_health([
            ContainerHealthStatus.HEALTHY,
            ContainerHealthStatus.HEALTHY,
            ContainerHealthStatus.UNHEALTHY,
        ])
        assert health.healthy_count == 2

    def test_unhealthy_count(self) -> None:
        health = self._make_health([
            ContainerHealthStatus.HEALTHY,
            ContainerHealthStatus.UNREACHABLE,
        ])
        assert health.unhealthy_count == 1

    def test_is_fully_operational_when_all_healthy(self) -> None:
        health = self._make_health([
            ContainerHealthStatus.HEALTHY,
            ContainerHealthStatus.HEALTHY,
        ])
        assert health.is_fully_operational is True

    def test_is_not_fully_operational_when_one_unhealthy(self) -> None:
        health = self._make_health([
            ContainerHealthStatus.HEALTHY,
            ContainerHealthStatus.UNHEALTHY,
        ])
        assert health.is_fully_operational is False

    def test_is_not_fully_operational_when_no_containers(self) -> None:
        health = DigitalTwinHealth(overall_status=ContainerHealthStatus.UNKNOWN)
        assert health.is_fully_operational is False

    def test_to_summary_structure(self) -> None:
        health = self._make_health(
            [ContainerHealthStatus.HEALTHY, ContainerHealthStatus.HEALTHY],
            overall=ContainerHealthStatus.HEALTHY,
        )
        summary = health.to_summary()
        assert "digital_twin_status" in summary
        assert "containers_healthy" in summary
        assert "containers_total" in summary
        assert "total_events_generated" in summary
        assert "checked_at" in summary

    def test_to_summary_values(self) -> None:
        health = self._make_health(
            [ContainerHealthStatus.HEALTHY],
            overall=ContainerHealthStatus.HEALTHY,
        )
        summary = health.to_summary()
        assert summary["containers_healthy"] == 1
        assert summary["containers_total"] == 1


# ---------------------------------------------------------------------------
# TelemetryVolume Tests
# ---------------------------------------------------------------------------

class TestTelemetryVolume:
    def test_error_rate_zero_when_no_events(self) -> None:
        vol = TelemetryVolume(container_role=ContainerRole.OT_NODE)
        assert vol.error_rate == 0.0

    def test_error_rate_zero_events_zero_errors(self) -> None:
        vol = TelemetryVolume(
            container_role=ContainerRole.OT_NODE,
            total_events=100,
            error_events=0,
        )
        assert vol.error_rate == 0.0

    def test_error_rate_computed_correctly(self) -> None:
        vol = TelemetryVolume(
            container_role=ContainerRole.OT_NODE,
            total_events=100,
            error_events=5,
        )
        assert vol.error_rate == pytest.approx(0.05)

    def test_error_rate_clamps_at_one(self) -> None:
        vol = TelemetryVolume(
            container_role=ContainerRole.OT_NODE,
            total_events=10,
            error_events=10,
        )
        assert vol.error_rate == 1.0
