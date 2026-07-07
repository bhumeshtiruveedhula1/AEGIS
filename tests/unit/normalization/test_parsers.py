"""
tests/unit/normalization/test_parsers.py
=========================================
Unit tests for all 4 source parsers:
  - HospitalServerParser
  - DomainControllerParser
  - OTNodeParser
  - AttackerParser

Also tests the parser registry (get_parser, list_registered_sources).
"""

from __future__ import annotations

import pytest

from backend.normalization.exceptions import ParseError, SourceError
from backend.normalization.models import CanonicalEvent
from backend.normalization.parsers import get_parser, list_registered_sources
from backend.normalization.parsers.attacker import AttackerParser
from backend.normalization.parsers.domain_controller import DomainControllerParser
from backend.normalization.parsers.hospital_server import HospitalServerParser
from backend.normalization.parsers.ot_node import OTNodeParser
from tests.unit.normalization.conftest import (
    FIXED_TS,
    make_attacker_raw,
    make_dc_raw,
    make_hospital_raw,
    make_ot_raw,
)


# ===========================================================================
# Parser Registry
# ===========================================================================

class TestParserRegistry:
    """Tests for get_parser() and list_registered_sources()."""

    def test_get_hospital_parser(self) -> None:
        parser = get_parser("hospital_server")
        assert isinstance(parser, HospitalServerParser)

    def test_get_dc_parser(self) -> None:
        parser = get_parser("domain_controller")
        assert isinstance(parser, DomainControllerParser)

    def test_get_ot_parser(self) -> None:
        parser = get_parser("ot_node")
        assert isinstance(parser, OTNodeParser)

    def test_get_attacker_parser(self) -> None:
        parser = get_parser("attacker")
        assert isinstance(parser, AttackerParser)

    def test_unknown_source_raises_source_error(self) -> None:
        with pytest.raises(SourceError) as exc_info:
            get_parser("unknown_source_xyz")
        assert "unknown_source_xyz" in str(exc_info.value)

    def test_list_registered_sources_returns_all_four(self) -> None:
        sources = list_registered_sources()
        assert "hospital_server" in sources
        assert "domain_controller" in sources
        assert "ot_node" in sources
        assert "attacker" in sources

    def test_list_registered_sources_sorted(self) -> None:
        sources = list_registered_sources()
        assert sources == sorted(sources)


# ===========================================================================
# HospitalServerParser
# ===========================================================================

class TestHospitalServerParser:
    """Unit tests for HospitalServerParser."""

    @pytest.fixture()
    def parser(self) -> HospitalServerParser:
        return HospitalServerParser()

    # ── Happy path ───────────────────────────────────────────────────────

    def test_parse_process_create(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw()
        event = parser.parse(raw)
        assert isinstance(event, CanonicalEvent)
        assert event.source == "hospital_server"
        assert event.event_type == "ProcessCreate"
        assert event.process == "w3wp.exe"
        assert event.pid == 4812

    def test_host_lowercased(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw({"host": "HOSPITAL-SERVER-01"})
        event = parser.parse(raw)
        assert event.host == "hospital-server-01"

    def test_timestamp_utc_normalised(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw()
        event = parser.parse(raw)
        from datetime import UTC
        assert event.timestamp.tzinfo == UTC

    def test_timestamp_trailing_z_handled(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw({"timestamp": "2024-01-15T10:30:00.000000Z"})
        event = parser.parse(raw)
        assert event.timestamp.year == 2024

    def test_process_fields_mapped(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw({
            "process_name": "sqlservr.exe",
            "pid": 1234,
            "parent_process": "services.exe",
            "command_line": "sqlservr -s MSSQLSERVER",
        })
        event = parser.parse(raw)
        assert event.process == "sqlservr.exe"
        assert event.pid == 1234
        assert event.parent_process == "services.exe"
        assert "MSSQLSERVER" in event.command_line

    def test_network_fields_mapped(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw({
            "event_type": "NetworkConnect",
            "src_ip": "172.20.1.10",
            "dst_ip": "172.20.1.20",
            "dst_port": 1433,
            "protocol": "tcp",
            "bytes_sent": 512,
        })
        event = parser.parse(raw)
        assert event.src_ip == "172.20.1.10"
        assert event.dst_ip == "172.20.1.20"
        assert event.port == 1433
        assert event.protocol == "tcp"
        assert event.bytes_out == 512

    def test_file_fields_mapped(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw({
            "event_type": "FileAccess",
            "file_path": "C:\\ProgramData\\patients\\records.mdf",
        })
        event = parser.parse(raw)
        assert event.file_path == "C:\\ProgramData\\patients\\records.mdf"

    def test_db_fields_mapped(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw({
            "event_type": "DatabaseQuery",
            "query_type": "SELECT",
            "table_name": "patients",
        })
        event = parser.parse(raw)
        assert event.db_query == "SELECT"
        assert event.db_table == "patients"

    def test_windows_event_id_mapped(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw({"windows_event_id": 4688})
        event = parser.parse(raw)
        assert event.windows_event_id == 4688

    def test_extra_fields_collected(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw({"custom_field": "custom_value"})
        event = parser.parse(raw)
        assert event.extra_fields.get("custom_field") == "custom_value"

    def test_event_id_passed_through(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw({"event_id": "test-id-1234"})
        event = parser.parse(raw)
        assert event.event_id == "test-id-1234"

    # ── Optional fields absent → None ────────────────────────────────────

    def test_missing_optional_fields_are_none(self, parser: HospitalServerParser) -> None:
        raw = {
            "timestamp": FIXED_TS,
            "event_type": "ProcessCreate",
            "host": "server-01",
            "user": "SYSTEM",
            "resource": "cmd.exe",
            "action": "execute",
            "result": "success",
        }
        event = parser.parse(raw)
        assert event.process is None
        assert event.pid is None
        assert event.src_ip is None
        assert event.dst_ip is None
        assert event.file_path is None

    # ── Error handling ────────────────────────────────────────────────────

    def test_missing_timestamp_raises_parse_error(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw()
        del raw["timestamp"]
        with pytest.raises(ParseError):
            parser.parse(raw)

    def test_missing_event_type_raises_parse_error(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw()
        del raw["event_type"]
        with pytest.raises(ParseError):
            parser.parse(raw)

    def test_missing_host_raises_parse_error(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw()
        del raw["host"]
        with pytest.raises(ParseError):
            parser.parse(raw)

    def test_invalid_pid_emits_warning(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw({"pid": "not_a_number"})
        event = parser.parse(raw)
        assert event.pid is None
        assert any("pid" in w for w in event.parse_warnings)

    def test_invalid_timestamp_falls_back_to_now(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw({"timestamp": "not-a-timestamp"})
        event = parser.parse(raw)
        # Should have a warning and fall back to now
        assert event.timestamp is not None
        assert any("timestamp" in w.lower() for w in event.parse_warnings)

    def test_unknown_event_type_emits_warning(self, parser: HospitalServerParser) -> None:
        raw = make_hospital_raw({"event_type": "SomeNewFutureType"})
        event = parser.parse(raw)
        assert event.event_type == "SomeNewFutureType"
        assert any("Unknown" in w or "event_type" in w for w in event.parse_warnings)


# ===========================================================================
# DomainControllerParser
# ===========================================================================

class TestDomainControllerParser:
    """Unit tests for DomainControllerParser."""

    @pytest.fixture()
    def parser(self) -> DomainControllerParser:
        return DomainControllerParser()

    def test_parse_user_logon(self, parser: DomainControllerParser) -> None:
        raw = make_dc_raw()
        event = parser.parse(raw)
        assert event.source == "domain_controller"
        assert event.event_type == "UserLogon"

    def test_auth_fields_mapped(self, parser: DomainControllerParser) -> None:
        raw = make_dc_raw()
        event = parser.parse(raw)
        assert event.logon_type == "network"
        assert event.auth_package == "Kerberos"
        assert event.domain == "HOSPITAL"

    def test_logon_type_integer_normalised(self, parser: DomainControllerParser) -> None:
        raw = make_dc_raw({"logon_type": 3})  # 3 = network
        event = parser.parse(raw)
        assert event.logon_type == "network"

    def test_logon_type_integer_5_service(self, parser: DomainControllerParser) -> None:
        raw = make_dc_raw({"logon_type": 5})
        event = parser.parse(raw)
        assert event.logon_type == "service"

    def test_windows_event_id_4624(self, parser: DomainControllerParser) -> None:
        raw = make_dc_raw({"windows_event_id": 4624})
        event = parser.parse(raw)
        assert event.windows_event_id == 4624

    def test_src_ip_from_ip_address_field(self, parser: DomainControllerParser) -> None:
        raw = make_dc_raw({"ip_address": "172.20.1.10"})
        event = parser.parse(raw)
        assert event.src_ip == "172.20.1.10"

    def test_host_lowercased(self, parser: DomainControllerParser) -> None:
        raw = make_dc_raw({"host": "DC-01"})
        event = parser.parse(raw)
        assert event.host == "dc-01"

    def test_process_fields_none_for_dc_events(self, parser: DomainControllerParser) -> None:
        raw = make_dc_raw()
        event = parser.parse(raw)
        assert event.process is None
        assert event.file_path is None
        assert event.db_query is None

    def test_missing_required_field_raises_parse_error(self, parser: DomainControllerParser) -> None:
        raw = make_dc_raw()
        del raw["timestamp"]
        with pytest.raises(ParseError):
            parser.parse(raw)

    def test_failed_logon_event(self, parser: DomainControllerParser) -> None:
        raw = make_dc_raw({
            "event_type": "UserLogonFailed",
            "result": "failure",
            "windows_event_id": 4625,
        })
        event = parser.parse(raw)
        assert event.event_type == "UserLogonFailed"
        assert event.result == "failure"

    def test_unknown_logon_type_int_emits_warning(self, parser: DomainControllerParser) -> None:
        raw = make_dc_raw({"logon_type": 999})
        event = parser.parse(raw)
        assert any("logon_type" in w.lower() or "Unknown" in w for w in event.parse_warnings)


# ===========================================================================
# OTNodeParser
# ===========================================================================

class TestOTNodeParser:
    """Unit tests for OTNodeParser."""

    @pytest.fixture()
    def parser(self) -> OTNodeParser:
        return OTNodeParser()

    def test_parse_modbus_read(self, parser: OTNodeParser) -> None:
        raw = make_ot_raw()
        event = parser.parse(raw)
        assert event.source == "ot_node"
        assert event.event_type == "ModbusRead"

    def test_modbus_fields_mapped(self, parser: OTNodeParser) -> None:
        raw = make_ot_raw()
        event = parser.parse(raw)
        assert event.modbus_register == 15
        assert event.modbus_value == 2847
        assert event.modbus_function_code == "FC03"
        assert event.supervisory_host == "192.168.1.100"

    def test_supervisory_host_maps_to_src_ip(self, parser: OTNodeParser) -> None:
        raw = make_ot_raw({"supervisory_host": "192.168.1.100"})
        event = parser.parse(raw)
        assert event.src_ip == "192.168.1.100"

    def test_protocol_always_modbus(self, parser: OTNodeParser) -> None:
        raw = make_ot_raw()
        event = parser.parse(raw)
        assert event.protocol == "modbus"

    def test_port_defaults_to_502(self, parser: OTNodeParser) -> None:
        raw = make_ot_raw()
        event = parser.parse(raw)
        assert event.port == 502

    def test_port_from_raw_overrides_default(self, parser: OTNodeParser) -> None:
        raw = make_ot_raw({"port": 5020})
        event = parser.parse(raw)
        assert event.port == 5020

    def test_modbus_write_event(self, parser: OTNodeParser) -> None:
        raw = make_ot_raw({
            "event_type": "ModbusWrite",
            "resource": "register_35",
            "action": "write",
            "modbus_register": 35,
            "modbus_value": 1000,
            "modbus_function_code": "FC06",
        })
        event = parser.parse(raw)
        assert event.event_type == "ModbusWrite"
        assert event.modbus_function_code == "FC06"
        assert event.modbus_register == 35

    def test_process_auth_file_fields_are_none(self, parser: OTNodeParser) -> None:
        raw = make_ot_raw()
        event = parser.parse(raw)
        assert event.process is None
        assert event.logon_type is None
        assert event.file_path is None
        assert event.auth_package is None

    def test_missing_timestamp_raises_parse_error(self, parser: OTNodeParser) -> None:
        raw = make_ot_raw()
        del raw["timestamp"]
        with pytest.raises(ParseError):
            parser.parse(raw)

    def test_invalid_modbus_register_emits_warning(self, parser: OTNodeParser) -> None:
        raw = make_ot_raw({"modbus_register": "not_a_number"})
        event = parser.parse(raw)
        assert event.modbus_register is None
        assert any("modbus_register" in w for w in event.parse_warnings)

    def test_extra_fields_like_cpu_load_preserved(self, parser: OTNodeParser) -> None:
        raw = make_ot_raw({"cpu_load": 12.4, "memory_free_kb": 8192})
        event = parser.parse(raw)
        assert event.extra_fields.get("cpu_load") == 12.4
        assert event.extra_fields.get("memory_free_kb") == 8192

    def test_host_lowercased(self, parser: OTNodeParser) -> None:
        raw = make_ot_raw({"host": "OT-NODE-01"})
        event = parser.parse(raw)
        assert event.host == "ot-node-01"


# ===========================================================================
# AttackerParser
# ===========================================================================

class TestAttackerParser:
    """Unit tests for AttackerParser."""

    @pytest.fixture()
    def parser(self) -> AttackerParser:
        return AttackerParser()

    def test_parse_heartbeat(self, parser: AttackerParser) -> None:
        raw = make_attacker_raw()
        event = parser.parse(raw)
        assert event.source == "attacker"
        assert event.event_type == "AttackerHeartbeat"

    def test_src_ip_mapped(self, parser: AttackerParser) -> None:
        raw = make_attacker_raw({"src_ip": "172.20.3.10"})
        event = parser.parse(raw)
        assert event.src_ip == "172.20.3.10"

    def test_network_fields_for_recon(self, parser: AttackerParser) -> None:
        raw = make_attacker_raw({
            "event_type": "ReconScan",
            "dst_ip": "172.20.1.10",
            "dst_port": 22,
            "protocol": "tcp",
            "payload_size": 64,
        })
        event = parser.parse(raw)
        assert event.event_type == "ReconScan"
        assert event.dst_ip == "172.20.1.10"
        assert event.port == 22
        assert event.bytes_out == 64

    def test_unknown_future_event_type_accepted_with_warning(self, parser: AttackerParser) -> None:
        raw = make_attacker_raw({"event_type": "FutureAttackType"})
        event = parser.parse(raw)
        assert event.event_type == "FutureAttackType"
        assert any("Unknown" in w or "FutureAttackType" in w for w in event.parse_warnings)

    def test_process_ot_auth_fields_are_none(self, parser: AttackerParser) -> None:
        raw = make_attacker_raw()
        event = parser.parse(raw)
        assert event.process is None
        assert event.modbus_register is None
        assert event.logon_type is None

    def test_missing_timestamp_raises_parse_error(self, parser: AttackerParser) -> None:
        raw = make_attacker_raw()
        del raw["timestamp"]
        with pytest.raises(ParseError):
            parser.parse(raw)

    def test_host_lowercased(self, parser: AttackerParser) -> None:
        raw = make_attacker_raw({"host": "ATTACKER-01"})
        event = parser.parse(raw)
        assert event.host == "attacker-01"

    def test_extra_fields_preserved(self, parser: AttackerParser) -> None:
        raw = make_attacker_raw({"scan_type": "SYN", "target_os": "Windows"})
        event = parser.parse(raw)
        assert event.extra_fields.get("scan_type") == "SYN"
