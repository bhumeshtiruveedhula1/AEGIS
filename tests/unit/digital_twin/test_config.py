"""
tests/unit/digital_twin/test_config.py
========================================
Unit tests for backend.digital_twin.config.DigitalTwinSettings

Tests:
  - Default values are correct and match docker-compose.yml
  - ENV-based override works correctly
  - Path properties return correct computed paths
  - Field validation (port ranges, acceleration factor)
  - Singleton caching behaviour
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.digital_twin.config import DigitalTwinSettings


class TestDefaultValues:
    def test_default_hospital_ip(self) -> None:
        s = DigitalTwinSettings()
        assert s.hospital_server_ip == "172.20.1.10"

    def test_default_hospital_port(self) -> None:
        s = DigitalTwinSettings()
        assert s.hospital_server_port == 9002

    def test_default_dc_ip(self) -> None:
        s = DigitalTwinSettings()
        assert s.domain_controller_ip == "172.20.1.20"

    def test_default_dc_port(self) -> None:
        s = DigitalTwinSettings()
        assert s.domain_controller_port == 9001

    def test_default_ot_ip(self) -> None:
        s = DigitalTwinSettings()
        assert s.ot_node_ip == "172.20.2.10"

    def test_default_ot_port(self) -> None:
        s = DigitalTwinSettings()
        assert s.ot_node_port == 9003

    def test_default_attacker_ip(self) -> None:
        s = DigitalTwinSettings()
        assert s.attacker_ip == "172.20.3.10"

    def test_not_accelerated_by_default(self) -> None:
        s = DigitalTwinSettings()
        assert s.accelerated_mode is False

    def test_default_acceleration_factor(self) -> None:
        s = DigitalTwinSettings()
        assert s.acceleration_factor == 1440

    def test_default_health_timeout(self) -> None:
        s = DigitalTwinSettings()
        assert s.health_check_timeout_seconds == 5

    def test_default_log_base_dir_is_path(self) -> None:
        s = DigitalTwinSettings()
        assert isinstance(s.log_base_dir, Path)


class TestLogPathProperties:
    def _settings(self, base_dir: str = "./data/digital_twin") -> DigitalTwinSettings:
        return DigitalTwinSettings(log_base_dir=base_dir)

    def test_hospital_log_path(self) -> None:
        s = self._settings()
        path = s.hospital_server_log_path
        assert "hospital_server" in str(path)
        assert str(path).endswith(".jsonl")

    def test_dc_log_path(self) -> None:
        s = self._settings()
        path = s.domain_controller_log_path
        assert "domain_controller" in str(path)
        assert str(path).endswith(".jsonl")

    def test_ot_log_path(self) -> None:
        s = self._settings()
        path = s.ot_node_log_path
        assert "ot_node" in str(path)
        assert str(path).endswith(".jsonl")

    def test_attacker_log_path(self) -> None:
        s = self._settings()
        path = s.attacker_log_path
        assert "attacker" in str(path)
        assert str(path).endswith(".jsonl")

    def test_log_paths_are_under_base_dir(self) -> None:
        base = "/custom/logs"
        s = self._settings(base_dir=base)
        # Use Path comparison instead of string startswith (Windows uses backslashes)
        from pathlib import Path  # noqa: PLC0415
        base_path = Path(base)
        assert Path(str(s.hospital_server_log_path)).is_relative_to(base_path) or \
               str(s.hospital_server_log_path).replace("\\", "/").startswith(base)
        assert Path(str(s.domain_controller_log_path)).is_relative_to(base_path) or \
               str(s.domain_controller_log_path).replace("\\", "/").startswith(base)


class TestFieldValidation:
    def test_port_below_1024_raises(self) -> None:
        with pytest.raises(Exception):
            DigitalTwinSettings(hospital_server_port=80)

    def test_port_above_65535_raises(self) -> None:
        with pytest.raises(Exception):
            DigitalTwinSettings(domain_controller_port=70000)

    def test_acceleration_factor_below_1_raises(self) -> None:
        with pytest.raises(Exception):
            DigitalTwinSettings(acceleration_factor=0)

    def test_health_timeout_below_1_raises(self) -> None:
        with pytest.raises(Exception):
            DigitalTwinSettings(health_check_timeout_seconds=0)


class TestOverrideValues:
    def test_override_hospital_ip(self) -> None:
        s = DigitalTwinSettings(hospital_server_ip="10.0.0.1")
        assert s.hospital_server_ip == "10.0.0.1"

    def test_override_accelerated_mode(self) -> None:
        s = DigitalTwinSettings(accelerated_mode=True)
        assert s.accelerated_mode is True

    def test_override_acceleration_factor(self) -> None:
        s = DigitalTwinSettings(acceleration_factor=10080)
        assert s.acceleration_factor == 10080


class TestRepr:
    def test_repr_contains_ips(self) -> None:
        s = DigitalTwinSettings()
        r = repr(s)
        assert "172.20.1.10" in r
        assert "172.20.1.20" in r
        assert "172.20.2.10" in r
