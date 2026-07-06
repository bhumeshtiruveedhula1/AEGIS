"""
OT Node Telemetry Generator — Modbus Simulation
================================================
Simulates a minimal Operational Technology (OT) device: a PLC (Programmable
Logic Controller) running in a hospital's building management / medical
equipment control environment.

This is intentionally LIGHTWEIGHT. The architecture specifies:
  "The OT node is a representative OT device, not a full SCADA implementation."

What it simulates
------------------
A single Modbus TCP PLC that:
  1. Reads sensor registers (temperature, pressure, flow rate) every 5 seconds
  2. Writes control registers (setpoints, commands) every 60 seconds
  3. Emits heartbeat events every 30 seconds
  4. Reports PLC operational status periodically

Normal Baseline Behaviour
--------------------------
Event category             | Interval   | Notes
---------------------------|------------|------
ModbusRead                 | 5 seconds  | Registers 10-20 (sensor polling)
ModbusWrite                | 60 seconds | Registers 30-40 (control commands)
ModbusHeartbeat            | 30 seconds | Supervisory host connection check
PLCStatus                  | 60 seconds | PLC operational state

Attack Injection Points (future modules)
-----------------------------------------
Future attack scenarios will inject:
  - Reads from unusual registers (40-100) → Stuxnet-like discovery
  - High-frequency writes (10x normal) → Stuxnet-like sabotage
  - Connections from unexpected IPs → Intrusion
  - Cross-subnet traffic from 172.20.3.x (attacker)

References
-----------
- ICS-CERT Advisory on Modbus exploitation
- Stuxnet analysis: abnormal register write patterns
- NIST SP 800-82: Guide to ICS Security
"""

from __future__ import annotations

import os
import random
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.base_generator import BaseGenerator
from shared.event_schema import TelemetryEvent, make_event


# ---------------------------------------------------------------------------
# Normal register ranges (from DT configuration / architecture spec)
# ---------------------------------------------------------------------------

# Sensor registers (read-only, polled by SCADA)
NORMAL_READ_REGISTERS = list(range(10, 21))   # 10 to 20 inclusive

# Control registers (written by SCADA supervisor)
NORMAL_WRITE_REGISTERS = list(range(30, 41))  # 30 to 40 inclusive

# Realistic register names for human-readable logging
REGISTER_NAMES = {
    10: "HVAC_Temperature_C",
    11: "HVAC_Humidity_Pct",
    12: "Oxygen_Pressure_kPa",
    13: "Water_Flow_LPM",
    14: "Generator_Voltage_V",
    15: "UPS_Battery_Pct",
    16: "MRI_Room_Temp_C",
    17: "ICU_Air_Pressure_Pa",
    18: "Pharmacy_Temp_C",
    19: "Boiler_Temp_C",
    20: "Chiller_Temp_C",
    30: "HVAC_Setpoint_C",
    31: "Oxygen_Valve_Pct",
    32: "Water_Pump_State",
    33: "Generator_Breaker",
    34: "UPS_Charge_Mode",
    35: "Alarm_Enable",
    36: "MRI_Cooling_Setpoint",
    37: "ICU_Pressure_Setpoint",
    38: "Pharmacy_Cooling_Setpoint",
    39: "Boiler_Setpoint_C",
    40: "Chiller_Setpoint_C",
}

# Normal PLC operational states
PLC_STATES = ["RUNNING", "IDLE", "MAINTENANCE_WINDOW"]

# Normal value ranges per register (realistic process values)
REGISTER_VALUE_RANGES = {
    10: (20.0, 24.0),    # Temperature: 20-24°C
    11: (40.0, 60.0),    # Humidity: 40-60%
    12: (101.0, 103.0),  # Oxygen pressure
    13: (50.0, 80.0),    # Water flow
    14: (220.0, 240.0),  # Generator voltage
    15: (80.0, 100.0),   # UPS battery
    16: (20.0, 22.0),    # MRI room temp
    17: (100.0, 110.0),  # ICU air pressure
    18: (4.0, 8.0),      # Pharmacy temp (cold storage)
    19: (75.0, 85.0),    # Boiler temp
    20: (6.0, 10.0),     # Chiller temp
}


class OTNodeGenerator(BaseGenerator):
    """
    OT Node Modbus simulation generator.

    Produces realistic ICS telemetry for a hospital building management PLC.
    All events are within the normal operational envelope.
    """

    def __init__(self) -> None:
        super().__init__()
        self.hostname = os.environ.get("DT_CONTAINER_HOSTNAME", "plc-01")
        self.supervisory_host = os.environ.get("DT_SUPERVISORY_HOST", "192.168.1.100")

        # Timing (in generator ticks, not seconds — converted via tick interval)
        self.read_interval_seconds = int(
            os.environ.get("DT_OT_READ_INTERVAL_SECONDS", "5")
        )
        self.write_interval_seconds = int(
            os.environ.get("DT_OT_WRITE_INTERVAL_SECONDS", "60")
        )
        self.heartbeat_interval_seconds = int(
            os.environ.get("DT_OT_HEARTBEAT_INTERVAL_SECONDS", "30")
        )

        # Normal register ranges from env (matches DigitalTwinSettings)
        read_start = int(os.environ.get("DT_OT_READ_REG_START", "10"))
        read_end = int(os.environ.get("DT_OT_READ_REG_END", "20"))
        write_start = int(os.environ.get("DT_OT_WRITE_REG_START", "30"))
        write_end = int(os.environ.get("DT_OT_WRITE_REG_END", "40"))

        self._read_registers = list(range(read_start, read_end + 1))
        self._write_registers = list(range(write_start, write_end + 1))
        self._rng = random.Random(int(os.environ.get("DT_RANDOM_SEED", "44")))

        # Internal timing state
        self._ticks_since_read = 0
        self._ticks_since_write = 0
        self._ticks_since_heartbeat = 0
        self._ticks_since_status = 0

        # Simulated register state (current values)
        self._register_state: dict[int, float] = {}
        self._init_register_state()

    def _init_register_state(self) -> None:
        """Initialise all registers to midpoint normal values."""
        for reg in self._read_registers:
            lo, hi = REGISTER_VALUE_RANGES.get(reg, (0.0, 100.0))
            self._register_state[reg] = (lo + hi) / 2.0

    def _realistic_value(self, register: int) -> float:
        """
        Generate a realistic sensor value for a register.

        Applies small random walk from current value to simulate realistic
        process behaviour (values don't jump randomly).
        """
        lo, hi = REGISTER_VALUE_RANGES.get(register, (0.0, 100.0))
        current = self._register_state.get(register, (lo + hi) / 2.0)
        # Small random walk: ±1% of range
        delta = (hi - lo) * 0.01 * self._rng.uniform(-1.0, 1.0)
        new_val = max(lo, min(hi, current + delta))
        self._register_state[register] = new_val
        return round(new_val, 2)

    def generate_normal_events(self, tick: int) -> list[TelemetryEvent]:
        """Generate OT events based on elapsed ticks and timing configuration."""
        events: list[TelemetryEvent] = []
        interval = max(1.0, self._tick_interval_seconds)

        self._ticks_since_read += interval
        self._ticks_since_write += interval
        self._ticks_since_heartbeat += interval
        self._ticks_since_status += interval

        # Modbus Read poll
        if self._ticks_since_read >= self.read_interval_seconds:
            self._ticks_since_read = 0
            # Read all registers in one sweep
            for reg in self._rng.sample(self._read_registers, k=min(3, len(self._read_registers))):
                events.append(self._modbus_read(reg))

        # Modbus Write (control commands)
        if self._ticks_since_write >= self.write_interval_seconds:
            self._ticks_since_write = 0
            reg = self._rng.choice(self._write_registers)
            events.append(self._modbus_write(reg))

        # Heartbeat
        if self._ticks_since_heartbeat >= self.heartbeat_interval_seconds:
            self._ticks_since_heartbeat = 0
            events.append(self._heartbeat_event())

        # PLC Status
        if self._ticks_since_status >= 60:
            self._ticks_since_status = 0
            events.append(self._plc_status())

        return events

    # -----------------------------------------------------------------------
    # Event Builders
    # -----------------------------------------------------------------------

    def _modbus_read(self, register: int) -> TelemetryEvent:
        """Modbus register read event."""
        value = self._realistic_value(register)
        reg_name = REGISTER_NAMES.get(register, f"register_{register}")

        return make_event(
            source="ot_node",
            event_type="ModbusRead",
            host=self.hostname,
            user="SCADA",
            resource=f"register_{register}",
            action="read",
            result="success",
            modbus_function_code=3,   # Read Holding Registers
            modbus_register=register,
            modbus_register_name=reg_name,
            modbus_value=value,
            supervisory_host=self.supervisory_host,
            unit_id=1,
        )

    def _modbus_write(self, register: int) -> TelemetryEvent:
        """Modbus register write event (control command from SCADA)."""
        # Write a setpoint value (realistic range for control registers)
        lo, hi = (0.0, 100.0)
        value = round(self._rng.uniform(lo * 0.8, hi * 0.8), 1)
        reg_name = REGISTER_NAMES.get(register, f"register_{register}")

        return make_event(
            source="ot_node",
            event_type="ModbusWrite",
            host=self.hostname,
            user="SCADA",
            resource=f"register_{register}",
            action="write",
            result="success",
            modbus_function_code=6,   # Write Single Register
            modbus_register=register,
            modbus_register_name=reg_name,
            modbus_value=value,
            supervisory_host=self.supervisory_host,
            unit_id=1,
        )

    def _heartbeat_event(self) -> TelemetryEvent:
        """Supervisory heartbeat — SCADA checks PLC is alive."""
        return make_event(
            source="ot_node",
            event_type="ModbusHeartbeat",
            host=self.hostname,
            user="SCADA",
            resource="plc_heartbeat",
            action="heartbeat",
            result="success",
            supervisory_host=self.supervisory_host,
            response_time_ms=self._rng.randint(1, 15),
        )

    def _plc_status(self) -> TelemetryEvent:
        """PLC operational status report."""
        state = "RUNNING"  # Normal baseline — always running
        return make_event(
            source="ot_node",
            event_type="PLCStatus",
            host=self.hostname,
            user="SYSTEM",
            resource="plc_status",
            action="heartbeat",
            result="success",
            plc_state=state,
            active_registers=len(self._read_registers) + len(self._write_registers),
            uptime_ticks=self._tick,
            supervisory_host=self.supervisory_host,
        )

    def health_extras(self) -> dict[str, Any]:
        return {
            "plc_state": "RUNNING",
            "registers_monitored": len(self._read_registers),
            "supervisory_host": self.supervisory_host,
            "last_read_seconds_ago": round(self._ticks_since_read, 1),
            "last_write_seconds_ago": round(self._ticks_since_write, 1),
        }


if __name__ == "__main__":
    import importlib.util  # noqa: PLC0415
    spec = importlib.util.spec_from_file_location(
        "health_server", Path(__file__).parent / "health_server.py"
    )
    if spec and spec.loader:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
        mod.start_health_server()

    generator = OTNodeGenerator()
    generator.run()
