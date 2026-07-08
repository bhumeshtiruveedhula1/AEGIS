# Digital Twin Foundation

**Module:** 1.2  
**Status:** Implemented  
**Tag:** `v0.2.0`  

---

## Overview

The Digital Twin Foundation provides the **permanent simulation infrastructure** for the
CyberShield AI-Driven Cyber Resilience Platform. It creates a realistic CNI environment
that produces authentic telemetry used by all subsequent modules for detection, analysis,
and response validation.

> This is not a demo environment. Every later module builds directly on this infrastructure.

---

## Container Architecture

### Services

| Container | Role | Network IP | Health Port | Telemetry Log |
|-----------|------|-----------|-------------|---------------|
| `domain-controller` | Active Directory identity infrastructure | `172.20.1.20` | `9001` | `domain_controller.jsonl` |
| `hospital-server` | Critical application server | `172.20.1.10` | `9002` | `hospital_server.jsonl` |
| `ot-node` | Modbus PLC simulation | `172.20.2.10` | `9003` | `ot_node.jsonl` |
| `attacker` | Controlled attack source | `172.20.3.10` | None | `attacker.jsonl` |
| `cybershield-api` | Management backbone | `172.20.0.10` | `8000` | — |

### Network Topology

```
+====================================================================+
|              cybershield-net                                       |
|                                                                    |
|  Management (172.20.0.0/24)                                        |
|  └── cybershield-api (172.20.0.5)                                  |
|                                                                    |
|  IT Segment (172.20.1.0/24)                                        |
|  ├── hospital-server    (172.20.1.10)  ← API probes this           |
|  └── domain-controller  (172.20.1.20)  ← Hospital depends on this  |
|                                                                    |
|  OT Segment (172.20.2.0/24)  ← Isolated from IT                   |
|  └── ot-node            (172.20.2.10)  ← Independent PLC node      |
|                                                                    |
|  Attacker Segment (172.20.3.0/24)  ← Isolated, no inbound          |
|  └── attacker           (172.20.3.10)  ← Infrastructure only       |
+====================================================================+
```

**Isolation design:**
- OT segment containers cannot directly reach IT segment containers
- Attacker segment has no inbound ports
- API can probe all segments for health checks (multi-homed)

---

## Startup Sequence

Services start in this strict order enforced by `depends_on` + `condition: service_healthy`:

```
1. domain-controller   → starts and becomes healthy
2. hospital-server     → starts ONLY after domain-controller is healthy
3. ot-node             → starts independently in parallel
4. attacker            → starts last, no dependencies
5. cybershield-api     → starts after hospital-server AND ot-node are healthy
```

This ensures telemetry is flowing before the API begins health-checking the Digital Twin.

---

## Telemetry

### Schema Contract

Every event produced by any container conforms to the `BaseEvent` schema:

```json
{
  "event_id":    "550e8400-e29b-41d4-a716-446655440000",
  "timestamp":   "2024-01-15T10:30:00.000000Z",
  "source":      "hospital_server | domain_controller | ot_node | attacker",
  "event_type":  "ProcessCreate | UserLogon | ModbusRead | ...",
  "host":        "hospital-server-01 | dc-01 | plc-01",
  "user":        "svc-iis | CORP\\jsmith | SCADA",
  "resource":    "sqlservr.exe | 172.20.1.20 | register_10",
  "action":      "execute | authenticate | read | write",
  "result":      "success | failure",
  "raw_log":     "{ full event payload as JSON string }"
}
```

### Hospital Server Events

| Event Type | Windows Equivalent | Rate (normal) |
|------------|-------------------|---------------|
| `ProcessCreate` | Event ID 4688 | 75/hour |
| `ProcessTerminate` | Event ID 4689 | ~30/hour |
| `NetworkConnect` | Sysmon EID 3 | 150/hour |
| `FileAccess` | Sysmon EID 10 | ~40/hour |
| `FileCreate` | Sysmon EID 11 | ~10/hour |
| `DatabaseQuery` | Custom | 40/hour |
| `UserLogon` | Event ID 4624 | ~18/hour |
| `UserLogonFailed` | Event ID 4625 | ~2/hour |

### Domain Controller Events

| Event Type | Windows Equivalent | Rate (normal) |
|------------|-------------------|---------------|
| `UserLogon` | Event ID 4624 | 12/hour |
| `UserLogonFailed` | Event ID 4625 | 5/hour |
| `UserLogoff` | Event ID 4634 | 10/hour |
| `PrivilegeAssigned` | Event ID 4672 | 3/hour |
| `UserCreated` | Event ID 4720 | ~1/hour |
| `GroupMembershipChanged` | Event ID 4728 | ~1/hour |
| `KerberosTicketRequest` | Event ID 4769 | 30/hour |

### OT Node Events

| Event Type | Modbus | Rate (normal) |
|------------|--------|---------------|
| `ModbusRead` | FC 03 (Read Holding Registers) | Every 5 seconds |
| `ModbusWrite` | FC 06 (Write Single Register) | Every 60 seconds |
| `ModbusHeartbeat` | — | Every 30 seconds |
| `PLCStatus` | — | Every 60 seconds |

**Normal register ranges:**
- Reads: Registers 10–20 (sensor data: temperature, pressure, flow)
- Writes: Registers 30–40 (setpoints: HVAC, oxygen valve, pump control)

**Attack detection signals (consumed by downstream modules):**
- Access to registers 0–9 or 41–100 → discovery/reconnaissance (T0840)
- Write frequency >10x normal → Stuxnet-like sabotage (T0836)
- Source IP not `192.168.1.100` → unauthorised connection (T0861)

---

## Configuration

### Generation Rates

Set in `docker/digital_twin/config/generation_rates.env`:

```env
DT_ACCELERATED_MODE=false          # true = 7 days in ~10 minutes (CI mode)
DT_ACCELERATION_FACTOR=1440        # 1 day compressed to 1 minute
DT_PROCESS_CREATES_PER_HOUR=75     # Hospital server
DT_DC_KERBEROS_PER_HOUR=30         # Domain controller
DT_OT_READ_INTERVAL_SECONDS=5      # OT node
```

### CI Baseline Generation (Accelerated Mode)

To generate a 7-day baseline in approximately 10 minutes:

```bash
DT_ACCELERATED_MODE=true DT_ACCELERATION_FACTOR=10080 \
  docker compose -f docker/docker-compose.yml up
```

Watch progress:
```bash
docker logs cybershield-hospital-server -f   # hospital events
docker logs cybershield-ot-node -f           # OT events
ls -la data/digital_twin/                   # log file sizes
```

---

## Service Discovery API

Downstream modules discover telemetry sources via the `DigitalTwinRegistry`:

```python
from backend.digital_twin.registry import get_registry
from backend.digital_twin.models import ContainerRole

registry = get_registry()

# Discover all log paths for ingestion (Module 1.3)
for source in registry.list_telemetry_sources():
    print(source.host_log_path, source.event_types)

# Check if OT node is healthy (Module 2.x)
status = registry.get_container_status(ContainerRole.OT_NODE)
print(status.is_healthy)

# Get full topology for anomaly context (Module 2.x)
topology = registry.get_topology()
it_subnet = topology.it_subnet
```

---

## Health Endpoints

### Digital Twin aggregate health

`GET /health` (via API gateway):

```json
{
  "status": "healthy",
  "components": {
    "digital_twin": {
      "status": "healthy",
      "hospital_server": { "status": "healthy" },
      "domain_controller": { "status": "healthy" },
      "ot_node": { "status": "healthy" },
      "attacker": { "status": "unknown" }
    }
  }
}
```

### Individual container health

```bash
curl http://localhost:9001/health  # domain-controller
curl http://localhost:9002/health  # hospital-server
curl http://localhost:9003/health  # ot-node
```

```json
{
  "status": "running",
  "generator": "DomainControllerGenerator",
  "hostname": "dc-01",
  "total_events_written": 1247,
  "uptime_seconds": 3602.4,
  "accelerated_mode": false
}
```

---

## Integration Points — Downstream Modules

| Module | What it uses from Module 1.2 |
|--------|------------------------------|
| **1.3 Normalization** | `registry.list_telemetry_sources()` → log paths and event types |
| **2.1 Baseline** | `registry.get_all_log_paths()` → reads all JSONL logs for baseline stats |
| **2.4 Detection** | `ContainerRole` → maps `DetectionAlert` to specific containers |
| **3.3 MITRE Mapper** | `TelemetryEventType` → maps event types to ATT&CK techniques |
| **3.X Synthetic Attack** | `attacker` container config → target host/IP selection |
| **4.1 Attack Context** | `DigitalTwinRegistry.get_topology()` → host/subnet context for evidence |
| **5+ Dashboard** | `DigitalTwinHealth.to_summary()` → DT status widget (Phase 5) |

---

## Files Added

```
backend/
└── digital_twin/
    ├── __init__.py        ← Module documentation and architecture
    ├── config.py          ← DigitalTwinSettings (extends Module 1.1)
    ├── models.py          ← All Pydantic models (ContainerStatus, TelemetrySource, etc.)
    ├── registry.py        ← DigitalTwinRegistry singleton
    └── health.py          ← Health check implementations

docker/
└── digital_twin/
    ├── config/
    │   ├── network.env           ← Static IPs and ports
    │   └── generation_rates.env  ← Event generation rates
    ├── shared/
    │   ├── __init__.py
    │   ├── event_schema.py       ← Canonical event schema (no ext deps)
    │   ├── writer.py             ← Thread-safe JSONL writer
    │   └── base_generator.py     ← Abstract base generator
    ├── hospital_server/
    │   ├── Dockerfile
    │   ├── entrypoint.sh
    │   ├── generator.py          ← IT telemetry generator
    │   └── health_server.py
    ├── domain_controller/
    │   ├── Dockerfile
    │   ├── entrypoint.sh
    │   ├── generator.py          ← DC authentication generator
    │   └── health_server.py
    ├── ot_node/
    │   ├── Dockerfile
    │   ├── entrypoint.sh
    │   ├── generator.py          ← Modbus simulation generator
    │   └── health_server.py
    └── attacker/
        ├── Dockerfile
        ├── entrypoint.sh
        └── tools/
            ├── __init__.py
            └── reconnaissance.py ← Infrastructure scaffold only

data/digital_twin/                ← Log output directories (gitkeep)
tests/
├── unit/digital_twin/
│   ├── test_models.py
│   ├── test_registry.py
│   └── test_config.py
└── integration/
    └── test_digital_twin_health.py
```
