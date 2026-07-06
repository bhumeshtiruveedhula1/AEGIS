"""
backend.digital_twin — Digital Twin Foundation Module
======================================================
[Module 1.2 — Week 1, Phase 1A]

RESPONSIBILITY
--------------
Provide the complete Digital Twin environment model that all future modules
depend on for telemetry consumption, attack simulation, and validation.

The Digital Twin represents a simulated Critical National Infrastructure (CNI)
deployment consisting of:

  1. Hospital Server       — Critical IT application server (IT segment)
  2. Domain Controller     — Centralised identity infrastructure (IT segment)
  3. OT Node               — Operational Technology PLC/sensor node (OT segment)
  4. Attacker Node         — Controlled attack source (Attacker segment)

WHAT THIS MODULE PROVIDES
--------------------------
- ContainerStatus         : Per-container health and telemetry metadata
- TelemetrySource         : Descriptor for each log source a container produces
- DigitalTwinHealth       : Aggregate health model for the entire DT environment
- NetworkTopology         : Network segment and IP address registry
- DigitalTwinRegistry     : Singleton service registry — future modules import this
                            to discover telemetry sources and container endpoints
- Health checks           : Integrates with Module 1.1 register_health_check()
- DigitalTwinSettings     : Environment configuration for the DT (rates, IPs, paths)

WHAT THIS MODULE DOES NOT PROVIDE
----------------------------------
- Log normalization (Module 1.3)
- Anomaly detection (Module 2.1)
- MITRE mapping (Module 2.3)
- LLM enrichment (Module 3.1)
- Response orchestration (Module 3.2)
- Any detection or business logic

CONTAINER TOPOLOGY
------------------
                Management (172.20.0.0/24)
                        |
         +--------------+--------------+
         |                             |
   IT Segment                     Management
   (172.20.1.0/24)                Backbone
         |                             |
   hospital-server (172.20.1.10)       |
   domain-controller (172.20.1.20)     |
                                       |
                              OT Segment (172.20.2.0/24)
                                   |
                            ot-node (172.20.2.10)
                                       |
                           Attacker (172.20.3.0/24)
                                   |
                           attacker (172.20.3.10)

TELEMETRY SCHEMA CONTRACT
--------------------------
All Digital Twin containers produce JSONL logs whose events extend
backend.shared.models.BaseEvent. Schema is enforced at the generator
level and validated in the normalization module.

DEPENDENCY RULE
---------------
backend.digital_twin imports ONLY from:
  - Python standard library
  - Third-party libraries (pydantic, structlog)
  - backend.core
  - backend.shared

It must NOT import from backend.ingestion, backend.detection, or any
later-phase module. This prevents circular imports.
"""

__version__ = "0.1.0"
__module__ = "digital_twin"
