# ADR-002: Digital Twin Network Design

**Date:** 2024-01-15  
**Status:** Accepted  
**Module:** 1.2 — Digital Twin Foundation  

---

## Context

Module 1.2 requires a Docker-based simulation environment that models a Critical
National Infrastructure (CNI) hospital deployment. The environment must:

1. Produce realistic telemetry for IT, identity, and OT systems
2. Support future attack injection scenarios
3. Be completely isolated between network segments
4. Integrate with the existing Module 1.1 API backbone
5. Be runnable on a single developer machine

The key architectural decision was: **how to design the network topology**.

---

## Decision

Use **4 separate Docker bridge networks** with **static IP assignments** per container,
modelling 4 distinct network segments:

| Segment | CIDR | Purpose |
|---------|------|---------|
| Management | `172.20.0.0/24` | API and service discovery |
| IT | `172.20.1.0/24` | Hospital server + Domain Controller |
| OT | `172.20.2.0/24` | PLC / Sensor node |
| Attacker | `172.20.3.0/24` | Controlled attack source |

---

## Alternatives Considered

### A: Single bridge network (rejected)
All containers on one network. Simple, but:
- No network-level isolation between IT and OT
- Attacker can freely reach OT (unrealistic)
- Cross-subnet traffic anomalies impossible to detect
- Not representative of real CNI architecture

### B: macvlan network (rejected)
Real-looking IPs, closer to production. But:
- Requires host network configuration
- Not portable across developer machines
- OS-dependent (Windows Docker Desktop has known issues)

### C: 4 bridge networks with static IPs (chosen)
- Explicit isolation between segments
- Attacker → OT communication is impossible without network policy change
- Static IPs enable anomaly detection training:
  - Unexpected source IP = clear signal
  - Cross-subnet traffic = detectable pattern
- Works on all platforms (Windows, Mac, Linux)
- IPAM configuration in docker-compose = reproducible

---

## Consequences

### Benefits
- OT isolation is real: the ot-node cannot receive connections from the attacker segment
  (Docker bridge does not route between separate bridge networks)
- Static IPs mean detection training data is reproducible
- 4-segment topology mirrors real CNI architectures (NIST SP 800-82)
- Future attack simulation can enable/disable routing between segments

### Tradeoffs
- More complex docker-compose (4 network definitions vs 1)
- Containers that need multi-segment access (API) are multi-homed
- IP address conflicts must be manually managed (172.20.x.x range reserved)

### Future Considerations
- Module 3.x attack simulation may need to add the attacker to the IT network
  temporarily to simulate lateral movement. This can be done via `docker network connect`
  at attack injection time without changing this baseline architecture.
- Production deployment would use Kubernetes NetworkPolicy instead of Docker bridge isolation.

---

## Why Static IPs?

Dynamic IPs (Docker DNS) would work for service-to-service communication, but:
- Telemetry events need to embed source IPs that match the network model
- Detection models train on fixed IP patterns (OT reads always from `192.168.1.100`)
- Any change in IP → retraining required
- Static IPs = deterministic, reproducible baseline

Static IP assignments are documented in `docker/digital_twin/config/network.env`
and must be kept in sync with `docker/docker-compose.yml`.
