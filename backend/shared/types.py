"""
backend.shared.types — Domain Type Aliases
==========================================
Centralised type aliases for domain concepts.

Using explicit type aliases instead of bare primitives:
  - Improves readability (AlertId vs str)
  - Enables precise mypy checking
  - Makes refactoring safe (change one place, propagate everywhere)
  - Documents intent at the call site

Usage
-----
    from backend.shared.types import AlertId, AnomalyScore, HostName

    def score_event(host: HostName) -> AnomalyScore: ...
"""

from __future__ import annotations

from typing import Annotated, Literal, NewType

from pydantic import Field

# ---------------------------------------------------------------------------
# Identity Types
# ---------------------------------------------------------------------------
AlertId = NewType("AlertId", str)
"""UUID v4 string identifying a unique alert."""

ActionId = NewType("ActionId", str)
"""UUID v4 string identifying a response action."""

IncidentId = NewType("IncidentId", str)
"""UUID v4 string identifying an incident (correlated chain of alerts)."""

RequestId = NewType("RequestId", str)
"""UUID v4 string injected per HTTP request for log correlation."""

ChainId = NewType("ChainId", str)
"""UUID v4 string identifying an attack chain hypothesis."""

ModelId = NewType("ModelId", str)
"""UUID v4 string identifying a trained ML model artifact."""

# ---------------------------------------------------------------------------
# Infrastructure Types
# ---------------------------------------------------------------------------
HostName = NewType("HostName", str)
"""Hostname or IP address of a monitored system."""

UserName = NewType("UserName", str)
"""Username or service account name (may include domain, e.g., DOMAIN\\user)."""

ProcessName = NewType("ProcessName", str)
"""Process executable name (e.g., 'cmd.exe', 'svchost.exe')."""

IpAddress = NewType("IpAddress", str)
"""IPv4 or IPv6 address string."""

MacAddress = NewType("MacAddress", str)
"""MAC address string in colon-separated format."""

DnsName = NewType("DnsName", str)
"""Fully qualified domain name."""

# ---------------------------------------------------------------------------
# Security / Detection Types
# ---------------------------------------------------------------------------
AnomalyScore = Annotated[
    float,
    Field(ge=-1.0, le=1.0, description="Isolation Forest anomaly score [-1, 1]"),
]
"""Isolation Forest anomaly score. Values closer to +1 are more anomalous."""

ShapValue = Annotated[
    float,
    Field(description="SHAP feature contribution value (can be negative)"),
]
"""SHAP value representing a feature's contribution to an anomaly score."""

ConfidenceScore = Annotated[
    float,
    Field(ge=0.0, le=1.0, description="Confidence score [0, 1]"),
]
"""Confidence value, always in [0.0, 1.0] range."""

MITRETechniqueId = NewType("MITRETechniqueId", str)
"""MITRE ATT&CK technique identifier (e.g., 'T1059', 'T1059.001')."""

MITRETacticId = NewType("MITRETacticId", str)
"""MITRE ATT&CK tactic identifier (e.g., 'TA0002')."""

# ---------------------------------------------------------------------------
# Action / Response Types
# ---------------------------------------------------------------------------
ApproverEmail = NewType("ApproverEmail", str)
"""Email address of the SOC analyst who approved a response action."""

# ---------------------------------------------------------------------------
# Literal Types (used in Pydantic field definitions)
# ---------------------------------------------------------------------------
LogSourceLiteral = Literal[
    "sysmon",
    "windows_event",
    "auditd",
    "iptables",
    "dns",
    "netflow",
    "modbus_simulator",
]
"""Literal union of all valid log source identifiers."""

EventTypeLiteral = Literal[
    "ProcessCreate",
    "ProcessTerminate",
    "NetworkConnect",
    "NetworkDisconnect",
    "FileCreate",
    "FileDelete",
    "RegistryAccess",
    "RegistryModify",
    "UserLogin",
    "UserLogout",
    "UserLoginFailed",
    "PrivilegeEscalation",
    "DnsQuery",
    "FirewallBlock",
    "FirewallAllow",
    "ModbusRead",
    "ModbusWrite",
    "Unknown",
]
"""Literal union of all normalised event types."""

SeverityLiteral = Literal["critical", "high", "medium", "low", "info"]
"""Literal union of alert severity levels."""

ActionTypeLiteral = Literal[
    "isolate_host",
    "block_ip",
    "disable_account",
    "kill_process",
    "trigger_pcap",
    "investigate",
    "none",
]
"""Literal union of supported response action types."""

ApprovalStatusLiteral = Literal["pending", "approved", "denied", "expired"]
"""Literal union of response action approval states."""

ExecutionStatusLiteral = Literal[
    "pending",
    "executing",
    "executed",
    "failed",
    "rolled_back",
]
"""Literal union of action execution states."""

AppEnvironmentLiteral = Literal["development", "staging", "production"]
"""Literal union of deployment environments."""
