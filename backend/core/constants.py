"""
backend.core.constants — Project-Wide Constants
================================================
All constants that are shared across modules.

Design Rules
------------
- No mutable state: all values are str, int, float, frozenset, or tuple.
- Enum classes are preferred over bare strings for type-checked values.
- Module-specific constants belong in their own module, not here.
- When a constant needs to change per environment, promote it to config.py.
"""

from __future__ import annotations

from enum import StrEnum, auto, unique


# ---------------------------------------------------------------------------
# Application Identity
# ---------------------------------------------------------------------------
APP_NAME = "CyberShield"
APP_VERSION = "0.1.0"
APP_DESCRIPTION = (
    "AI-Driven Cyber Resilience Platform for Critical National Infrastructure"
)
API_PREFIX = "/api/v1"


# ---------------------------------------------------------------------------
# Pipeline Module Names
# Used for structured log correlation and health-check registration.
# ---------------------------------------------------------------------------
@unique
class ModuleName(StrEnum):
    """Canonical names for all platform modules."""

    FOUNDATION = "foundation"
    INGESTION = "ingestion"
    NORMALIZATION = "normalization"
    FEATURES = "features"
    DETECTION = "detection"
    EXPLAINABILITY = "explainability"
    MITRE = "mitre"
    GRAPH = "graph"
    LLM = "llm"
    RESPONSE = "response"
    AUDIT = "audit"
    DASHBOARD = "dashboard"


# ---------------------------------------------------------------------------
# Log Sources — Module: ingestion / normalization
# ---------------------------------------------------------------------------
@unique
class LogSource(StrEnum):
    """Supported log source identifiers."""

    SYSMON = "sysmon"
    WINDOWS_EVENT = "windows_event"
    AUDITD = "auditd"
    IPTABLES = "iptables"
    DNS = "dns"
    NETFLOW = "netflow"
    MODBUS = "modbus_simulator"          # OT / ICS

    @classmethod
    def all_sources(cls) -> frozenset["LogSource"]:
        """Return all supported log sources."""
        return frozenset(cls)


# ---------------------------------------------------------------------------
# Event Types — Module: normalization
# Canonical event type names used in the normalized schema.
# ---------------------------------------------------------------------------
@unique
class EventType(StrEnum):
    """Normalised event type identifiers."""

    PROCESS_CREATE = "ProcessCreate"
    PROCESS_TERMINATE = "ProcessTerminate"
    NETWORK_CONNECT = "NetworkConnect"
    NETWORK_DISCONNECT = "NetworkDisconnect"
    FILE_CREATE = "FileCreate"
    FILE_DELETE = "FileDelete"
    REGISTRY_ACCESS = "RegistryAccess"
    REGISTRY_MODIFY = "RegistryModify"
    USER_LOGIN = "UserLogin"
    USER_LOGOUT = "UserLogout"
    USER_LOGIN_FAILED = "UserLoginFailed"
    PRIVILEGE_ESCALATION = "PrivilegeEscalation"
    DNS_QUERY = "DnsQuery"
    FIREWALL_BLOCK = "FirewallBlock"
    FIREWALL_ALLOW = "FirewallAllow"
    MODBUS_READ = "ModbusRead"
    MODBUS_WRITE = "ModbusWrite"
    UNKNOWN = "Unknown"


# ---------------------------------------------------------------------------
# Severity Levels — Modules: detection, llm, response
# ---------------------------------------------------------------------------
@unique
class Severity(StrEnum):
    """Alert severity levels aligned with the LLM enrichment schema."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def numeric(self) -> int:
        """Numeric representation for sorting (higher = more severe)."""
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]


# ---------------------------------------------------------------------------
# Action Types — Module: response
# ---------------------------------------------------------------------------
@unique
class ActionType(StrEnum):
    """Supported autonomous response action types."""

    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    KILL_PROCESS = "kill_process"
    TRIGGER_PCAP = "trigger_pcap"
    INVESTIGATE = "investigate"
    NONE = "none"


# ---------------------------------------------------------------------------
# Approval Status — Module: response / audit
# ---------------------------------------------------------------------------
@unique
class ApprovalStatus(StrEnum):
    """Human approval gate status for response actions."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


# ---------------------------------------------------------------------------
# Execution Status — Module: response / audit
# ---------------------------------------------------------------------------
@unique
class ExecutionStatus(StrEnum):
    """Status of an action after approval and execution."""

    PENDING = "pending"
    EXECUTING = "executing"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


# ---------------------------------------------------------------------------
# MITRE ATT&CK Constants — Module: mitre / graph
# ---------------------------------------------------------------------------
MITRE_ATTACK_VERSION = "14.1"
MITRE_TECHNIQUE_PREFIX = "T"
MITRE_SUBTECHNIQUE_SEPARATOR = "."

# High-value Windows Event IDs (monitored sources)
WINDOWS_EVENT_IDS: frozenset[int] = frozenset({
    4624,   # Successful login
    4625,   # Failed login
    4688,   # Process creation
    4698,   # Scheduled task creation
    4720,   # User account creation
    4732,   # Member added to security-enabled group
    4768,   # Kerberos authentication (TGT request)
    4769,   # Kerberos service ticket request
    1102,   # Audit log cleared
    1104,   # UAC bypass indicator
})

# Suspicious process names (used in baseline feature extraction)
SUSPICIOUS_PROCESSES: frozenset[str] = frozenset({
    "mimikatz.exe",
    "psexec.exe",
    "wmiexec.py",
    "bloodhound.exe",
    "cobalt strike",
    "meterpreter",
    "nc.exe",           # netcat
    "ncat.exe",
    "procdump.exe",
    "lsass.exe",        # suspicious if spawned directly
})

# Normal administrative processes (baseline)
KNOWN_GOOD_PROCESSES: frozenset[str] = frozenset({
    "svchost.exe",
    "explorer.exe",
    "chrome.exe",
    "firefox.exe",
    "cmd.exe",
    "powershell.exe",
    "notepad.exe",
    "taskmgr.exe",
    "msiexec.exe",
    "services.exe",
    "lsass.exe",        # context-dependent
    "winlogon.exe",
})


# ---------------------------------------------------------------------------
# OT / ICS Constants — Module: ingestion
# ---------------------------------------------------------------------------
MODBUS_NORMAL_READ_REGISTERS: tuple[int, ...] = tuple(range(10, 21))     # 10–20
MODBUS_NORMAL_WRITE_REGISTERS: tuple[int, ...] = tuple(range(30, 41))    # 30–40
MODBUS_SUPERVISORY_HOST = "192.168.1.100"
MODBUS_NORMAL_READ_INTERVAL_SECONDS = 5
MODBUS_NORMAL_WRITE_INTERVAL_SECONDS = 60


# ---------------------------------------------------------------------------
# Anomaly Detection Thresholds — Module: detection
# ---------------------------------------------------------------------------
ANOMALY_SCORE_MIN: float = -1.0
ANOMALY_SCORE_MAX: float = 1.0
ANOMALY_SCORE_DEFAULT_THRESHOLD: float = 0.5
BASELINE_WINDOW_DAYS: int = 7
BASELINE_HOURS: int = BASELINE_WINDOW_DAYS * 24


# ---------------------------------------------------------------------------
# Timing Constants
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT_SECONDS: int = 30
LLM_TIMEOUT_SECONDS: int = 2
METRICS_INTERVAL_SECONDS: int = 3600
AUDIT_LOG_RETENTION_DAYS: int = 30


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
HTTP_200_OK = 200
HTTP_201_CREATED = 201
HTTP_400_BAD_REQUEST = 400
HTTP_401_UNAUTHORIZED = 401
HTTP_403_FORBIDDEN = 403
HTTP_404_NOT_FOUND = 404
HTTP_422_UNPROCESSABLE_ENTITY = 422
HTTP_429_TOO_MANY_REQUESTS = 429
HTTP_500_INTERNAL_SERVER_ERROR = 500
HTTP_503_SERVICE_UNAVAILABLE = 503
