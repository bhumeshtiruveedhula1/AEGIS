"""
backend.mitre.knowledge_base — Local ATT&CK Knowledge Layer
============================================================
Module 3.3 — MITRE ATT&CK Mapper

All knowledge is embedded in this module as Python structures.
No internet calls. No live ATT&CK downloads. Fully deterministic.

Knowledge Base Version: ATT&CK v15
Schema Version: 1.0.0

Organisation
------------
TACTICS     — dict[tactic_id, AttackTactic]
TECHNIQUES  — dict[technique_id, AttackTechnique]

Feature → Technique Mapping
----------------------------
Each feature name (from ALL_FEATURE_NAMES) maps to a list of technique IDs.
The mapper uses this to look up candidate techniques from SHAP contributors.
O(1) lookup via pre-built dict.

Behavioral Indicator Groups
----------------------------
Beyond feature-level mapping, the knowledge base also exposes
indicator-group → [technique_id] for higher-level behavioral patterns
(e.g. "credential_brute_force", "lateral_movement_smb").

Versioning
----------
KNOWLEDGE_VERSION and KNOWLEDGE_DATE allow compatibility checks.
Bump version and date whenever techniques/mappings change.
"""

from __future__ import annotations

from backend.mitre.models import AttackTactic, AttackTechnique

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

KNOWLEDGE_VERSION: str = "ATT&CK-v15"
KNOWLEDGE_DATE: str = "2024-10-01"
SCHEMA_VERSION: str = "1.0.0"


# ---------------------------------------------------------------------------
# Tactics
# ---------------------------------------------------------------------------

def _tactic(tid: str, name: str, short: str, desc: str = "") -> AttackTactic:
    return AttackTactic(tactic_id=tid, name=name, short_name=short, description=desc)


_TACTICS: dict[str, AttackTactic] = {
    "TA0001": _tactic("TA0001", "Initial Access", "initial-access"),
    "TA0002": _tactic("TA0002", "Execution", "execution"),
    "TA0003": _tactic("TA0003", "Persistence", "persistence"),
    "TA0004": _tactic("TA0004", "Privilege Escalation", "privilege-escalation"),
    "TA0005": _tactic("TA0005", "Defense Evasion", "defense-evasion"),
    "TA0006": _tactic("TA0006", "Credential Access", "credential-access"),
    "TA0007": _tactic("TA0007", "Discovery", "discovery"),
    "TA0008": _tactic("TA0008", "Lateral Movement", "lateral-movement"),
    "TA0009": _tactic("TA0009", "Collection", "collection"),
    "TA0010": _tactic("TA0010", "Exfiltration", "exfiltration"),
    "TA0011": _tactic("TA0011", "Command and Control", "command-and-control"),
    "TA0040": _tactic("TA0040", "Impact", "impact"),
    "TA0042": _tactic("TA0042", "Resource Development", "resource-development"),
    # ICS-specific
    "TA0100": _tactic("TA0100", "Inhibit Response Function", "inhibit-response"),
    "TA0104": _tactic("TA0104", "Impair Process Control", "impair-process-control"),
    "TA0108": _tactic("TA0108", "ICS Discovery", "ics-discovery"),
}


# ---------------------------------------------------------------------------
# Techniques — covers all feature groups present in the project
# ---------------------------------------------------------------------------

def _tech(
    tid: str, name: str, tactic_id: str, desc: str = "", url: str = ""
) -> AttackTechnique:
    tactic = _TACTICS[tactic_id]
    return AttackTechnique(
        technique_id=tid, name=name, tactic=tactic, description=desc, url=url
    )


_TECHNIQUES: dict[str, AttackTechnique] = {
    # ── Credential Access ───────────────────────────────────────────────────
    "T1110": _tech(
        "T1110", "Brute Force", "TA0006",
        "Adversaries use brute force to gain access via credential guessing.",
        "https://attack.mitre.org/techniques/T1110/",
    ),
    "T1110.001": _tech(
        "T1110.001", "Brute Force: Password Guessing", "TA0006",
        "Systematic password guessing against one or more accounts.",
    ),
    "T1110.003": _tech(
        "T1110.003", "Brute Force: Password Spraying", "TA0006",
        "Using a single common password against many accounts.",
    ),
    "T1078": _tech(
        "T1078", "Valid Accounts", "TA0001",
        "Adversaries obtain and abuse legitimate credentials.",
        "https://attack.mitre.org/techniques/T1078/",
    ),
    "T1552": _tech(
        "T1552", "Unsecured Credentials", "TA0006",
        "Searching compromised systems for insecurely stored credentials.",
    ),
    # ── Discovery ───────────────────────────────────────────────────────────
    "T1087": _tech(
        "T1087", "Account Discovery", "TA0007",
        "Adversaries enumerate user accounts to aid later targeting.",
        "https://attack.mitre.org/techniques/T1087/",
    ),
    "T1083": _tech(
        "T1083", "File and Directory Discovery", "TA0007",
        "Adversaries enumerate files and directories on target systems.",
        "https://attack.mitre.org/techniques/T1083/",
    ),
    "T1046": _tech(
        "T1046", "Network Service Discovery", "TA0007",
        "Adversaries scan to enumerate services on remote hosts.",
        "https://attack.mitre.org/techniques/T1046/",
    ),
    "T1057": _tech(
        "T1057", "Process Discovery", "TA0007",
        "Adversaries enumerate running processes on a system.",
        "https://attack.mitre.org/techniques/T1057/",
    ),
    "T1082": _tech(
        "T1082", "System Information Discovery", "TA0007",
        "Adversaries gather OS and hardware details.",
        "https://attack.mitre.org/techniques/T1082/",
    ),
    # ── Execution ────────────────────────────────────────────────────────────
    "T1059": _tech(
        "T1059", "Command and Scripting Interpreter", "TA0002",
        "Adversaries use command-line interfaces to execute commands.",
        "https://attack.mitre.org/techniques/T1059/",
    ),
    "T1059.001": _tech(
        "T1059.001", "Command and Scripting Interpreter: PowerShell", "TA0002",
        "Adversaries abuse PowerShell to execute commands.",
    ),
    "T1059.003": _tech(
        "T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "TA0002",
        "Adversaries abuse cmd.exe to execute commands.",
    ),
    "T1204": _tech(
        "T1204", "User Execution", "TA0002",
        "Adversaries rely on user execution of a malicious payload.",
    ),
    # ── Lateral Movement ─────────────────────────────────────────────────────
    "T1021": _tech(
        "T1021", "Remote Services", "TA0008",
        "Adversaries use remote service protocols to move laterally.",
        "https://attack.mitre.org/techniques/T1021/",
    ),
    "T1021.001": _tech(
        "T1021.001", "Remote Services: Remote Desktop Protocol", "TA0008",
        "Adversaries use RDP to log on to remote systems.",
    ),
    "T1021.002": _tech(
        "T1021.002", "Remote Services: SMB/Windows Admin Shares", "TA0008",
        "Adversaries use SMB to access shared drives on remote systems.",
    ),
    "T1210": _tech(
        "T1210", "Exploitation of Remote Services", "TA0008",
        "Adversaries exploit vulnerable network services to move laterally.",
    ),
    # ── Command and Control ──────────────────────────────────────────────────
    "T1071": _tech(
        "T1071", "Application Layer Protocol", "TA0011",
        "Adversaries use application-layer protocols for C2 communication.",
        "https://attack.mitre.org/techniques/T1071/",
    ),
    "T1095": _tech(
        "T1095", "Non-Application Layer Protocol", "TA0011",
        "Adversaries use non-standard protocols for C2.",
    ),
    "T1571": _tech(
        "T1571", "Non-Standard Port", "TA0011",
        "Adversaries use non-standard ports for C2 traffic.",
    ),
    # ── Exfiltration ─────────────────────────────────────────────────────────
    "T1041": _tech(
        "T1041", "Exfiltration Over C2 Channel", "TA0010",
        "Data exfiltrated over the existing C2 channel.",
        "https://attack.mitre.org/techniques/T1041/",
    ),
    "T1048": _tech(
        "T1048", "Exfiltration Over Alternative Protocol", "TA0010",
        "Adversaries exfiltrate data over a different protocol.",
    ),
    # ── Persistence ──────────────────────────────────────────────────────────
    "T1053": _tech(
        "T1053", "Scheduled Task/Job", "TA0003",
        "Adversaries abuse task scheduling to persist on a system.",
        "https://attack.mitre.org/techniques/T1053/",
    ),
    "T1547": _tech(
        "T1547", "Boot or Logon Autostart Execution", "TA0003",
        "Adversaries configure system settings to execute at boot.",
    ),
    # ── Privilege Escalation ─────────────────────────────────────────────────
    "T1068": _tech(
        "T1068", "Exploitation for Privilege Escalation", "TA0004",
        "Adversaries exploit software vulnerabilities to elevate privileges.",
        "https://attack.mitre.org/techniques/T1068/",
    ),
    "T1134": _tech(
        "T1134", "Access Token Manipulation", "TA0004",
        "Adversaries manipulate access tokens to operate under a different context.",
    ),
    # ── Defense Evasion ──────────────────────────────────────────────────────
    "T1055": _tech(
        "T1055", "Process Injection", "TA0005",
        "Adversaries inject code into processes to evade defenses.",
        "https://attack.mitre.org/techniques/T1055/",
    ),
    "T1036": _tech(
        "T1036", "Masquerading", "TA0005",
        "Adversaries disguise malicious activity as legitimate.",
    ),
    # ── Collection ───────────────────────────────────────────────────────────
    "T1005": _tech(
        "T1005", "Data from Local System", "TA0009",
        "Adversaries search local system sources for sensitive data.",
        "https://attack.mitre.org/techniques/T1005/",
    ),
    # ── Impact ───────────────────────────────────────────────────────────────
    "T1499": _tech(
        "T1499", "Endpoint Denial of Service", "TA0040",
        "Adversaries degrade or disrupt service availability.",
    ),
    # ── ICS / OT (ICS-specific ATT&CK matrix) ───────────────────────────────
    "T0855": _tech(
        "T0855", "Unauthorized Command Message", "TA0104",
        "Adversaries send unauthorized commands to PLCs/RTUs via fieldbus protocols.",
        "https://attack.mitre.org/techniques/T0855/",
    ),
    "T0836": _tech(
        "T0836", "Modify Parameter", "TA0104",
        "Adversaries modify process parameter values to cause abnormal operation.",
        "https://attack.mitre.org/techniques/T0836/",
    ),
    "T0861": _tech(
        "T0861", "Point & Tag Identification", "TA0108",
        "Adversaries enumerate OT system data points for targeting.",
        "https://attack.mitre.org/techniques/T0861/",
    ),
    "T0846": _tech(
        "T0846", "Remote System Discovery", "TA0108",
        "Adversaries enumerate devices on the ICS network.",
        "https://attack.mitre.org/techniques/T0846/",
    ),
    "T0800": _tech(
        "T0800", "Activate Firmware Update Mode", "TA0100",
        "Adversaries push rogue firmware to field devices.",
    ),
}


# ---------------------------------------------------------------------------
# Feature → [technique_id] mapping
# O(1) lookup — keyed by exact feature name from ALL_FEATURE_NAMES
# ---------------------------------------------------------------------------

# Feature groups and their primary technique associations.
# A feature can map to multiple techniques (multiple hypotheses).
# The mapper uses SHAP value magnitude to rank among them.

FEATURE_TECHNIQUE_MAP: dict[str, list[str]] = {
    # ── Temporal anomalies ───────────────────────────────────────────────────
    "hour_of_day":                  ["T1078", "T1021"],
    "day_of_week":                  ["T1078"],
    "is_business_hours":            ["T1078", "T1021"],
    "hour_baseline_frequency":      ["T1078", "T1021"],
    "hour_relative_frequency":      ["T1078", "T1021"],
    "day_baseline_frequency":       ["T1078"],
    "is_peak_hour":                 ["T1078"],
    "time_since_last_seen_hours":   ["T1078", "T1021.001"],

    # ── Behavioural frequency ────────────────────────────────────────────────
    "event_type_frequency":         ["T1078", "T1059"],
    "event_type_frequency_rank":    ["T1078", "T1059"],
    "action_frequency":             ["T1059", "T1083"],
    "result_failure_rate_baseline": ["T1110", "T1110.001"],
    "result_is_failure":            ["T1110", "T1110.003"],
    "source_frequency":             ["T1078", "T1021"],
    "entity_observation_count":     ["T1078"],
    "baseline_window_days":         ["T1078"],

    # ── Network novelty ──────────────────────────────────────────────────────
    "dst_ip_is_novel":              ["T1021", "T1071", "T1041", "T1571"],
    "src_ip_is_novel":              ["T1021", "T1078"],
    "port_is_novel":                ["T1571", "T1095", "T1021"],
    "protocol_is_novel":            ["T1095", "T1071", "T1048"],
    "port_baseline_frequency":      ["T1571", "T1046"],
    "protocol_baseline_frequency":  ["T1095", "T1071"],
    "bytes_out_z_score":            ["T1041", "T1048"],
    "bytes_out_percentile_rank":    ["T1041", "T1048"],
    "unique_dst_ips_baseline":      ["T1046", "T1021", "T1041"],
    "connection_count_baseline":    ["T1046", "T1499", "T1071"],

    # ── Process novelty ──────────────────────────────────────────────────────
    "process_is_novel":             ["T1059", "T1055", "T1036"],
    "parent_process_is_novel":      ["T1059.001", "T1055", "T1068"],
    "parent_child_pair_is_novel":   ["T1059", "T1055", "T1068"],
    "process_frequency_rank":       ["T1059", "T1204"],
    "unique_processes_baseline":    ["T1059", "T1083", "T1057"],
    "process_event_count_baseline": ["T1059", "T1204"],
    "pid_z_score":                  ["T1055", "T1059"],
    "has_command_line":             ["T1059", "T1059.003", "T1059.001"],

    # ── Authentication anomalies ─────────────────────────────────────────────
    "logon_type_is_novel":          ["T1078", "T1021.001", "T1021.002"],
    "auth_package_is_novel":        ["T1078", "T1134"],
    "logon_type_baseline_frequency": ["T1078", "T1021.001"],
    "auth_package_baseline_frequency": ["T1078", "T1134"],
    "auth_failure_rate_baseline":   ["T1110", "T1110.001", "T1110.003"],
    "auth_event_count_baseline":    ["T1110", "T1078"],
    "windows_event_id_is_novel":    ["T1078", "T1134", "T1068"],

    # ── OT / ICS (Modbus) anomalies ──────────────────────────────────────────
    "modbus_register_z_score":      ["T0836", "T0855"],
    "modbus_value_z_score":         ["T0836", "T0855"],
    "modbus_register_is_in_range":  ["T0836", "T0800"],
    "modbus_value_is_in_range":     ["T0836", "T0855"],
    "modbus_function_code_is_novel": ["T0855", "T0836"],
    "supervisory_host_is_novel":    ["T0846", "T0861", "T0855"],
    "modbus_event_count_baseline":  ["T0855", "T0836"],

    # ── Baseline availability ────────────────────────────────────────────────
    "has_user_baseline":            ["T1078"],
    "has_host_baseline":            ["T1078", "T1021"],
    "has_source_baseline":          ["T1078"],
    "has_user_host_baseline":       ["T1078", "T1021"],

    # ── Entity-level aggregates ───────────────────────────────────────────────
    "entity_unique_dst_ips":        ["T1046", "T1041", "T1021"],
    "entity_unique_processes":      ["T1059", "T1083"],
    "entity_auth_failure_count":    ["T1110", "T1110.001", "T1110.003"],
    "entity_modbus_event_count":    ["T0855", "T0836"],
}


# ---------------------------------------------------------------------------
# Behavioral indicator groups → [technique_id]
# Higher-level patterns built from co-occurring features
# ---------------------------------------------------------------------------

INDICATOR_TECHNIQUE_MAP: dict[str, list[str]] = {
    "credential_brute_force":   ["T1110", "T1110.001", "T1110.003"],
    "novel_logon":              ["T1078", "T1021.001"],
    "novel_process_execution":  ["T1059", "T1059.001", "T1055"],
    "lateral_movement_smb":     ["T1021.002", "T1021"],
    "lateral_movement_rdp":     ["T1021.001"],
    "data_exfiltration":        ["T1041", "T1048"],
    "c2_communication":         ["T1071", "T1095", "T1571"],
    "ot_command_injection":     ["T0855", "T0836"],
    "ot_enumeration":           ["T0861", "T0846"],
    "privilege_escalation":     ["T1068", "T1134", "T1078"],
    "process_injection":        ["T1055", "T1068"],
    "network_scan":             ["T1046", "T1087"],
    "anomalous_off_hours":      ["T1078", "T1021"],
    "high_exfil_volume":        ["T1041", "T1048"],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class MitreKnowledgeBase:
    """
    In-memory ATT&CK knowledge base for the CyberShield platform.

    Provides O(1) lookups for techniques and feature-to-technique mappings.
    Fully deterministic — no external I/O.

    Thread-safe: all state is read-only after __init__.
    """

    def __init__(self) -> None:
        self._tactics: dict[str, AttackTactic] = _TACTICS
        self._techniques: dict[str, AttackTechnique] = _TECHNIQUES
        self._feature_map: dict[str, list[str]] = FEATURE_TECHNIQUE_MAP
        self._indicator_map: dict[str, list[str]] = INDICATOR_TECHNIQUE_MAP

    @property
    def version(self) -> str:
        return KNOWLEDGE_VERSION

    @property
    def schema_version(self) -> str:
        return SCHEMA_VERSION

    @property
    def technique_count(self) -> int:
        return len(self._techniques)

    @property
    def tactic_count(self) -> int:
        return len(self._tactics)

    # ── Lookups ──────────────────────────────────────────────────────────────

    def get_tactic(self, tactic_id: str) -> AttackTactic | None:
        return self._tactics.get(tactic_id)

    def get_technique(self, technique_id: str) -> AttackTechnique | None:
        return self._techniques.get(technique_id)

    def techniques_for_feature(self, feature_name: str) -> list[AttackTechnique]:
        """Return ATT&CK techniques associated with a feature name. Empty if unknown."""
        ids = self._feature_map.get(feature_name, [])
        return [t for tid in ids if (t := self._techniques.get(tid))]

    def technique_ids_for_feature(self, feature_name: str) -> list[str]:
        return self._feature_map.get(feature_name, [])

    def techniques_for_indicator(self, indicator: str) -> list[AttackTechnique]:
        """Return ATT&CK techniques for a named behavioral indicator group."""
        ids = self._indicator_map.get(indicator, [])
        return [t for tid in ids if (t := self._techniques.get(tid))]

    def all_techniques(self) -> list[AttackTechnique]:
        return list(self._techniques.values())

    def all_tactics(self) -> list[AttackTactic]:
        return list(self._tactics.values())

    def is_known_feature(self, feature_name: str) -> bool:
        return feature_name in self._feature_map

    def is_known_technique(self, technique_id: str) -> bool:
        return technique_id in self._techniques

    def is_known_tactic(self, tactic_id: str) -> bool:
        return tactic_id in self._tactics

    def known_features(self) -> list[str]:
        return list(self._feature_map.keys())

    def known_indicators(self) -> list[str]:
        return list(self._indicator_map.keys())

    # ── Combined lookup ───────────────────────────────────────────────────────

    def techniques_for_features(
        self, feature_names: list[str]
    ) -> dict[str, list[AttackTechnique]]:
        """
        Batch lookup: feature_name → [AttackTechnique].
        Only includes features that have at least one mapped technique.
        """
        return {
            f: techs
            for f in feature_names
            if (techs := self.techniques_for_feature(f))
        }


# ---------------------------------------------------------------------------
# Singleton instance (module-level)
# ---------------------------------------------------------------------------

_KB_INSTANCE: MitreKnowledgeBase | None = None


def get_knowledge_base() -> MitreKnowledgeBase:
    """Return the shared MitreKnowledgeBase singleton. Thread-safe after first call."""
    global _KB_INSTANCE  # noqa: PLW0603
    if _KB_INSTANCE is None:
        _KB_INSTANCE = MitreKnowledgeBase()
    return _KB_INSTANCE
