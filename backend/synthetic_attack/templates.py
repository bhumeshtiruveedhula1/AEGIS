"""
backend.synthetic_attack.templates — Built-in Attack Templates
==============================================================
Module 3.X — Synthetic Attack Generation

Reusable attack templates only. No execution logic.

Each template corresponds to one or more MITRE ATT&CK kill-chain scenarios
and produces CanonicalEvents that exercise the full existing pipeline.

Registered templates
--------------------
Template ID                    Domain        Techniques
------------------------------ ------------- ----------------------------
brute_force_auth               auth          T1110 (Brute Force)
credential_stuffing            auth          T1110.004
lateral_movement_smb           network       T1021.002, T1078
privilege_escalation_token     process       T1134
persistence_scheduled_task     process       T1053.005
command_execution_powershell   process       T1059.001
network_discovery_scan         network       T1046
data_exfiltration_http         network       T1041
ot_register_manipulation       ot_ics        T0836
full_kill_chain_it             it            T1110, T1021, T1059, T1041
"""

from __future__ import annotations

from backend.synthetic_attack.models import AttackDomain, AttackStage, AttackTemplate

# ---------------------------------------------------------------------------
# Template Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, AttackTemplate] = {}


def register(tpl: AttackTemplate) -> AttackTemplate:
    _REGISTRY[tpl.template_id] = tpl
    return tpl


def get_template(template_id: str) -> AttackTemplate | None:
    return _REGISTRY.get(template_id)


def get_all_templates() -> list[AttackTemplate]:
    return list(_REGISTRY.values())


def list_template_ids() -> list[str]:
    return list(_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Built-in Templates
# ---------------------------------------------------------------------------

register(AttackTemplate(
    template_id="brute_force_auth",
    name="Brute Force Authentication",
    description=(
        "Simulates a credential brute-force: repeated failed logins followed "
        "by a successful access. Exercises T1110."
    ),
    domain=AttackDomain.AUTHENTICATION,
    mitre_techniques=["T1110"],
    mitre_tactics=["TA0006"],
    stages=[
        AttackStage(
            name="Failed Authentication Burst",
            description="Rapid sequence of failed login attempts",
            source="windows",
            event_type="authentication",
            action="logon_failure",
            result="failure",
            event_count=20,
            delay_seconds=0.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            resource_template="{target_host}",
            logon_type_hint="network",
            auth_package_hint="NTLM",
            windows_event_id_hint=4625,
            mitre_technique_hint="T1110",
            mitre_tactic_hint="TA0006",
        ),
        AttackStage(
            name="Successful Authentication",
            description="Attacker gains access after brute force",
            source="windows",
            event_type="authentication",
            action="logon_success",
            result="success",
            event_count=1,
            delay_seconds=2.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            resource_template="{target_host}",
            windows_event_id_hint=4624,
            mitre_technique_hint="T1110",
            mitre_tactic_hint="TA0006",
        ),
    ],
    tags=["authentication", "credential"],
))


register(AttackTemplate(
    template_id="credential_stuffing",
    name="Credential Stuffing",
    description=(
        "Simulates credential stuffing using compromised username/password pairs. "
        "Exercises T1110.004."
    ),
    domain=AttackDomain.AUTHENTICATION,
    mitre_techniques=["T1110.004"],
    mitre_tactics=["TA0006"],
    stages=[
        AttackStage(
            name="Stuffing Attempts",
            description="Multiple logon failures across different accounts",
            source="linux",
            event_type="authentication",
            action="ssh_auth_failed",
            result="failure",
            event_count=30,
            delay_seconds=0.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            src_ip_template="{source_ip}",
            mitre_technique_hint="T1110.004",
            mitre_tactic_hint="TA0006",
        ),
        AttackStage(
            name="Valid Credential Hit",
            description="One credential pair succeeds",
            source="linux",
            event_type="authentication",
            action="ssh_auth_success",
            result="success",
            event_count=1,
            delay_seconds=1.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            src_ip_template="{source_ip}",
            mitre_technique_hint="T1110.004",
            mitre_tactic_hint="TA0006",
        ),
    ],
    tags=["authentication", "credential", "linux"],
))


register(AttackTemplate(
    template_id="lateral_movement_smb",
    name="Lateral Movement via SMB",
    description=(
        "Attacker uses valid credentials to authenticate via SMB and move "
        "laterally. Exercises T1021.002 and T1078."
    ),
    domain=AttackDomain.NETWORK,
    mitre_techniques=["T1021.002", "T1078"],
    mitre_tactics=["TA0001", "TA0008"],
    stages=[
        AttackStage(
            name="Initial Valid Credential Use",
            description="Attacker logs in with valid credentials",
            source="windows",
            event_type="authentication",
            action="logon_success",
            result="success",
            event_count=1,
            delay_seconds=0.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            windows_event_id_hint=4624,
            mitre_technique_hint="T1078",
            mitre_tactic_hint="TA0001",
        ),
        AttackStage(
            name="SMB Network Share Access",
            description="Remote file system access via SMB",
            source="windows",
            event_type="network",
            action="smb_connect",
            result="success",
            event_count=5,
            delay_seconds=3.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            src_ip_template="{source_ip}",
            dst_ip_template="{target_ip}",
            port=445,
            protocol="smb",
            mitre_technique_hint="T1021.002",
            mitre_tactic_hint="TA0008",
        ),
        AttackStage(
            name="File Transfer via SMB",
            description="Copying tools or payloads across the network",
            source="windows",
            event_type="file",
            action="file_copy",
            result="success",
            event_count=3,
            delay_seconds=2.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            resource_template="\\\\{target_host}\\ADMIN$",
            mitre_technique_hint="T1021.002",
            mitre_tactic_hint="TA0008",
        ),
    ],
    tags=["lateral_movement", "windows", "smb"],
))


register(AttackTemplate(
    template_id="privilege_escalation_token",
    name="Privilege Escalation via Token Manipulation",
    description="Attacker manipulates access tokens to escalate privileges. Exercises T1134.",
    domain=AttackDomain.PROCESS,
    mitre_techniques=["T1134"],
    mitre_tactics=["TA0004"],
    stages=[
        AttackStage(
            name="Token Impersonation",
            description="Process creates impersonation token for SYSTEM",
            source="windows",
            event_type="process",
            action="token_impersonation",
            result="success",
            event_count=2,
            delay_seconds=0.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            process_template="lsass.exe",
            windows_event_id_hint=4672,
            mitre_technique_hint="T1134",
            mitre_tactic_hint="TA0004",
        ),
        AttackStage(
            name="Elevated Process Spawn",
            description="New process spawned with SYSTEM token",
            source="windows",
            event_type="process",
            action="process_create",
            result="success",
            event_count=1,
            delay_seconds=1.0,
            host_template="{target_host}",
            user_template="SYSTEM",
            process_template="cmd.exe",
            command_line_template="cmd.exe /c whoami",
            windows_event_id_hint=4688,
            mitre_technique_hint="T1134",
            mitre_tactic_hint="TA0004",
        ),
    ],
    tags=["privilege_escalation", "windows", "process"],
))


register(AttackTemplate(
    template_id="persistence_scheduled_task",
    name="Persistence via Scheduled Task",
    description="Attacker creates a scheduled task for persistence. Exercises T1053.005.",
    domain=AttackDomain.PROCESS,
    mitre_techniques=["T1053.005"],
    mitre_tactics=["TA0003"],
    stages=[
        AttackStage(
            name="Scheduled Task Creation",
            description="schtasks.exe used to register malicious task",
            source="windows",
            event_type="process",
            action="process_create",
            result="success",
            event_count=1,
            delay_seconds=0.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            process_template="schtasks.exe",
            command_line_template=(
                "schtasks /create /tn Updater /tr C:\\Windows\\Temp\\payload.exe "
                "/sc ONLOGON /ru SYSTEM"
            ),
            windows_event_id_hint=4698,
            mitre_technique_hint="T1053.005",
            mitre_tactic_hint="TA0003",
        ),
        AttackStage(
            name="Scheduled Task Execution",
            description="Payload launched by scheduled task",
            source="windows",
            event_type="process",
            action="process_create",
            result="success",
            event_count=1,
            delay_seconds=10.0,
            host_template="{target_host}",
            user_template="SYSTEM",
            process_template="payload.exe",
            command_line_template="C:\\Windows\\Temp\\payload.exe",
            windows_event_id_hint=4688,
            mitre_technique_hint="T1053.005",
            mitre_tactic_hint="TA0003",
        ),
    ],
    tags=["persistence", "windows", "scheduled_task"],
))


register(AttackTemplate(
    template_id="command_execution_powershell",
    name="Malicious PowerShell Execution",
    description=(
        "Attacker executes encoded PowerShell commands to evade detection. "
        "Exercises T1059.001."
    ),
    domain=AttackDomain.PROCESS,
    mitre_techniques=["T1059.001"],
    mitre_tactics=["TA0002"],
    stages=[
        AttackStage(
            name="Encoded PowerShell Launch",
            description="Base64 encoded PowerShell command executed",
            source="windows",
            event_type="process",
            action="process_create",
            result="success",
            event_count=3,
            delay_seconds=0.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            process_template="powershell.exe",
            command_line_template=(
                "powershell.exe -NonInteractive -NoProfile "
                "-EncodedCommand JABjAGwAaQBlAG4AdA=="
            ),
            windows_event_id_hint=4688,
            mitre_technique_hint="T1059.001",
            mitre_tactic_hint="TA0002",
        ),
        AttackStage(
            name="Network Callback",
            description="PowerShell downloads secondary payload",
            source="windows",
            event_type="network",
            action="http_connect",
            result="success",
            event_count=1,
            delay_seconds=2.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            src_ip_template="{source_ip}",
            dst_ip_template="185.220.101.1",
            port=443,
            protocol="https",
            mitre_technique_hint="T1059.001",
            mitre_tactic_hint="TA0002",
        ),
    ],
    tags=["execution", "powershell", "windows"],
))


register(AttackTemplate(
    template_id="network_discovery_scan",
    name="Internal Network Discovery Scan",
    description="Attacker performs internal network reconnaissance. Exercises T1046.",
    domain=AttackDomain.NETWORK,
    mitre_techniques=["T1046"],
    mitre_tactics=["TA0007"],
    stages=[
        AttackStage(
            name="Port Scan Sweep",
            description="Rapid connection attempts to discover live hosts/services",
            source="linux",
            event_type="network",
            action="port_scan",
            result="success",
            event_count=50,
            delay_seconds=0.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            src_ip_template="{source_ip}",
            protocol="tcp",
            mitre_technique_hint="T1046",
            mitre_tactic_hint="TA0007",
        ),
    ],
    tags=["discovery", "network", "reconnaissance"],
))


register(AttackTemplate(
    template_id="data_exfiltration_http",
    name="Data Exfiltration via HTTP",
    description="Attacker exfiltrates data over HTTP to external server. Exercises T1041.",
    domain=AttackDomain.NETWORK,
    mitre_techniques=["T1041"],
    mitre_tactics=["TA0010"],
    stages=[
        AttackStage(
            name="Data Collection",
            description="Attacker reads sensitive files before exfil",
            source="windows",
            event_type="file",
            action="file_read",
            result="success",
            event_count=10,
            delay_seconds=0.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            resource_template="C:\\sensitive\\data.csv",
            mitre_technique_hint="T1041",
            mitre_tactic_hint="TA0010",
        ),
        AttackStage(
            name="HTTP POST Exfiltration",
            description="Large outbound HTTP POST to attacker-controlled server",
            source="linux",
            event_type="network",
            action="http_post",
            result="success",
            event_count=5,
            delay_seconds=5.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            src_ip_template="{source_ip}",
            dst_ip_template="185.220.101.99",
            port=80,
            protocol="http",
            bytes_out_hint=524288,
            mitre_technique_hint="T1041",
            mitre_tactic_hint="TA0010",
        ),
    ],
    tags=["exfiltration", "network", "http"],
))


register(AttackTemplate(
    template_id="ot_register_manipulation",
    name="OT/ICS Modbus Register Manipulation",
    description=(
        "Simulates an attacker writing illegal values to OT Modbus registers "
        "to disrupt industrial processes. Exercises T0836."
    ),
    domain=AttackDomain.OT_ICS,
    mitre_techniques=["T0836"],
    mitre_tactics=["TA0105"],
    stages=[
        AttackStage(
            name="OT Device Reconnaissance",
            description="Attacker scans for Modbus-capable devices",
            source="ot",
            event_type="network",
            action="modbus_scan",
            result="success",
            event_count=10,
            delay_seconds=0.0,
            host_template="{supervisory_host}",
            user_template="{attacker_user}",
            src_ip_template="{source_ip}",
            port=502,
            protocol="modbus",
            mitre_technique_hint="T0836",
            mitre_tactic_hint="TA0105",
            extra_context={"supervisory_host": "{target_host}"},
        ),
        AttackStage(
            name="Register Write — Setpoint Override",
            description="Modbus WRITE_REGISTER to override a critical setpoint",
            source="ot",
            event_type="ot_modbus",
            action="write_register",
            result="success",
            event_count=5,
            delay_seconds=2.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            modbus_register=40001,
            modbus_value=9999,
            modbus_function_code=6,
            mitre_technique_hint="T0836",
            mitre_tactic_hint="TA0105",
            extra_context={"supervisory_host": "{target_host}"},
        ),
        AttackStage(
            name="Register Write — Safety Disable",
            description="Attacker disables safety relay via register write",
            source="ot",
            event_type="ot_modbus",
            action="write_register",
            result="success",
            event_count=2,
            delay_seconds=3.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            modbus_register=40010,
            modbus_value=0,
            modbus_function_code=6,
            mitre_technique_hint="T0836",
            mitre_tactic_hint="TA0105",
        ),
    ],
    tags=["ot", "ics", "modbus", "critical_infrastructure"],
))


register(AttackTemplate(
    template_id="full_kill_chain_it",
    name="Full IT Kill Chain",
    description=(
        "End-to-end IT attack simulation: credential brute force → lateral movement "
        "→ command execution → data exfiltration. "
        "Exercises T1110, T1021.002, T1059.001, T1041."
    ),
    domain=AttackDomain.IT,
    mitre_techniques=["T1110", "T1021.002", "T1059.001", "T1041"],
    mitre_tactics=["TA0006", "TA0008", "TA0002", "TA0010"],
    stages=[
        # Stage 1: Credential brute force
        AttackStage(
            name="Credential Brute Force",
            source="windows",
            event_type="authentication",
            action="logon_failure",
            result="failure",
            event_count=15,
            delay_seconds=0.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            windows_event_id_hint=4625,
            mitre_technique_hint="T1110",
            mitre_tactic_hint="TA0006",
        ),
        AttackStage(
            name="Authentication Success",
            source="windows",
            event_type="authentication",
            action="logon_success",
            result="success",
            event_count=1,
            delay_seconds=1.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            windows_event_id_hint=4624,
            mitre_technique_hint="T1110",
            mitre_tactic_hint="TA0006",
        ),
        # Stage 2: Lateral movement
        AttackStage(
            name="SMB Lateral Movement",
            source="windows",
            event_type="network",
            action="smb_connect",
            result="success",
            event_count=3,
            delay_seconds=5.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            src_ip_template="{source_ip}",
            dst_ip_template="{target_ip}",
            port=445,
            protocol="smb",
            mitre_technique_hint="T1021.002",
            mitre_tactic_hint="TA0008",
        ),
        # Stage 3: Command execution
        AttackStage(
            name="PowerShell Command Execution",
            source="windows",
            event_type="process",
            action="process_create",
            result="success",
            event_count=2,
            delay_seconds=3.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            process_template="powershell.exe",
            command_line_template="powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdA==",
            windows_event_id_hint=4688,
            mitre_technique_hint="T1059.001",
            mitre_tactic_hint="TA0002",
        ),
        # Stage 4: Exfiltration
        AttackStage(
            name="Data Exfiltration",
            source="linux",
            event_type="network",
            action="http_post",
            result="success",
            event_count=5,
            delay_seconds=10.0,
            host_template="{target_host}",
            user_template="{attacker_user}",
            src_ip_template="{source_ip}",
            dst_ip_template="185.220.101.99",
            port=80,
            protocol="http",
            mitre_technique_hint="T1041",
            mitre_tactic_hint="TA0010",
        ),
    ],
    tags=["kill_chain", "it", "multi_tactic"],
))
