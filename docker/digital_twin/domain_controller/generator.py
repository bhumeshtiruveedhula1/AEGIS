"""
Domain Controller Telemetry Generator
========================================
Simulates realistic Active Directory / Windows Domain Controller
authentication and identity management event streams.

The domain controller represents the central identity infrastructure —
the backbone of the hospital's enterprise Active Directory environment.

Events produced model:
  - Windows Security Event ID 4624 — Successful logon
  - Windows Security Event ID 4625 — Failed logon
  - Windows Security Event ID 4634 — Logoff
  - Windows Security Event ID 4648 — Logon with explicit credentials
  - Windows Security Event ID 4672 — Special privileges assigned to new logon
  - Windows Security Event ID 4720 — User account was created
  - Windows Security Event ID 4726 — User account was deleted
  - Windows Security Event ID 4728 — Member added to security-enabled global group
  - Windows Security Event ID 4769 — Kerberos service ticket requested

Normal Baseline Behaviour
--------------------------
Event category             | Events/hour | Notes
---------------------------|-------------|------
Successful logons          | 12          | Service accounts + users
Failed logons              | 5           | Typos, expired passwords (normal noise)
Privilege assignments      | 3           | Admin logons
User management            | 2           | Routine account changes
Kerberos requests          | 30          | Service ticket grants
Logoff events              | 10          | Matching logons
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
# Simulated user database (normal hospital domain users)
# ---------------------------------------------------------------------------

DOMAIN_USERS = [
    # (username,         department,        is_admin)
    ("jsmith",           "Radiology",       False),
    ("mwilliams",        "Emergency",       False),
    ("ajohnson",         "Administration",  False),
    ("rbrown",           "IT",              True),
    ("kdavis",           "Nursing",         False),
    ("lwilson",          "Pharmacy",        False),
    ("pmartinez",        "Surgery",         False),
    ("cthomas",          "ICU",             False),
    ("dtaylor",          "Laboratory",      False),
    ("sanderson",        "HR",              True),
]

SERVICE_ACCOUNTS = [
    ("svc-iis",          "IIS Application Pool"),
    ("svc-mssql",        "SQL Server Service Account"),
    ("svc-backup",       "Backup Service"),
    ("svc-monitoring",   "Monitoring Agent"),
    ("svc-antivirus",    "Antivirus Service"),
    ("svc-hspadmin",     "Hospital Admin App"),
]

SECURITY_GROUPS = [
    "Domain Users",
    "Medical Staff",
    "IT Administrators",
    "Server Operators",
    "Remote Desktop Users",
    "Backup Operators",
]

# Normal workstations / servers that logon to DC
NORMAL_SOURCES = [
    "hospital-server-01",
    "ADMIN-PC-01",
    "NURSE-STATION-01",
    "NURSE-STATION-02",
    "RADIOLOGY-WS-01",
    "ICU-WS-01",
    "PHARMACY-WS-01",
]

# Normal logon types (network, batch, service, interactive)
LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    10: "RemoteInteractive",
}


class DomainControllerGenerator(BaseGenerator):
    """
    Domain controller telemetry generator.

    Produces authentic Windows Active Directory authentication event streams
    covering logons, failures, privilege assignments, and Kerberos requests.
    """

    def __init__(self) -> None:
        super().__init__()
        self.hostname = os.environ.get("DT_CONTAINER_HOSTNAME", "dc-01")
        self.domain_name = os.environ.get("DT_DOMAIN_NAME", "CORP.HOSPITAL.LOCAL")
        self.dc_ip = os.environ.get("DT_DC_IP", "172.20.1.20")

        # Per-hour target rates
        self.successful_logins_per_hour = int(
            os.environ.get("DT_DC_SUCCESSFUL_LOGINS_PER_HOUR", "12")
        )
        self.failed_logins_per_hour = int(
            os.environ.get("DT_DC_FAILED_LOGINS_PER_HOUR", "5")
        )
        self.privilege_events_per_hour = int(
            os.environ.get("DT_DC_PRIVILEGE_EVENTS_PER_HOUR", "3")
        )
        self.user_mgmt_per_hour = int(
            os.environ.get("DT_DC_USER_MGMT_PER_HOUR", "2")
        )
        self.kerberos_per_hour = int(
            os.environ.get("DT_DC_KERBEROS_PER_HOUR", "30")
        )

        self._rng = random.Random(int(os.environ.get("DT_RANDOM_SEED", "43")))

        # Active session tracking (logon_id → (user, workstation))
        self._active_sessions: dict[str, tuple[str, str]] = {}

    def on_start(self) -> None:
        """Pre-seed some active sessions (long-running service accounts)."""
        for svc_name, _ in SERVICE_ACCOUNTS[:3]:
            logon_id = self._new_logon_id()
            self._active_sessions[logon_id] = (
                f"{self.domain_name}\\{svc_name}",
                self.hostname,
            )

    def _new_logon_id(self) -> str:
        """Generate a Windows-style logon ID (hex string)."""
        return f"0x{self._rng.randint(0x100000, 0xFFFFFF):X}"

    def generate_normal_events(self, tick: int) -> list[TelemetryEvent]:
        """Generate DC events for one tick."""
        events: list[TelemetryEvent] = []
        interval = self._tick_interval_seconds or 1.0

        def should_emit(per_hour: int) -> bool:
            return self._rng.random() < (per_hour / 3600.0) * interval

        # 1. Successful logon
        if should_emit(self.successful_logins_per_hour):
            events.append(self._successful_logon())

        # 2. Failed logon
        if should_emit(self.failed_logins_per_hour):
            events.append(self._failed_logon())

        # 3. Logoff (from existing sessions)
        if self._active_sessions and should_emit(10):
            events.append(self._logoff_event())

        # 4. Privilege assignment (admin logon)
        if should_emit(self.privilege_events_per_hour):
            events.append(self._privilege_assigned())

        # 5. Kerberos service ticket
        if should_emit(self.kerberos_per_hour):
            events.append(self._kerberos_request())

        # 6. User management (rare)
        if should_emit(self.user_mgmt_per_hour):
            events.append(self._user_management_event())

        return events

    # -----------------------------------------------------------------------
    # Event Builders
    # -----------------------------------------------------------------------

    def _successful_logon(self) -> TelemetryEvent:
        """Windows Event ID 4624 — Successful logon."""
        # Mix of domain users and service accounts
        if self._rng.random() < 0.6:
            user_info = self._rng.choice(DOMAIN_USERS)
            user = f"{self.domain_name}\\{user_info[0]}"
        else:
            svc = self._rng.choice(SERVICE_ACCOUNTS)
            user = f"{self.domain_name}\\{svc[0]}"

        logon_type_id = self._rng.choice([2, 3, 3, 3, 5, 5])  # weighted: network + service most common
        workstation = self._rng.choice(NORMAL_SOURCES)
        logon_id = self._new_logon_id()
        self._active_sessions[logon_id] = (user, workstation)

        return make_event(
            source="domain_controller",
            event_type="UserLogon",
            host=self.hostname,
            user=user,
            resource=workstation,
            action="authenticate",
            result="success",
            logon_id=logon_id,
            logon_type=logon_type_id,
            logon_type_name=LOGON_TYPES.get(logon_type_id, "Unknown"),
            workstation=workstation,
            domain=self.domain_name,
            auth_package="Kerberos" if logon_type_id in (3, 10) else "NTLM",
            ip_address=self.dc_ip,
            windows_event_id=4624,
        )

    def _failed_logon(self) -> TelemetryEvent:
        """Windows Event ID 4625 — Failed logon."""
        user_info = self._rng.choice(DOMAIN_USERS)
        user = f"{self.domain_name}\\{user_info[0]}"
        workstation = self._rng.choice(NORMAL_SOURCES)

        # Normal failure reasons (not attacks)
        failure_reasons = [
            (0xC000006A, "Wrong password"),
            (0xC0000234, "Account locked out — too many wrong passwords"),
            (0xC0000072, "Account currently disabled"),
            (0xC000006F, "User not allowed to log on at this time"),
        ]
        code, reason = self._rng.choice(failure_reasons[:2])  # mostly wrong password

        return make_event(
            source="domain_controller",
            event_type="UserLogonFailed",
            host=self.hostname,
            user=user,
            resource=workstation,
            action="authenticate",
            result="failure",
            failure_reason=reason,
            failure_code=hex(code),
            workstation=workstation,
            domain=self.domain_name,
            auth_package="NTLM",
            windows_event_id=4625,
        )

    def _logoff_event(self) -> TelemetryEvent:
        """Windows Event ID 4634 — Logoff."""
        logon_id = self._rng.choice(list(self._active_sessions.keys()))
        user, workstation = self._active_sessions.pop(logon_id)

        return make_event(
            source="domain_controller",
            event_type="UserLogoff",
            host=self.hostname,
            user=user,
            resource=workstation,
            action="disconnect",
            result="success",
            logon_id=logon_id,
            domain=self.domain_name,
            windows_event_id=4634,
        )

    def _privilege_assigned(self) -> TelemetryEvent:
        """Windows Event ID 4672 — Special privileges assigned."""
        admin_users = [u for u in DOMAIN_USERS if u[2]]
        user_info = self._rng.choice(admin_users) if admin_users else DOMAIN_USERS[0]
        user = f"{self.domain_name}\\{user_info[0]}"
        logon_id = self._new_logon_id()

        privileges = [
            "SeDebugPrivilege",
            "SeSecurityPrivilege",
            "SeTakeOwnershipPrivilege",
            "SeBackupPrivilege",
        ]

        return make_event(
            source="domain_controller",
            event_type="PrivilegeAssigned",
            host=self.hostname,
            user=user,
            resource="local_security_authority",
            action="modify",
            result="success",
            logon_id=logon_id,
            privileges_assigned=self._rng.sample(privileges, k=self._rng.randint(1, 3)),
            domain=self.domain_name,
            windows_event_id=4672,
        )

    def _kerberos_request(self) -> TelemetryEvent:
        """Windows Event ID 4769 — Kerberos service ticket requested."""
        user_info = self._rng.choice(DOMAIN_USERS + [("svc-iis", "IT", False)])
        user = f"{self.domain_name}\\{user_info[0]}"
        service = self._rng.choice(NORMAL_SOURCES)

        return make_event(
            source="domain_controller",
            event_type="KerberosTicketRequest",
            host=self.hostname,
            user=user,
            resource=f"host/{service}.{self.domain_name}",
            action="authenticate",
            result="success",
            service_name=f"host/{service}.{self.domain_name}",
            ticket_encryption_type="0x12",  # AES256
            ticket_options="0x40810000",
            client_ip=self.dc_ip,
            domain=self.domain_name,
            windows_event_id=4769,
        )

    def _user_management_event(self) -> TelemetryEvent:
        """Windows Event ID 4720 or 4728 — User creation or group membership change."""
        admin_users = [u for u in DOMAIN_USERS if u[2]]
        admin = self._rng.choice(admin_users) if admin_users else DOMAIN_USERS[0]
        admin_user = f"{self.domain_name}\\{admin[0]}"

        event_options = [
            ("UserCreated", 4720, "create"),
            ("GroupMembershipChanged", 4728, "modify"),
        ]
        event_type, win_event_id, action = self._rng.choice(event_options)
        target_user = f"{self.domain_name}\\{self._rng.choice(DOMAIN_USERS)[0]}"
        group = self._rng.choice(SECURITY_GROUPS)

        return make_event(
            source="domain_controller",
            event_type=event_type,
            host=self.hostname,
            user=admin_user,
            resource=target_user,
            action=action,
            result="success",
            target_user=target_user,
            target_group=group if event_type == "GroupMembershipChanged" else None,
            domain=self.domain_name,
            windows_event_id=win_event_id,
        )

    def health_extras(self) -> dict[str, Any]:
        return {
            "active_sessions": len(self._active_sessions),
            "domain": self.domain_name,
        }


if __name__ == "__main__":
    # Start health server in background thread
    import importlib.util  # noqa: PLC0415
    spec = importlib.util.spec_from_file_location(
        "health_server", Path(__file__).parent / "health_server.py"
    )
    if spec and spec.loader:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
        mod.start_health_server()

    generator = DomainControllerGenerator()
    generator.run()
