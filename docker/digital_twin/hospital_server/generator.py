"""
Hospital Server Telemetry Generator
=====================================
Simulates a realistic hospital application server telemetry stream.

The hospital server represents a critical IT asset — a server running:
  - Microsoft IIS (web tier for the hospital application)
  - SQL Server (patient record database)
  - Windows services (WinRM, SMB, Task Scheduler)
  - Active Directory client (authenticates against domain-controller)

Normal Baseline Behaviour
--------------------------
Event category             | Events/hour | Notes
---------------------------|-------------|------
Process creation           | 75          | IIS workers, SQL, svchost, scheduled tasks
Process termination        | 30          | Matching process creates
Network connections        | 150         | DB connections, AD auth, health checks
File access                | 50          | Patient records (read), log writes
Database queries           | 40          | SELECT queries, stored procedure calls
Authentication             | 20          | Service account logons, IIS app pool auth

All events conform to the TelemetryEvent schema (event_schema.py).
Events are written to /logs/hospital_server.jsonl via EventWriter.

Attack Injection Points (for future modules)
---------------------------------------------
Future modules inject anomalies by modifying DT_ANOMALY_INJECTION_RATE or
by overriding generate_normal_events() with a subclass. This generator
produces ONLY normal baseline data.

References
-----------
- Windows Event ID 4688: A new process has been created
- Windows Event ID 4689: A process has exited
- Windows Event ID 4624: An account was successfully logged on
- Windows Event ID 4625: An account failed to log on
- Sysmon Event ID 3:     Network connection detected
- Sysmon Event ID 11:    FileCreate
"""

from __future__ import annotations

import os
import random
import sys
from pathlib import Path
from typing import Any

# Add shared/ to path (copied into /app/shared in Docker)
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.base_generator import BaseGenerator
from shared.event_schema import TelemetryEvent, make_event


# ---------------------------------------------------------------------------
# Realistic process lists (normal hospital server activity)
# ---------------------------------------------------------------------------

# Legitimate IIS / SQL Server / Windows processes
NORMAL_PROCESSES = [
    ("w3wp.exe",         "svc-iis",    "IIS worker process"),
    ("sqlservr.exe",     "svc-mssql",  "SQL Server database engine"),
    ("svchost.exe",      "SYSTEM",     "Windows service host"),
    ("msdtc.exe",        "SYSTEM",     "Distributed Transaction Coordinator"),
    ("powershell.exe",   "svc-admin",  "Windows PowerShell (scheduled maintenance)"),
    ("wscript.exe",      "svc-admin",  "Windows Script Host"),
    ("robocopy.exe",     "svc-backup", "Backup copy utility"),
    ("vssvc.exe",        "SYSTEM",     "Volume Shadow Copy Service"),
    ("WmiApSrv.exe",     "SYSTEM",     "WMI Performance Adapter"),
    ("SearchIndexer.exe","SYSTEM",     "Windows Search Indexer"),
    ("msiexec.exe",      "svc-admin",  "Windows Installer"),
    ("taskhostw.exe",    "SYSTEM",     "Host for Windows Tasks"),
    ("conhost.exe",      "SYSTEM",     "Console Window Host"),
    ("dllhost.exe",      "SYSTEM",     "COM Surrogate"),
    ("RuntimeBroker.exe","SYSTEM",     "Runtime Broker"),
]

# Legitimate file paths accessed by hospital server processes
NORMAL_FILE_PATHS = [
    r"C:\inetpub\wwwroot\HospitalApp\data",
    r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Log",
    r"C:\Windows\System32",
    r"C:\Windows\Temp",
    r"C:\inetpub\logs\LogFiles\W3SVC1",
    r"D:\PatientData\Records",
    r"D:\Backups\Daily",
    r"C:\Windows\System32\winevt\Logs",
]

NORMAL_FILE_NAMES = [
    "ERRORLOG", "app.log", "access.log", "backup.bak",
    "web.config", "hospital_records_2024.mdf", "tempdb.mdf",
    "audit_2024.log", "archive_20240101.zip",
]

# Legitimate network destinations
NORMAL_NETWORK_DESTINATIONS = [
    ("172.20.1.20", "445",  "SMB - Domain Controller"),
    ("172.20.1.20", "88",   "Kerberos - Domain Controller"),
    ("172.20.1.20", "389",  "LDAP - Domain Controller"),
    ("172.20.1.10", "1433", "SQL Server self (loopback)"),
    ("10.0.0.1",    "443",  "External HTTPS - vendor updates"),
    ("10.0.0.53",   "53",   "DNS - internal resolver"),
    ("172.20.0.10", "8000", "CyberShield API - health reporting"),
]

# Legitimate service accounts
SERVICE_ACCOUNTS = [
    "svc-iis",
    "svc-mssql",
    "svc-backup",
    "svc-admin",
    "SYSTEM",
    "CORP\\svc-hspadmin",
    "CORP\\db-monitor",
]

# Stored procedure names for DB queries
SQL_PROCEDURES = [
    "sp_GetPatientRecord",
    "sp_UpdateAppointment",
    "sp_GetAvailableBeds",
    "sp_LogAccess",
    "sp_GetLabResults",
    "sp_InsertAuditLog",
    "DBCC CHECKDB",
    "SELECT * FROM sys.dm_exec_requests",
]


class HospitalServerGenerator(BaseGenerator):
    """
    Hospital server telemetry generator.

    Produces five categories of normal baseline events on a configurable schedule:
      1. Process creation
      2. Process termination
      3. Network connections
      4. File access
      5. Database queries
      6. Authentication events
    """

    def __init__(self) -> None:
        super().__init__()
        self.hostname = os.environ.get("DT_CONTAINER_HOSTNAME", "hospital-server-01")
        self.domain_controller_ip = os.environ.get("DT_DC_IP", "172.20.1.20")

        # Per-hour target rates (read from env or use defaults)
        self.process_creates_per_hour = int(os.environ.get("DT_PROCESS_CREATES_PER_HOUR", "75"))
        self.network_connects_per_hour = int(os.environ.get("DT_NETWORK_CONNECTS_PER_HOUR", "150"))
        self.file_events_per_hour = int(os.environ.get("DT_FILE_EVENTS_PER_HOUR", "50"))
        self.auth_events_per_hour = int(os.environ.get("DT_AUTH_EVENTS_PER_HOUR", "20"))

        # Deterministic seed for reproducible baselines
        self._rng = random.Random(int(os.environ.get("DT_RANDOM_SEED", "42")))

        # Active process table (pid → (name, user))
        self._active_processes: dict[int, tuple[str, str]] = {}
        self._next_pid: int = 1000

    def on_start(self) -> None:
        """Pre-populate some long-running processes."""
        long_running = [
            ("sqlservr.exe", "svc-mssql"),
            ("w3wp.exe",     "svc-iis"),
            ("svchost.exe",  "SYSTEM"),
            ("svchost.exe",  "SYSTEM"),
            ("svchost.exe",  "SYSTEM"),
        ]
        for process_name, user in long_running:
            pid = self._allocate_pid()
            self._active_processes[pid] = (process_name, user)

    def _allocate_pid(self) -> int:
        self._next_pid += self._rng.randint(1, 20)
        return self._next_pid

    def generate_normal_events(self, tick: int) -> list[TelemetryEvent]:
        """
        Generate the events for one tick.

        The number of events per tick is probabilistically determined
        based on the per-hour target rates and tick interval.
        """
        events: list[TelemetryEvent] = []
        interval = self._tick_interval_seconds or 1.0

        # Compute expected events per tick for each category
        def should_emit(per_hour: int) -> bool:
            """Probabilistic emission based on rate and interval."""
            prob = (per_hour / 3600.0) * interval
            return self._rng.random() < prob

        # 1. Process Creation
        if should_emit(self.process_creates_per_hour):
            events.extend(self._process_create_events())

        # 2. Process Termination (terminate some long-running processes occasionally)
        if self._active_processes and tick % 5 == 0:
            events.extend(self._process_terminate_events())

        # 3. Network Connection
        if should_emit(self.network_connects_per_hour):
            events.append(self._network_connect_event())

        # 4. File Access
        if should_emit(self.file_events_per_hour):
            events.append(self._file_access_event())

        # 5. Authentication
        if should_emit(self.auth_events_per_hour):
            events.append(self._auth_event())

        # 6. Database Query (tied to IIS worker rate)
        if should_emit(40):
            events.append(self._db_query_event())

        return events

    # -----------------------------------------------------------------------
    # Event Builders
    # -----------------------------------------------------------------------

    def _process_create_events(self) -> list[TelemetryEvent]:
        """Generate a process creation event."""
        process_name, user, description = self._rng.choice(NORMAL_PROCESSES)
        pid = self._allocate_pid()
        parent_pid = self._rng.choice(list(self._active_processes.keys()) or [4])

        self._active_processes[pid] = (process_name, user)

        return [make_event(
            source="hospital_server",
            event_type="ProcessCreate",
            host=self.hostname,
            user=user,
            resource=process_name,
            action="execute",
            result="success",
            pid=pid,
            parent_pid=parent_pid,
            command_line=f"{process_name} -service",
            process_description=description,
            windows_event_id=4688,
        )]

    def _process_terminate_events(self) -> list[TelemetryEvent]:
        """Occasionally terminate a short-lived process."""
        # Only terminate non-core processes
        terminable = [
            (pid, name, user)
            for pid, (name, user) in self._active_processes.items()
            if name not in ("sqlservr.exe", "w3wp.exe")
        ]
        if not terminable:
            return []

        pid, process_name, user = self._rng.choice(terminable)
        del self._active_processes[pid]
        exit_code = 0  # Normal exit

        return [make_event(
            source="hospital_server",
            event_type="ProcessTerminate",
            host=self.hostname,
            user=user,
            resource=process_name,
            action="execute",
            result="success",
            pid=pid,
            exit_code=exit_code,
            windows_event_id=4689,
        )]

    def _network_connect_event(self) -> TelemetryEvent:
        """Generate a network connection event."""
        dest_ip, dest_port, dest_desc = self._rng.choice(NORMAL_NETWORK_DESTINATIONS)
        user = self._rng.choice(SERVICE_ACCOUNTS)
        src_port = self._rng.randint(49152, 65535)

        return make_event(
            source="hospital_server",
            event_type="NetworkConnect",
            host=self.hostname,
            user=user,
            resource=f"{dest_ip}:{dest_port}",
            action="connect",
            result="success",
            source_ip=self.hostname,
            source_port=src_port,
            dest_ip=dest_ip,
            dest_port=int(dest_port),
            dest_description=dest_desc,
            protocol="TCP",
            sysmon_event_id=3,
        )

    def _file_access_event(self) -> TelemetryEvent:
        """Generate a file access event."""
        file_dir = self._rng.choice(NORMAL_FILE_PATHS)
        file_name = self._rng.choice(NORMAL_FILE_NAMES)
        user = self._rng.choice(SERVICE_ACCOUNTS)
        action = self._rng.choice(["read", "write", "create"])

        return make_event(
            source="hospital_server",
            event_type="FileAccess" if action == "read" else "FileCreate",
            host=self.hostname,
            user=user,
            resource=f"{file_dir}{file_name}",
            action=action,
            result="success",
            file_path=f"{file_dir}{file_name}",
            file_size_bytes=self._rng.randint(512, 10 * 1024 * 1024),
            sysmon_event_id=11 if action == "create" else 0,
        )

    def _auth_event(self) -> TelemetryEvent:
        """Generate an authentication event (service account logon)."""
        user = self._rng.choice(SERVICE_ACCOUNTS)
        # 90% success rate for normal baseline
        success = self._rng.random() < 0.90
        return make_event(
            source="hospital_server",
            event_type="UserLogon" if success else "UserLogonFailed",
            host=self.hostname,
            user=user,
            resource=self.domain_controller_ip,
            action="authenticate",
            result="success" if success else "failure",
            logon_type=3,          # Network logon
            auth_package="NTLM",
            windows_event_id=4624 if success else 4625,
        )

    def _db_query_event(self) -> TelemetryEvent:
        """Generate a database query event."""
        procedure = self._rng.choice(SQL_PROCEDURES)
        duration_ms = self._rng.randint(5, 500)
        rows_returned = self._rng.randint(0, 1000)

        return make_event(
            source="hospital_server",
            event_type="DatabaseQuery",
            host=self.hostname,
            user="svc-mssql",
            resource="HospitalDB",
            action="query",
            result="success",
            procedure_name=procedure,
            duration_ms=duration_ms,
            rows_returned=rows_returned,
            database="HospitalDB",
        )

    def health_extras(self) -> dict[str, Any]:
        return {
            "active_processes": len(self._active_processes),
            "next_pid": self._next_pid,
        }


if __name__ == "__main__":
    # Start health server in background thread (mirrors domain-controller pattern)
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location(
        "health_server", Path(__file__).parent / "health_server.py"
    )
    _mod = _ilu.module_from_spec(_spec)  # type: ignore[arg-type]
    _spec.loader.exec_module(_mod)  # type: ignore[union-attr]
    _mod.start_health_server()

    generator = HospitalServerGenerator()
    generator.run()
