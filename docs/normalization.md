# Module 1.3 — Unified Log Collection & Normalization

**Operation AEGIS — Phase 1**  
**Tag:** `v0.3.0`  
**Status:** Complete

---

## Overview

Module 1.3 builds the permanent telemetry foundation for the entire platform.
It reads telemetry produced by the Digital Twin (Module 1.2), normalizes every
event into one canonical schema, and writes clean, ordered output for all future
modules to consume.

Everything downstream of this module receives **only** `CanonicalEvent` objects.
No future module ever reads raw JSONL or source-specific dicts.

---

## Data Flow

```
DigitalTwinRegistry (Module 1.2)
        │
        │  list_telemetry_sources()
        ▼
TelemetryCollector  ←── streams JSONL line-by-line (generator, O(1) memory)
        │
        │  yields RawRecord(source, file, line_number, raw_dict)
        ▼
NormalizationPipeline
        │
        │  dispatch via PARSER_REGISTRY[source]
        ├──▶ HospitalServerParser.parse(raw_dict) → CanonicalEvent
        ├──▶ DomainControllerParser.parse(raw_dict) → CanonicalEvent
        ├──▶ OTNodeParser.parse(raw_dict) → CanonicalEvent
        └──▶ AttackerParser.parse(raw_dict) → CanonicalEvent
        │
        ├──▶ NormalizedEventWriter  →  data/normalized/normalized_events.jsonl
        └──▶ Dead-letter writer     →  data/normalized/error_events.jsonl
        │
        └── ParseReport             →  data/normalized/pipeline_report.json
```

---

## Canonical Event Schema

`CanonicalEvent` extends `BaseEvent` (from `backend.shared.models`).

### Field Presence Matrix

| Field               | Hospital | DC  | OT  | Attacker | Notes                              |
|---------------------|----------|-----|-----|----------|------------------------------------|
| `event_id`          | ✓        | ✓   | ✓   | ✓        | UUID v4                            |
| `timestamp`         | ✓        | ✓   | ✓   | ✓        | UTC-normalised                     |
| `source`            | ✓        | ✓   | ✓   | ✓        | Canonical source ID                |
| `event_type`        | ✓        | ✓   | ✓   | ✓        | e.g., ProcessCreate, ModbusRead    |
| `host`              | ✓        | ✓   | ✓   | ✓        | Lowercased                         |
| `user`              | ✓        | ✓   | ✓   | ✓        | Service account or SYSTEM          |
| `resource`          | ✓        | ✓   | ✓   | ✓        | Process, register, IP, domain      |
| `action`            | ✓        | ✓   | ✓   | ✓        | execute, read, write, authenticate |
| `result`            | ✓        | ✓   | ✓   | ✓        | success / failure                  |
| `raw_log`           | ✓        | ✓   | ✓   | ✓        | Original JSON verbatim             |
| `process`           | ✓        | ✓   | —   | —        | Executable name                    |
| `pid`               | ✓        | —   | —   | —        | Process ID                         |
| `parent_process`    | ✓        | —   | —   | —        | Parent executable                  |
| `command_line`      | ✓        | —   | —   | —        | Full command string                |
| `src_ip`            | ✓        | ✓   | ✓   | ✓        | Source IP                          |
| `dst_ip`            | ✓        | ✓   | ✓   | ✓        | Destination IP                     |
| `port`              | ✓        | —   | ✓   | ✓        | TCP/UDP/Modbus port                |
| `protocol`          | ✓        | —   | ✓   | ✓        | tcp / udp / modbus                 |
| `bytes_out`         | ✓        | —   | —   | ✓        | Bytes sent outbound                |
| `modbus_register`   | —        | —   | ✓   | —        | OT register address                |
| `modbus_value`      | —        | —   | ✓   | —        | OT register value                  |
| `modbus_function_code` | —     | —   | ✓   | —        | FC03 (read) / FC06 (write)         |
| `supervisory_host`  | —        | —   | ✓   | —        | SCADA controller IP                |
| `logon_type`        | —        | ✓   | —   | —        | interactive / network / service    |
| `auth_package`      | —        | ✓   | —   | —        | NTLM / Kerberos / negotiate        |
| `domain`            | —        | ✓   | —   | —        | Windows domain                     |
| `windows_event_id`  | ✓        | ✓   | —   | —        | 4624, 4625, 4688, etc.             |
| `file_path`         | ✓        | —   | —   | —        | Full filesystem path               |
| `db_query`          | ✓        | —   | —   | —        | SELECT / INSERT / EXEC             |
| `db_table`          | ✓        | —   | —   | —        | Database table name                |
| `normalizer_version`| ✓        | ✓   | ✓   | ✓        | `"1.0.0"` — schema version         |
| `parse_warnings`    | ✓        | ✓   | ✓   | ✓        | Non-fatal parse issues             |
| `source_file`       | ✓        | ✓   | ✓   | ✓        | Source JSONL file path             |
| `normalized_at`     | ✓        | ✓   | ✓   | ✓        | UTC timestamp of normalization     |
| `extra_fields`      | ✓        | ✓   | ✓   | ✓        | Unrecognised source-specific keys  |

**`—` means `None` for this source.** The Feature Engine treats `None` as 
"not applicable", never as 0 or "unknown value".

---

## Parser Architecture

### BaseParser (ABC)

All parsers extend `backend.normalization.parsers.BaseParser`.

```python
class BaseParser(ABC):
    SOURCE: str = ""

    def parse(self, raw: dict[str, Any]) -> CanonicalEvent:
        ...   # must be implemented

    def _get_required(self, raw, field) -> Any:
        ...   # raises MissingFieldError if absent

    def _get_optional(self, raw, field, *, default=None) -> Any:
        ...   # returns default if absent

    def _warn(self, warnings, message) -> None:
        ...   # appends to warnings list (non-fatal)
```

### Parser Registry

```python
# backend/normalization/parsers/__init__.py
PARSER_REGISTRY = {
    "hospital_server":   HospitalServerParser,
    "domain_controller": DomainControllerParser,
    "ot_node":           OTNodeParser,
    "attacker":          AttackerParser,
}

# Usage
parser = get_parser("hospital_server")  # → HospitalServerParser()
```

No `if/elif` chains in the pipeline. Source routing is a dict lookup.

---

## Extension Mechanism

To add a new telemetry source (e.g., `firewall_logs`):

1. **Create parser** — `backend/normalization/parsers/firewall.py`
   ```python
   class FirewallParser(BaseParser):
       SOURCE = "firewall_logs"

       def parse(self, raw: dict) -> CanonicalEvent:
           return CanonicalEvent(
               source=self.SOURCE,
               event_type=raw["event_type"],
               ...
           )
   ```

2. **Register** — in `backend/normalization/parsers/__init__.py`:
   ```python
   from backend.normalization.parsers.firewall import FirewallParser

   "firewall_logs": FirewallParser,
   ```

3. **Test** — `tests/unit/normalization/test_firewall_parser.py`

No other files require modification.

---

## Error Handling

| Error Type             | Cause                            | Recovery                              |
|------------------------|----------------------------------|---------------------------------------|
| `ParseError`           | Missing required field (timestamp, event_type, host) | Record written to error_events.jsonl; pipeline continues |
| `SchemaValidationError`| Field present but invalid type/value | Record written to error_events.jsonl; pipeline continues |
| `SourceError`          | Log file not found or unreadable | Source skipped; other sources continue |
| Non-fatal warning      | Invalid optional field (bad int) | Warning appended to `parse_warnings`; event still produced |

---

## Output Files

| File | Description |
|------|-------------|
| `data/normalized/normalized_events.jsonl` | All successfully normalized events |
| `data/normalized/error_events.jsonl` | Failed records with error reason |
| `data/normalized/pipeline_report.json` | ParseReport: counts, timing, per-source stats |

---

## Usage

### Run the full pipeline

```python
from backend.digital_twin.registry import get_registry
from backend.normalization.pipeline import NormalizationPipeline

registry = get_registry()
pipeline = NormalizationPipeline(registry)
report = pipeline.run()

print(f"Normalized: {report.total_events_normalized}")
print(f"Errors:     {report.total_parse_errors}")
print(f"Duration:   {report.duration_seconds:.2f}s")
```

### Stream normalized events in-process

```python
for event in pipeline.stream_normalized():
    # event is a CanonicalEvent
    print(event.source, event.event_type, event.host)
```

### Via IngestionService

```python
from backend.ingestion.service import IngestionService

service = IngestionService()
report = service.run()  # Reads from registry, writes to data/normalized/

# In async context (FastAPI background task)
report = await service.run_async()
```

---

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `NORM_OUTPUT_DIR` | `./data/normalized` | Normalized JSONL output directory |
| `NORM_ERROR_DIR` | `./data/normalized/errors` | Dead-letter directory |
| `NORM_MAX_LINES_PER_SOURCE` | `0` | Max lines per source (0 = unlimited) |
| `NORM_OVERWRITE_OUTPUT` | `false` | Truncate output before each run |
| `FEATURE_INGESTION_ENABLED` | `true` | Enable ingestion pipeline |
| `FEATURE_NORMALIZATION_ENABLED` | `true` | Enable normalization pipeline |

---

## Schema Evolution

The `normalizer_version` field on every `CanonicalEvent` enables safe migration:

- **Breaking change** (remove field, change type) → bump `MAJOR.0.0`
- **Non-breaking addition** (add Optional field) → no version bump needed
- Downstream consumers should check `normalizer_version` when reading archived events

---

## Test Coverage

```
tests/unit/normalization/
  test_models.py      — CanonicalEvent, RawRecord, ParseStats, ParseReport (34 tests)
  test_parsers.py     — All 4 parsers + registry (55 tests)
  test_collector.py   — TelemetryCollector (30 tests)
  test_writer.py      — NormalizedEventWriter (30 tests)
  test_pipeline.py    — NormalizationPipeline (30 tests)

tests/integration/
  test_normalization_pipeline.py — Full pipeline (40 tests)
```

**Total: ~220 tests**

---

## Future Extension Points

The following are documented injection points for future modules — no architectural changes required:

| Module | Extension |
|--------|-----------|
| **Module 2.x** — Feature Engine | Consume `CanonicalEvent` stream from `NormalizationPipeline.stream_normalized()` |
| **Module 2.x** — Attack Injection | Attacker parser already accepts unknown event types with `parse_warning` |
| **Module 3.x** — SIEM Integration | Add new parser (e.g., `SplunkParser`) and register in `PARSER_REGISTRY` |
| **Module 4.x** — Real-time ingestion | Replace `TelemetryCollector.stream_records()` with Kafka consumer; same `RawRecord` output |
