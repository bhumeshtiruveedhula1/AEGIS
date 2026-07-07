"""
backend.normalization.parsers — Parser Registry & Base Class
=============================================================
Module 1.3 — Unified Log Collection & Normalization

The parser layer converts source-specific raw dicts into the unified
CanonicalEvent schema.  Each parser is responsible for exactly one
log source.  Source-specific logic NEVER escapes this package.

Architecture
------------
  BaseParser (ABC)           — interface all parsers implement
  PARSER_REGISTRY            — maps source string → parser class
  get_parser(source) → obj   — factory function for pipeline use

Extension Pattern
-----------------
To add a new log source (e.g., "firewall_logs"):
  1. Create backend/normalization/parsers/firewall.py
  2. class FirewallParser(BaseParser): def parse(self, raw) → CanonicalEvent
  3. Add to PARSER_REGISTRY here:
         "firewall_logs": FirewallParser,
  4. Write tests in tests/unit/normalization/test_firewall_parser.py
  NO other files need modification.

Design Principles
-----------------
- Parsers are PURE functions of their input — no I/O, no state.
- Each parser owns exactly ONE source's field mapping.
- Unknown source → get_parser() raises SourceError (never silently fails).
- Optional fields: set to None if absent, never to "", never to 0.
- Warnings: non-fatal issues appended to CanonicalEvent.parse_warnings.
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Any

from backend.normalization.exceptions import SourceError

if TYPE_CHECKING:
    from backend.normalization.models import CanonicalEvent


class BaseParser(abc.ABC):
    """
    Abstract base class for all telemetry source parsers.

    Concrete parsers must implement exactly one method: parse().

    Parsing Contract
    ----------------
    - Input:  raw dict as parsed from a JSONL line
    - Output: CanonicalEvent with all known fields populated
    - Raise:  ParseError   for structural failures (missing required fields)
    - Raise:  SchemaValidationError for type/value failures
    - Append: parse_warnings for non-fatal issues

    Subclass Example
    ----------------
        class MySourceParser(BaseParser):
            SOURCE = "my_source"

            def parse(self, raw: dict[str, Any]) -> CanonicalEvent:
                return CanonicalEvent(
                    source=self.SOURCE,
                    event_type=raw["event_type"],
                    host=raw["host"],
                    user=raw.get("user", "SYSTEM"),
                    ...
                )
    """

    #: Must be set by subclasses — must match the JSONL `source` field value
    SOURCE: str = ""

    @abc.abstractmethod
    def parse(self, raw: dict[str, Any]) -> "CanonicalEvent":
        """
        Parse a raw event dict into a CanonicalEvent.

        Parameters
        ----------
        raw:    Parsed JSON dict from a JSONL telemetry line.

        Returns
        -------
        CanonicalEvent with all available fields populated.
        Optional fields absent in this source are set to None.

        Raises
        ------
        ParseError            when required fields are missing or malformed.
        SchemaValidationError when values violate schema constraints.
        """

    def _get_required(
        self,
        raw: dict[str, Any],
        field: str,
    ) -> Any:
        """
        Extract a required field from raw, raising MissingFieldError if absent.

        Parameters
        ----------
        raw:    The raw event dict.
        field:  Field name to extract.
        """
        from backend.normalization.exceptions import MissingFieldError  # noqa: PLC0415

        value = raw.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise MissingFieldError(
                f"Required field '{field}' is absent or empty in raw record "
                f"from source '{self.SOURCE}'.",
                source=self.SOURCE,
                raw_record=raw,
                field=field,
            )
        return value

    def _get_optional(
        self,
        raw: dict[str, Any],
        field: str,
        *,
        default: Any = None,
    ) -> Any:
        """
        Extract an optional field, returning default if absent.

        Parameters
        ----------
        raw:     The raw event dict.
        field:   Field name to extract.
        default: Value to return when field is absent or None.
        """
        return raw.get(field, default)

    def _warn(self, warnings: list[str], message: str) -> None:
        """Append a non-fatal parse warning."""
        warnings.append(f"[{self.SOURCE}] {message}")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(source={self.SOURCE!r})"


# ---------------------------------------------------------------------------
# Lazy imports to avoid circular dependencies at import time.
# The registry is populated after all parser modules are loaded.
# ---------------------------------------------------------------------------

def _build_registry() -> dict[str, type[BaseParser]]:
    """
    Build the parser registry by importing all concrete parsers.

    This function is called ONCE at module load time.  All parsers
    must be imported here to ensure they are registered.

    To add a new parser: import it here and add to the dict.
    """
    from backend.normalization.parsers.hospital_server import (  # noqa: PLC0415
        HospitalServerParser,
    )
    from backend.normalization.parsers.domain_controller import (  # noqa: PLC0415
        DomainControllerParser,
    )
    from backend.normalization.parsers.ot_node import OTNodeParser  # noqa: PLC0415
    from backend.normalization.parsers.attacker import AttackerParser  # noqa: PLC0415

    return {
        "hospital_server":    HospitalServerParser,
        "domain_controller":  DomainControllerParser,
        "ot_node":            OTNodeParser,
        "attacker":           AttackerParser,
    }


# Global parser registry — maps source name → parser class
PARSER_REGISTRY: dict[str, type[BaseParser]] = {}


def _ensure_registry_loaded() -> None:
    """Lazily populate the registry on first access."""
    global PARSER_REGISTRY  # noqa: PLW0603
    if not PARSER_REGISTRY:
        PARSER_REGISTRY.update(_build_registry())


def get_parser(source: str) -> BaseParser:
    """
    Return an instantiated parser for the given source identifier.

    Parameters
    ----------
    source: Log source name (e.g., "hospital_server", "ot_node").

    Returns
    -------
    An instantiated BaseParser subclass for the given source.

    Raises
    ------
    SourceError if no parser is registered for this source.

    Examples
    --------
    >>> parser = get_parser("hospital_server")
    >>> event = parser.parse(raw_dict)
    """
    _ensure_registry_loaded()
    parser_class = PARSER_REGISTRY.get(source)
    if parser_class is None:
        registered = sorted(PARSER_REGISTRY.keys())
        raise SourceError(
            f"No parser registered for source '{source}'. "
            f"Registered sources: {registered}",
            source=source,
        )
    return parser_class()


def list_registered_sources() -> list[str]:
    """
    Return a sorted list of all registered source identifiers.

    Used by the pipeline to validate registry discoveries against
    available parsers.
    """
    _ensure_registry_loaded()
    return sorted(PARSER_REGISTRY.keys())


__all__ = [
    "BaseParser",
    "PARSER_REGISTRY",
    "get_parser",
    "list_registered_sources",
]
