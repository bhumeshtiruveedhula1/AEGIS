"""
backend.shared — Shared Types, Base Models, and Utilities
==========================================================
Provides the building blocks that every module imports:

- types.py              Type aliases and domain Literal types
- models.py             Pydantic base models (timestamped, event)
- schemas.py            Shared request/response API schemas
- utils/                Pure utility functions (no I/O, no business logic)
    datetime_utils.py   UTC enforcement and ISO 8601 helpers
    id_utils.py         UUID v4 generation and validation
    json_utils.py       Safe JSON serialisation
    validation_utils.py Reusable Pydantic field validators

Dependency Rule
---------------
backend.shared imports ONLY from:
  - Python standard library
  - Third-party libraries (pydantic, structlog)
  - backend.core

It must NOT import from any module-specific package (backend.ingestion,
backend.detection, etc.).  This prevents circular imports.
"""
