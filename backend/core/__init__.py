"""
backend.core — Cross-Cutting Infrastructure
============================================
Provides foundational services consumed by every module in the platform:

- config.py       Application settings and environment variable loading
- constants.py    Project-wide constants and enumerations
- logging.py      Structured JSON logging foundation
- exceptions.py   Custom exception hierarchy
- health.py       Health check primitives

Design Principles
-----------------
- No module in the system imports from another module's internal code.
  All inter-module dependencies flow through `backend.core` or `backend.shared`.
- Settings are instantiated ONCE at application startup and passed via
  dependency injection (never re-read from env at call time).
- All exceptions are typed and carry structured context for audit logging.
"""
