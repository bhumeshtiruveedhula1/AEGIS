#!/usr/bin/env python3
"""
verify_environment.py — CyberShield Development Environment Verification
=========================================================================
Checks that the development environment is correctly configured.

Usage:
    python verify_environment.py          # full check
    python verify_environment.py --quiet  # exit code only (CI mode)

Exit codes:
    0  All checks passed
    1  One or more checks failed
"""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path

# Reconfigure stdout to UTF-8 on Windows (default is cp1252 which can't encode
# box-drawing characters used by this script's output formatting).
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# ANSI colours (disabled automatically on Windows without VT mode or CI)
# ---------------------------------------------------------------------------
def _supports_colour() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") != "1"


if _supports_colour():
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    RED = "\033[0;31m"
    CYAN = "\033[0;36m"
    NC = "\033[0m"
else:
    GREEN = YELLOW = RED = CYAN = NC = ""

QUIET = "--quiet" in sys.argv or "-q" in sys.argv


def ok(msg: str) -> None:
    print(f"  {GREEN}[PASS]{NC} {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}[WARN]{NC} {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}[FAIL]{NC} {msg}")


def head(msg: str) -> None:
    if not QUIET:
        print(f"\n{CYAN}{'─' * 50}{NC}")
        print(f"{CYAN}  {msg}{NC}")
        print(f"{CYAN}{'─' * 50}{NC}")


# ---------------------------------------------------------------------------
# Check results accumulator
# ---------------------------------------------------------------------------
_failures: list[str] = []
_warnings: list[str] = []


def check_ok(msg: str) -> None:
    ok(msg)


def check_warn(msg: str) -> None:
    _warnings.append(msg)
    warn(msg)


def check_fail(msg: str) -> None:
    _failures.append(msg)
    fail(msg)


# ---------------------------------------------------------------------------
# CHECK 1 — Python version
# ---------------------------------------------------------------------------
head("CHECK 1 — Python version")

major = sys.version_info.major
minor = sys.version_info.minor
micro = sys.version_info.micro
full_version = f"{major}.{minor}.{micro}"

if major == 3 and minor == 11:
    check_ok(f"Python {full_version} (3.11 — fully supported)")
elif major == 3 and minor == 10:
    check_warn(
        f"Python {full_version} (3.10 — acceptable but pyproject.toml requires >=3.11; "
        "upgrade to Python 3.11 for full support)"
    )
elif major == 3 and minor >= 12:
    check_warn(f"Python {full_version} (3.{minor} — untested, may have compatibility issues)")
else:
    check_fail(f"Python {full_version} is not supported. Need 3.10 or 3.11.")


# ---------------------------------------------------------------------------
# CHECK 2 — Virtual environment is active
# ---------------------------------------------------------------------------
head("CHECK 2 — Virtual environment")

venv_active = sys.prefix != sys.base_prefix
if venv_active:
    check_ok(f"Virtual environment active: {sys.prefix}")
else:
    check_fail(
        "No virtual environment detected. "
        "Activate it first:\n"
        "    Windows : .venv\\Scripts\\Activate.ps1\n"
        "    Linux   : source .venv/bin/activate"
    )

# Verify .venv is the active one (not some other venv)
venv_path = Path(sys.prefix)
if venv_active:
    expected_markers = [
        venv_path / "Scripts" / "python.exe",  # Windows
        venv_path / "bin" / "python",  # Linux/macOS
    ]
    if not any(p.exists() for p in expected_markers):
        check_warn(f"Unexpected venv structure at {venv_path} — may not be the project .venv")


# ---------------------------------------------------------------------------
# CHECK 3 — pip sanity
# ---------------------------------------------------------------------------
head("CHECK 3 — pip health")

try:
    result = subprocess.run(
        [sys.executable, "-m", "pip", "check"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode == 0:
        check_ok("No broken dependencies (pip check passed)")
    else:
        check_fail(f"pip check found issues:\n{result.stdout.strip()}")
except subprocess.TimeoutExpired:
    check_warn("pip check timed out (network may be slow)")
except Exception as exc:
    check_warn(f"Could not run pip check: {exc}")


# ---------------------------------------------------------------------------
# CHECK 4 — Required packages importable
# ---------------------------------------------------------------------------
head("CHECK 4 — Package imports")

REQUIRED_PACKAGES = [
    # Production
    ("fastapi", "fastapi"),
    ("pydantic", "pydantic"),
    ("pydantic_settings", "pydantic_settings"),
    ("structlog", "structlog"),
    ("uvicorn", "uvicorn"),
    ("python-dotenv", "dotenv"),
    ("httpx", "httpx"),
    ("anyio", "anyio"),
    # Dev/Test
    ("pytest", "pytest"),
    ("pytest-asyncio", "pytest_asyncio"),
    ("pytest-cov", "pytest_cov"),
    ("ruff", "ruff"),
    ("mypy", "mypy"),
    ("pre-commit", "pre_commit"),
    ("factory-boy", "factory"),
    # ML
    ("scikit-learn", "sklearn"),
    ("numpy", "numpy"),
    ("pandas", "pandas"),
    ("shap", "shap"),
    ("networkx", "networkx"),
    # DB
    ("sqlalchemy", "sqlalchemy"),
    ("alembic", "alembic"),
    ("aiosqlite", "aiosqlite"),
    # LLM
    ("anthropic", "anthropic"),
    ("tenacity", "tenacity"),
    # Utilities
    ("rich", "rich"),
]

import_failures = []
for pkg_name, import_name in REQUIRED_PACKAGES:
    try:
        importlib.import_module(import_name)
        if not QUIET:
            ok(f"{pkg_name}")
    except Exception as exc:  # — broad catch intentional for diagnostic script
        import_failures.append(pkg_name)
        fail(f"{pkg_name}  ← NOT IMPORTABLE ({type(exc).__name__}: {exc})")

if import_failures:
    check_fail(
        f"{len(import_failures)} package(s) could not be imported: "
        f"{', '.join(import_failures)}\n"
        f"  Fix: pip install -r requirements-dev.txt"
    )
else:
    check_ok(f"All {len(REQUIRED_PACKAGES)} required packages importable")


# ---------------------------------------------------------------------------
# CHECK 5 — Backend package importable (project itself)
# ---------------------------------------------------------------------------
head("CHECK 5 — CyberShield backend package")

try:
    import backend

    check_ok("backend package importable")
except ImportError as exc:
    # Try adding project root to sys.path (common when not installed as editable)
    project_root = Path(__file__).resolve().parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    try:
        import backend  # noqa: F401

        check_warn(
            "backend importable only after adding project root to sys.path. "
            "Install in editable mode for clean imports: pip install -e . --no-deps"
        )
    except ImportError:
        check_fail(
            f"Cannot import 'backend': {exc}\n"
            "  Fix: cd cybershield && pip install -e . --no-deps"
        )


# ---------------------------------------------------------------------------
# CHECK 6 — .env file exists
# ---------------------------------------------------------------------------
head("CHECK 6 — Environment configuration (.env)")

env_path = Path(".env")
if env_path.exists():
    check_ok(".env file exists")
    # Quick scan for unfilled REQUIRED placeholders
    env_content = env_path.read_text(encoding="utf-8", errors="replace")
    if "change-me-in-production" in env_content or "dev-api-key-change" in env_content:
        check_warn(
            ".env still contains placeholder values. "
            "Review and update SECRET_KEY, API_KEY before running in production."
        )
else:
    check_fail(
        ".env file not found.\n"
        "  Fix: cp .env.example .env    (Linux/macOS)\n"
        "       copy .env.example .env  (Windows CMD)\n"
        "       Copy-Item .env.example .env  (PowerShell)"
    )


# ---------------------------------------------------------------------------
# CHECK 7 — pre-commit hooks installed
# ---------------------------------------------------------------------------
head("CHECK 7 — pre-commit hooks")

git_hooks_dir = Path(".git") / "hooks" / "pre-commit"
precommit_config = Path(".pre-commit-config.yaml")

if not precommit_config.exists():
    check_warn("No .pre-commit-config.yaml — skipping pre-commit check")
elif git_hooks_dir.exists():
    check_ok("pre-commit hook installed at .git/hooks/pre-commit")
else:
    check_warn("pre-commit hook not installed.\n" "  Fix: python -m pre_commit install")


# ---------------------------------------------------------------------------
# CHECK 8 — Key backend modules importable (smoke test)
# ---------------------------------------------------------------------------
head("CHECK 8 — Core backend module smoke test")

SMOKE_IMPORTS = [
    ("backend.core.config", "Settings / config layer"),
    ("backend.shared.models", "Shared Pydantic base models"),
    ("backend.normalization.models", "CanonicalEvent model"),
    ("backend.baseline.models", "Baseline data models"),
    ("backend.baseline.statistics", "Statistics engine"),
    ("backend.features.models", "Feature schema"),
    ("backend.features.pipeline", "Feature pipeline"),
    ("backend.metrics.models", "Metrics models"),
    ("backend.metrics.store", "MetricStore"),
]

smoke_failures = []
for module_path, description in SMOKE_IMPORTS:
    try:
        importlib.import_module(module_path)
        if not QUIET:
            ok(f"{module_path}  ({description})")
    except Exception as exc:
        smoke_failures.append((module_path, str(exc)))
        fail(f"{module_path}  ← {exc}")

if smoke_failures:
    check_fail(
        f"{len(smoke_failures)} backend module(s) failed to import — "
        "likely a missing dependency or configuration issue."
    )
else:
    check_ok(f"All {len(SMOKE_IMPORTS)} core backend modules importable")


# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
print()
print(f"{CYAN}{'=' * 52}{NC}")
print(f"{CYAN}  ENVIRONMENT VERIFICATION SUMMARY{NC}")
print(f"{CYAN}{'=' * 52}{NC}")
print()

total_fail = len(_failures)
total_warn = len(_warnings)

if total_fail == 0 and total_warn == 0:
    print(f"  {GREEN}✓ ALL CHECKS PASSED — environment is ready{NC}")
elif total_fail == 0:
    print(f"  {YELLOW}✓ PASSED with {total_warn} warning(s){NC}")
    for w in _warnings:
        print(f"    {YELLOW}→ {w[:80]}{'...' if len(w) > 80 else ''}{NC}")
else:
    print(f"  {RED}✗ {total_fail} check(s) FAILED, {total_warn} warning(s){NC}")
    for f_ in _failures:
        print(f"    {RED}→ {f_[:80]}{'...' if len(f_) > 80 else ''}{NC}")
    for w in _warnings:
        print(f"    {YELLOW}→ {w[:80]}{'...' if len(w) > 80 else ''}{NC}")

print()
print(f"  Python  : {sys.version.split()[0]}")
print(f"  Prefix  : {sys.prefix}")
print()

sys.exit(0 if total_fail == 0 else 1)
