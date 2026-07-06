#!/usr/bin/env bash
# =============================================================================
# CyberShield — Lint Script
# =============================================================================
# Runs all code quality checks:
#   1. ruff linter (with auto-fix)
#   2. ruff formatter (check only — no auto-fix)
#   3. mypy static type checker
#
# Exit code: 0 = all checks pass, 1 = any check failed
# =============================================================================

set -uo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

PASS=0
FAIL=0

run_check() {
    local name="$1"
    shift
    echo -e "\n→ Running: $name"
    if "$@"; then
        echo -e "${GREEN}✓ $name passed${NC}"
    else
        echo -e "${RED}✗ $name failed${NC}"
        FAIL=$((FAIL + 1))
    fi
}

cd "$(dirname "$0")/.."

run_check "ruff lint"       ruff check backend tests --fix
run_check "ruff format"     ruff format --check backend tests
run_check "mypy typecheck"  mypy backend

echo ""
if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}All lint checks passed.${NC}"
    exit 0
else
    echo -e "${RED}$FAIL lint check(s) failed.${NC}"
    exit 1
fi
