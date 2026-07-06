#!/usr/bin/env bash
# =============================================================================
# CyberShield — Test Runner Script
# =============================================================================
# Runs the full pytest suite with coverage.
# Usage:
#   ./scripts/run_tests.sh                     # all tests with coverage
#   ./scripts/run_tests.sh --no-cov            # skip coverage (faster)
#   ./scripts/run_tests.sh -k "test_health"    # run specific tests
#   ./scripts/run_tests.sh -m unit             # run unit tests only
# =============================================================================

set -uo pipefail

cd "$(dirname "$0")/.."

echo "CyberShield Test Suite"
echo "======================"
echo "Running: pytest tests/ $*"
echo ""

pytest tests/ \
    --tb=short \
    --strict-markers \
    "$@"

EXIT_CODE=$?

if [[ $EXIT_CODE -eq 0 ]]; then
    echo ""
    echo "✓ All tests passed."
    echo "  Coverage report: reports/coverage/index.html"
else
    echo ""
    echo "✗ Some tests failed. Exit code: $EXIT_CODE"
fi

exit $EXIT_CODE
