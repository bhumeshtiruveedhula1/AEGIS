#!/usr/bin/env bash
# =============================================================================
# CyberShield — Developer Onboarding Script
# =============================================================================
# Run once after cloning the repository:
#   chmod +x scripts/setup_dev.sh
#   ./scripts/setup_dev.sh
#
# What it does:
#   1. Verifies Python 3.11+
#   2. Creates a virtual environment (.venv/)
#   3. Installs all development dependencies
#   4. Installs pre-commit hooks
#   5. Copies .env.example → .env (if not exists)
#   6. Creates required data directories
# =============================================================================

set -euo pipefail

# ANSI colours for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Colour

info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

info "CyberShield — Developer Setup"
info "================================="
info "Project root: $PROJECT_ROOT"
cd "$PROJECT_ROOT"

# ---------------------------------------------------------------------------
# Step 1: Verify Python version
# ---------------------------------------------------------------------------
info "Step 1/6: Checking Python version..."

PYTHON_CMD="python3.11"
if ! command -v "$PYTHON_CMD" &>/dev/null; then
    PYTHON_CMD="python3"
fi
if ! command -v "$PYTHON_CMD" &>/dev/null; then
    PYTHON_CMD="python"
fi

PYTHON_VERSION=$("$PYTHON_CMD" --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [[ "$PYTHON_MAJOR" -lt 3 || ( "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 11 ) ]]; then
    error "Python 3.11+ required. Found: $PYTHON_VERSION"
fi
info "✓ Python $PYTHON_VERSION found at: $(command -v $PYTHON_CMD)"

# ---------------------------------------------------------------------------
# Step 2: Create virtual environment
# ---------------------------------------------------------------------------
info "Step 2/6: Creating virtual environment (.venv/)..."

if [[ -d ".venv" ]]; then
    warn ".venv/ already exists — skipping creation"
else
    "$PYTHON_CMD" -m venv .venv
    info "✓ Virtual environment created"
fi

# Activate venv
source .venv/bin/activate

# ---------------------------------------------------------------------------
# Step 3: Install dependencies
# ---------------------------------------------------------------------------
info "Step 3/6: Installing development dependencies..."
pip install --upgrade pip setuptools wheel --quiet
pip install -r requirements-dev.txt --quiet
info "✓ Dependencies installed"

# ---------------------------------------------------------------------------
# Step 4: Install pre-commit hooks
# ---------------------------------------------------------------------------
info "Step 4/6: Installing pre-commit hooks..."
pre-commit install --install-hooks
info "✓ Pre-commit hooks installed"

# ---------------------------------------------------------------------------
# Step 5: Create .env file
# ---------------------------------------------------------------------------
info "Step 5/6: Setting up environment configuration..."

if [[ -f ".env" ]]; then
    warn ".env already exists — not overwriting"
else
    cp .env.example .env
    info "✓ .env created from .env.example"
    warn "  → Review and update .env with your configuration"
fi

# ---------------------------------------------------------------------------
# Step 6: Create required directories
# ---------------------------------------------------------------------------
info "Step 6/6: Creating project directories..."
mkdir -p data/raw data/normalized data/baseline data/attack_reference
mkdir -p models reports
info "✓ Directories created"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  CyberShield dev environment is ready!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit .env with your settings"
echo "  2. source .venv/bin/activate    (activate venv)"
echo "  3. make run                     (start dev server)"
echo "  4. make test                    (run test suite)"
echo "  5. make lint                    (run linting)"
echo ""
echo "API documentation: http://localhost:8000/docs"
