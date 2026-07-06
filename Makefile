# =============================================================================
# CyberShield — Developer Workflow Makefile
# =============================================================================
# Usage:
#   make install      — Set up development environment
#   make lint         — Run all linting (ruff + mypy)
#   make test         — Run full test suite with coverage
#   make test-fast    — Run tests without coverage (faster)
#   make run          — Start development server
#   make docker-build — Build Docker images
#   make docker-up    — Start all services via Docker Compose
#   make clean        — Remove generated artifacts
# =============================================================================

.PHONY: all install install-prod lint format typecheck test test-fast test-unit \
        test-integration run run-prod docker-build docker-up docker-down \
        clean clean-cache pre-commit-install pre-commit-run help

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------
PYTHON      := python3.11
VENV        := .venv
PIP         := $(VENV)/bin/pip
PYTEST      := $(VENV)/bin/pytest
RUFF        := $(VENV)/bin/ruff
MYPY        := $(VENV)/bin/mypy
UVICORN     := $(VENV)/bin/uvicorn
PRE_COMMIT  := $(VENV)/bin/pre-commit

APP_MODULE  := backend.api.app:create_app
APP_HOST    := 0.0.0.0
APP_PORT    := 8000
LOG_LEVEL   := info

# ---------------------------------------------------------------------------
# Default Target
# ---------------------------------------------------------------------------
all: install lint test

# ---------------------------------------------------------------------------
# Environment Setup
# ---------------------------------------------------------------------------
install: ## Set up full development environment
	@echo "→ Creating virtual environment..."
	$(PYTHON) -m venv $(VENV)
	@echo "→ Upgrading pip..."
	$(PIP) install --upgrade pip setuptools wheel
	@echo "→ Installing development dependencies..."
	$(PIP) install -r requirements-dev.txt
	@echo "→ Installing pre-commit hooks..."
	$(PRE_COMMIT) install
	@echo "→ Creating .env from template (if not exists)..."
	@test -f .env || cp .env.example .env
	@echo "✓ Development environment ready. Edit .env with your settings."

install-prod: ## Install production dependencies only
	@echo "→ Installing production dependencies..."
	pip install -r requirements.txt
	@echo "✓ Production dependencies installed."

# ---------------------------------------------------------------------------
# Code Quality
# ---------------------------------------------------------------------------
lint: format typecheck ## Run all linting checks

format: ## Run ruff linter + formatter
	@echo "→ Running ruff linter..."
	$(RUFF) check backend tests --fix
	@echo "→ Running ruff formatter..."
	$(RUFF) format backend tests
	@echo "✓ Formatting complete."

format-check: ## Check formatting without fixing
	$(RUFF) check backend tests
	$(RUFF) format --check backend tests

typecheck: ## Run mypy static type checker
	@echo "→ Running mypy type checker..."
	$(MYPY) backend
	@echo "✓ Type checking complete."

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------
test: ## Run full test suite with coverage
	@echo "→ Running full test suite..."
	$(PYTEST) tests/ -v
	@echo "✓ Tests complete. Coverage report: reports/coverage/index.html"

test-fast: ## Run tests without coverage (faster iteration)
	@echo "→ Running tests (no coverage)..."
	$(PYTEST) tests/ -v -p no:cov

test-unit: ## Run unit tests only
	@echo "→ Running unit tests..."
	$(PYTEST) tests/unit/ -v -p no:cov -m unit

test-integration: ## Run integration tests only
	@echo "→ Running integration tests..."
	$(PYTEST) tests/integration/ -v -m integration

# ---------------------------------------------------------------------------
# Running the Application
# ---------------------------------------------------------------------------
run: ## Start development server with auto-reload
	@echo "→ Starting CyberShield development server..."
	$(UVICORN) $(APP_MODULE) \
		--factory \
		--host $(APP_HOST) \
		--port $(APP_PORT) \
		--reload \
		--log-level $(LOG_LEVEL)

run-prod: ## Start production server (no reload)
	@echo "→ Starting CyberShield production server..."
	$(UVICORN) $(APP_MODULE) \
		--factory \
		--host $(APP_HOST) \
		--port $(APP_PORT) \
		--workers 4 \
		--log-level warning

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------
docker-build: ## Build Docker images (dev + prod)
	@echo "→ Building Docker images..."
	docker compose -f docker/docker-compose.yml build
	@echo "✓ Docker images built."

docker-up: ## Start all services via Docker Compose
	@echo "→ Starting services..."
	docker compose -f docker/docker-compose.yml up -d
	@echo "✓ Services started. API: http://localhost:$(APP_PORT)"

docker-down: ## Stop all services
	docker compose -f docker/docker-compose.yml down

docker-logs: ## Tail service logs
	docker compose -f docker/docker-compose.yml logs -f

# ---------------------------------------------------------------------------
# Pre-commit
# ---------------------------------------------------------------------------
pre-commit-install: ## Install pre-commit hooks
	$(PRE_COMMIT) install

pre-commit-run: ## Run all pre-commit hooks on all files
	$(PRE_COMMIT) run --all-files

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
clean: clean-cache ## Remove all generated artifacts
	@echo "→ Removing reports..."
	rm -rf reports/coverage/ reports/*.json reports/*.html
	@echo "✓ Clean complete."

clean-cache: ## Remove Python cache files
	@echo "→ Removing Python cache..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/
	@echo "✓ Cache cleared."

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
help: ## Show this help message
	@echo "CyberShield — Available Make Targets"
	@echo "====================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
