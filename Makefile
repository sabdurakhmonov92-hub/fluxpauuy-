# ==============================================================================
# FluxPay Makefile — Local Development & CI Symmetry
#
# RULE: Every recipe line that invokes Python tooling MUST run through `uv run`.
# Bare invocations (e.g. `pytest`, `mypy`, `ruff`) risk invoking the ambient
# system interpreter instead of the locked virtual environment.
# ==============================================================================

SHELL := bash
.DELETE_ON_ERROR:
.DEFAULT_GOAL := help

# Guard: Ensure `uv` is installed and discoverable on PATH before executing recipes
ifeq ($(shell command -v uv 2> /dev/null),)
    $(error "uv is not installed or not found on PATH. Install it via: curl -LsSf https://astral.sh/uv/install.sh | sh")
endif

.PHONY: help setup check verify fix test up down db-init env doctor clean

help: ## Show this help message with target descriptions
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Sync locked dependencies and generate local .env if absent
	uv sync --frozen
	@test -f .env || $(MAKE) env

check: ## Fast local quality gate (ruff format check, ruff check, mypy, unit tests; no services needed)
	uv run ruff format --check src tests
	uv run ruff check src tests
	uv run mypy
	uv run pytest -m unit

# CI symmetry: `make verify` mirrors the full CI pipeline (.github/workflows/ci.yml).
# Runs static analysis, strict type checking, and the complete test suite against live services.
# Any pull request must pass `make verify` locally before being pushed to remote.
verify: ## Full CI mirror: sync, format check, lint, mypy, and all tests (requires services)
	uv sync --frozen
	uv run ruff format --check src tests
	uv run ruff check src tests
	uv run mypy
	uv run pytest

fix: ## Format code and automatically fix auto-fixable lint issues (never touches mypy)
	uv run ruff format src tests
	uv run ruff check --fix src tests

test: ## Run test suite via pytest
	uv run pytest

up: ## Start native PostgreSQL and Valkey services, wait until ready, and initialize database
	./scripts/dev_services.sh start
	$(MAKE) db-init

down: ## Stop native PostgreSQL and Valkey services
	./scripts/dev_services.sh stop

# LOCAL DEV ONLY: Default role and database creation for local developer environments.
# In production and staging, roles and credentials are securely provisioned via Doppler/Terraform.
# This target is idempotent: safe to re-run multiple times without error.
db-init: ## Idempotently create local PostgreSQL role (fluxpay/fluxpay) and database (fluxpay)
	@echo "Initializing local PostgreSQL role and database..."
	psql -d postgres -v ON_ERROR_STOP=1 -c \
		"DO \$$\$$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fluxpay') THEN CREATE ROLE fluxpay WITH LOGIN SUPERUSER PASSWORD 'fluxpay'; ELSE ALTER ROLE fluxpay WITH LOGIN SUPERUSER PASSWORD 'fluxpay'; END IF; END \$$\$$;"
	psql -d postgres -v ON_ERROR_STOP=1 -c \
		"SELECT 'CREATE DATABASE fluxpay OWNER fluxpay' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'fluxpay')\gexec"
	@echo "PostgreSQL role 'fluxpay' and database 'fluxpay' are ready."

env: ## Generate local .env from .env.example with random secrets (use FORCE=1 to overwrite)
	./scripts/gen_env.sh $(if $(filter 1,$(FORCE)),--force,)

doctor: ## Audit local environment and verify all required native tools
	./scripts/doctor.sh

clean: ## Clean local test, type, lint, and coverage caches (never touches .env)
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov coverage.xml
	find . -type d -name "__pycache__" -exec rm -rf {} +

# --- Task 18 edit/append ---
.PHONY: smoke verify-ledger

smoke: ## Run sustained-write ledger throughput smoke test suite (requires local services up)
	uv run pytest -m throughput

verify-ledger: ## Run ledger SHA-256 hash chain verification CLI against live database
	uv run python -m fluxpay.ledger.verify

