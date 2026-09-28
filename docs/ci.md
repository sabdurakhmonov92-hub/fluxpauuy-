# Continuous Integration (CI) Quality Gate

## Overview
The CI pipeline (`.github/workflows/ci.yml`) is the automated immune system of FluxPay. In a regulated fintech codebase touched by distributed contributors, this gate guarantees that no code can be merged into `main` unless it strictly conforms to static analysis invariants and passes integration tests against real infrastructure services.

The gate is divided into two sequential stages:
1. **`static`**: Verifies formatting, linting, and strict type safety with zero external service dependencies.
2. **`tests`**: Executes the test suite with branch coverage enforcement against production-grade PostgreSQL 17 and Valkey 8 services.

---

## Hardening Decisions (The "WHY")

### 1. Action SHA Pinning (Supply-Chain Security)
All third-party GitHub Actions are pinned to full 40-character Git commit SHAs rather than mutable version tags (e.g. `@v4` or `@v5`).
- **Why**: Git tags can be modified, deleted, or hijacked upstream. In regulated financial software, pulling mutable code directly into build pipelines introduces supply-chain attack vectors. Pinning immutable SHAs ensures bit-for-bit repeatability and audit compliance.

### 2. Service Health Checks (`pg_isready` & `valkey-cli ping`)
CI services define explicit `--health-cmd` options for PostgreSQL and Valkey.
- **Why**: Container start does not equal readiness. Without explicit polling, tests race against PostgreSQL buffer pool initialization and Valkey socket binding, causing intermittent test failures (flakiness). Health checks ensure tests only run when sockets are actively accepting connections.

### 3. Frozen Lockfile Sync (`uv sync --frozen`)
All jobs execute `uv sync --frozen`.
- **Why**: The lockfile (`uv.lock`) is the single source of truth. Under no circumstances should CI resolve newer sub-dependencies dynamically. If a PR requires dependency updates, `uv.lock` must be updated and checked in explicitly.

### 4. Workflow Least Privilege (`permissions: contents: read`)
Default GitHub Actions tokens are restricted to read-only repository contents.
- **Why**: Limits the blast radius of compromised dependencies or actions from modifying repository assets, creating tags, or writing to releases.

### 5. Job Timeouts (`timeout-minutes`)
`static` is capped at 10 minutes; `tests` is capped at 15 minutes.
- **Why**: Hung processes (e.g., deadlock on an unclosed connection or endless loops) consume runner minutes and indefinitely block deployment queues. Timeouts act as automated circuit breakers.

### 6. Concurrency Control (`cancel-in-progress: true`)
Pushes to active pull requests immediately cancel preceding in-flight workflow runs.
- **Why**: Eliminates wasted runner minutes on superseded commits.

---

## Local Reproduction

CI runs exactly what local development runs. There are no CI-only magic environment variables or hidden steps.

### 1. Install Exact Dependencies
```bash
uv sync --frozen
```

### 2. Run Static Analysis
```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
```

### 3. Run Test Suite
Integration tests require active PostgreSQL 17 and Valkey 8 instances matching CI:
```bash
# Start local development services (to be wired into `make dev` in Task 6):
# PostgreSQL 17 on localhost:5432 (user: test, password: test, db: test)
# Valkey 8 on localhost:6379
# RabbitMQ 3.13 on localhost:5672 (Task 10: reliable event bus quorum queues & DLQ)

export FLX_PG_DSN="postgresql://test:test@localhost:5432/test"
uv run pytest --cov --cov-report=xml
```
