# FluxPay Changelog

All notable changes to the FluxPay autonomous payment infrastructure are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.0.0] - 2026-09-30 (Production Hardening Release)

### Added
- **Centralized Dependency Injection Container (`src/fluxpay/di.py`)**:
  - Pure request-scoped and application-scoped DI via FastAPI `Depends()`.
  - Zero global singletons, no import-time side-effects.
- **Hourly Blockchain Reconciliation Worker (`src/fluxpay/workers/blockchain_reconciliation.py`)**:
  - Independent truth audit comparing Base L2 on-chain USDC reserves against ledger liabilities.
  - Automatic detection of orphaned deposits, unconfirmed withdrawals, and broken hashchains.
  - Promotes `FLX_LEDGER_IMBALANCE` gauge for Prometheus alerting.
- **x402 Protocol Router (`src/fluxpay/gateway/x402_router.py`)**:
  - Endpoints for `POST /x402/challenge`, `POST /x402/verify`, and `POST /x402/settle`.
  - Full RFC 7231 Payment Required and EIP-3009 gasless authorization integration.
- **Admin Emergency Circuit Breakers (`src/fluxpay/admin/emergency_router.py`)**:
  - High-privilege operational endpoints: `freeze-agent`, `halt-withdrawals`, `emergency-stop`, and `system-status`.
- **Multi-Backend Secrets Management (`src/fluxpay/shared/secrets.py`)**:
  - Transparent abstraction supporting Environment Variables, AWS Secrets Manager, HashiCorp Vault, and Local Encrypted Storage.
- **Database Hardening Migration (`migrations/0014_hardening_and_observability.sql`)**:
  - Added `x402_payments`, `x402_nonces`, `kms_audit_log`, `health_checks`, and `incident_log` tables.
- **Production Migration Runner (`scripts/migrate.py`)**:
  - Deterministic migration sequencing with SHA-256 checksum verification, `--dry-run`, and rollback support.
- **Multi-Stage Production Dockerfile & Compose Stacks**:
  - Multi-stage build with Astral uv; minimal Python 3.12 slim runtime; non-root user `fluxpay`.
  - `docker-compose.yml` (development) and `docker-compose.prod.yml` (production).
- **Comprehensive Runbooks & Operational Documentation**:
  - 10 operational runbooks in `docs/runbooks/` covering deployment, rollback, key rotation, failover, disaster recovery, and on-call escalation.
  - `docs/ARCHITECTURE.md`, `docs/CONFIGURATION.md`, `docs/OPERATIONS.md`, `docs/SECURITY.md`.
- **Complete Test Suites & CI/CD**:
  - Unit tests for DI container, secrets manager, emergency router, x402 router, and reconciliation worker.
  - k6 load testing script (`scripts/load_test_k6.js`) targeting 1,000 RPS with p99 < 500ms SLA.
  - GitHub Actions CI/CD workflow (`.github/workflows/ci.yml`).

### Changed
- Refactored `run_fluxpay.py` into a unified production runner supporting CLI flags (`--env`, `--host`, `--port`, `--workers`, `--migrate`, `--no-browser`), fail-fast validation, and graceful Uvicorn shutdown.
- Updated `src/fluxpay/main.py` application factory to mount x402 and emergency routers, operational `/health`, `/ready`, and `/version` endpoints, and Prometheus metrics.
- Updated `tests/deploy/test_no_docker.py` to enforce container hardening and non-root policies.
