# FluxPay v3: Payment Infrastructure for Autonomous AI Agent Economies

[![CI/CD](https://github.com/fluxpay/fluxpay/actions/workflows/ci.yml/badge.svg)](https://github.com/fluxpay/fluxpay/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Base L2](https://img.shields.io/badge/network-Base%20L2%20(8453)-0052FF.svg)](https://base.org)
[![USDC](https://img.shields.io/badge/token-Native%20USDC-2775CA.svg)](https://basescan.org/token/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)
[![License: Proprietary](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)

FluxPay is institutional-grade, zero-trust financial infrastructure engineered for autonomous AI agent economies. Settled natively on Ethereum Base L2 with USDC, FluxPay provides high-throughput micro-transactions, cryptographic double-entry ledgering, and gasless EIP-3009 transfer authorizations.

---

## ⚡ 5-Minute Quickstart

### Prerequisites
- Python 3.12+ and [uv package manager](https://github.com/astral-sh/uv) (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- Docker & Docker Compose (or local PostgreSQL 16 + Redis 7 + RabbitMQ 3)

### 1. Clone & Bootstrap
```bash
git clone https://github.com/fluxpay/fluxpay.git
cd fluxpay
uv sync
```

### 2. Configure Environment
```bash
cp .env.development .env
```

### 3. Run Migrations & Start Unified Server
```bash
python run_fluxpay.py --migrate
```
The server will boot, validate all environment constraints fail-fast, apply schema migrations, and automatically open the unified console in your default web browser at `http://127.0.0.1:8000/`.

---

## 🐳 Containerized Deployment (Docker Compose)

### Development Cluster (Local Ports Exposed)
```bash
docker compose up -d
```
Services spun up:
- **FluxPay API**: `http://localhost:8000` (docs: `/docs`, console: `/`, health: `/health`, metrics: `/metrics`)
- **FluxPay Background Worker**: Hourly blockchain reconciler & deposit indexer
- **PostgreSQL 16**: Port 5432
- **Redis 7 (Valkey)**: Port 6379
- **RabbitMQ 3**: Port 5672 (Management UI: `http://localhost:15672`)
- **Prometheus**: `http://localhost:9090`
- **Grafana**: `http://localhost:3000` (user: `admin`, pass: `fluxpay_admin`)

### Production Cluster (Hardened)
```bash
docker compose -f docker-compose.prod.yml up -d
```

---

## 🏗️ Architecture & Core Components

- **Payment Gateway (`src/fluxpay/gateway/`)**:
  - `POST /v1/payments`: Sub-millisecond payment execution with three-tier idempotency.
  - `POST /x402/challenge`: Dynamic RFC 7231 / x402 challenge generation for AI agents.
  - `POST /x402/verify` & `POST /x402/settle`: Gasless EIP-3009 transfer authorization.
- **Double-Entry Cryptographic Ledger (`src/fluxpay/ledger/`)**:
  - Exact minor-unit integer arithmetic (zero floating-point operations).
  - Continuous SHA-256 hashchain linking every entry to its immutable predecessor.
- **Base L2 Blockchain Rails (`src/fluxpay/integrations/`)**:
  - Inbound ERC-20 transfer event indexer with reorg detection and recovery.
  - Outbound EIP-1559 transaction writer with AWS KMS / Cloud HSM asymmetric signing.
- **Automated Workers (`src/fluxpay/workers/`)**:
  - Hourly blockchain ↔ ledger reconciliation worker comparing on-chain truth with balance liabilities.
  - Asynchronous webhook dispatcher with exponential backoff and HMAC-SHA256 signatures.

---

## 🧪 Testing & Quality Gates

FluxPay enforces strict automated quality gates. Every PR must pass all checks:

```bash
# 1. Static Linting & Style Check (Zero warnings tolerated)
uv run ruff check .
uv run ruff format --check .

# 2. Strict Static Type Analysis (0 errors allowed)
uv run mypy src/fluxpay tests

# 3. Unit Test Suite (Fast in-memory unit tests)
uv run pytest -m unit

# 4. Invariant Contract & Integration Tests
uv run pytest
```

---

## 📚 Documentation Reference

- **[System Architecture](docs/ARCHITECTURE.md)**: Deep dive into invariants, data flows, and subsystem topology.
- **[Configuration Guide](docs/CONFIGURATION.md)**: Complete catalog of all environment variables and secret controls.
- **[Operations Manual](docs/OPERATIONS.md)**: Day-2 operational maintenance, emergency circuit breakers, and runbooks.
- **[Security Policy](docs/SECURITY.md)**: Threat model, key management lifecycle, and vulnerability disclosure.
- **[Runbooks](docs/runbooks/)**: Incident playbooks for deployments, rollbacks, failovers, and on-call rotations.
