# Local Development Guide

## The 2-Command Promise

Every engineer onboarded to FluxPay goes from a fresh `git clone` to passing green tests with **two commands maximum**:

```bash
make setup
make up && make verify
```

There are no undocumented configuration steps, no manual secret exchanges, and no container layers. Local development is a direct mirror of continuous integration.

---

## Prerequisites (Native Installation)

FluxPay enforces a **strict Zero-Docker policy** across all development workflows. All databases, key-value stores, and tooling run natively on the host operating system.

| Tool | Minimum Version | macOS (Homebrew) | Linux (apt / systemd) | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **uv** | `>= 0.5.0` | `curl -LsSf https://astral.sh/uv/install.sh \| sh` | `curl -LsSf https://astral.sh/uv/install.sh \| sh` | Fast Python package & venv management |
| **Python** | `3.12.x` | `uv python install 3.12` | `uv python install 3.12` | Core runtime |
| **PostgreSQL** | `17.x` | `brew install postgresql@17 && brew link postgresql@17` | `sudo apt install postgresql-17 postgresql-client-17` | Primary ACID relational database |
| **Valkey** | `>= 8.0` | `brew install valkey` | `sudo apt install valkey` *(or `redis-server`)* | Rate limiting, distributed locks, caching |
| **OpenSSL** | `>= 3.0` | `brew install openssl@3` | `sudo apt install openssl` | Cryptographic secret generation |
| **Git** | `>= 2.40` | `brew install git` | `sudo apt install git` | Version control |
| **Bash** | `>= 4.0` | `brew install bash` | `sudo apt install bash` | Script execution & Makefile shell |

Verify your local toolchain at any time with:
```bash
make doctor
```

---

## Quickstart Workflow

Follow this sequence when bootstrapping a clean clone:

```bash
# 1. Sync locked dependencies and generate local .env with cryptographic secrets
make setup

# 2. Start native PostgreSQL & Valkey services, wait until ready, and initialize database
make up

# 3. Run the full quality gate and test suite (exact CI mirror)
make verify
```

---

## Makefile Target Reference

All repository automation is coordinated through the `Makefile`. Run `make help` to inspect available targets:

| Target | Description | Dependencies / Services Required |
| :--- | :--- | :--- |
| `make help` | Show target summary with descriptions (default goal). | None |
| `make setup` | Install locked dependencies (`uv sync --frozen`) and generate `.env` if absent. | None |
| `make check` | Fast local quality gate: `ruff format --check`, `ruff check`, `mypy`, and unit tests (`pytest -m unit`). | None (no services needed) |
| `make verify` | Full CI mirror: `uv sync --frozen`, formatting, linting, strict typing, and all tests. | PostgreSQL 17 + Valkey |
| `make fix` | Automatically format code and apply safe auto-fixes (`ruff format` + `ruff check --fix`). | None |
| `make test` | Run the complete test suite via `pytest`. | PostgreSQL 17 + Valkey |
| `make up` | Start native PostgreSQL and Valkey services, wait for readiness, and initialize database role/db. | Native OS services |
| `make down` | Stop native PostgreSQL and Valkey services. | Native OS services |
| `make db-init` | Idempotently create local PostgreSQL role (`fluxpay/fluxpay`) and database (`fluxpay`). | Running PostgreSQL 17 |
| `make env` | Generate local `.env` with random 32-byte vault key and 64-char webhook key (use `FORCE=1` to overwrite). | OpenSSL |
| `make doctor` | Audit local environment, verify all required native tools, and report live service connectivity. | None |
| `make clean` | Remove `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.coverage`, and `__pycache__` artifacts. | None (preserves `.env`) |

---

## CI Symmetry (`make verify == CI`)

FluxPay enforces strict symmetry between local development and the continuous integration pipeline (`.github/workflows/ci.yml`).

- In Task 2, CI established a two-stage quality gate:
  1. `static`: `uv sync --frozen`, `ruff check`, `ruff format --check`, `mypy`
  2. `tests`: `uv run pytest --cov --cov-report=xml` against real PostgreSQL 17 and Valkey 8 services.
- `make verify` executes this identical sequence locally. 
- **The Golden Rule**: If `make verify` fails on your workstation, CI will fail on GitHub. Run `make verify` before opening or pushing to any pull request.

---

## Zero-Docker Philosophy

FluxPay deliberately rejects Docker, Docker Compose, and containerized development environments. In production payment infrastructure, services run directly on hardened Linux kernels managed by `systemd`, with kernel-level connection pools, direct Unix domain sockets, and deterministic network routing. Adding Docker in local development introduces virtualization overhead, file-system synchronization lag on macOS, brittle socket forwarding, and hidden configuration drift that masks production failure modes. By running native services via `brew services` on macOS and `systemctl` on Linux, the developer's workstation mirrors the deployment reality, eliminating "works in my container" surprises.

---

## Troubleshooting

### 1. Port Conflicts (5432 / 6379)
If `make up` or `pg_isready` reports port collisions:
- Check for existing processes bound to the ports:
  ```bash
  # macOS / Linux
  lsof -i :5432
  lsof -i :6379
  ```
- Terminate rogue background containers or legacy database instances:
  ```bash
  # Ensure no old Docker containers are occupying the ports
  docker stop $(docker ps -q) 2>/dev/null || true
  ```

### 2. PostgreSQL `pg_hba.conf` Local Trust Authentication
`make db-init` relies on local trust or peer authentication without password prompts mid-flow.
- If you receive `FATAL: password authentication failed for user "fluxpay"` during initial bootstrap:
  - Check your local `pg_hba.conf` (macOS: `$(brew --prefix)/var/postgresql@17/pg_hba.conf`; Linux: `/etc/postgresql/17/main/pg_hba.conf`).
  - Ensure local connections allow `trust` for development:
    ```
    # TYPE  DATABASE        USER            ADDRESS                 METHOD
    local   all             all                                     trust
    host    all             all             127.0.0.1/32            trust
    host    all             all             ::1/128                 trust
    ```
  - Reload PostgreSQL:
    - macOS: `brew services restart postgresql@17`
    - Linux: `sudo systemctl restart postgresql`

### 3. Homebrew vs. System PostgreSQL Collision (macOS)
If running `psql --version` returns an older system version (e.g. PostgreSQL 14 or 16) instead of 17:
- Unlink older versions and explicitly link `postgresql@17`:
  ```bash
  brew unlink postgresql@16 2>/dev/null || true
  brew link --overwrite --force postgresql@17
  ```
- Ensure Homebrew's binary path precedes system paths in `~/.zshrc` or `~/.bashrc`:
  ```bash
  export PATH="$(brew --prefix postgresql@17)/bin:$PATH"
  ```

### 4. Valkey vs. Redis Naming on Linux
- Valkey is a drop-in open-source fork of Redis. On some Linux distributions (e.g. Ubuntu 22.04 / Debian 12), the package repositories may not yet distribute the binary under the `valkey` name.
- In those environments, install `redis-server` and `redis-tools`. `scripts/dev_services.sh` and `scripts/doctor.sh` automatically detect `valkey` first, falling back to `redis-server` or `redis` transparently.
