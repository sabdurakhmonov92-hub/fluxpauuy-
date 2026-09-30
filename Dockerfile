# ==============================================================================
# FluxPay Multi-Stage Production Dockerfile (Part 4.1)
#
# Target: Production-hardened container image (< 300MB)
# Standards:
# - Multi-stage build with Astral uv for deterministic dependency compilation
# - Minimal python:3.12-slim runtime base
# - Non-root execution under UID 10001 (fluxpay:fluxpay)
# - Container healthcheck via native HTTP liveness probe
# - Memory and compilation hygiene (no pyc cache, unbuffered stdout)
# ==============================================================================

# --- Stage 1: Dependency Builder ---
FROM python:3.12-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_SYSTEM_PYTHON=1

WORKDIR /build

# Install build essentials for C-extensions (asyncpg, cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv package manager
COPY --from=ghcr.io/astral-sh/uv:0.4.15 /uv /bin/uv

# Copy dependency manifests
COPY pyproject.toml uv.lock ./

# Install dependencies into dedicated prefix
RUN uv pip install --no-cache --target=/install -r pyproject.toml

# --- Stage 2: Hardened Runtime ---
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src:/app \
    PATH=/install/bin:$PATH

WORKDIR /app

# Install minimal runtime dependencies (curl for healthcheck, libpq for PostgreSQL)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user and group
RUN groupadd --system --gid 10001 fluxpay && \
    useradd --system --uid 10001 --gid fluxpay --home-dir /app --shell /sbin/nologin fluxpay

# Copy compiled dependencies from builder stage
COPY --from=builder /install /usr/local/lib/python3.12/site-packages/

# Copy application source, migrations, static assets, and templates
COPY src/ /app/src/
COPY migrations/ /app/migrations/
COPY static/ /app/static/
COPY templates/ /app/templates/
COPY scripts/ /app/scripts/
COPY run_fluxpay.py /app/run_fluxpay.py

# Create persistent state directory and grant non-root permissions
RUN mkdir -p /app/data && \
    chown -R fluxpay:fluxpay /app

VOLUME ["/app/data"]

EXPOSE 8000 9110

USER fluxpay

# Integrated container health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["python", "run_fluxpay.py", "--host", "0.0.0.0", "--port", "8000", "--no-browser"]
