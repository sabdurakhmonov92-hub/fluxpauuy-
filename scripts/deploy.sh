#!/usr/bin/env bash
# ==============================================================================
# FluxPay Zero-Downtime Deployment Script (Part 6.2)
# Orchestrates production deployment via Docker Compose or Systemd
# ==============================================================================
set -euo pipefail

ENV="${1:-production}"
TAG="${2:-latest}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "========================================================================"
echo " Starting FluxPay Deployment: Target Env=${ENV}, Tag=${TAG}"
echo "========================================================================"

cd "${REPO_DIR}"

# Step 1: Pre-flight Checks
echo "[1/6] Running pre-flight configuration validation..."
if [ ! -f ".env.${ENV}" ] && [ ! -f ".env" ]; then
    echo "ERROR: Missing environment file for ${ENV} (.env.${ENV})"
    exit 1
fi

# Step 2: Database Migration Check
echo "[2/6] Running database migrations..."
python scripts/migrate.py

# Step 3: Deployment Mode Execution
if command -v docker &> /dev/null && [ -f "docker-compose.prod.yml" ]; then
    echo "[3/6] Container Deployment: Building and pulling Docker images..."
    docker compose -f docker-compose.prod.yml pull || true
    docker compose -f docker-compose.prod.yml build fluxpay-api fluxpay-worker

    echo "[4/6] Rolling update of services..."
    docker compose -f docker-compose.prod.yml up -d --no-deps --scale fluxpay-api=4 --no-recreate fluxpay-api
    docker compose -f docker-compose.prod.yml up -d
else
    echo "[3/6] Bare-metal systemd deployment..."
    sudo systemctl restart fluxpay-worker.service
    sudo systemctl reload-or-restart fluxpay-api.service
fi

# Step 5: Post-deployment Health Check
echo "[5/6] Verifying system readiness..."
MAX_ATTEMPTS=12
ATTEMPT=0
READY=false

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    ATTEMPT=$((ATTEMPT + 1))
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/ready || true)
    if [ "$HTTP_CODE" -eq 200 ]; then
        echo "FluxPay API reports READY (HTTP 200) on attempt ${ATTEMPT}."
        READY=true
        break
    fi
    echo "Waiting for health check... (attempt ${ATTEMPT}/${MAX_ATTEMPTS}, status=${HTTP_CODE})"
    sleep 3
done

if [ "$READY" = false ]; then
    echo "CRITICAL: Deployment failed readiness probe! Triggering automatic rollback..."
    bash scripts/rollback.sh "${ENV}"
    exit 1
fi

echo "[6/6] Deployment completed successfully! FluxPay is serving traffic."
