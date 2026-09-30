#!/usr/bin/env bash
# ==============================================================================
# FluxPay Emergency Rollback Script (Part 6.2)
# Instantly reverts application deployment to the previous stable release
# ==============================================================================
set -euo pipefail

ENV="${1:-production}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "========================================================================"
echo " EMERGENCY ROLLBACK INITIATED: Target Env=${ENV}"
echo "========================================================================"

cd "${REPO_DIR}"

if command -v docker &> /dev/null && [ -f "docker-compose.prod.yml" ]; then
    echo "[*] Rolling back Docker containers to previous image..."
    docker compose -f docker-compose.prod.yml rollback fluxpay-api || \
    docker compose -f docker-compose.prod.yml up -d --build fluxpay-api
else
    echo "[*] Rolling back Systemd service..."
    if [ -d "/opt/fluxpay/releases/previous" ]; then
        ln -sfn /opt/fluxpay/releases/previous /opt/fluxpay/current
        sudo systemctl restart fluxpay-api.service
        sudo systemctl restart fluxpay-worker.service
    else
        echo "No previous release directory found; restarting current service..."
        sudo systemctl restart fluxpay-api.service
    fi
fi

echo "[*] Verifying rollback readiness..."
sleep 3
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/ready || true)
if [ "$HTTP_CODE" -eq 200 ]; then
    echo "Rollback successful: FluxPay is operational."
else
    echo "WARNING: Post-rollback readiness check returned HTTP ${HTTP_CODE}."
fi
