#!/usr/bin/env bash
# ==============================================================================
# FluxPay External Health & SLA Monitor (Part 6.2)
# Polls liveness, readiness, and metrics endpoints to evaluate system health
# ==============================================================================
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8000}"

echo "========================================================================"
echo " FluxPay Production External Health Monitor"
echo " Target Endpoint: ${BASE_URL}"
echo "========================================================================"

# 1. Liveness Probe
LIVENESS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/health" || echo "000")
if [ "${LIVENESS_STATUS}" -eq 200 ]; then
    echo "  [PASS] Liveness Check (/health) -> HTTP 200 OK"
else
    echo "  [FAIL] Liveness Check (/health) -> HTTP ${LIVENESS_STATUS}"
    exit 1
fi

# 2. Readiness Probe
READINESS_RESP=$(curl -s "${BASE_URL}/ready" || echo '{"status":"unreachable"}')
if echo "${READINESS_RESP}" | grep -q '"status":"ready"'; then
    echo "  [PASS] Readiness Check (/ready) -> All Subsystems Ready"
else
    echo "  [FAIL] Readiness Check (/ready) -> Degraded or Down:"
    echo "         ${READINESS_RESP}"
    exit 2
fi

# 3. Metrics Exposition
METRICS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/metrics" || echo "000")
if [ "${METRICS_STATUS}" -eq 200 ]; then
    echo "  [PASS] Prometheus Metrics (/metrics) -> HTTP 200 OK"
else
    echo "  [WARN] Metrics endpoint returned HTTP ${METRICS_STATUS}"
fi

echo "========================================================================"
echo " ALL HEALTH CHECKS PASSED: SYSTEM OPERATIONAL"
echo "========================================================================"
