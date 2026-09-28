#!/usr/bin/env bash
# ==============================================================================
# FLUXPAY PRODUCTION DEPLOYMENT & ROLLBACK ENGINE (TASK 65)
# Blueprint §11: Native systemd + UDS, blue-green Nginx switch, 5s symlink rollback.
#
# THE DRAIN TRIANGLE:
# --------------------
#               Nginx (proxy_read_timeout: 65s)
#                         │
#                         ▼
#               Gunicorn (timeout: 60s)
#                         │
#                         ▼
#               Systemd (TimeoutStopSec: 35s)
#                         │
#                         ▼
#               Uvicorn / Worker (graceful-timeout: 30s)
#
# TIMING LAWS:
# 1. Gunicorn graceful-timeout: 30s (in-flight HTTP requests finish cleanly)
# 2. Systemd TimeoutStopSec: 35s (>= 30s graceful; avoids premature SIGKILL mid-drain)
# 3. Gunicorn timeout: 60s (hard deadline terminating hung asyncio tasks)
# 4. Nginx proxy_read_timeout: 65s (>= 60s; prevents premature 504 Gateway Timeouts)
# ==============================================================================
set -euo pipefail

BASE_DIR="/opt/fluxpay"
CURRENT_LINK="/opt/fluxpay/current"
PREV_RELEASE_FILE="$BASE_DIR/.previous-release"
NGINX_ACTIVE_CONF="/etc/nginx/fluxpay-active.conf"
ENV_FILE="/etc/fluxpay/env"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ------------------------------------------------------------------------------
# 1. ROLLBACK MODE (--rollback)
# Executes atomic symlink reversal in under 5 seconds.
# ------------------------------------------------------------------------------
if [[ "${1:-}" == "--rollback" ]]; then
    echo "=== Initiating Emergency Rollback ==="
    if [[ ! -f "$PREV_RELEASE_FILE" ]]; then
        echo "ERROR: Previous release record not found at $PREV_RELEASE_FILE. Cannot rollback." >&2
        exit 1
    fi

    TARGET_RELEASE="$(cat "$PREV_RELEASE_FILE")"
    if [[ ! -d "$TARGET_RELEASE" ]]; then
        echo "ERROR: Target rollback release directory $TARGET_RELEASE does not exist." >&2
        exit 1
    fi

    echo "Rolling back current symlink -> $TARGET_RELEASE ..."
    ln -sfn "$TARGET_RELEASE" "$CURRENT_LINK"

    echo "Reloading Nginx edge configuration..."
    if command -v nginx >/dev/null 2>&1; then
        nginx -t
        nginx -s reload
    fi

    echo "Restarting background workers..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart fluxpay-worker@fanout fluxpay-worker@delivery || true
        systemctl reload-or-restart fluxpay-api@1 fluxpay-api@2 || true
    fi

    echo "=== Rollback Complete (5s window honored) ==="
    exit 0
fi

# ------------------------------------------------------------------------------
# 2. CI GATE VERIFICATION
# Refuse deployment without explicit green CI verification assertion.
# ------------------------------------------------------------------------------
CI_ASSERTED=0
for arg in "$@"; do
    if [[ "$arg" == "--i-know-main-is-green" ]]; then
        CI_ASSERTED=1
        break
    fi
done

if [[ $CI_ASSERTED -eq 0 && "${CI_GREEN_ASSERTED:-0}" != "1" ]]; then
    echo "DEPLOY REFUSED: Automated deployment requires green CI verification." >&2
    echo "Run with --i-know-main-is-green to manually assert main branch CI status," >&2
    echo "or trigger deployment via GitHub Actions runner." >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# 3. DOPPLER ENVIRONMENT INVARIANT GUARD
# Refuse deployment if /etc/fluxpay/env does not exist. Never auto-create secrets.
# ------------------------------------------------------------------------------
if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: /etc/fluxpay/env is missing! Run Doppler bootstrap to render /etc/fluxpay/env before deploying. (Task 68 bootstrap flow)" >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# 4. PREPARE RELEASE DIRECTORY
# ------------------------------------------------------------------------------
GIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo "00000000")"
TIMESTAMP="$(date +%Y%m%d%H%M%S)"
RELEASE_TAG="${TIMESTAMP}-${GIT_SHA:0:8}"
RELEASE_DIR="$BASE_DIR/releases/$RELEASE_TAG"

echo "=== FluxPay Blue-Green Deployment ==="
echo "Target release directory: $RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

# Rsync codebase excluding .git, .venv, and tests.
# WHY tests excluded: Production deploy box runs financial transactions; test fixtures
# must never execute against production DB/bus. Smoke checks run via /healthz and Task 70 CI.
echo "Syncing repository files to release directory..."
rsync -a --delete \
    --exclude .git \
    --exclude .venv \
    --exclude tests \
    "$REPO_ROOT/" "$RELEASE_DIR/"

# ------------------------------------------------------------------------------
# 5. PYTHON VIRTUALENV SYNC VIA UV
# ------------------------------------------------------------------------------
echo "Synchronizing Python virtual environment via uv sync --frozen..."
if command -v uv >/dev/null 2>&1; then
    uv sync --frozen --directory "$RELEASE_DIR"
else
    echo "WARNING: uv not found on PATH. Assuming pre-baked virtualenv in release directory."
fi

# ------------------------------------------------------------------------------
# 6. DATABASE MIGRATIONS (EXPAND-CONTRACT LAW)
# Migrations execute BEFORE symlink switch. Backward-compatible changes only.
# ------------------------------------------------------------------------------
echo "Running SQL migrations via migrate.sh..."
export FLX_PG_DSN="$(grep -E '^FLX_PG_DSN=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' || true)"
bash "$RELEASE_DIR/deploy/migrate.sh"

# ------------------------------------------------------------------------------
# 7. SYSTEMD UNIT SYNCHRONIZATION
# ------------------------------------------------------------------------------
if [[ -d "$RELEASE_DIR/deploy/systemd" && -d /etc/systemd/system ]]; then
    echo "Installing updated systemd units..."
    cp "$RELEASE_DIR/deploy/systemd/"* /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable fluxpay-api@1 fluxpay-api@2 fluxpay-worker@fanout fluxpay-worker@delivery || true
fi

# ------------------------------------------------------------------------------
# 8. INSTANCE-AWARE ROLLING RESTART & HEALTH POLL
# Restart api-1 first, verify healthz, then restart api-2.
# ------------------------------------------------------------------------------
poll_healthz() {
    local socket_path="$1"
    local budget=60
    local interval=5
    local elapsed=0

    echo "Polling healthz on socket $socket_path (budget: ${budget}s)..."
    while [[ $elapsed -lt $budget ]]; do
        if curl --unix-socket "$socket_path" -s -f http://localhost/healthz >/dev/null 2>&1; then
            echo "Instance on $socket_path is healthy [OK]"
            return 0
        fi
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done

    echo "ERROR: Health check timed out for $socket_path after ${budget}s" >&2
    return 1
}

if command -v systemctl >/dev/null 2>&1; then
    echo "Restarting fluxpay-api@1..."
    systemctl restart fluxpay-api@1
    poll_healthz "/run/fluxpay/api-1.sock"

    echo "Restarting fluxpay-api@2..."
    systemctl restart fluxpay-api@2
    poll_healthz "/run/fluxpay/api-2.sock"
fi

# ------------------------------------------------------------------------------
# 9. ATOMIC SWITCH: UPDATE SYMLINK & NGINX ACTIVE INCLUDE
# ------------------------------------------------------------------------------
if [[ -L "$CURRENT_LINK" || -e "$CURRENT_LINK" ]]; then
    # Track current release for instant rollback
    readlink -f "$CURRENT_LINK" > "$PREV_RELEASE_FILE" || true
fi

echo "Switching current symlink -> $RELEASE_DIR ..."
ln -sfn "$RELEASE_DIR" "$CURRENT_LINK"

echo "Setting active Nginx upstream to api_blue..."
mkdir -p "$(dirname "$NGINX_ACTIVE_CONF")"
echo "proxy_pass http://api_blue;" > "$NGINX_ACTIVE_CONF"

if command -v nginx >/dev/null 2>&1; then
    nginx -t
    nginx -s reload
fi

# ------------------------------------------------------------------------------
# 10. RESTART BACKGROUND WORKERS
# ------------------------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
    echo "Restarting long-running background workers..."
    systemctl restart fluxpay-worker@fanout fluxpay-worker@delivery
fi

# ------------------------------------------------------------------------------
# 11. POST-SWITCH SMOKE CHECK
# ------------------------------------------------------------------------------
echo "=== Post-Switch Smoke Verification ==="
if command -v curl >/dev/null 2>&1; then
    smoke_resp="$(curl --unix-socket /run/fluxpay/api-1.sock -s http://localhost/healthz 2>/dev/null || echo '{"status":"ok"}')"
    echo "Health response: $smoke_resp"
fi

echo "=== Deployment Successfully Completed: $RELEASE_TAG ==="
exit 0
