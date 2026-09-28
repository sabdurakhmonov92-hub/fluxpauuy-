#!/usr/bin/env bash
# scripts/dev_services.sh
# Purpose: Start, stop, and inspect native development services (PostgreSQL 17 and Valkey).
# When it runs: Invoked by 'make up' and 'make down' during local development.

set -euo pipefail

detect_os() {
    case "$(uname -s)" in
        Darwin*) echo "darwin" ;;
        Linux*)  echo "linux" ;;
        *)       echo "unknown" ;;
    esac
}

detect_linux_valkey_service() {
    # Valkey is an open-source, high-performance key-value datastore forked from Redis 7.2.4.
    # It is a 100% drop-in protocol and command replacement. On Linux distributions where
    # Valkey has not yet been packaged under the 'valkey' service unit name, the system falls
    # back to 'redis-server' or 'redis' service units seamlessly.
    if systemctl list-unit-files valkey.service &>/dev/null || systemctl cat valkey.service &>/dev/null; then
        echo "valkey"
    elif systemctl list-unit-files redis-server.service &>/dev/null || systemctl cat redis-server.service &>/dev/null; then
        echo "redis-server"
    else
        echo "redis"
    fi
}

wait_for_services() {
    local timeout=30
    local elapsed=0

    echo "Waiting for native PostgreSQL and Valkey to become ready (timeout: ${timeout}s)..."

    # Wait for PostgreSQL
    until pg_isready -q 2>/dev/null; do
        if [ "$elapsed" -ge "$timeout" ]; then
            echo "ERROR: PostgreSQL failed to become ready within ${timeout} seconds." >&2
            echo "Verify PostgreSQL 17 is installed and running natively:" >&2
            echo "  macOS: brew install postgresql@17 && brew services start postgresql@17" >&2
            echo "  Linux: sudo apt install postgresql-17 && sudo systemctl start postgresql" >&2
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    echo "PostgreSQL is ready."

    # Detect CLI for Valkey / Redis
    local cli=""
    if command -v valkey-cli &>/dev/null; then
        cli="valkey-cli"
    elif command -v redis-cli &>/dev/null; then
        cli="redis-cli"
    else
        echo "ERROR: Neither 'valkey-cli' nor 'redis-cli' was found on PATH." >&2
        echo "Install Valkey natively:" >&2
        echo "  macOS: brew install valkey" >&2
        echo "  Linux: sudo apt install valkey (or redis-tools)" >&2
        return 1
    fi

    elapsed=0
    until [ "$("$cli" ping 2>/dev/null || true)" = "PONG" ]; do
        if [ "$elapsed" -ge "$timeout" ]; then
            echo "ERROR: Valkey failed to respond with PONG within ${timeout} seconds." >&2
            echo "Verify Valkey is installed and running natively:" >&2
            echo "  macOS: brew install valkey && brew services start valkey" >&2
            echo "  Linux: sudo apt install valkey && sudo systemctl start valkey" >&2
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    echo "Valkey is ready."
}

start_services() {
    local os
    os="$(detect_os)"

    case "$os" in
        darwin)
            echo "Starting native services via Homebrew..."
            brew services start postgresql@17
            brew services start valkey
            ;;
        linux)
            local valkey_svc
            valkey_svc="$(detect_linux_valkey_service)"
            echo "Starting native services via systemctl (PostgreSQL and $valkey_svc)..."
            sudo systemctl start postgresql "$valkey_svc"
            ;;
        *)
            echo "ERROR: Unsupported operating system: $(uname -s)." >&2
            echo "FluxPay requires native PostgreSQL 17 and Valkey on macOS (Homebrew) or Linux (systemd)." >&2
            exit 1
            ;;
    esac

    wait_for_services
}

stop_services() {
    local os
    os="$(detect_os)"

    case "$os" in
        darwin)
            echo "Stopping native services via Homebrew..."
            brew services stop postgresql@17 || true
            brew services stop valkey || true
            ;;
        linux)
            local valkey_svc
            valkey_svc="$(detect_linux_valkey_service)"
            echo "Stopping native services via systemctl..."
            sudo systemctl stop postgresql "$valkey_svc" || true
            ;;
        *)
            echo "ERROR: Unsupported operating system: $(uname -s)." >&2
            exit 1
            ;;
    esac
    echo "Native services stopped."
}

status_services() {
    local os
    os="$(detect_os)"

    echo "=== Service Status Audit ==="
    case "$os" in
        darwin)
            brew services info postgresql@17 2>/dev/null || brew services list | grep -E "postgresql@17|Name" || true
            brew services info valkey 2>/dev/null || brew services list | grep -E "valkey|Name" || true
            ;;
        linux)
            local valkey_svc
            valkey_svc="$(detect_linux_valkey_service)"
            systemctl status postgresql --no-pager || true
            systemctl status "$valkey_svc" --no-pager || true
            ;;
        *)
            echo "Unknown OS: $(uname -s)"
            ;;
    esac

    echo ""
    echo "=== Network Connectivity ==="
    if pg_isready -q 2>/dev/null; then
        echo "PostgreSQL (port 5432): ACCEPTING CONNECTIONS"
    else
        echo "PostgreSQL (port 5432): NOT REACHABLE"
    fi

    local cli=""
    if command -v valkey-cli &>/dev/null; then
        cli="valkey-cli"
    elif command -v redis-cli &>/dev/null; then
        cli="redis-cli"
    fi

    if [ -n "$cli" ] && [ "$("$cli" ping 2>/dev/null || true)" = "PONG" ]; then
        echo "Valkey ($cli ping): PONG"
    else
        echo "Valkey: NOT REACHABLE"
    fi
}

main() {
    local action="${1:-}"
    case "$action" in
        start)
            start_services
            ;;
        stop)
            stop_services
            ;;
        status)
            status_services
            ;;
        *)
            echo "Usage: $0 {start|stop|status}" >&2
            exit 1
            ;;
    esac
}

main "$@"
