#!/usr/bin/env bash
# scripts/doctor.sh
# Purpose: Audit local development environment, verifying required native tools and service status.
# When it runs: Invoked by 'make doctor' during onboarding and environment troubleshooting.

set -euo pipefail

detect_os() {
    case "$(uname -s)" in
        Darwin*) echo "darwin" ;;
        Linux*)  echo "linux" ;;
        *)       echo "unknown" ;;
    esac
}

OS="$(detect_os)"
MISSING_COUNT=0

echo "=== FluxPay Local Environment Doctor ==="

# 1. bash >= 4
if [ "${BASH_VERSINFO[0]}" -ge 4 ]; then
    echo "FOUND bash ${BASH_VERSION}"
else
    echo "MISSING bash >= 4 (current: ${BASH_VERSION}) — " \
         "$( [ "$OS" = "darwin" ] && echo "brew install bash" || echo "sudo apt install bash" )"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# 2. git
if command -v git &>/dev/null; then
    GIT_VER="$(git --version 2>/dev/null | awk '{print $3}')"
    echo "FOUND git ${GIT_VER}"
else
    echo "MISSING git — " \
         "$( [ "$OS" = "darwin" ] && echo "brew install git" || echo "sudo apt install git" )"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# 3. uv
if command -v uv &>/dev/null; then
    UV_VER="$(uv --version 2>/dev/null | awk '{print $2}')"
    echo "FOUND uv ${UV_VER}"
else
    echo "MISSING uv — curl -LsSf https://astral.sh/uv/install.sh | sh"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# 4. python 3.12 (via uv)
if command -v uv &>/dev/null; then
    PY_VER="$(uv run python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || true)"
    if [[ "$PY_VER" =~ ^3\.12\. ]]; then
        echo "FOUND python 3.12 (via uv: ${PY_VER})"
    else
        echo "MISSING python 3.12 (found: ${PY_VER:-none}) — uv python install 3.12"
        MISSING_COUNT=$((MISSING_COUNT + 1))
    fi
else
    echo "MISSING python 3.12 — requires uv; install uv first"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# 5. psql / pg_isready (postgresql@17)
if command -v psql &>/dev/null && command -v pg_isready &>/dev/null; then
    PSQL_VER="$(psql --version 2>/dev/null | awk '{print $3}')"
    echo "FOUND postgresql (psql ${PSQL_VER}, pg_isready)"
else
    echo "MISSING postgresql (psql/pg_isready) — " \
         "$( [ "$OS" = "darwin" ] && echo "brew install postgresql@17 && brew link postgresql@17" || echo "sudo apt install postgresql-17 postgresql-client-17" )"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# 6. valkey-cli OR redis-cli
if command -v valkey-cli &>/dev/null; then
    VK_VER="$(valkey-cli --version 2>/dev/null | awk '{print $2}' || echo "available")"
    echo "FOUND valkey-cli ${VK_VER}"
elif command -v redis-cli &>/dev/null; then
    RD_VER="$(redis-cli --version 2>/dev/null | awk '{print $2}' || echo "available")"
    echo "FOUND redis-cli (Valkey drop-in) ${RD_VER}"
else
    echo "MISSING valkey-cli or redis-cli — " \
         "$( [ "$OS" = "darwin" ] && echo "brew install valkey" || echo "sudo apt install valkey (or redis-tools)" )"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# 7. openssl
if command -v openssl &>/dev/null; then
    SSL_VER="$(openssl version 2>/dev/null | awk '{print $2}')"
    echo "FOUND openssl ${SSL_VER}"
else
    echo "MISSING openssl — " \
         "$( [ "$OS" = "darwin" ] && echo "brew install openssl@3" || echo "sudo apt install openssl" )"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

echo ""
echo "=== Live Service Connectivity (INFO) ==="

# PostgreSQL responsiveness
if pg_isready -q 2>/dev/null; then
    echo "INFO: PostgreSQL service is running and accepting connections."
else
    echo "INFO: PostgreSQL service is not currently reachable (run 'make up' to start native services)."
fi

# Valkey / Redis responsiveness
CLI=""
if command -v valkey-cli &>/dev/null; then
    CLI="valkey-cli"
elif command -v redis-cli &>/dev/null; then
    CLI="redis-cli"
fi

if [ -n "$CLI" ] && [ "$("$CLI" ping 2>/dev/null || true)" = "PONG" ]; then
    echo "INFO: Valkey service is running and responding to ping."
else
    echo "INFO: Valkey service is not currently reachable (run 'make up' to start native services)."
fi

echo ""
if [ "$MISSING_COUNT" -gt 0 ]; then
    echo "FAIL: $MISSING_COUNT required tool(s) missing. Install them natively using the instructions above." >&2
    exit 1
else
    echo "SUCCESS: All required native tools are installed."
    exit 0
fi
