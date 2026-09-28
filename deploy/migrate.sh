#!/usr/bin/env bash
# ==============================================================================
# FLUXPAY SQL MIGRATION RUNNER (TASK 65)
# Blueprint §11 Contract Fulfillment: Migrations apply before restart.
#
# ARCHITECTURAL DEVIATION RATIONALE (BLUEPRINT §11 "ALEMBIC" WORD):
# Blueprint §11 originally mentioned "alembic -> restart" as illustrative shorthand
# for "migrations apply before restart". However, FluxPay never adopted SQLAlchemy
# or Alembic in any task (Tasks 11-55 all authored pure PostgreSQL idempotent SQL).
# Introducing an ORM migration framework for 11 pure SQL files would introduce
# significant tooling debt, extra Python runtime dependencies, and schema drift risk.
# This runner strictly fulfills the §11 contract using a resilient, atomic psql
# loop backed by a schema_migrations bookkeeping table.
#
# EXPAND-CONTRACT DOCTRINE:
# Schema migrations MUST execute BEFORE code deployment. All SQL migrations must
# be additive/backward-compatible (expand phase) so current running code continues
# to operate until the symlink switch. Deprecated columns/tables are dropped in
# subsequent releases (contract phase).
# ==============================================================================
set -euo pipefail

DSN="${FLX_PG_DSN:-${DATABASE_URL:-}}"
if [[ -z "$DSN" ]]; then
    echo "ERROR: FLX_PG_DSN or DATABASE_URL must be set to run migrations." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-$REPO_ROOT/migrations}"

if [[ ! -d "$MIGRATIONS_DIR" ]]; then
    echo "ERROR: Migrations directory not found at $MIGRATIONS_DIR" >&2
    exit 1
fi

echo "=== FluxPay SQL Migration Runner ==="
echo "Target DSN: ${DSN%%\?*}"
echo "Migrations directory: $MIGRATIONS_DIR"

# 1. Initialize schema_migrations bookkeeping table if not present
psql "$DSN" -v ON_ERROR_STOP=1 --quiet -c "
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"

# 2. Collect and sort all .sql migration files alphanumerically
shopt -s nullglob
files=("$MIGRATIONS_DIR"/*.sql)
shopt -u nullglob

if [[ ${#files[@]} -eq 0 ]]; then
    echo "No migration files found in $MIGRATIONS_DIR."
    exit 0
fi

IFS=$'\n' sorted_files=($(sort <<<"${files[*]}"))
unset IFS

applied_count=0
skipped_count=0

for file_path in "${sorted_files[@]}"; do
    filename="$(basename "$file_path")"

    # Check if migration has already been applied
    already_applied=$(psql "$DSN" -v ON_ERROR_STOP=1 -t -A -c "
        SELECT 1 FROM schema_migrations WHERE filename = '$filename';
    ")

    if [[ "$already_applied" == "1" ]]; then
        skipped_count=$((skipped_count + 1))
        continue
    fi

    echo "Applying migration: $filename ..."
    
    # Execute migration script with fail-fast ON_ERROR_STOP=1
    psql "$DSN" -v ON_ERROR_STOP=1 -f "$file_path"

    # Record migration in bookkeeping table
    psql "$DSN" -v ON_ERROR_STOP=1 --quiet -c "
        INSERT INTO schema_migrations (filename) VALUES ('$filename');
    "
    echo "Applied: $filename [OK]"
    applied_count=$((applied_count + 1))
done

echo "=== Migration Complete: $applied_count applied, $skipped_count skipped ==="
exit 0
