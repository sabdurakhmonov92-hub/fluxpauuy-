#!/usr/bin/env bash
# ==============================================================================
# FLUXPAY SQL MIGRATION RUNNER
# Blueprint §11 Contract Fulfillment: Migrations apply before restart.
#
# ARCHITECTURAL RATIONALE:
# Pure PostgreSQL idempotent migrations run via psql without ORM bloat.
# All schema migrations execute BEFORE code deployment (expand-contract law).
#
# CRASH & IDEMPOTENCY SAFETY:
# Success is recorded in schema_migrations strictly AFTER each file applies.
# A crash between SQL execution and the bookkeeping record causes the migration
# to re-apply on the next run. Because all migrations in migrations/*.sql are
# written to be strictly idempotent (CREATE TABLE IF NOT EXISTS, DO $$ blocks,
# ADD COLUMN IF NOT EXISTS), re-applying an already-applied migration is safe.
# ==============================================================================
set -euo pipefail

# DSN from FLX_PG_DSN (with DATABASE_URL fallback)
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
    already_applied=$(psql "$DSN" -v ON_ERROR_STOP=1 -v fname="$filename" -t -A -c "
        SELECT 1 FROM schema_migrations WHERE filename = :'fname';
    ")

    if [[ "$already_applied" == "1" ]]; then
        skipped_count=$((skipped_count + 1))
        continue
    fi

    echo "Applying migration: $filename ..."
    
    # Execute migration script with fail-fast ON_ERROR_STOP=1 (exit 1 on first failure)
    psql "$DSN" -v ON_ERROR_STOP=1 -f "$file_path"

    # Record success AFTER the file applies
    psql "$DSN" -v ON_ERROR_STOP=1 -v fname="$filename" --quiet -c "
        INSERT INTO schema_migrations (filename) VALUES (:'fname');
    "
    echo "Applied: $filename [OK]"
    applied_count=$((applied_count + 1))
done

echo "=== Migration Complete: $applied_count applied, $skipped_count skipped ==="
exit 0
