#!/usr/bin/env bash
# ==============================================================================
# FluxPay Disaster Recovery Database Restore Script (Part 6.2)
# Decrypts and restores a PostgreSQL snapshot from S3 or local storage
# ==============================================================================
set -euo pipefail

BACKUP_SOURCE="${1:-}"

if [ -z "${BACKUP_SOURCE}" ]; then
    echo "Usage: $0 <path-to-backup.dump.gpg or s3://...>"
    exit 1
fi

TEMP_RESTORE_DIR=$(mktemp -d)
trap 'rm -rf "${TEMP_RESTORE_DIR}"' EXIT

LOCAL_DUMP="${TEMP_RESTORE_DIR}/restore.dump"

if [[ "${BACKUP_SOURCE}" == s3://* ]]; then
    echo "[*] Downloading backup from S3: ${BACKUP_SOURCE}..."
    aws s3 cp "${BACKUP_SOURCE}" "${TEMP_RESTORE_DIR}/downloaded.dump.gpg"
    ENCRYPTED_FILE="${TEMP_RESTORE_DIR}/downloaded.dump.gpg"
else
    ENCRYPTED_FILE="${BACKUP_SOURCE}"
fi

echo "[*] Decrypting database dump..."
gpg --decrypt "${ENCRYPTED_FILE}" > "${LOCAL_DUMP}"

echo "========================================================================"
echo " WARNING: THIS WILL OVERWRITE THE TARGET DATABASE!"
echo " Target DB: ${PGDATABASE:-fluxpay_production} on ${PGHOST:-localhost}"
echo "========================================================================"
read -p "Type 'RESTORE-CONFIRMED' to proceed: " CONFIRMATION

if [ "${CONFIRMATION}" != "RESTORE-CONFIRMED" ]; then
    echo "Restore aborted by operator."
    exit 1
fi

echo "[*] Terminating existing connections to database..."
PGPASSWORD="${PGPASSWORD:-fluxpay_prod_pass}" psql \
    -h "${PGHOST:-localhost}" \
    -U "${PGUSER:-fluxpay_prod_app}" \
    -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${PGDATABASE:-fluxpay_production}' AND pid <> pg_backend_pid();" || true

echo "[*] Restoring database schema and records..."
PGPASSWORD="${PGPASSWORD:-fluxpay_prod_pass}" pg_restore \
    -h "${PGHOST:-localhost}" \
    -p "${PGPORT:-5432}" \
    -U "${PGUSER:-fluxpay_prod_app}" \
    -d "${PGDATABASE:-fluxpay_production}" \
    --clean --if-exists --exit-on-error \
    "${LOCAL_DUMP}"

echo "[+] Database restore completed successfully."
