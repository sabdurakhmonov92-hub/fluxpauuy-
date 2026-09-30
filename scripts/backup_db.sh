#!/usr/bin/env bash
# ==============================================================================
# FluxPay Production Database Backup Automation (Part 6.2)
# Creates encrypted, compressed PostgreSQL snapshot and uploads to secure S3 bucket
# ==============================================================================
set -euo pipefail

TIMESTAMP=$(date -u +"%Y%m%d_%H%M%SZ")
BACKUP_DIR="${BACKUP_DIR:-/var/backups/fluxpay}"
BACKUP_FILE="${BACKUP_DIR}/fluxpay_db_${TIMESTAMP}.dump.gpg"
S3_BUCKET="${S3_BACKUP_BUCKET:-s3://fluxpay-prod-backups/postgres}"
GPG_RECIPIENT="${BACKUP_GPG_RECIPIENT:-security@fluxpay.io}"

mkdir -p "${BACKUP_DIR}"

echo "[*] Starting PostgreSQL encrypted backup at ${TIMESTAMP}..."

# Export database with custom format (-Fc), compress, and encrypt via GPG on-the-fly
PGPASSWORD="${PGPASSWORD:-fluxpay_prod_pass}" pg_dump \
    -h "${PGHOST:-localhost}" \
    -p "${PGPORT:-5432}" \
    -U "${PGUSER:-fluxpay_prod_app}" \
    -d "${PGDATABASE:-fluxpay_production}" \
    -Fc --no-owner --no-privileges | \
    gpg --encrypt --recipient "${GPG_RECIPIENT}" --trust-model always \
    > "${BACKUP_FILE}"

echo "[*] Encrypted backup created: ${BACKUP_FILE} ($(du -h "${BACKUP_FILE}" | cut -f1))"

# Upload to S3 if AWS CLI is available
if command -v aws &> /dev/null; then
    echo "[*] Shipping encrypted backup to S3: ${S3_BUCKET}..."
    aws s3 cp "${BACKUP_FILE}" "${S3_BUCKET}/$(basename "${BACKUP_FILE}")" --sse aws:kms
    echo "[+] S3 upload complete."
fi

# Prune local backups older than 7 days
find "${BACKUP_DIR}" -name "fluxpay_db_*.dump.gpg" -type f -mtime +7 -delete
echo "[+] Local retention pruned (retained last 7 days)."
