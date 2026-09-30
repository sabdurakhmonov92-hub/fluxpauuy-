# Runbook: Database Backup & Restore Procedures (`backup-restore.md`)

## 1. Automated Backup Cadence
- **Full Base Backup**: Executed every 24 hours at 02:00 UTC via `scripts/backup_db.sh`.
- **WAL Archiving**: Continuous streaming to encrypted S3 bucket (`s3://fluxpay-prod-backups/wal/`).
- **Retention**: 30 days point-in-time recovery; 365 days weekly archive.

## 2. On-Demand Backup Execution
To create a manual encrypted snapshot prior to maintenance:
```bash
bash scripts/backup_db.sh
```

## 3. Restore Verification Procedure (Quarterly Drill)
1. Restore to an isolated staging database:
   ```bash
   PGDATABASE=fluxpay_restore_test bash scripts/restore_db.sh /var/backups/fluxpay/fluxpay_db_latest.dump.gpg
   ```
2. Verify table row counts and schema integrity:
   ```bash
   psql -d fluxpay_restore_test -c "SELECT count(*) FROM ledger_entries; SELECT count(*) FROM accounts;"
   ```
3. Run cryptographic hash-chain validator across the restored ledger:
   ```bash
   python -m fluxpay.workers.hash_validator
   ```
