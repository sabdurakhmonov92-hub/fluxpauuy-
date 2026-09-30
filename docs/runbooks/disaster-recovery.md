# Runbook: Full Platform Disaster Recovery (`disaster-recovery.md`)

## 1. Targets & SLA
- **RTO (Recovery Time Objective)**: < 15 minutes.
- **RPO (Recovery Point Objective)**: < 5 minutes (via continuous WAL archiving).

## 2. Disaster Recovery Activation Checklist
1. Declare SEV1 Disaster Recovery on incident channel.
2. Provision target cluster in disaster recovery region (e.g. `us-east-1` -> `us-west-2`).
3. Restore latest base database backup from off-site S3:
   ```bash
   bash scripts/restore_db.sh s3://fluxpay-prod-backups/postgres/latest.dump.gpg
   ```
4. Replay continuous WAL archives to point-in-time of disaster.
5. Deploy application infrastructure using production container image or systemd:
   ```bash
   bash scripts/deploy.sh production latest
   ```
6. Run cryptographic hash-chain and blockchain balance verification:
   ```bash
   python -m fluxpay.workers.blockchain_reconciliation
   ```
7. Repoint DNS records (Route 53 / Cloudflare) to the new secondary region ingress IP.
