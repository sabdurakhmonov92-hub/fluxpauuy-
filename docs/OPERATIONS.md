# FluxPay Day-2 Operations Manual

This guide defines standard operating procedures (SOP), maintenance cadences, and operational incident workflows for the FluxPay autonomous AI agent payment operating system.

---

## 1. Operational Rhythms & Maintenance Cadence

### Hourly Automated Tasks
- **Blockchain Reconciliation**: Executed by `fluxpay-worker` via `fluxpay.workers.blockchain_reconciliation`. Compares Base L2 confirmed ERC-20 deposits against double-entry ledger balances. Emits `FLX_LEDGER_IMBALANCE`.
- **Deposit Ingestion Watermark Check**: Ensures `indexer_cursor` advances within 5 blocks of the latest Base L2 tip.

### Daily Automated Tasks
- **Database Encrypted Backup**: Executed at 02:00 UTC via `scripts/backup_db.sh`. Encrypted with GPG and uploaded to S3.
- **Cryptographic Hashchain Audit**: Exhaustive scan across 100% of all ledger entries to verify sequential SHA-256 links.
- **Ledger Invariant Verification**: Verifies `sum(debits) == sum(credits)` for every settled transaction in PostgreSQL.

### Weekly & Monthly Tasks
- **Log Archival & Rotation**: Rotates journald logs and archives structured JSON logs to cold storage.
- **PostgreSQL Autovacuum & Index Reindex**: Evaluates bloat on high-frequency tables (`idempotency_keys`, `ledger_entries`).
- **Quarterly Disaster Recovery Drill**: Simulates catastrophic regional failure by restoring an encrypted database snapshot to an isolated staging VPC (`docs/runbooks/backup-restore.md`).

---

## 2. Emergency Operations & Circuit Breakers

FluxPay provides three operational circuit breakers exposed via the administrative API (`src/fluxpay/admin/emergency_router.py`):

### 1. Freeze Suspicious Autonomous Agent
Instantly invalidates agent credentials, revokes API keys, and rejects all subsequent payment ingress:
```bash
curl -X POST http://localhost:8000/admin/freeze-agent \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -H "Content-Type: application/json" \
     -d '{
       "agent_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
       "reason": "Exceeded abnormal velocity threshold ($50,000/hour)"
     }'
```

### 2. Halt Outbound Withdrawals
Freezes all on-chain payouts and cold treasury sweeps while keeping payment processing active:
```bash
curl -X POST http://localhost:8000/admin/halt-withdrawals \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -H "Content-Type: application/json" \
     -d '{
       "enabled": true,
       "reason": "Base L2 sequencer experiencing elevated reorg depth"
     }'
```

### 3. Global Emergency Stop (Platform Killswitch)
Engages fail-closed admission rejection across all public HTTP and WebSocket endpoints:
```bash
curl -X POST http://localhost:8000/admin/emergency-stop \
     -H "Authorization: Bearer $ADMIN_JWT" \
     -H "Content-Type: application/json" \
     -d '{
       "enabled": true,
       "reason": "Immediate security mitigation during active audit"
     }'
```

---

## 3. SLA Targets & Operational Metrics

| Metric | Target SLA | Alert Threshold | Escalation Path |
| :--- | :--- | :--- | :--- |
| **API Availability** | **99.9%** | Availability < 99.5% over 5m | SEV1 (Immediate Page) |
| **p99 Gateway Latency** | **< 500ms** | p99 > 2000ms over 5m | SEV2 |
| **Ledger Imbalance** | **0 USDC** | `flx_ledger_imbalance != 0` | SEV1 (Immediate Page) |
| **Indexer Block Lag** | **< 10 blocks** | Lag > 100 blocks | SEV1 (Immediate Page) |
| **Hot Wallet Gas** | **> 0.05 ETH** | Balance < 0.005 ETH | SEV1 |
