# Runbook: Incident Classification & Response Playbook (`incident-response.md`)

## 1. Severity Classifications

| Severity | Definition | Target Response SLA | Target Resolution | Examples |
| :--- | :--- | :--- | :--- | :--- |
| **SEV1** | Platform outage or financial integrity compromise | **< 5 minutes** | < 1 hour | Ledger imbalance != 0, Hashchain broken, KMS unreachable, Database down |
| **SEV2** | Degraded performance or non-critical feature broken | **< 15 minutes** | < 4 hours | High p99 latency (> 2s), Indexer lag > 50 blocks, Webhook delays |
| **SEV3** | Minor operational defect with workaround | **< 1 hour** | < 24 hours | Flaky external provider, Dashboard visual glitch, Non-blocking alert |

## 2. Emergency Incident Response Protocol
1. **Declare Incident**:
   - Post to `#incident-room` on Slack/Discord: `[INCIDENT DECLARED] SEV-X: <Brief Title>`
   - Page primary on-call engineer via PagerDuty.
2. **Mitigate First, Investigate Later**:
   - If security breach suspected: trigger emergency stop:
     ```bash
     curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8000/admin/emergency-stop \
          -d '{"scope": "all", "reason": "Suspected breach under investigation"}'
     ```
   - If bad release deployed: run `bash scripts/rollback.sh production`.
   - If on-chain balance mismatch detected: halt withdrawals:
     ```bash
     curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8000/admin/halt-withdrawals \
          -d '{"reason": "Investigating ledger imbalance"}'
     ```
3. **Communication**:
   - Update external status page every 15 minutes for SEV1 incidents.
4. **Post-Mortem**:
   - Within 48 hours, conduct blameless post-mortem documenting timeline, root cause, and remediation tasks.
