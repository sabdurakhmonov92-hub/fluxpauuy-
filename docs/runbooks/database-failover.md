# Runbook: PostgreSQL Database Failover (`database-failover.md`)

## 1. Overview
- **Trigger**: Primary PostgreSQL database instance unreachable or disk/hardware failure.
- **RTO**: < 30 seconds.
- **RPO**: 0 (synchronous replication standby).

## 2. Automated / Managed Failover (Patroni / AWS RDS Multi-AZ)
1. Verify replica promotion:
   ```bash
   patronictl -c /etc/patroni/fluxpay.yml topology
   ```
2. If automatic failover did not execute, trigger manual switchover:
   ```bash
   patronictl -c /etc/patroni/fluxpay.yml switchover
   ```

## 3. Application Reconnection Verification
1. PgBouncer automatically routes queries to the newly promoted primary.
2. Check API readiness:
   ```bash
   curl -f http://localhost:8000/ready
   ```
3. Verify timezone and synchronous_commit invariants on the new primary:
   ```bash
   psql $FLX_PG_DSN -c "SHOW timezone; SHOW synchronous_commit;"
   ```
   Both MUST return `UTC` and `on`.
