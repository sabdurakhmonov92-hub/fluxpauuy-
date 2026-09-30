# Runbook: Base L2 Indexer Recovery (`indexer-recovery.md`)

## 1. Overview & Triggers
- **Trigger**: Alert `IndexerLagCritical` (`flx_indexer_lag_blocks > 100`).
- **Symptom**: Autonomous agents report deposits to Base L2 not credited to ledger balance.

## 2. Diagnosis Steps
1. Check indexer worker status and logs:
   ```bash
   sudo systemctl status fluxpay-indexer.service
   journalctl -u fluxpay-indexer.service -n 50 --no-pager
   ```
2. Verify Base L2 RPC node health:
   ```bash
   curl -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        $FLX_BASE_RPC_URL
   ```
3. Query database indexer cursor vs node latest block:
   ```bash
   psql $FLX_PG_DSN -c "SELECT chain_id, last_processed_block, updated_at FROM indexer_cursor;"
   ```

## 3. Recovery Actions
1. **Case A: Worker Stalled / Deadlocked**:
   - Restart the indexer service:
     ```bash
     sudo systemctl restart fluxpay-indexer.service
     ```
2. **Case B: RPC Node Rate-Limited or Failing**:
   - Update `FLX_BASE_RPC_URL` in `.env.production` to secondary provider (e.g. Infura or QuickNode backup).
   - Reload configuration:
     ```bash
     sudo systemctl restart fluxpay-indexer.service
     ```
3. **Case C: Blockchain Reorg Detected**:
   - Check `indexer_reorgs` audit table:
     ```bash
     psql $FLX_PG_DSN -c "SELECT * FROM indexer_reorgs ORDER BY detected_at DESC LIMIT 5;"
     ```
   - The indexer automatically rolls back provisional events. Monitor logs for `reorg_recovered` event.
