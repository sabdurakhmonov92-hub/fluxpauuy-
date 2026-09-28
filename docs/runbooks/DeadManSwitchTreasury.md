# Runbook: DeadManSwitchTreasury (SEV1)

## 1. Symptom
Prometheus alert `DeadManSwitchTreasury` fired: `time() - flx_worker_last_success_timestamp{worker="treasury_monitor"} > 3600`. The 15-minute treasury hot-wallet balance monitor has failed to report in over 1 hour. Custody tracking and solvency alerting are unobserved.

## 2. First Command (Triage)
```bash
sudo systemctl status fluxpay-treasury-monitor.timer fluxpay-treasury-monitor.service --no-pager
sudo journalctl -u fluxpay-treasury-monitor.service -n 50 --no-pager
```

## 3. Remediation & Escalation
1. Test on-chain RPC node connectivity: `curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' $RPC_URL`.
2. Execute manual check: `sudo -u fluxpay-worker /opt/fluxpay/current/.venv/bin/python -m fluxpay.treasury.cli monitor --once`.
3. If hot-wallet balance is critically depleted or RPC node is stalled, escalate to Treasury On-Call.
4. Cross-references: See Task 44 hot wallet monitor and Task 45 sweep contracts.
