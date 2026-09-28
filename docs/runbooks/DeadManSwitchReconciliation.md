# Runbook: DeadManSwitchReconciliation (SEV1)

## 1. Symptom
Prometheus alert `DeadManSwitchReconciliation` fired: `time() - flx_worker_last_success_timestamp{worker="reconciliation"} > 93600`. The 24-hour financial reconciliation job has not executed successfully within the last 26 hours. Absence of financial audit signal is a critical compliance alarm.

## 2. First Command (Triage)
```bash
sudo systemctl status fluxpay-reconciliation.timer fluxpay-reconciliation.service --no-pager
sudo journalctl -u fluxpay-reconciliation.service -n 50 --no-pager
```

## 3. Remediation & Escalation
1. Verify systemd timer scheduled state: `systemctl list-timers 'fluxpay*'`.
2. Execute manual reconciliation: `sudo -u fluxpay-worker /opt/fluxpay/current/.venv/bin/python -m fluxpay.workers.reconciliation`.
3. Check database load, deadlocks, or long-running transactions that may have caused query timeouts.
4. Cross-references: See Task 41 specification in [ledger documentation](file:///c:/Users/User/Desktop/fluxpauy/docs/ledger.md#genesis-balance).
