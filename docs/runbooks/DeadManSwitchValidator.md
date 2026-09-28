# Runbook: DeadManSwitchValidator (SEV1)

## 1. Symptom
Prometheus alert `DeadManSwitchValidator` is firing: `time() - flx_worker_last_success_timestamp{worker="hash_validator"} > 7200`. The hourly cryptographic hash-chain validator has been silent for over 2 hours. Absence of signal indicates hanging process, crashed timer, or silent failure.

## 2. First Command (Triage)
```bash
sudo systemctl status fluxpay-hash-validator.timer fluxpay-hash-validator.service --no-pager
sudo journalctl -u fluxpay-hash-validator.service -n 100 --no-pager
```

## 3. Remediation & Escalation
1. Check timer status and last run timestamp: `systemctl list-timers 'fluxpay*'`.
2. Execute manual dry-run: `sudo -u fluxpay-worker /opt/fluxpay/current/.venv/bin/python -m fluxpay.workers.hash_validator`.
3. If exit code is 1, immediately switch to [ChainBroken](file:///c:/Users/User/Desktop/fluxpauy/docs/runbooks/ChainBroken.md).
4. If exit code is 2, check PostgreSQL connection pool and credentials.
5. Cross-references: See Task 40 contract in [ledger documentation](file:///c:/Users/User/Desktop/fluxpauy/docs/ledger.md#verification).
