# Runbook: ReconciliationMismatch (SEV1)

## 1. Symptom
Prometheus alert `ReconciliationMismatch` fired: `flx_validator_ok{worker="reconciliation"} == 0`. Daily financial reconciliation detected imbalance in ledger debits vs credits, account balance vs journal entry sum, or Valkey outflow counter drift.

## 2. First Command (Triage)
```bash
sudo journalctl -u fluxpay-reconciliation.service -n 100 --no-pager
sudo -u fluxpay-worker /opt/fluxpay/current/.venv/bin/python -m fluxpay.workers.reconciliation
```

## 3. Remediation & Escalation
1. Inspect the JSON report emitted to stdout to isolate the exact mismatch category.
2. If `global_balanced == false`, halt gateway immediately — global double-entry zero-sum invariant breached.
3. If balance mismatch on single account, inspect pending holds or uncommitted UoW state.
4. Cross-references: See Task 41 reconciliation rules and genesis balance invariant in [ledger documentation](file:///c:/Users/User/Desktop/fluxpauy/docs/ledger.md#genesis-balance).
