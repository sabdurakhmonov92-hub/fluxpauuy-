# Runbook: ChainBroken (SEV1)

## 1. Symptom
Prometheus alert `ChainBroken` fired immediately: `flx_validator_ok{worker="hash_validator"} == 0`. The cryptographic SHA-256 chain integrity of the double-entry journal has broken. Sequence mismatch or entry hash divergence detected.

## 2. First Command (Triage)
```bash
sudo -u fluxpay-worker /opt/fluxpay/current/.venv/bin/python -m fluxpay.ledger.verify --json
```

## 3. Remediation & Escalation
1. DO NOT restart or run automated fixes. Auto-repair is strictly prohibited by platform law.
2. Identify broken sequence range and recomputed hash from the verifier JSON output.
3. Review audit log for unauthorized `UPDATE`/`DELETE` attempts on `ledger_entries`.
4. Follow the sanctioned emergency data-fix procedure in [ledger documentation](file:///c:/Users/User/Desktop/fluxpauy/docs/ledger.md#correction-runbook).
5. Cross-references: See Task 14/16/18 ledger immutability and recovery contracts in [ledger](file:///c:/Users/User/Desktop/fluxpauy/docs/ledger.md).
