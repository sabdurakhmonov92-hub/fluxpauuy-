# FluxPay Ledger Core: Block C Technical & Forensic Audit Document

This document defines the mathematical, architectural, and operational invariants governing
the FluxPay immutable double-entry ledger (Block C).

---

## §invariants — The 6 Core Ledger Invariants

Every financial invariant is enforced across multiple defensive rings and verified by automated tests.
Auditors and regulators navigate directly via this proof map:

| Invariant | Description & Defense-in-Depth | Verifying Test |
| :--- | :--- | :--- |
| **1. Double-Entry Balance** | Every transaction is zero-sum per currency: `sum(DEBIT) == sum(CREDIT)`. Pre-lock check in app layer; deferred constraint trigger `trg_ledger_entries_balanced` at transaction COMMIT. | `tests/integration/test_ledger_store.py::test_happy_double_entry_post_transaction`<br>`tests/integration/test_ledger_invariants_db.py::test_unbalanced_transaction_rejected_by_trigger` |
| **2. Solvency Invariant** | Account balances cannot drop below zero (`balance >= 0`). Fast application pre-check followed by database `CHECK (balance >= 0)` constraint. | `tests/integration/test_ledger_store.py::test_insufficient_funds_leaves_no_trace`<br>`tests/integration/test_ledger_invariants_db.py::test_overdraft_prevention_at_database_level` |
| **3. Monotonic Gapless Sequences** | Global sequence numbers are strictly consecutive (`seq = prev_seq + 1`). Allocated under singleton row lock `SELECT ... FOR UPDATE` on `ledger_chain_tip`. | `tests/integration/test_ledger_store.py::test_concurrent_serialization_load`<br>`tests/integration/test_ledger_throughput.py::test_sustained_write_ledger_throughput` |
| **4. Cryptographic Hash Chain** | Every entry hashes its canonical fields together with `prev_hash` via SHA-256 (`compute_entry_hash`). Linkage is verified via constant-time `verify_link`. | `tests/integration/test_ledger_store.py::test_chain_linkage_across_transactions`<br>`tests/integration/test_verify_cli.py::test_verify_cli_broken_chain_and_self_cleaning` |
| **5. Genesis Anchor Root** | Sequence 1 iff `prev_hash == 'GENESIS'`. Proves ledger roots back to the initial platform mint state without circular or dangling history. | `tests/unit/test_ledger_store_contract.py::test_genesis_invariant`<br>`tests/integration/test_ledger_store.py::test_verify_chain_tamper_detection_self_cleaning` |
| **6. Table Immutability** | `ledger_entries` partitions are strictly INSERT-only. UPDATE, DELETE, and TRUNCATE operations are forbidden by engine-level trigger `trg_ledger_entries_immutable`. | `tests/integration/test_ledger_invariants_db.py::test_entries_immutable_trigger_blocks_update_and_delete` |

---

## §architecture — Storage & Concurrency Model

- **Global Chain Serialization**: The mutable singleton row in `ledger_chain_tip` (`SELECT ... FOR UPDATE`) serializes all ledger writes globally, eliminating sequence gaps upon transaction aborts.
- **Optimistic Concurrency Control (OCC)**: High-contention account balances update conditionally (`WHERE id = $1 AND version = $2`), retrying with exponential jittered backoff on conflict.
- **SHA-256 Hash Chaining**: Canonical ASCII byte serialization (ASCII unit separator `0x1F`, lowercase hex, UTC ISO timestamps) guarantees forensic auditability.
- **Partitioned Ledger**: `ledger_entries` is partitioned by month (`RANGE (created_at)`), ensuring high write throughput and performant index compaction.
- *Source of Truth*: Code and typing contracts in [`src/fluxpay/ledger/store.py`](file:///c:/Users/User/Desktop/fluxpauy/src/fluxpay/ledger/store.py) and [`src/fluxpay/ledger/postgres.py`](file:///c:/Users/User/Desktop/fluxpauy/src/fluxpay/ledger/postgres.py).

---

## §genesis-balance — System Account Exception & Reconciliation

- **The Bootstrap Rule**: The `system` owner account (`owner_type='system'`) is the single out-of-ledger balance in the platform. It is initialized directly at account creation (`INSERT INTO ledger_accounts (..., balance, ...)`) bypassing entry creation.
- **The Mint**: All agent and merchant accounts begin at zero balance and receive initial funds exclusively through balanced transfers debited from the system account.
- **Reconciliation Invariant**: At any point in time, the sum of all circulating balances plus the remaining system balance must equal the initial genesis mint:
  $$\sum \text{balance}_{\text{agent}} + \sum \text{balance}_{\text{merchant}} + \text{balance}_{\text{system}} = \text{Initial Mint}$$

---

## §correction-runbook — Sanctioned Emergency Data-Fix Procedure

Direct SQL mutation on `ledger_entries` is blocked by database triggers and will break hash chain verification.
If catastrophic data corruption requires manual remediation, the ONLY sanctioned procedure is:

1. **Acquire Owner/Superuser Connection**: Access PostgreSQL with superuser privileges (regular application roles lack trigger control permissions).
2. **Disable Immutability Trigger**:
   ```sql
   ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;
   ```
3. **Execute Targeted Remediation**: Perform the exact required SQL UPDATE or INSERT.
4. **Re-Enable Immutability Trigger**:
   ```sql
   ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;
   ```
5. **Run Ledger Verifier CLI**:
   ```bash
   python -m fluxpay.ledger.verify
   ```
   *The command MUST exit with code 0. If it exits with 1, hash links downstream of the correction must be recalculated.*
6. **Log Audit Record**: Document the incident, affected sequences, reason, and operator ID in the platform security incident log.
- *Proof*: Any unsanctioned or incomplete data tampering is caught by `verify_chain` as proven in [`tests/integration/test_ledger_store.py::test_verify_chain_tamper_detection_self_cleaning`](file:///c:/Users/User/Desktop/fluxpauy/tests/integration/test_ledger_store.py) and [`tests/integration/test_verify_cli.py::test_verify_cli_broken_chain_and_self_cleaning`](file:///c:/Users/User/Desktop/fluxpauy/tests/integration/test_verify_cli.py).

---

## §verification — Continuous Chain Validator Contract

The verification engine runs via CLI or in-process background worker:
```bash
python -m fluxpay.ledger.verify [--from-seq N] [--to-seq N] [--json]
```

### Exit Codes (Ops Contract)
- `0` = OK: Chain cryptographically verified.
- `1` = Chain Broken: Data integrity alarm (SEV1). Immediate pager alert to on-call duty.
- `2` = Operational Failure: Unreachable DB, invalid CLI arguments, or missing configuration.

### JSON Alert Payload (--json)
Single-line JSON output for log aggregators (Loki) and alerting webhooks (Telegram / PagerDuty):
```json
{"ok":false,"last_verified_seq":1042,"broken_seq":1043,"reason":"Cryptographic hash recomputation mismatch at seq=1043","checked_at":"2026-09-24T16:00:00Z","from_seq":1,"to_seq":null,"elapsed_ms":42}
```

### Downstream Handoffs
- **Task 40 Handoff (Scheduler)**: Systemd hourly timer invokes verification. Can wrap `python -m fluxpay.ledger.verify --json` or invoke `PostgresLedgerStore.verify_chain` in-process. In-process invocation is recommended for richest error telemetry; CLI serves on-call ops and manual runbook execution.
- **Task 70 Handoff (Alerting)**: When the verifier returns exit code 1, the alert payload maps directly to the SEV1 Telegram/PagerDuty alert channel.

# --- Task 40 append ---
### Hourly Integrity Audit Worker & Dead-Man Switch Contract
The continuous hourly audit is executed in-process by `python -m fluxpay.workers.hash_validator`, orchestrated via systemd timer (`deploy/systemd/fluxpay-hash-validator.timer` triggering `fluxpay-hash-validator.service`).

- **One-Shot vs. Daemon**: The validator runs as a clean, single-pass one-shot process rather than a persistent poll-loop worker (`base.Worker`). A continuous daemon would hold process memory and database pool connections idle for 3599 seconds of every hour; systemd timer scheduling guarantees deterministic cadence and automatic recovery (`Persistent=true` ensures audits missed during host reboot trigger immediately).
- **The Speaking Contract & Dead-Man Switch**: A silent validator is indistinguishable from a dead one. Every run emits exactly ONE single-line JSON report to stdout (`mode="hash_validator"`, `scope="full"`). Task 69 configures a dead-man switch alert (firing if no report matching `mode="hash_validator"` is ingested within 2 hours). Silence itself is an alarm.
- **Asymmetric Operational Failure**: On infrastructure or configuration failures (unreachable database, invalid settings), the worker exits with code 2, prints diagnostics to stderr, and emits NOTHING on stdout. Silence trips the dead-man switch while the exit code alerts operations.
- **Zero Auto-Repair**: Cryptographic tampering or sequence gaps trigger exit code 1, write the incident report to stdout, and emit the runbook pointer (`docs/ledger.md §correction-runbook`) to stderr. Remediation is strictly manual and human-gated.

---

## §coverage-gate — Locked Quality Threshold (>= 95%)

Test coverage for `src/fluxpay/ledger` is enforced as an unbending CI gate:
```bash
uv run python scripts/check_coverage.py src/fluxpay/ledger 95
```

- **Rationale (95% not 100%)**: `verify_chain` and concurrency machinery contain defensive branches (such as database connection timeout paths and unreachable cursor cleanups) that cannot be simulated without fragile socket-killing mocks. Two dead cleanup paths are explicitly marked `# pragma: no cover`. 95% threshold with per-file missing lines (`show_missing = true`) maintains rigorous code health without ceremonial tests.
- **Governance**: Raising the gate above 95% requires senior engineering review. Lowering the threshold below 95% is strictly forbidden.
