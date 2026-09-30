# FluxPay Security Model & Threat Assessment

## 1. Security Philosophy: Fail-Closed & Cryptographic Truth
FluxPay operates as high-throughput financial infrastructure settling real capital on Base L2. The fundamental security invariant of the system is:
**Ambiguity equals immediate rejection.** If an cryptographic signature cannot be verified, an RPC endpoint fails to return consistent block data, or an anti-replay nonce was previously observed, the system halts the transaction fail-closed.

---

## 2. Threat Model & Mitigations

### 2.1. Private Key Compromise Defense (AWS KMS / HSM)
- **Threat**: Extraction of private keys via server compromise, memory dump, or log leakage.
- **Mitigation**:
  - Outbound settlement transactions are signed using AWS KMS ECC_SECG_P256K1 asymmetric keys.
  - Raw private keys never exist in application process memory.
  - Development environments enforce `LocalDevSigner` which strictly refuses to execute if `FLX_ENV=production`.
  - Cold reserves are strictly held in multi-signature smart contract wallets (Gnosis Safe) requiring 3-of-5 hardware key approvals.

### 2.2. Replay & Double-Spend Defense
- **Threat**: Malicious actors intercepting and replaying signed EIP-3009 transfer authorizations or FLXP1 HTTP requests.
- **Mitigation**:
  - Every API request enforces a strictly validated ±30s anti-replay window (`FLX_REPLAY_WINDOW_MS=30000`).
  - Cryptographic nonces are recorded in Redis and PostgreSQL (`x402_nonces`) with a TTL >= 2x the replay window.
  - EIP-3009 authorizations enforce explicit `validBefore` and `validAfter` block timestamps.

### 2.3. SQL & Data Tampering Defense
- **Threat**: SQL injection or direct database modification to inflate agent balances.
- **Mitigation**:
  - 100% of database access uses parameterized asynchronous queries via `asyncpg`. No string concatenation or raw SQL injection vectors.
  - The double-entry ledger is fortified by a continuous SHA-256 hashchain linking every entry to its immediate predecessor. Any manual database alteration breaks all subsequent block hashes.

### 2.4. Denial of Service & Rate Exhaustion
- **Threat**: Rogue autonomous AI agents overwhelming gateway capacity with rapid micro-requests.
- **Mitigation**:
  - Two-tier rate limiting: Nginx connection burst limiting at the network edge (`limit_req zone=ip_rate_limit`) and atomic Redis sliding window limiting per agent account (`FLX_RATE_LIMIT_MAX=100/min`).
  - Strict daily operation quotas enforced at the admission gate (`FLX_DAILY_QUOTA_MAX=10000`).

---

## 3. Vulnerability Disclosure Policy
Security researchers and auditors should report potential vulnerabilities to:
`security@fluxpay.io` (GPG Key ID: `0xFLUXPAY2026`). Please allow 48 hours for triage prior to public disclosure.
