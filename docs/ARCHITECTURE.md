# FluxPay System Architecture Blueprint

## 1. Executive Architecture Summary
FluxPay is an institutional payment infrastructure and double-entry financial operating system engineered specifically for autonomous AI agent economies settled on Ethereum Base L2.

FluxPay combines:
- **Zero-Trust Financial Invariants**: Monotonic sequence numbers, immutable transaction hashchains, and strict double-entry debits and credits.
- **Layer 2 Native Protocols**: ERC-20 Base USDC custody, EIP-3009 gasless transfer authorizations, and x402 payment requirements.
- **Defense-in-Depth Hardware Security**: Cloud HSM and AWS KMS asymmetric transaction signing, memory hygiene, and automatic fail-closed circuit breakers.

```
                    +------------------------------------------+
                    |    Autonomous AI Agents / Clients        |
                    +------------------------------------------+
                                       |
                                       | HTTPS (EIP-712 / FLXP1 HMAC)
                                       v
                    +------------------------------------------+
                    |        Nginx Reverse Proxy & WAF         |
                    |     (TLS 1.3, Rate-Limit, CSP/HSTS)      |
                    +------------------------------------------+
                                       |
                                       v
               +-----------------------------------------------+
               |           FastAPI Gateway Engine              |
               |                                               |
               |  [GatewayMiddleware: Anti-Replay + HMAC]      |
               |  [FastPath Idempotency Tier]                  |
               |  [Atomic Valkey Quota & Rate Gate]            |
               +-----------------------------------------------+
                  /               |                 \
                 /                |                  \
                v                 v                   v
      +------------------+  +------------------+  +------------------+
      |  x402 Protocol   |  | Double-Entry     |  | Administrative   |
      |  & EIP-3009      |  | Ledger Engine    |  | Operations & KYC |
      +------------------+  +------------------+  +------------------+
                |                 |                   |
                v                 v                   v
      +--------------------------------------------------------------+
      |              PostgreSQL 16 (Synchronous Commit)              |
      |       (Accounts, Hashchain Entries, Nonces, Invariants)      |
      +--------------------------------------------------------------+
                |
                +-------------------------+
                |                         |
                v                         v
      +-------------------+     +--------------------+
      | Base L2 Indexer   |     | Outbound Settlement|
      | (Deposit Monitor) |     | (BaseL2Writer/KMS) |
      +-------------------+     +--------------------+
                \                         /
                 \                       /
                  v                     v
            +----------------------------------+
            |      Base L2 Blockchain Node     |
            |     (EVM Native USDC Contract)   |
            +----------------------------------+
```

---

## 2. Core Invariants & Architectural Laws

### Law 1: Absolute Precision (No Float Invariant)
Every financial amount within the platform is represented either as an integer count of minor units ($1.00 USDC = `1000000` minor units) or an exact `Decimal` value. Floating-point types (`float`) are strictly forbidden across models, database schemas, and calculation engines.

### Law 2: Cryptographic Hashchain Integrity
Every ledger entry computes an immutable SHA-256 fingerprint:
```
entry_hash = SHA256(seq || tx_id || account_id || direction || amount || currency || balance_after || prev_hash || created_at)
```
Any modification of past rows breaks the chain downstream. The hourly and nightly audit workers verify hashchain continuity across the entire database.

### Law 3: Fail-Closed Security Operations
If Cloud KMS, Redis rate limiting, or PostgreSQL becomes unreachable or returns an error, all mutation operations fail closed immediately. Transactions are rejected with descriptive RFC-compliant errors; funds are never placed at risk during ambiguous infrastructure state.

### Law 4: Idempotency Three-Tier Dance
1. **Tier 1 (Redis Fast-Path)**: In-flight requests lock the idempotency key with a 24-hour TTL. Duplicate requests within this window receive cached responses with zero DB overhead.
2. **Tier 2 (Postgres Idempotency Journal)**: Settled transaction outputs are persisted in `idempotency_keys` table with SHA-256 body hash validation.
3. **Tier 3 (Fresh Execution)**: Transaction is executed inside an atomic PostgreSQL serializable transaction.

---

## 3. Subsystem Breakdown

1. **`src/fluxpay/gateway/`**: Ingress authentication, anti-replay sliding windows, rate-limiting, and x402 payment challenge generation.
2. **`src/fluxpay/ledger/`**: Double-entry ledger store, OCC retry loop, balance calculation, and hashchain auditing.
3. **`src/fluxpay/integrations/`**: Base L2 on-chain reader, deposit indexer, HD wallet derivation, and EIP-1559 gas writer.
4. **`src/fluxpay/shared/kms.py`**: AWS KMS and Cloud HSM asymmetric Secp256k1 transaction signing.
5. **`src/fluxpay/workers/`**: Hourly reconciliation worker, webhook delivery worker, and automated audit sweepers.
