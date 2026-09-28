# FluxPay Gateway Security Pipeline: Architecture, Protocol & Operational Reference

This document defines the architectural invariants, wire protocol specification, and error-handling
contracts governing the FluxPay Agent Gateway (`Block D`).

---

## 1. Frozen Security Pipeline Architecture

All requests destined for signed routes (`/v1/*`) traverse the mandatory 10-stage security pipeline
implemented in [`GatewayMiddleware`](file:///c:/Users/User/Desktop/fluxpauy/src/fluxpay/gateway/middleware.py).
Unauthenticated traffic is structurally barred by construction from reaching business handlers.

```
Incoming Request
       │
       ▼
 [Stage 0: Context] ──────────► Generate X-FLX-Request-Id; bind structlog context
       │
       ▼
 [Stage 1: Scope] ────────────► Path starts with /v1/? If NO, pass-through directly
       │
       ▼
 [Stage 2: Query Rejection] ──► URL contains '?' query string? If YES, reject 401
       │
       ▼
 [Stage 3: Auth Parse] ───────► Parse 'FLXP1 <agent_id>:<sig>'; resolve via AgentRepo
       │
       ▼
 [Stage 4: Freshness] ────────► |now_ms - X-FLX-Timestamp| <= 30,000 ms? If NO, reject 401
       │
       ▼
 [Stage 5: HMAC Verification] ► Constant-time HMAC-SHA256(secret, canonical_bytes) == sig?
       │
       ▼
 [Stage 6: Body Size Cap] ────► len(raw_body) <= 65,536 bytes (64 KiB)? If NO, reject 422
       │
       ▼
 [Stage 7: Nonce + Gate] ─────► Atomic Lua: anti-replay tombstone, rate limit, daily quota
       │
       ▼
 [Stage 8: Idempotency Fast] ─► Mutating verb (POST)?
       │                        ├─ NO (GET): proceed to Stage 9
       │                        └─ YES: Fast-path single RTT (SET NX lock + GET lock + GET resp)
       │                             ├─ REPLAY_CACHED ──► Return 201 + X-FLX-Idempotent-Replay: true
       │                             ├─ IN_PROGRESS   ──► Raise 409 idempotency_conflict
       │                             ├─ CONFLICT      ──► Raise 409 idempotency_conflict
       │                             └─ PROCEED       ──► Execute Stage 9 with lock held
       ▼
 [Stage 9: Handover & Finish] ─► Bind request.state.agent; invoke downstream handler
       │                        └─ Fast-path finish: 2xx caches resp; non-2xx/exception releases lock
       ▼
  HTTP Response (+ X-FLX-Request-Id header; clear context in finally)
```

---

## 2. Agent Error-Retry Contract (Task 4 Taxonomy)

In autonomous agent systems, HTTP status codes and machine-readable error codes govern autonomous loop
decision-making. The `retryable` boolean determines whether a client agent should back off and retry,
or halt and alert human operators.

| Status | Error Code (`code`) | `retryable` | Client Agent Action | Verifying Test(s) |
| :---: | :--- | :---: | :--- | :--- |
| **401** | `authentication_failed` | **`false`** | **HALT & ALERT.** Bad signature, corrupt key, deactivated agent, or forbidden query string. Do not retry without credential remediation. | `test_error_envelope_matrix_and_retryable_taxonomy`<br>`test_adversarial_tamper_table`<br>`test_adversarial_unknown_agent_uuid`<br>`test_adversarial_inactive_agent`<br>`test_lifecycle_suspend_immediate_del_invalidation` |
| **401** | `replay_detected` | **`false`** | **RESET NONCE & CLOCK.** Reused nonce or clock drift (> ±30s). Synchronize system clock with NTP and generate a new UUID nonce. | `test_error_envelope_matrix_and_retryable_taxonomy`<br>`test_adversarial_tamper_table` |
| **409** | `idempotency_conflict` | **`false`** | **BRANCH.** If twin in-flight, await original flight. If payload mismatch with same key, generate a NEW idempotency key. Never retry conflicting payload with existing key. | `test_error_envelope_matrix_and_retryable_taxonomy`<br>`test_duplicate_post_different_body_conflict`<br>`test_twin_lock_held_then_del_retry` |
| **422** | `validation_failed` | **`false`** | **FIX REQUEST.** Request body failed schema validation, payload exceeded 64 KiB, or `X-FLX-Idempotency-Key` was missing/malformed. | `test_error_envelope_matrix_and_retryable_taxonomy`<br>`test_adversarial_tamper_table` |
| **429** | `rate_limited` | **`true`** | **EXPONENTIAL BACKOFF.** Sliding-window rate limit or daily quota cap reached. Back off with jitter and retry. | `test_error_envelope_matrix_and_retryable_taxonomy`<br>`test_limits_per_agent_rate_limit_from_db`<br>`test_limits_daily_quota_from_db`<br>`test_concurrency_atomicity_twenty_requests_ten_rate_limit` |
| **500** | `internal_error` | **`false`** | **REPORT INCIDENT.** Unhandled server failure. Details and diagnostics are masked from wire responses (zero stack or connection string leak). | `test_resilience_resolver_broken_pool_fail_total_no_leak` |
| **503** | `gate_unavailable` | **`true`** | **RETRY WITH BACKOFF.** Valkey/Redis rate-limiting gate is unreachable. Gateway fails closed for safety. Retry after short interval. | `test_error_envelope_matrix_and_retryable_taxonomy`<br>`test_resilience_dead_valkey_runner_fail_closed` |

---

## 3. Request Signing Quickstart (FLXP1 Protocol)

FluxPay uses the **FLXP1** canonical HMAC-SHA256 signature scheme.

### Required HTTP Headers
- `Authorization`: `FLXP1 <agent_id>:<hmac_sha256_hex_signature>`
- `X-FLX-Timestamp`: Current UTC epoch milliseconds (13-digit ASCII decimal, e.g. `1774472400000`)
- `X-FLX-Nonce`: Unique cryptographic client nonce (16–64 alphanumeric characters)
- `X-FLX-Idempotency-Key`: Required on POST writes (16–128 alphanumeric characters plus hyphen)

### Canonical Byte Construction
```
canonical = (
    "FLXP1"            || 0x0A ||
    METHOD_UPPER       || 0x0A ||
    PATH               || 0x0A ||
    TIMESTAMP_MS_DEC   || 0x0A ||
    NONCE              || 0x0A ||
    SHA256_HEX(body)
)
signature = lowercase_hex( HMAC-SHA256( agent_secret_bytes, canonical ) )
```

### Quickstart `curl` Example (Simulated Values)
```bash
# Agent ID: 018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e
# Secret: test-secret-key-32-bytes-long!!
# Timestamp: 1774472400000
# Nonce: fedcba9876543210
# Idempotency-Key: idem-7b2c-9d3e-4f5a-6b7c8d9e0123

curl -X POST https://api.fluxpay.internal/v1/payments \
  -H "Authorization: FLXP1 018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e:3dc25e0205bba581b3acdadb09503d183bdda58a9f712594d1d3ad9f0cc5ad5d" \
  -H "X-FLX-Timestamp: 1774472400000" \
  -H "X-FLX-Nonce: fedcba9876543210" \
  -H "X-FLX-Idempotency-Key: idem-7b2c-9d3e-4f5a-6b7c8d9e0123" \
  -H "Content-Type: application/json" \
  -d '{"amount":10000,"currency":"USDC","recipient_id":"018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e"}'
```

### Known Answer Test (KAT) Vectors
SDK implementers in Python, TypeScript, and Go must validate their canonicalization and signing
logic against the frozen test vectors:
- Source of Truth: [`FROZEN_VECTORS`](file:///c:/Users/User/Desktop/fluxpauy/src/fluxpay/gateway/canonical.py#L207-L270) in `src/fluxpay/gateway/canonical.py`.

---

## 4. Test Harness Usage Note for Downstream Tasks (Tasks 31 & 33)

> [!IMPORTANT]
> **Harness Rule**: `build_gateway_app` and `signed_request` in `tests/integration/conftest.py`
> are designed as the foundational test harness for Block E (Task 31 Payment Handler and Task 33 Full E2E).
> **Extend, do not fork.**

### Reusable Fixtures Contract
1. **`build_gateway_app(**overrides) -> (app, calls: list)`**:
   - Spins up a full Starlette ASGI app pre-configured with `GatewayMiddleware`, `AgentRepo` (backed by PostgreSQL
     and live Valkey), `GateRunner`, and `IdempotencyFastPath`.
   - Pass route overrides or custom handlers as Task 31 implements the real ledger-backed payments endpoint.
   - The returned `calls` list serves as the handler execution counter to prove deduplication invariants.
2. **`signed_request(client, creds, method, path, *, body=b"", nonce=None, ts_ms=None, idem=None, overrides=None)`**:
   - The canonical caller for all HTTP tests. Handles automatic FLXP1 signing, nonce generation, timestamping,
     and auto-generated 32-character idempotency keys for POST requests.
3. **`make_agent(**overrides) -> AgentCredentials`**:
   - Reused from Task 23. Provisions authenticated agents directly into PostgreSQL with automatic test cleanup.
