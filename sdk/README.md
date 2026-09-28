# FluxPay SDKs: Python + Node/TypeScript

> **The Cross-Language Contract (Block K | Tasks 57–60)**  
> High-performance, thin, safe-by-default payment SDKs for autonomous AI agents.  
> Grounded in the frozen **FLXP1** canonical signing scheme and byte-exact Known Answer Tests (KAT).

---

## 1. The 3-Line Quickstart (Blueprint §0)

Both SDKs expose an identical, ergonomic 3-line face. Request signing (HMAC-SHA256), timestamping, cryptographic nonces, idempotency key generation, and bounded retries happen automatically inside the client.

### Python (Async)

```python
from fluxpay_sdk import FluxPayClient

client = FluxPayClient(agent_id=AGENT_ID, secret=SECRET, base_url="https://api.fluxpay.dev")
payment = await client.pay(to="merchant_handle", amount=1050)  # $10.50 USDC
print(f"Payment {payment.id} settled: {payment.status}")
```

### Node / TypeScript

```typescript
import { FluxPayClient } from "fluxpay";

const client = new FluxPayClient({ agentId: AGENT_ID, secret: SECRET, baseUrl: "https://api.fluxpay.dev" });
const payment = await client.pay({ to: "merchant_handle", amount: 1050 }); // $10.50 USDC
console.log(`Payment ${payment.id} settled: ${payment.status}`);
```

---

## 2. Retry Semantics & Error Taxonomy (Task 4 Parity)

Autonomous agents must not guess whether an error is transient or terminal. The SDK mirrors the platform's frozen error taxonomy:

| HTTP Status | Error Code | Retryable? | Platform Reason | SDK Client Behavior | Verified In Test |
|:---|:---|:---:|:---|:---|:---|
| **400** | `insufficient_funds` | **False** | Agent lacks available balance | **Fails immediately.** Raises `FluxPayApiError`. Never retried. | `test_client_never_retries_permanent_errors` |
| **401** | `authentication_failed` | **False** | Invalid secret, agent UUID, or HMAC signature | **Fails immediately.** Client cannot recover from wrong credentials. | `test_client_never_retries_permanent_errors` |
| **403** | `forbidden` | **False** | Insufficient agent permissions | **Fails immediately.** Raises `FluxPayApiError`. | `test_client_never_retries_permanent_errors` |
| **404** | `not_found` | **False** | Merchant handle or payment ID does not exist | **Fails immediately.** Fails fast, saving useless roundtrips. | `test_client_never_retries_permanent_errors` |
| **409** | `idempotency_conflict` | **False** | Key reused with different payload / parameters | **Fails immediately.** Calling agent must supply a new key. | `test_client_never_retries_permanent_errors` |
| **422** | `validation_failed` / `payment_policy_rejected` | **False** | Payload syntax error or velocity policy breach | **Fails immediately.** Schema errors require code/input fixes. | `test_client_never_retries_permanent_errors` |
| **429** | `rate_limited` | **True** | Agent exceeded sliding window request limit | **Retries with backoff.** `0.5s * 2^n + jitter` (cap 8s). Same idempotency key preserved. | `test_client_retry_ladder_mocked` |
| **502** | `bad_gateway` | **True** | Reverse proxy or ingress transit blip | **Retries with backoff.** Bounded by `max_retries` (default: 3). | `test_client_retry_ladder_mocked` |
| **503** | `conflict_retry_required` / `gate_unavailable` | **True** | Optimistic concurrency conflict or Valkey blip | **Retries with backoff.** State is transient; converges on retry. | `test_client_retry_ladder_mocked` |
| **Network** | `TransportError` / `ReadTimeout` | **True** | Socket dropped, network timeout, connection reset | **Retries with backoff.** If retries exhausted, raises `FluxPayNetworkError(retryable=True)`. | `test_client_exhausts_retries_on_network_timeout` |

---

## 3. The Same-Key Retry Law (Idempotency Guidance)

In financial protocols, retrying a write operation with a new idempotency key causes **double-spends**. Conversely, retrying with the **same** idempotency key guarantees **exactly-once execution**:

1. **Auto-Generated Keys (Default)**:
   - When `idempotency_key` is omitted in `pay()`, the SDK generates an opaque, collision-free UUID-v4 hex string.
   - If a request times out or receives a transient 429/503 error, **the SDK retries using the exact same idempotency key** across all attempts.
   - Fresh timestamps (`X-FLX-Timestamp`) and nonces (`X-FLX-Nonce`) are generated on every retry attempt so requests satisfy replay-window constraints, while the idempotency key remains pinned.
2. **Business-Meaningful Keys**:
   - For domain-specific deduplication (e.g. invoice numbers or workflow IDs), pass `idempotency_key="inv-2026-09-28-001"`.
   - Keys must match `^[A-Za-z0-9-]{16,128}$`.
3. **Idempotency Convergence**:
   - If a request succeeds on the server but the network connection drops before the client receives the 201 response, the client retries with the same key. The server detects the key in the Valkey fast-path or PostgreSQL idempotency store and returns the cached 201 response without posting duplicate ledger entries.
   - Verified end-to-end in `test_python_sdk_idempotent_retry_under_injected_network_drop`.

---

## 4. Vendoring & Offline Air-Gapped Usage

FluxPay SDKs are engineered under the **Vendoring Law**: an offline, air-gapped agent system must be able to copy the SDK files directly into its codebase with minimal external dependencies.

- **Python SDK (`fluxpay_sdk`)**:
  - `signing.py`: Zero dependencies (pure Python standard library: `hashlib`, `hmac`, `re`).
  - `client.py`: Requires `httpx` (pinned HTTP client) + standard library (`asyncio`, `json`, `dataclasses`, `uuid`).
  - **Zero Server Imports**: `fluxpay_sdk` never imports anything from the `fluxpay` backend application. Verified via AST meta-tests (`test_python_sdk_vendoring_law_meta_test`).
- **Node SDK (`fluxpay`)**:
  - **Zero Runtime Dependencies**: Relies exclusively on Node 18+ built-ins (`node:crypto` and global `fetch`).
  - Verified via package manifest meta-test (`test_node_sdk_zero_deps_meta_test`).

### Offline Copy:
```bash
# Python vendoring: copy the 3 files
cp -r sdk/python/fluxpay_sdk /path/to/your/agent/vendor/

# Node vendoring: copy the package
cp -r sdk/node/fluxpay /path/to/your/agent/vendor/
```

---

## 5. Cross-Language Equivalence & KAT Verification

The ground-truth authority for request signing is Task 19's frozen **FLXP1** specification in `src/fluxpay/gateway/canonical.py`. Both the Python SDK and Node.js port hardcode identical Known Answer Test (KAT) vectors.

### Running the Node KAT Runner:
```bash
node sdk/node/tests/run_kat.mjs
```
Expected output:
```text
PASS vector 1: POST /v1/payments/empty (signature: 4f33eb63343aa8d19ac3adb785c5ee7d30e2a14bdee3bb48d23e19e90bde12c7)
PASS vector 2: POST /v1/payments (signature: 3dc25e0205bba581b3acdadb09503d183bdda58a9f712594d1d3ad9f0cc5ad5d)
PASS vector 3: GET /v1/agents/me (signature: 1564b8f509dd03b1ac17f99a9bdf6ac98c0cf564f0d305ac814c290167833f66)
All 3 KAT vectors PASSED
```

### Running Node Unit Tests:
```bash
cd sdk/node/fluxpay
npm test
```

### Running Python E2E & Cross-Language Equivalence Suite:
```bash
uv run pytest tests/e2e/test_sdk_e2e.py
```

### Parity Status:
- **Python SDK**: Full end-to-end integration tested against live PostgreSQL + Valkey + RabbitMQ gateway stack (Phase 1).
- **Node SDK**: KAT-proven byte-for-byte signing equivalence and unit-tested retry matrix with mocked fetch (Phase 1). Real-stack e2e integration testing scheduled for Phase 2 with its first live consumer.
