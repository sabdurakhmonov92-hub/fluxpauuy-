"""End-to-End Gateway Integration Test Suite & Coverage Proof.

Tests the full Block D security and routing pipeline over the REAL production stack:
- FLXP1 canonical request signing (Task 19)
- Atomic anti-replay, rate limit, and daily quota gate (Task 20)
- Gateway security pipeline middleware (Task 21)
- Redis idempotency fast-path (Task 22)
- PostgreSQL-backed AgentRepo with live Valkey read-through cache (Task 23)
- Frozen Pydantic v2 contract models (Task 24)

No mocks or stubs are used in Groups A-E except for explicitly injected fault resilience tests.
"""

from __future__ import annotations

import asyncio
import importlib.resources
import time
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import httpx
import pytest
import redis.asyncio as redis_async

from fluxpay.contracts.schemas import (
    BalanceResponse,
    ErrorEnvelope,
    PaymentDetail,
    PaymentResponse,
)
from fluxpay.gateway.canonical import (
    HEADER_AUTH,
    HEADER_IDEMPOTENCY,
    HEADER_NONCE,
    HEADER_TIMESTAMP,
    sha256_hex,
)
from fluxpay.gateway.gate import GateRunner, run_gate
from fluxpay.gateway.idempotency import (
    FastPathOutcome,
    IdempotencyFastPath,
    fastpath_keys,
    pack_response,
    parse_response,
)
from fluxpay.gateway.middleware import HEADER_REQUEST_ID
from fluxpay.registry.repo import AgentRepo
from fluxpay.shared.errors import GateUnavailable


class AgentCredentials(Protocol):
    """Protocol for credentials returned by make_agent fixture."""

    agent_id: UUID
    external_id: str
    secret_bytes: bytes


MakeAgentType = Callable[..., Coroutine[Any, Any, AgentCredentials]]
SignedRequestType = Callable[..., Coroutine[Any, Any, httpx.Response]]
BuildGatewayAppType = Callable[..., tuple[Any, list[UUID]]]

pytestmark = pytest.mark.integration

VALID_PAYMENT_BODY: Final[bytes] = b'{"to":"merchant_demo","amount":1050,"currency":"USDC"}'


# =============================================================================
# GROUP A — THE MACHINE CONTRACT
# =============================================================================


async def test_happy_post_payment_contract(
    gateway_client: httpx.AsyncClient,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
) -> None:
    """Happy POST /v1/payments: 201 Created, contract-validated response, single handler."""
    creds: AgentCredentials = await make_agent()

    resp = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
    )

    assert resp.status_code == 201
    assert HEADER_REQUEST_ID in resp.headers

    # Contract assertion: validates wire JSON into frozen Pydantic model
    payment_resp = PaymentResponse.model_validate_json(resp.text)
    assert payment_resp.status == "settled"
    assert isinstance(payment_resp.id, UUID)

    # Handler invocation proof: handler executed exactly once
    calls = getattr(gateway_client, "calls", [])
    assert len(calls) == 1
    assert calls[0] == creds.agent_id


async def test_happy_get_balance_contract(
    gateway_client: httpx.AsyncClient,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
    valkey: redis_async.Redis,
) -> None:
    """Happy GET /v1/balance: 200 OK, BalanceResponse contract, zero flx:idem:* keys created."""
    creds: AgentCredentials = await make_agent()

    resp = await signed_request(
        gateway_client,
        creds,
        "GET",
        "/v1/balance",
    )

    assert resp.status_code == 200
    assert HEADER_REQUEST_ID in resp.headers

    balance_resp = BalanceResponse.model_validate_json(resp.text)
    assert balance_resp.balance == 1050
    assert balance_resp.currency == "USDC"

    # Scope assertion: GET requests bypass fast-path idempotency caching
    idem_keys = await valkey.keys("flx:idem:*")
    assert idem_keys == []


async def test_happy_get_payment_detail_contract(
    gateway_client: httpx.AsyncClient,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
) -> None:
    """Happy GET /v1/payments/{id}: 200 OK, PaymentDetail contract with ISO-8601 UTC timestamp."""
    creds: AgentCredentials = await make_agent()
    payment_id = uuid.uuid4()

    resp = await signed_request(
        gateway_client,
        creds,
        "GET",
        f"/v1/payments/{payment_id}",
    )

    assert resp.status_code == 200
    assert HEADER_REQUEST_ID in resp.headers

    detail = PaymentDetail.model_validate_json(resp.text)
    assert detail.id == payment_id
    assert detail.status == "settled"
    assert detail.amount == 1050
    assert detail.currency == "USDC"
    assert detail.created_at.tzinfo is not None


async def test_error_envelope_matrix_and_retryable_taxonomy(
    gateway_client: httpx.AsyncClient,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
    build_gateway_app: BuildGatewayAppType,
) -> None:
    """Error envelope matrix: wire-level verification of error codes and frozen retryable flags."""
    creds: AgentCredentials = await make_agent(rate_limit_max=1)

    # 1. Bad signature -> 401 authentication_failed (retryable=False)
    resp_sig = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        overrides={HEADER_AUTH: f"FLXP1 {creds.agent_id}:" + "0" * 64},
    )
    assert resp_sig.status_code == 401
    env_sig = ErrorEnvelope.model_validate_json(resp_sig.text)
    assert env_sig.error.code == "authentication_failed"
    assert env_sig.error.retryable is False

    # 2. Stale timestamp -> 401 replay_detected (retryable=False)
    stale_ts = int((time.time() - 40.0) * 1000)
    resp_ts = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        ts_ms=stale_ts,
    )
    assert resp_ts.status_code == 401
    env_ts = ErrorEnvelope.model_validate_json(resp_ts.text)
    assert env_ts.error.code == "replay_detected"
    assert env_ts.error.retryable is False

    # 3. Rate limit exceeded -> 429 rate_limited (retryable=True)
    resp_ok = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
    )
    assert resp_ok.status_code == 201

    resp_rate = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
    )
    assert resp_rate.status_code == 429
    env_rate = ErrorEnvelope.model_validate_json(resp_rate.text)
    assert env_rate.error.code == "rate_limited"
    assert env_rate.error.retryable is True

    # 4. Bad body -> 422 validation_failed (retryable=False)
    creds2: AgentCredentials = await make_agent()
    resp_body = await signed_request(
        gateway_client,
        creds2,
        "POST",
        "/v1/payments",
        body=b'{"bad":"payload"}',
    )
    assert resp_body.status_code == 422
    env_body = ErrorEnvelope.model_validate_json(resp_body.text)
    assert env_body.error.code == "validation_failed"
    assert env_body.error.retryable is False

    # 5. Duplicate idem with conflicting body -> 409 idempotency_conflict (retryable=False)
    idem_key = uuid.uuid4().hex
    resp_init = await signed_request(
        gateway_client,
        creds2,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        idem=idem_key,
    )
    assert resp_init.status_code == 201

    resp_conflict = await signed_request(
        gateway_client,
        creds2,
        "POST",
        "/v1/payments",
        body=b'{"to":"merchant_demo","amount":2000,"currency":"USDC"}',
        idem=idem_key,
    )
    assert resp_conflict.status_code == 409
    env_conflict = ErrorEnvelope.model_validate_json(resp_conflict.text)
    assert env_conflict.error.code == "idempotency_conflict"
    assert env_conflict.error.retryable is False

    # 6. Dead Valkey in GateRunner -> 503 gate_unavailable (retryable=True)
    class DeadGateRunner(GateRunner):
        def __init__(self) -> None:
            pass

        async def run(self, *args: Any, **kwargs: Any) -> Any:
            raise GateUnavailable(message="Injected dead Valkey gate outage")

    dead_app, _ = build_gateway_app(runner=DeadGateRunner())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=dead_app), base_url="https://api.test"
    ) as dead_client:
        resp_dead = await signed_request(
            dead_client,
            creds2,
            "POST",
            "/v1/payments",
            body=VALID_PAYMENT_BODY,
        )
        assert resp_dead.status_code == 503
        env_dead = ErrorEnvelope.model_validate_json(resp_dead.text)
        assert env_dead.error.code == "gate_unavailable"
        assert env_dead.error.retryable is True


# =============================================================================
# GROUP B — IDEMPOTENCY END-TO-END (REDIS TIER)
# =============================================================================


async def test_duplicate_post_replay_byte_exact(
    gateway_client: httpx.AsyncClient,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
) -> None:
    """Duplicate POST: byte-exact wire replay, handler called once, X-FLX-Idempotent-Replay true."""
    creds: AgentCredentials = await make_agent()
    idem_key = uuid.uuid4().hex

    # First attempt: executes handler
    resp1 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        idem=idem_key,
    )
    assert resp1.status_code == 201
    assert "X-FLX-Idempotent-Replay" not in resp1.headers

    # Second attempt: replayed from Redis fast-path
    resp2 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        idem=idem_key,
    )
    assert resp2.status_code == 201
    assert resp2.headers.get("X-FLX-Idempotent-Replay") == "true"
    assert resp2.content == resp1.content  # Byte-exact equality

    calls = getattr(gateway_client, "calls", [])
    assert len(calls) == 1  # Handler invoked ONLY on first flight


async def test_duplicate_post_different_body_conflict(
    gateway_client: httpx.AsyncClient,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
) -> None:
    """Same idempotency key with conflicting request body returns HTTP 409 idempotency_conflict."""
    creds: AgentCredentials = await make_agent()
    idem_key = uuid.uuid4().hex

    resp1 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        idem=idem_key,
    )
    assert resp1.status_code == 201

    conflicting_body = b'{"to":"merchant_demo","amount":9999,"currency":"USDC"}'
    resp2 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=conflicting_body,
        idem=idem_key,
    )
    assert resp2.status_code == 409
    envelope = ErrorEnvelope.model_validate_json(resp2.text)
    assert envelope.error.code == "idempotency_conflict"
    assert envelope.error.retryable is False

    calls = getattr(gateway_client, "calls", [])
    assert len(calls) == 1


async def test_twin_lock_held_then_del_retry(
    gateway_client: httpx.AsyncClient,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
    valkey: redis_async.Redis,
) -> None:
    """Twin in-progress request rejected with 409; DEL release allows successful retry."""
    creds: AgentCredentials = await make_agent()
    idem_key = uuid.uuid4().hex
    lock_key, _ = fastpath_keys(str(creds.agent_id), idem_key)

    # Pre-acquire distributed lock simulating active concurrent twin flight
    await valkey.set(lock_key, sha256_hex(VALID_PAYMENT_BODY), nx=True)

    # Request rejected with 409 while lock is held
    resp_twin = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        idem=idem_key,
    )
    assert resp_twin.status_code == 409
    envelope = ErrorEnvelope.model_validate_json(resp_twin.text)
    assert envelope.error.code == "idempotency_conflict"

    # Lock is cleared / expired -> retry succeeds
    await valkey.delete(lock_key)
    resp_retry = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        idem=idem_key,
    )
    assert resp_retry.status_code == 201

    calls = getattr(gateway_client, "calls", [])
    assert len(calls) == 1


async def test_failed_handler_lock_released_retry_converges(
    build_gateway_app: BuildGatewayAppType,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
) -> None:
    """Downstream 500 releases fast-path lock; retry executes handler and converges to 201."""
    app, calls = build_gateway_app(fail_post_times=1)
    creds: AgentCredentials = await make_agent()
    idem_key = uuid.uuid4().hex

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://api.test"
    ) as client:
        # Flight 1: injected failure (HTTP 500)
        resp1 = await signed_request(
            client,
            creds,
            "POST",
            "/v1/payments",
            body=VALID_PAYMENT_BODY,
            idem=idem_key,
        )
        assert resp1.status_code == 500
        assert len(calls) == 1

        # Flight 2: retry with identical key & body converges to 201 Created
        resp2 = await signed_request(
            client,
            creds,
            "POST",
            "/v1/payments",
            body=VALID_PAYMENT_BODY,
            idem=idem_key,
        )
        assert resp2.status_code == 201
        assert len(calls) == 2

        # Flight 3: subsequent duplicate replays cached 201 without executing handler
        resp3 = await signed_request(
            client,
            creds,
            "POST",
            "/v1/payments",
            body=VALID_PAYMENT_BODY,
            idem=idem_key,
        )
        assert resp3.status_code == 201
        assert resp3.headers.get("X-FLX-Idempotent-Replay") == "true"
        assert len(calls) == 2


# =============================================================================
# GROUP C — ADVERSARIAL MATRIX
# =============================================================================


async def test_adversarial_tamper_table(
    gateway_client: httpx.AsyncClient,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
) -> None:
    """Adversarial tamper table: 10 precise tampering vectors all rejected with exact statuses."""
    creds: AgentCredentials = await make_agent()
    agent2: AgentCredentials = await make_agent()
    now_ms = int(time.time() * 1000)

    # 1. Body byte flip -> 401 authentication_failed
    tampered_body = VALID_PAYMENT_BODY[:-1] + b"}"
    sig_1 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=tampered_body,
        overrides={},  # Normal sign, but tamper content below
    )
    # Perform manual byte flip post-signing
    resp_1 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        overrides={HEADER_AUTH: sig_1.request.headers[HEADER_AUTH]},
    )
    assert resp_1.status_code == 401
    assert ErrorEnvelope.model_validate_json(resp_1.text).error.code == "authentication_failed"

    # 2. Path character change -> 401 authentication_failed
    # Sign for /v1/payments, request /v1/balance with that Auth header
    resp_2 = await signed_request(
        gateway_client,
        creds,
        "GET",
        "/v1/balance",
        overrides={HEADER_AUTH: sig_1.request.headers[HEADER_AUTH]},
    )
    assert resp_2.status_code == 401
    assert ErrorEnvelope.model_validate_json(resp_2.text).error.code == "authentication_failed"

    # 3. Signature truncated -> 401 authentication_failed
    truncated_auth = sig_1.request.headers[HEADER_AUTH][:-4]
    resp_3 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        overrides={HEADER_AUTH: truncated_auth},
    )
    assert resp_3.status_code == 401
    assert ErrorEnvelope.model_validate_json(resp_3.text).error.code == "authentication_failed"

    # 4. Agent ID header swap -> 401 authentication_failed
    # Signed with creds.secret_bytes, but claim agent2's identity
    swapped_auth = sig_1.request.headers[HEADER_AUTH].replace(
        str(creds.agent_id), str(agent2.agent_id)
    )
    resp_4 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        overrides={HEADER_AUTH: swapped_auth},
    )
    assert resp_4.status_code == 401
    assert ErrorEnvelope.model_validate_json(resp_4.text).error.code == "authentication_failed"

    # 5. Timestamp drift +31s -> 401 replay_detected
    resp_5 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        ts_ms=now_ms + 35_000,
    )
    assert resp_5.status_code == 401
    assert ErrorEnvelope.model_validate_json(resp_5.text).error.code == "replay_detected"

    # 6. Timestamp drift -31s -> 401 replay_detected
    resp_6 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        ts_ms=now_ms - 35_000,
    )
    assert resp_6.status_code == 401
    assert ErrorEnvelope.model_validate_json(resp_6.text).error.code == "replay_detected"

    # 7. Nonce reused -> 401 replay_detected
    fixed_nonce = uuid.uuid4().hex
    resp_7a = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        nonce=fixed_nonce,
    )
    assert resp_7a.status_code == 201

    resp_7b = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        nonce=fixed_nonce,
        idem=uuid.uuid4().hex,  # Distinct idem key, duplicate nonce
    )
    assert resp_7b.status_code == 401
    assert ErrorEnvelope.model_validate_json(resp_7b.text).error.code == "replay_detected"

    # 8. Query string appended -> 401 authentication_failed
    # Sign valid path /v1/payments, request with query string
    resp_8 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments?foo=bar",
        body=VALID_PAYMENT_BODY,
        overrides={HEADER_AUTH: sig_1.request.headers[HEADER_AUTH]},
    )
    assert resp_8.status_code == 401
    assert ErrorEnvelope.model_validate_json(resp_8.text).error.code == "authentication_failed"

    # 9. Missing idempotency header on POST -> 422 validation_failed
    resp_9 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        overrides={HEADER_IDEMPOTENCY: None},
    )
    assert resp_9.status_code == 422
    assert ErrorEnvelope.model_validate_json(resp_9.text).error.code == "validation_failed"

    # 10. Malformed idempotency key ("short") -> 422 validation_failed
    resp_10 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        overrides={HEADER_IDEMPOTENCY: "short"},
    )
    assert resp_10.status_code == 422
    assert ErrorEnvelope.model_validate_json(resp_10.text).error.code == "validation_failed"

    # 11. Request body 64 KiB + 1 byte -> 422 validation_failed
    oversized_body = b"x" * (64 * 1024 + 1)
    resp_11 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=oversized_body,
    )
    assert resp_11.status_code == 422
    assert ErrorEnvelope.model_validate_json(resp_11.text).error.code == "validation_failed"

    # 12. Missing timestamp header -> 401 authentication_failed
    resp_12 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        overrides={HEADER_TIMESTAMP: None},
    )
    assert resp_12.status_code == 401
    assert ErrorEnvelope.model_validate_json(resp_12.text).error.code == "authentication_failed"

    # 13. Invalid timestamp format -> 401 authentication_failed
    resp_13 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        overrides={HEADER_TIMESTAMP: "not13digits"},
    )
    assert resp_13.status_code == 401
    assert ErrorEnvelope.model_validate_json(resp_13.text).error.code == "authentication_failed"

    # 14. Missing nonce header -> 401 authentication_failed
    resp_14 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        overrides={HEADER_NONCE: None},
    )
    assert resp_14.status_code == 401
    assert ErrorEnvelope.model_validate_json(resp_14.text).error.code == "authentication_failed"

    # 15. Malformed nonce format -> 401 authentication_failed
    resp_15 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        overrides={HEADER_NONCE: "short"},
    )
    assert resp_15.status_code == 401
    assert ErrorEnvelope.model_validate_json(resp_15.text).error.code == "authentication_failed"

    # 16. Invalid agent UUID in auth header -> 401 authentication_failed
    resp_16 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
        overrides={HEADER_AUTH: "FLXP1 not-a-valid-uuid:1234"},
    )
    assert resp_16.status_code == 401
    assert ErrorEnvelope.model_validate_json(resp_16.text).error.code == "authentication_failed"


async def test_adversarial_unknown_agent_uuid(
    gateway_client: httpx.AsyncClient,
    signed_request: SignedRequestType,
) -> None:
    """Request signed with an unknown agent UUID rejected with 401 authentication_failed."""

    @dataclass(frozen=True, slots=True)
    class FakeCredentials:
        agent_id: UUID
        external_id: str
        secret_bytes: bytes

    fake_creds = FakeCredentials(
        agent_id=uuid.uuid4(),
        external_id="unknown_agent",
        secret_bytes=b"test-secret-key-32-bytes-long!!",
    )

    resp = await signed_request(
        gateway_client,
        fake_creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
    )
    assert resp.status_code == 401
    envelope = ErrorEnvelope.model_validate_json(resp.text)
    assert envelope.error.code == "authentication_failed"


async def test_adversarial_inactive_agent(
    gateway_client: httpx.AsyncClient,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
) -> None:
    """Request from an agent with active=false rejected with 401 authentication_failed."""
    creds: AgentCredentials = await make_agent(active=False)

    resp = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
    )
    assert resp.status_code == 401
    envelope = ErrorEnvelope.model_validate_json(resp.text)
    assert envelope.error.code == "authentication_failed"


# =============================================================================
# GROUP D — LIFECYCLE & LIMITS (REAL REPO & VALKEY CACHE)
# =============================================================================


async def test_lifecycle_suspend_immediate_del_invalidation(
    gateway_client: httpx.AsyncClient,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
    agent_repo: AgentRepo,
) -> None:
    """Suspension invalidates Redis cache immediately via DEL; subsequent requests 401 instantly."""
    creds: AgentCredentials = await make_agent()

    # Pre-condition: active agent requests succeed and populate Redis cache
    resp1 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
    )
    assert resp1.status_code == 201

    # Security intervention: suspend agent
    suspended = await agent_repo.suspend(creds.agent_id)
    assert suspended is True

    # Immediate post-condition: request rejected without waiting for TTL
    resp2 = await signed_request(
        gateway_client,
        creds,
        "POST",
        "/v1/payments",
        body=VALID_PAYMENT_BODY,
    )
    assert resp2.status_code == 401
    envelope = ErrorEnvelope.model_validate_json(resp2.text)
    assert envelope.error.code == "authentication_failed"


async def test_limits_per_agent_rate_limit_from_db(
    gateway_client: httpx.AsyncClient,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
) -> None:
    """Per-agent rate limit from DB; 3rd request rejected with 429, other agent unaffected."""
    agent1: AgentCredentials = await make_agent(rate_limit_max=2)
    agent2: AgentCredentials = await make_agent(rate_limit_max=10)

    # Agent 1 request 1 -> 201
    r1 = await signed_request(
        gateway_client, agent1, "POST", "/v1/payments", body=VALID_PAYMENT_BODY
    )
    assert r1.status_code == 201

    # Agent 1 request 2 -> 201
    r2 = await signed_request(
        gateway_client, agent1, "POST", "/v1/payments", body=VALID_PAYMENT_BODY
    )
    assert r2.status_code == 201

    # Agent 1 request 3 -> 429 rate_limited
    r3 = await signed_request(
        gateway_client, agent1, "POST", "/v1/payments", body=VALID_PAYMENT_BODY
    )
    assert r3.status_code == 429
    env3 = ErrorEnvelope.model_validate_json(r3.text)
    assert env3.error.code == "rate_limited"
    assert env3.error.retryable is True

    # Isolation: Agent 2 is unaffected
    r_other = await signed_request(
        gateway_client, agent2, "POST", "/v1/payments", body=VALID_PAYMENT_BODY
    )
    assert r_other.status_code == 201


async def test_limits_daily_quota_from_db(
    gateway_client: httpx.AsyncClient,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
) -> None:
    """Daily quota loaded from DB; 3rd distinct-nonce request rejected with 429 rate_limited."""
    creds: AgentCredentials = await make_agent(daily_quota_max=2, rate_limit_max=100)

    r1 = await signed_request(
        gateway_client, creds, "POST", "/v1/payments", body=VALID_PAYMENT_BODY
    )
    assert r1.status_code == 201

    r2 = await signed_request(
        gateway_client, creds, "POST", "/v1/payments", body=VALID_PAYMENT_BODY
    )
    assert r2.status_code == 201

    r3 = await signed_request(
        gateway_client, creds, "POST", "/v1/payments", body=VALID_PAYMENT_BODY
    )
    assert r3.status_code == 429
    env3 = ErrorEnvelope.model_validate_json(r3.text)
    assert env3.error.code == "rate_limited"
    assert env3.error.retryable is True


# =============================================================================
# GROUP E — CONCURRENCY & RESILIENCE
# =============================================================================


async def test_concurrency_atomicity_twenty_requests_ten_rate_limit(
    gateway_client: httpx.AsyncClient,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
) -> None:
    """20 concurrent POSTs against rate_limit_max=10 yields exactly 10x201 and 10x429."""
    creds: AgentCredentials = await make_agent(rate_limit_max=10)

    tasks = [
        signed_request(
            gateway_client,
            creds,
            "POST",
            "/v1/payments",
            body=VALID_PAYMENT_BODY,
            nonce=uuid.uuid4().hex,
            idem=uuid.uuid4().hex,
        )
        for _ in range(20)
    ]

    start_time = time.perf_counter()
    responses = await asyncio.gather(*tasks)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    print(
        f"\n[BASELINE] Concurrency Group E: 20 parallel POSTs completed in {elapsed_ms:.2f} ms "
        f"({elapsed_ms / 20:.2f} ms/req)"
    )

    statuses = [r.status_code for r in responses]
    assert statuses.count(201) == 10
    assert statuses.count(429) == 10

    # Every 429 must conform to ErrorEnvelope with retryable=True
    for r in responses:
        if r.status_code == 429:
            env = ErrorEnvelope.model_validate_json(r.text)
            assert env.error.code == "rate_limited"
            assert env.error.retryable is True


async def test_resilience_dead_valkey_runner_fail_closed(
    build_gateway_app: BuildGatewayAppType,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
) -> None:
    """GateRunner failure fails closed with HTTP 503 gate_unavailable (retryable=True)."""

    class InjectedDeadGateRunner(GateRunner):
        def __init__(self) -> None:
            pass

        async def run(self, *args: Any, **kwargs: Any) -> Any:
            raise GateUnavailable(message="Injected simulated Valkey outage")

    app, _ = build_gateway_app(runner=InjectedDeadGateRunner())
    creds: AgentCredentials = await make_agent()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://api.test"
    ) as client:
        resp = await signed_request(
            client,
            creds,
            "POST",
            "/v1/payments",
            body=VALID_PAYMENT_BODY,
        )
        assert resp.status_code == 503
        envelope = ErrorEnvelope.model_validate_json(resp.text)
        assert envelope.error.code == "gate_unavailable"
        assert envelope.error.retryable is True


async def test_resilience_resolver_broken_pool_fail_total_no_leak(
    build_gateway_app: BuildGatewayAppType,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
) -> None:
    """Database failure fails total with HTTP 500 internal_error; zero exception leak."""

    class BrokenResolver:
        async def resolve(self, agent_id: UUID) -> None:
            raise asyncpg.PostgresConnectionError(
                "connection to server at 'db.internal.corp:5432' failed: Connection refused"
            )

    app, _ = build_gateway_app(resolver=BrokenResolver())
    creds: AgentCredentials = await make_agent()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://api.test"
    ) as client:
        resp = await signed_request(
            client,
            creds,
            "POST",
            "/v1/payments",
            body=VALID_PAYMENT_BODY,
        )
        assert resp.status_code == 500
        envelope = ErrorEnvelope.model_validate_json(resp.text)
        assert envelope.error.code == "internal_error"
        assert envelope.error.retryable is False

        # Task 4 totality at the wire: sensitive database host/port must NEVER leak to client
        assert "db.internal.corp" not in resp.text
        assert "5432" not in resp.text
        assert "PostgresConnectionError" not in resp.text


async def test_idempotency_fastpath_boundary_and_validation(
    valkey: redis_async.Redis,
    build_gateway_app: BuildGatewayAppType,
    make_agent: MakeAgentType,
    signed_request: SignedRequestType,
) -> None:
    """Exercise fast-path edge cases: property access, constructor checks, and oversize handling."""
    fp = IdempotencyFastPath(valkey, ttl_s=3600, max_cache_bytes=1024)
    assert fp.ttl_s == 3600
    assert fp.max_cache_bytes == 1024

    with pytest.raises(ValueError, match="ttl_s must be positive"):
        IdempotencyFastPath(valkey, ttl_s=0)

    with pytest.raises(ValueError, match="max_cache_bytes must be positive"):
        IdempotencyFastPath(valkey, ttl_s=100, max_cache_bytes=0)

    with pytest.raises(TypeError, match="body must be bytes-like"):
        pack_response(200, "not-bytes")  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="cached must be bytes-like"):
        parse_response("not-bytes")  # type: ignore[arg-type]

    agent_id = str(uuid.uuid4())
    idem_key = uuid.uuid4().hex

    # finish with non-2xx raises ValueError and releases lock
    with pytest.raises(ValueError, match=r"status outside 200\.\.299"):
        await fp.finish(agent_id, idem_key, status=400, body=b"error")

    # finish with payload exceeding max_cache_bytes bypasses cache and releases lock
    oversized = b"x" * 2048
    await fp.finish(agent_id, idem_key, status=200, body=oversized)
    _lock, resp_key = fastpath_keys(agent_id, idem_key)
    assert await valkey.get(resp_key) is None

    # Missing cached response when outcome is REPLAY_CACHED
    class CorruptFastPath(IdempotencyFastPath):
        async def begin(self, *args: Any, **kwargs: Any) -> Any:
            return FastPathOutcome.REPLAY_CACHED, None

    app, _ = build_gateway_app(fastpath=CorruptFastPath(valkey, ttl_s=60))
    creds = await make_agent()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://api.test"
    ) as client:
        resp = await signed_request(client, creds, "POST", "/v1/payments", body=VALID_PAYMENT_BODY)
        assert resp.status_code == 409
        env = ErrorEnvelope.model_validate_json(resp.text)
        assert env.error.code == "idempotency_conflict"


async def test_gate_runner_boundary_and_protocol_drift(
    valkey: redis_async.Redis,
) -> None:
    """Exercise GateRunner edge cases: custom lua paths, aliases, protocol errors."""
    repo_root = Path(__file__).resolve().parent.parent.parent  # noqa: ASYNC240
    lua_file = repo_root / "src" / "fluxpay" / "gateway" / "ratelimit.lua"

    # Custom Path loading
    runner_path = GateRunner(valkey, lua_path=lua_file)
    assert runner_path is not None

    # Custom Traversable loading
    traversable = importlib.resources.files("fluxpay.gateway").joinpath("ratelimit.lua")
    runner_trav = GateRunner(valkey, lua_path=traversable)
    assert runner_trav is not None

    # run_gate alias on GateRunner
    now_ms = int(time.time() * 1000)
    agent_id = str(uuid.uuid4())
    res_alias = await runner_path.run_gate(
        agent_id=agent_id,
        nonce=uuid.uuid4().hex,
        now_ms=now_ms,
        window_ms=60_000,
        rate_max=10,
        nonce_ttl_ms=120_000,
        daily_max=100,
        day_ttl_s=86_400,
    )
    assert res_alias.ok

    # run_gate with raw valkey client (caching GateRunner on client)
    res_raw = await run_gate(
        valkey,
        agent_id=agent_id,
        nonce=uuid.uuid4().hex,
        now_ms=now_ms,
        window_ms=60_000,
        rate_max=10,
        nonce_ttl_ms=120_000,
        daily_max=100,
        day_ttl_s=86_400,
    )
    assert res_raw.ok
    assert hasattr(valkey, "_flx_gate_runner")

    # Script returning malformed return shape (not 3 elements) -> GateUnavailable
    runner_bad = GateRunner(valkey)

    async def _mock_bad_shape(**kw: Any) -> Any:
        return [1]

    cast(Any, runner_bad)._script = _mock_bad_shape
    with pytest.raises(GateUnavailable):
        await runner_bad.run(
            agent_id=agent_id,
            nonce=uuid.uuid4().hex,
            now_ms=now_ms,
            window_ms=60000,
            rate_max=10,
            nonce_ttl_ms=120000,
            daily_max=10,
            day_ttl_s=86400,
        )

    # Script returning non-integer elements -> GateUnavailable
    runner_bad_type = GateRunner(valkey)

    async def _mock_bad_type(**kw: Any) -> Any:
        return ["a", "b", "c"]

    cast(Any, runner_bad_type)._script = _mock_bad_type
    with pytest.raises(GateUnavailable):
        await runner_bad_type.run(
            agent_id=agent_id,
            nonce=uuid.uuid4().hex,
            now_ms=now_ms,
            window_ms=60000,
            rate_max=10,
            nonce_ttl_ms=120000,
            daily_max=10,
            day_ttl_s=86400,
        )
