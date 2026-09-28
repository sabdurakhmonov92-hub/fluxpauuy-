"""Integration tests for Idempotency Fast-Path: Redis tier over the database state machine.

Tests verify with real Valkey (DB 15) and NO PostgreSQL:
- First POST executes handler once (201).
- Duplicate request returns byte-exact cached response without handler execution (headline).
- Conflicting body under the same key returns 409 idempotency_conflict.
- In-flight concurrent twin returns 409; subsequent retry converges cleanly.
- Eviction self-repair: when lock is evicted while response remains, request replays response.
- Failure path: non-2xx response releases lock to allow legitimate client retry.
- Exception path: server exceptions release lock to avoid stranded keys.
- Oversized response (>64 KiB) bypasses cache and releases lock.
- PTTL contracts verify key lifetimes without sleeping.
- GET requests do not create idempotency keys (scope proof).
- Task 21 suite backwards-compatibility (fastpath=None default).
"""

from __future__ import annotations

import base64
import os
import time
from collections.abc import AsyncGenerator, Callable
from typing import Final
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as redis_async
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from fluxpay.config import Settings
from fluxpay.gateway import canonical
from fluxpay.gateway.canonical import (
    HEADER_AUTH,
    HEADER_IDEMPOTENCY,
    HEADER_NONCE,
    HEADER_TIMESTAMP,
    sha256_hex,
)
from fluxpay.gateway.gate import GateRunner
from fluxpay.gateway.idempotency import (
    IdempotencyFastPath,
    fastpath_keys,
)
from fluxpay.gateway.middleware import (
    AgentResolver,
    AuthenticatedAgent,
    GatewayMiddleware,
)
from fluxpay.shared.vault import SecretBytes

pytestmark = pytest.mark.integration

TEST_AGENT_ID: Final[str] = "018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e"
TEST_SECRET_BYTES: Final[bytes] = b"test-secret-key-32-bytes-long!!"


# =============================================================================
# Test Harness & Fixtures (NO Postgres, Real Valkey DB 15)
# =============================================================================


class StubAgentResolver:
    """In-memory stub implementing AgentResolver Protocol for zero-DB testing."""

    def __init__(self, agents: dict[UUID, AuthenticatedAgent]) -> None:
        self._agents = agents

    async def resolve(self, agent_id: UUID) -> AuthenticatedAgent | None:
        return self._agents.get(agent_id)


class CountingHandler:
    """Counting mock HTTP handler allowing controllable status, body, and exceptions."""

    def __init__(self) -> None:
        self.calls: int = 0
        self.return_status: int = 201
        self.return_body: bytes | None = None
        self.raise_exc: Exception | None = None

    async def handle(self, request: Request) -> Response:
        self.calls += 1
        if self.raise_exc is not None:
            raise self.raise_exc
        if self.return_body is not None:
            content = self.return_body
        else:
            req_body = await request.body()
            content = (
                f'{{"status":"paid","tx_id":"018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e",'
                f'"size":{len(req_body)}}}'
            ).encode()
        return Response(
            content=content,
            status_code=self.return_status,
            media_type="application/json",
        )


@pytest_asyncio.fixture
async def valkey() -> AsyncGenerator[redis_async.Redis, None]:
    """Provide a function-scoped Redis/Valkey client on DB 15 with flushdb teardown."""
    url = os.environ.get("FLX_VALKEY_URL", "redis://localhost:6379/15")
    client: redis_async.Redis = redis_async.Redis.from_url(url)
    try:
        yield client
    finally:
        await client.flushdb()
        await client.aclose()


def make_test_settings(*, ttl_s: int = 86400) -> Settings:
    """Create test settings instance with configurable fast-path TTL."""
    return Settings(
        pg_dsn="postgresql://test:test@localhost:5432/test",
        vault_master_key=base64.b64encode(b"0" * 32).decode("ascii"),
        webhook_signing_key="a" * 32,
        idempotency_fast_ttl_s=ttl_s,
    )


def make_test_agent() -> AuthenticatedAgent:
    """Create test agent with known credentials and generous rate limits."""
    return AuthenticatedAgent(
        agent_id=UUID(TEST_AGENT_ID),
        external_id="agent_integration_01",
        secret=SecretBytes(TEST_SECRET_BYTES),
        rate_limit_max=1000,
        daily_quota_max=100_000,
    )


def make_signed_headers(
    agent: AuthenticatedAgent,
    method: str,
    path: str,
    body: bytes,
    *,
    idem_key: str | None = None,
    ts_ms: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Helper to generate strictly valid FLXP1 signed request headers."""
    effective_ts = ts_ms if ts_ms is not None else int(time.time() * 1000)
    effective_nonce = nonce if nonce is not None else uuid4().hex[:16]
    sig = canonical.sign(
        secret=agent.secret,
        method=method,
        path=path,
        timestamp=str(effective_ts),
        nonce=effective_nonce,
        body=body,
    )
    headers = {
        HEADER_AUTH: f"FLXP1 {agent.agent_id}:{sig}",
        HEADER_TIMESTAMP: str(effective_ts),
        HEADER_NONCE: effective_nonce,
    }
    if idem_key is not None:
        headers[HEADER_IDEMPOTENCY] = idem_key
    elif method.upper() == "POST":
        headers[HEADER_IDEMPOTENCY] = "default-idemp-key-01"
    return headers


def create_gateway_app(
    resolver: AgentResolver,
    runner: GateRunner,
    settings: Settings,
    fastpath: IdempotencyFastPath | None,
    payments_handler: CountingHandler,
    clock: Callable[[], float] = time.time,
) -> Starlette:
    """Build test Starlette app with GatewayMiddleware and configured handlers."""

    async def dummy_balance(request: Request) -> Response:
        return Response(content=b'{"balance": 1000}', media_type="application/json")

    app = Starlette(
        routes=[
            Route("/v1/payments", payments_handler.handle, methods=["POST"]),
            Route("/v1/balance", dummy_balance, methods=["GET"]),
        ],
    )
    app.add_middleware(
        GatewayMiddleware,
        resolver=resolver,
        runner=runner,
        settings=settings,
        clock=clock,
        fastpath=fastpath,
    )
    return app


# =============================================================================
# Integration Tests (Real Valkey + Real FastPath + Real GatewayMiddleware)
# =============================================================================


async def test_first_post_and_duplicate_byte_exact_replay(valkey: redis_async.Redis) -> None:
    """Headline Guarantee:
    First POST executes handler (201); duplicate replays byte-exact (1 call).
    """
    settings = make_test_settings()
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = GateRunner(valkey)
    fastpath = IdempotencyFastPath(valkey, ttl_s=settings.idempotency_fast_ttl_s)
    handler = CountingHandler()
    app = create_gateway_app(resolver, runner, settings, fastpath, handler)

    idem_key = "idemp-headline-key-01234567"
    body = b'{"recipient":"agent_alice","amount":25000,"currency":"USDC"}'

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # 1. First POST -> 201, handler_calls == 1
        headers1 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        res1 = await client.post("/v1/payments", headers=headers1, content=body)

        assert res1.status_code == 201
        assert handler.calls == 1
        assert "X-FLX-Idempotent-Replay" not in res1.headers

        # 2. Duplicate POST (same key, same body, fresh transport nonce/ts)
        headers2 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        res2 = await client.post("/v1/payments", headers=headers2, content=body)

        assert res2.status_code == 201
        # Replay marker header present
        assert res2.headers.get("X-FLX-Idempotent-Replay") == "true"
        # Byte-exact identity: assert body == first body (== not equal-ish)
        assert res2.content == res1.content
        # Handler was NOT invoked a second time
        assert handler.calls == 1


async def test_different_body_same_key_conflict_409(valkey: redis_async.Redis) -> None:
    """Validate fraud guard: reusing key with DIFFERENT body returns 409 idempotency_conflict."""
    settings = make_test_settings()
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = GateRunner(valkey)
    fastpath = IdempotencyFastPath(valkey, ttl_s=settings.idempotency_fast_ttl_s)
    handler = CountingHandler()
    app = create_gateway_app(resolver, runner, settings, fastpath, handler)

    idem_key = "idemp-conflict-key-01234567"
    body1 = b'{"recipient":"agent_bob","amount":100}'
    body2 = b'{"recipient":"agent_bob","amount":200}'  # Different payload

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # First request succeeds
        h1 = make_signed_headers(agent, "POST", "/v1/payments", body1, idem_key=idem_key)
        r1 = await client.post("/v1/payments", headers=h1, content=body1)
        assert r1.status_code == 201

        # Second request with same key but different body -> 409 Conflict
        h2 = make_signed_headers(agent, "POST", "/v1/payments", body2, idem_key=idem_key)
        r2 = await client.post("/v1/payments", headers=h2, content=body2)

        assert r2.status_code == 409
        err = r2.json()["error"]
        assert err["code"] == "idempotency_conflict"
        assert err["retryable"] is False
        assert handler.calls == 1


async def test_in_flight_twin_storm_resolves(valkey: redis_async.Redis) -> None:
    """Validate twin storm: manual lock (no resp) yields 409; deleting lock allows 201 retry."""
    settings = make_test_settings()
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = GateRunner(valkey)
    fastpath = IdempotencyFastPath(valkey, ttl_s=settings.idempotency_fast_ttl_s)
    handler = CountingHandler()
    app = create_gateway_app(resolver, runner, settings, fastpath, handler)

    idem_key = "idemp-twin-flight-key-012345"
    body = b'{"amount": 500}'
    body_hash = sha256_hex(body)
    lock_key, _ = fastpath_keys(TEST_AGENT_ID, idem_key)

    # Manually hold lock (simulating concurrent twin execution in flight)
    await valkey.set(lock_key, body_hash, ex=60)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        h1 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        r1 = await client.post("/v1/payments", headers=h1, content=body)

        # In-flight collision yields 409 idempotency_conflict (retryable=False per taxonomy)
        assert r1.status_code == 409
        assert r1.json()["error"]["code"] == "idempotency_conflict"
        assert handler.calls == 0

        # Simulate first request finishing or crashing: release lock
        await valkey.delete(lock_key)

        # Retry now succeeds
        h2 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        r2 = await client.post("/v1/payments", headers=h2, content=body)

        assert r2.status_code == 201
        assert handler.calls == 1


async def test_eviction_self_repair_proven(valkey: redis_async.Redis) -> None:
    """Hole Closed Proof: deleting lock (resp remains) triggers self-repair to REPLAY_CACHED."""
    settings = make_test_settings()
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = GateRunner(valkey)
    fastpath = IdempotencyFastPath(valkey, ttl_s=settings.idempotency_fast_ttl_s)
    handler = CountingHandler()
    app = create_gateway_app(resolver, runner, settings, fastpath, handler)

    idem_key = "idemp-evict-repair-key-01234"
    body = b'{"amount": 1000}'
    lock_key, resp_key = fastpath_keys(TEST_AGENT_ID, idem_key)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # First request succeeds
        h1 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        r1 = await client.post("/v1/payments", headers=h1, content=body)
        assert r1.status_code == 201
        assert handler.calls == 1
        assert await valkey.exists(lock_key)
        assert await valkey.exists(resp_key)

        # EVICTION EVENT: lock expires or is evicted by Redis, but resp outlives it
        await valkey.delete(lock_key)
        assert not await valkey.exists(lock_key)
        assert await valkey.exists(resp_key)

        # Duplicate arrives: SETNX acquires fresh lock + observes existing resp -> REPLAY_CACHED
        h2 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        r2 = await client.post("/v1/payments", headers=h2, content=body)

        assert r2.status_code == 201
        assert r2.headers.get("X-FLX-Idempotent-Replay") == "true"
        assert r2.content == r1.content
        # Proof: handler was NOT called again; hot path self-repaired
        assert handler.calls == 1
        # Lock was re-acquired during self-repair to protect subsequent requests
        assert await valkey.exists(lock_key)


async def test_failure_path_releases_lock_and_retry_converges(valkey: redis_async.Redis) -> None:
    """Validate failure path:
    400 from handler releases lock; subsequent retry succeeds and caches.
    """
    settings = make_test_settings()
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = GateRunner(valkey)
    fastpath = IdempotencyFastPath(valkey, ttl_s=settings.idempotency_fast_ttl_s)
    handler = CountingHandler()
    app = create_gateway_app(resolver, runner, settings, fastpath, handler)

    idem_key = "idemp-fail-path-key-01234567"
    body = b'{"bad_param": true}'
    lock_key, resp_key = fastpath_keys(TEST_AGENT_ID, idem_key)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Handler configured to fail with 400
        handler.return_status = 400
        handler.return_body = b'{"error":"client_mistake"}'

        h1 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        r1 = await client.post("/v1/payments", headers=h1, content=body)

        assert r1.status_code == 400
        assert handler.calls == 1
        # Failure must release lock so client can retry
        assert await valkey.get(lock_key) is None
        assert await valkey.get(resp_key) is None

        # Handler fixed; client retries under same idempotency key
        handler.return_status = 201
        handler.return_body = None

        h2 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        r2 = await client.post("/v1/payments", headers=h2, content=body)

        assert r2.status_code == 201
        assert handler.calls == 2
        # Now cached: lock stays and resp is saved
        assert await valkey.exists(lock_key)
        assert await valkey.exists(resp_key)

        # Subsequent duplicate now replays
        h3 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        r3 = await client.post("/v1/payments", headers=h3, content=body)

        assert r3.status_code == 201
        assert r3.headers.get("X-FLX-Idempotent-Replay") == "true"
        assert handler.calls == 2  # Not called again


async def test_exception_path_releases_lock_clean_retry(valkey: redis_async.Redis) -> None:
    """Validate exception path: handler crash releases lock; client retry succeeds cleanly."""
    settings = make_test_settings()
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = GateRunner(valkey)
    fastpath = IdempotencyFastPath(valkey, ttl_s=settings.idempotency_fast_ttl_s)
    handler = CountingHandler()
    app = create_gateway_app(resolver, runner, settings, fastpath, handler)

    idem_key = "idemp-exc-path-key-012345678"
    body = b'{"amount": 900}'
    lock_key, _ = fastpath_keys(TEST_AGENT_ID, idem_key)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Handler crashes with unexpected exception
        handler.raise_exc = RuntimeError("Database connection pool died")

        h1 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        r1 = await client.post("/v1/payments", headers=h1, content=body)

        # Mapped to 500 internal_error
        assert r1.status_code == 500
        assert r1.json()["error"]["code"] == "internal_error"
        # Stranded-lock killer: lock is guaranteed released
        assert await valkey.get(lock_key) is None

        # Clean retry succeeds
        handler.raise_exc = None
        h2 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        r2 = await client.post("/v1/payments", headers=h2, content=body)

        assert r2.status_code == 201
        assert handler.calls == 2


async def test_too_big_response_bypasses_cache_and_releases_lock(
    valkey: redis_async.Redis,
) -> None:
    """Validate >64 KiB response bypasses fast-path caching and releases lock."""
    settings = make_test_settings()
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = GateRunner(valkey)
    fastpath = IdempotencyFastPath(valkey, ttl_s=settings.idempotency_fast_ttl_s)
    handler = CountingHandler()
    app = create_gateway_app(resolver, runner, settings, fastpath, handler)

    idem_key = "idemp-too-big-key-0123456789"
    body = b'{"amount": 10}'
    lock_key, resp_key = fastpath_keys(TEST_AGENT_ID, idem_key)

    # 70 KiB response (> 65_536 bytes)
    oversized_response = b"x" * 71680
    handler.return_status = 201
    handler.return_body = oversized_response

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        h1 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        r1 = await client.post("/v1/payments", headers=h1, content=body)

        assert r1.status_code == 201
        assert len(r1.content) == 71680
        # Fast path bypass: resp key is ABSENT, lock is RELEASED
        assert await valkey.get(resp_key) is None
        assert await valkey.get(lock_key) is None

        # Retry re-executes handler (documented bypass; DB tier remains safety net)
        h2 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        r2 = await client.post("/v1/payments", headers=h2, content=body)

        assert r2.status_code == 201
        assert handler.calls == 2


async def test_ttl_contracts_asserted_via_pttl_without_sleeps(
    valkey: redis_async.Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validate TTL contract: PTTL(lock) and PTTL(resp) are in (0, ttl_ms] with zero sleeps."""
    test_ttl_s = 60  # Short TTL for exact verification
    settings = make_test_settings(ttl_s=test_ttl_s)
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = GateRunner(valkey)
    fastpath = IdempotencyFastPath(valkey, ttl_s=test_ttl_s)
    handler = CountingHandler()
    app = create_gateway_app(resolver, runner, settings, fastpath, handler)

    idem_key = "idemp-ttl-check-key-012345678"
    body = b'{"amount": 100}'
    lock_key, resp_key = fastpath_keys(TEST_AGENT_ID, idem_key)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        h = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        res = await client.post("/v1/payments", headers=h, content=body)
        assert res.status_code == 201

    max_ttl_ms = test_ttl_s * 1000
    lock_pttl = await valkey.pttl(lock_key)
    resp_pttl = await valkey.pttl(resp_key)

    assert 0 < lock_pttl <= max_ttl_ms
    assert 0 < resp_pttl <= max_ttl_ms


async def test_get_requests_untouched_no_keys_created(valkey: redis_async.Redis) -> None:
    """Validate scope proof: GET requests bypass fastpath completely; no keys created."""
    settings = make_test_settings()
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = GateRunner(valkey)
    fastpath = IdempotencyFastPath(valkey, ttl_s=settings.idempotency_fast_ttl_s)
    handler = CountingHandler()
    app = create_gateway_app(resolver, runner, settings, fastpath, handler)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        h_get = make_signed_headers(agent, "GET", "/v1/balance", b"")
        res = await client.get("/v1/balance", headers=h_get)

    assert res.status_code == 200
    # Zero idempotency keys must exist in Valkey
    keys = await valkey.keys("flx:idem:*")
    assert keys == []


async def test_fastpath_none_default_preserves_task_21_behavior(
    valkey: redis_async.Redis,
) -> None:
    """Validate optional fastpath=None default preserves Task 21 pipeline
    with zero Valkey interaction.
    """
    settings = make_test_settings()
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = GateRunner(valkey)
    handler = CountingHandler()
    app = create_gateway_app(resolver, runner, settings, fastpath=None, payments_handler=handler)

    idem_key = "idemp-nofastpath-012345678"
    body = b'{"amount": 100}'

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        h1 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        r1 = await client.post("/v1/payments", headers=h1, content=body)
        assert r1.status_code == 201
        assert handler.calls == 1

        # Second identical request calls handler again (no Redis fastpath tier active)
        h2 = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key=idem_key)
        r2 = await client.post("/v1/payments", headers=h2, content=body)
        assert r2.status_code == 201
        assert handler.calls == 2

    # Zero idempotency keys created
    keys = await valkey.keys("flx:idem:*")
    assert keys == []
