"""Integration tests for GatewayMiddleware full security pipeline.

THE SEAM PAYOFF:
This integration test suite exercises the complete gateway pipeline against:
- REAL Valkey instance (DB 15) for atomic anti-replay, rate limiting, and quotas.
- REAL GateRunner executing the production ratelimit.lua script.
- REAL canonical signing & HMAC verification over wire bytes.
- REAL SecretBytes custody buffers from fluxpay.shared.vault.
- ZERO PostgreSQL database dependencies.

The AgentResolver Protocol seam enables high-fidelity end-to-end integration
testing of the full security barrier without booting or mocking PostgreSQL.
"""

from __future__ import annotations

import base64
import logging
import os
import time
from collections.abc import AsyncGenerator, Callable
from typing import Any, Final
from uuid import UUID, uuid4

import httpx
import orjson
import pytest
import pytest_asyncio
import redis.asyncio as redis_async
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from fluxpay.config import Settings
from fluxpay.gateway import canonical
from fluxpay.gateway.canonical import (
    HEADER_AUTH,
    HEADER_IDEMPOTENCY,
    HEADER_NONCE,
    HEADER_TIMESTAMP,
)
from fluxpay.gateway.gate import GateRunner
from fluxpay.gateway.middleware import (
    HEADER_REQUEST_ID,
    AgentResolver,
    AuthenticatedAgent,
    GatewayMiddleware,
)
from fluxpay.shared.logging import (
    clear_request_context,
    configure_logging,
)
from fluxpay.shared.vault import SecretBytes

pytestmark = pytest.mark.integration

DEFAULT_TEST_SECRET: Final[bytes] = b"integration-secret-key-32-bytes!"


# ---------------------------------------------------------------------------
# Fixtures & Test Infrastructure
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def valkey() -> AsyncGenerator[redis_async.Redis, None]:
    """Provide a function-scoped Redis/Valkey client connected to DB 15 with flushdb teardown."""
    url = os.environ.get("FLX_VALKEY_URL", "redis://localhost:6379/15")
    client: redis_async.Redis = redis_async.Redis.from_url(url)
    try:
        yield client
    finally:
        await client.flushdb()
        await client.aclose()


@pytest.fixture
def gate_runner(valkey: redis_async.Redis) -> GateRunner:
    """Provide production GateRunner instance backed by live Valkey client."""
    return GateRunner(valkey)


class InMemAgentResolver:
    """In-memory stub implementing AgentResolver Protocol for zero-Postgres integration."""

    def __init__(self, agents: dict[UUID, AuthenticatedAgent] | None = None) -> None:
        self.agents: dict[UUID, AuthenticatedAgent] = agents or {}

    async def resolve(self, agent_id: UUID) -> AuthenticatedAgent | None:
        return self.agents.get(agent_id)


def make_agent(
    agent_id: UUID | None = None,
    secret_bytes: bytes = DEFAULT_TEST_SECRET,
    rate_limit_max: int = 10,
    daily_quota_max: int = 100,
) -> AuthenticatedAgent:
    """Create AuthenticatedAgent with wipeable SecretBytes."""
    return AuthenticatedAgent(
        agent_id=agent_id if agent_id is not None else uuid4(),
        external_id=f"agent_int_{uuid4().hex[:8]}",
        secret=SecretBytes(secret_bytes),
        rate_limit_max=rate_limit_max,
        daily_quota_max=daily_quota_max,
    )


def make_integration_settings(
    replay_window_ms: int = 30_000,
    rate_limit_window_ms: int = 60_000,
    rate_limit_max: int = 100,
    daily_quota_max: int = 10_000,
    nonce_ttl_ms: int = 120_000,
) -> Settings:
    """Create test settings instance for integration suite."""
    return Settings(
        pg_dsn="postgresql://test:test@localhost:5432/test",
        vault_master_key=base64.b64encode(b"0" * 32).decode("ascii"),
        webhook_signing_key="a" * 32,
        replay_window_ms=replay_window_ms,
        rate_limit_window_ms=rate_limit_window_ms,
        rate_limit_max=rate_limit_max,
        daily_quota_max=daily_quota_max,
        nonce_ttl_ms=nonce_ttl_ms,
    )


def build_signed_request(
    agent: AuthenticatedAgent,
    method: str,
    path: str,
    body: bytes,
    *,
    nonce: str,
    ts_ms: int | None = None,
    clock: Callable[[], float] | None = None,
    idem_key: str | None = None,
) -> dict[str, str]:
    """Generate signed HTTP headers using canonical.sign with SecretBytes.

    Proves Task 7 SecretBytes -> Task 19 canonical.sign -> Task 21 middleware chain.
    """
    if ts_ms is None:
        c = clock or time.time
        ts_ms = int(c() * 1000)

    sig = canonical.sign(
        secret=agent.secret,
        method=method,
        path=path,
        timestamp=str(ts_ms),
        nonce=nonce,
        body=body,
    )
    headers = {
        HEADER_AUTH: f"FLXP1 {agent.agent_id}:{sig}",
        HEADER_TIMESTAMP: str(ts_ms),
        HEADER_NONCE: nonce,
    }
    if idem_key is not None:
        headers[HEADER_IDEMPOTENCY] = idem_key
    elif method.upper() == "POST":
        headers[HEADER_IDEMPOTENCY] = f"idem-{uuid4().hex[:16]}"
    return headers


def build_integration_app(
    resolver: AgentResolver,
    runner: GateRunner,
    settings: Settings,
    clock: Callable[[], float] = time.time,
    received_state: dict[str, Any] | None = None,
) -> Starlette:
    """Construct Starlette app with dummy business endpoints."""

    async def dummy_payments(request: Request) -> JSONResponse:
        body = await request.body()
        if received_state is not None:
            received_state["body"] = body
            received_state["agent"] = request.state.agent
            received_state["request_id"] = request.state.request_id
        return JSONResponse(
            {"status": "created", "agent_id": str(request.state.agent.agent_id)},
            status_code=201,
        )

    async def dummy_balance(request: Request) -> JSONResponse:
        return JSONResponse({"balance": 50000}, status_code=200)

    app = Starlette(
        routes=[
            Route("/v1/payments", dummy_payments, methods=["POST"]),
            Route("/v1/balance", dummy_balance, methods=["GET"]),
        ],
    )
    app.add_middleware(
        GatewayMiddleware,
        resolver=resolver,
        runner=runner,
        settings=settings,
        clock=clock,
    )
    return app


# ---------------------------------------------------------------------------
# 1. HAPPY PATH & BODY CACHE CONTRACT
# ---------------------------------------------------------------------------


async def test_pipeline_happy_path_and_body_cache_contract(gate_runner: GateRunner) -> None:
    """Validate valid signed request passes full pipeline and handler sees identical bytes.

    BaseHTTPMiddleware caches request._body: downstream handlers calling await request.body()
    MUST read the identical bytes verified by the HMAC stage.
    """
    agent = make_agent()
    resolver = InMemAgentResolver({agent.agent_id: agent})
    settings = make_integration_settings()
    handler_state: dict[str, Any] = {}
    app = build_integration_app(resolver, gate_runner, settings, received_state=handler_state)

    payload = (
        b'{"amount": 5000, "currency": "USDC", "recipient": "018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e"}'
    )
    headers = build_signed_request(
        agent,
        "POST",
        "/v1/payments",
        payload,
        nonce="noncehappy00112233",
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/v1/payments", headers=headers, content=payload)

    assert res.status_code == 201
    assert res.json()["status"] == "created"
    assert res.json()["agent_id"] == str(agent.agent_id)
    assert HEADER_REQUEST_ID in res.headers

    # BaseHTTPMiddleware body cache contract proof: handler received identical raw bytes
    assert handler_state["body"] == payload
    assert handler_state["agent"].agent_id == agent.agent_id
    assert handler_state["request_id"] == res.headers[HEADER_REQUEST_ID]


# ---------------------------------------------------------------------------
# 2. NONCE BURN & REAL REPLAY PREVENTED
# ---------------------------------------------------------------------------


async def test_pipeline_nonce_burn_rejects_replay(gate_runner: GateRunner) -> None:
    """Validate replaying an identical request is rejected by Valkey nonce tombstone."""
    agent = make_agent()
    resolver = InMemAgentResolver({agent.agent_id: agent})
    settings = make_integration_settings()
    app = build_integration_app(resolver, gate_runner, settings)

    payload = b'{"transfer_id": "tx_01"}'
    headers = build_signed_request(
        agent,
        "POST",
        "/v1/payments",
        payload,
        nonce="noncetombstone0001",
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # First request succeeds
        res1 = await client.post("/v1/payments", headers=headers, content=payload)
        assert res1.status_code == 201

        # Replayed identical request fails at Gate Stage 7 (nonce tombstone)
        res2 = await client.post("/v1/payments", headers=headers, content=payload)
        assert res2.status_code == 401
        payload_err = res2.json()
        assert payload_err["error"]["code"] == "replay_detected"
        assert payload_err["error"]["retryable"] is False


# ---------------------------------------------------------------------------
# 3. PER-AGENT RATE & QUOTA LIMIT EXHAUSTION
# ---------------------------------------------------------------------------


async def test_pipeline_rate_exhaustion_maps_to_429(gate_runner: GateRunner) -> None:
    """Validate per-agent rate limit: 4th request within window returns 429 rate_limited."""
    agent = make_agent(rate_limit_max=3)  # Max 3 requests per sliding window
    resolver = InMemAgentResolver({agent.agent_id: agent})
    settings = make_integration_settings(rate_limit_window_ms=60_000)
    app = build_integration_app(resolver, gate_runner, settings)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        for i in range(3):
            headers = build_signed_request(
                agent,
                "GET",
                "/v1/balance",
                b"",
                nonce=f"noncerate000{i}abcd",
            )
            res = await client.get("/v1/balance", headers=headers)
            assert res.status_code == 200, f"Request {i + 1} failed"

        # 4th request exceeds rate limit
        h_exhaust = build_signed_request(
            agent,
            "GET",
            "/v1/balance",
            b"",
            nonce="noncerate0003excd",
        )
        res_exhaust = await client.get("/v1/balance", headers=h_exhaust)
        assert res_exhaust.status_code == 429
        assert res_exhaust.json()["error"]["code"] == "rate_limited"
        assert res_exhaust.json()["error"]["retryable"] is True


async def test_pipeline_daily_quota_exhaustion_maps_to_429_generic(
    gate_runner: GateRunner,
) -> None:
    """Validate per-agent daily quota: 3rd request with quota=2 returns generic 429."""
    agent = make_agent(rate_limit_max=100, daily_quota_max=2)  # Quota cap is 2
    resolver = InMemAgentResolver({agent.agent_id: agent})
    settings = make_integration_settings()
    app = build_integration_app(resolver, gate_runner, settings)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        for i in range(2):
            headers = build_signed_request(
                agent,
                "GET",
                "/v1/balance",
                b"",
                nonce=f"noncequota00{i}abcd",
            )
            res = await client.get("/v1/balance", headers=headers)
            assert res.status_code == 200

        # 3rd request exceeds daily quota
        h_quota = build_signed_request(
            agent,
            "GET",
            "/v1/balance",
            b"",
            nonce="noncequota002excd",
        )
        res_quota = await client.get("/v1/balance", headers=h_quota)
        assert res_quota.status_code == 429
        payload = res_quota.json()
        # Financial policy details hidden: client sees generic rate_limited
        assert payload["error"]["code"] == "rate_limited"
        assert payload["error"]["retryable"] is True
        assert "quota" not in payload["error"]["message"].lower()


# ---------------------------------------------------------------------------
# 4. TAMPER MATRIX (Cryptographic Invariants & Agent ID Swap)
# ---------------------------------------------------------------------------


async def test_pipeline_tamper_matrix_all_rejected(gate_runner: GateRunner) -> None:
    """Validate tamper matrix: flipping body, path, sig, or swapping agent_id all yield 401.

    AGENT ID SWAP REASONING (Task 19 PROVEN):
    agent_id is excluded from canonical bytes because it acts as the vault routing key.
    When agent_id is swapped in the Authorization header, the resolver returns the other
    agent's secret. Verification recomputes HMAC using the wrong key, producing an
    immediate cryptographic mismatch.
    """
    agent_a = make_agent(secret_bytes=b"secret-for-agent-aaa-32-bytes!!!")
    agent_b = make_agent(secret_bytes=b"secret-for-agent-bbb-32-bytes!!!")
    resolver = InMemAgentResolver(
        {
            agent_a.agent_id: agent_a,
            agent_b.agent_id: agent_b,
        }
    )
    settings = make_integration_settings()
    app = build_integration_app(resolver, gate_runner, settings)

    valid_body = b'{"action": "tamper_test"}'
    base_headers = build_signed_request(
        agent_a,
        "POST",
        "/v1/payments",
        valid_body,
        nonce="noncetamper0001ab",
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Case 1: Flip one body byte
        tampered_body = b'{"action": "tamper_tesu"}'
        res_body = await client.post("/v1/payments", headers=base_headers, content=tampered_body)
        assert res_body.status_code == 401
        assert res_body.json()["error"]["code"] == "authentication_failed"

        # Case 2: Flip one path character (send to /v1/payments/x)
        res_path = await client.post("/v1/payments/x", headers=base_headers, content=valid_body)
        assert res_path.status_code == 401
        assert res_path.json()["error"]["code"] == "authentication_failed"

        # Case 3: Truncate signature
        h_truncated = dict(base_headers)
        h_truncated[HEADER_AUTH] = base_headers[HEADER_AUTH][:-1]
        res_trunc = await client.post("/v1/payments", headers=h_truncated, content=valid_body)
        assert res_trunc.status_code == 401
        assert res_trunc.json()["error"]["code"] == "authentication_failed"

        # Case 4: Swap agent_id in header (keep Agent A's signature, claim to be Agent B)
        sig_a = base_headers[HEADER_AUTH].split(":")[1]
        h_swapped = dict(base_headers)
        h_swapped[HEADER_AUTH] = f"FLXP1 {agent_b.agent_id}:{sig_a}"
        res_swap = await client.post("/v1/payments", headers=h_swapped, content=valid_body)
        assert res_swap.status_code == 401
        assert res_swap.json()["error"]["code"] == "authentication_failed"


# ---------------------------------------------------------------------------
# 5. GATE UNAVAILABLE (Fail-Closed 503)
# ---------------------------------------------------------------------------


async def test_pipeline_gate_unavailable_fail_closed() -> None:
    """Validate that when Valkey is down/unreachable, gate fails closed with 503 retryable."""
    agent = make_agent()
    resolver = InMemAgentResolver({agent.agent_id: agent})
    settings = make_integration_settings()

    # Point at a dead port to simulate Valkey outage
    dead_client = redis_async.Redis.from_url(
        "redis://localhost:6399/15",
        socket_connect_timeout=0.2,
        socket_timeout=0.2,
    )
    dead_runner = GateRunner(dead_client)
    app = build_integration_app(resolver, dead_runner, settings)

    headers = build_signed_request(
        agent,
        "GET",
        "/v1/balance",
        b"",
        nonce="noncedeadvalkey01",
    )

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            res = await client.get("/v1/balance", headers=headers)

        assert res.status_code == 503
        payload = res.json()
        assert payload["error"]["code"] == "gate_unavailable"
        assert payload["error"]["retryable"] is True
    finally:
        await dead_client.aclose()


# ---------------------------------------------------------------------------
# 6. STALE TIMESTAMP END-TO-END (Real Wall Clock)
# ---------------------------------------------------------------------------


async def test_pipeline_stale_timestamp_real_clock(gate_runner: GateRunner) -> None:
    """Validate timestamp freshness check fails with real wall-clock time."""
    agent = make_agent()
    resolver = InMemAgentResolver({agent.agent_id: agent})
    settings = make_integration_settings(replay_window_ms=30_000)
    app = build_integration_app(resolver, gate_runner, settings, clock=time.time)

    # Timestamp crafted 31 seconds in the past
    stale_ts = int((time.time() - 31.0) * 1000)
    headers = build_signed_request(
        agent,
        "GET",
        "/v1/balance",
        b"",
        nonce="noncestalereal01",
        ts_ms=stale_ts,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.get("/v1/balance", headers=headers)

    assert res.status_code == 401
    assert res.json()["error"]["code"] == "replay_detected"


# ---------------------------------------------------------------------------
# 7. LOG CORRELATION (ContextVar Binding Proof)
# ---------------------------------------------------------------------------


async def test_pipeline_log_correlation_captures_context_on_401(
    gate_runner: GateRunner,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validate structlog context capture: request_id AND agent_id captured on 401 path."""
    agent = make_agent()
    resolver = InMemAgentResolver({agent.agent_id: agent})
    settings = make_integration_settings()
    app = build_integration_app(resolver, gate_runner, settings)

    # Configure structured logging with valid environment
    monkeypatch.setenv("FLX_PG_DSN", "postgresql://test:test@localhost:5432/test")
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", base64.b64encode(b"0" * 32).decode("ascii"))
    monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", "a" * 32)
    monkeypatch.setenv("FLX_ENV", "production")
    monkeypatch.setenv("FLX_LOG_LEVEL", "INFO")

    from fluxpay.config import get_settings

    get_settings.cache_clear()
    configure_logging()
    root_logger = logging.getLogger()
    if root_logger.handlers:
        caplog.handler.setFormatter(root_logger.handlers[0].formatter)
    root_logger.addHandler(caplog.handler)
    caplog.set_level(logging.INFO)

    # Craft request that passes Stage 3 (agent resolved) but fails Stage 4 (stale ts)
    stale_ts = int((time.time() - 40.0) * 1000)
    headers = build_signed_request(
        agent,
        "GET",
        "/v1/balance",
        b"",
        nonce="noncelogcapture01",
        ts_ms=stale_ts,
    )

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            res = await client.get("/v1/balance", headers=headers)

        assert res.status_code == 401
        req_id = res.headers[HEADER_REQUEST_ID]

        # Assert caplog captured the structured JSON log entry
        matching_lines = [
            line
            for line in caplog.text.splitlines()
            if req_id in line and str(agent.agent_id) in line
        ]
        assert len(matching_lines) >= 1, (
            f"Expected JSON log with req_id={req_id} and agent_id={agent.agent_id}\n"
            f"in captured logs:\n{caplog.text}"
        )

        parsed = orjson.loads(matching_lines[0])
        assert parsed["request_id"] == req_id
        assert parsed["agent_id"] == str(agent.agent_id)
        assert parsed["error_code"] == "replay_detected"
        assert parsed["status_code"] == 401

    finally:
        clear_request_context()
