"""Unit tests for GatewayMiddleware mandatory security pipeline.

Tests verify:
- Pipeline ORDER proofs: short-circuiting ensures earlier stages protect later stages.
- Complete error mapping matrix to frozen wire shape.
- Freshness boundary conditions with injected clock (== passes, strict > fails).
- Body size limits (64 KiB rejected, 64 KiB - 1 accepted).
- POST idempotency presence and syntax validation.
- Gate result mapping (generic client surface, details hidden).
- Clock injection proof (zero time monkeypatching).
- X-FLX-Request-Id attached on success AND errors.
- Pass-through scope for unauthenticated routes (/healthz).
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
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
from fluxpay.gateway.gate import GateResult, GateRunner
from fluxpay.gateway.middleware import (
    HEADER_REQUEST_ID,
    MAX_BODY_BYTES,
    AgentResolver,
    AuthenticatedAgent,
    GatewayMiddleware,
)
from fluxpay.shared.errors import GateUnavailable
from fluxpay.shared.vault import SecretBytes

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Test Helpers & Stubs (The Seam Payoff)
# ---------------------------------------------------------------------------


class StubAgentResolver:
    """In-memory stub implementing AgentResolver Protocol for zero-DB testing."""

    def __init__(self, agents: dict[UUID, AuthenticatedAgent] | None = None) -> None:
        self.agents: dict[UUID, AuthenticatedAgent] = agents or {}
        self.calls: list[UUID] = []
        self.raise_exc: Exception | None = None

    async def resolve(self, agent_id: UUID) -> AuthenticatedAgent | None:
        self.calls.append(agent_id)
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.agents.get(agent_id)


class StubGateRunner(GateRunner):
    """Stub implementing GateRunner interface with recorded calls and controllable verdicts."""

    def __init__(
        self,
        result: GateResult | None = None,
        exc: Exception | None = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.result: GateResult = result if result is not None else GateResult.from_code(1, 1, 1)
        self.exc: Exception | None = exc

    async def run(
        self,
        *,
        agent_id: str,
        nonce: str,
        now_ms: int,
        window_ms: int,
        rate_max: int,
        nonce_ttl_ms: int,
        daily_max: int,
        day_ttl_s: int,
    ) -> GateResult:
        self.calls.append(
            {
                "agent_id": agent_id,
                "nonce": nonce,
                "now_ms": now_ms,
                "window_ms": window_ms,
                "rate_max": rate_max,
                "nonce_ttl_ms": nonce_ttl_ms,
                "daily_max": daily_max,
                "day_ttl_s": day_ttl_s,
            }
        )
        if self.exc is not None:
            raise self.exc
        return self.result


def make_test_settings(
    replay_window_ms: int = 30_000,
    rate_limit_window_ms: int = 60_000,
    rate_limit_max: int = 100,
    daily_quota_max: int = 10_000,
    nonce_ttl_ms: int = 120_000,
) -> Settings:
    """Create immutable test settings instance."""
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


def make_test_agent(
    agent_id: UUID | None = None,
    secret_bytes: bytes = b"test-secret-key-32-bytes-long!!",
    rate_limit_max: int = 10,
    daily_quota_max: int = 100,
) -> AuthenticatedAgent:
    """Create test AuthenticatedAgent with wipeable SecretBytes."""
    return AuthenticatedAgent(
        agent_id=agent_id if agent_id is not None else uuid4(),
        external_id="agent_test_ext_01",
        secret=SecretBytes(secret_bytes),
        rate_limit_max=rate_limit_max,
        daily_quota_max=daily_quota_max,
    )


def make_signed_headers(
    agent: AuthenticatedAgent,
    method: str,
    path: str,
    body: bytes,
    *,
    nonce: str = "testnonce0123456789",
    ts_ms: int = 1774483200000,
    idem_key: str | None = None,
) -> dict[str, str]:
    """Helper to generate strictly valid FLXP1 signed request headers."""
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
        headers[HEADER_IDEMPOTENCY] = "test-idempotency-key-01"
    return headers


def create_test_app(
    resolver: AgentResolver,
    runner: GateRunner,
    settings: Settings,
    clock: Callable[[], float],
) -> Starlette:
    """Build dummy Starlette application with GatewayMiddleware mounted."""

    async def dummy_healthz(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    async def dummy_payments(request: Request) -> JSONResponse:
        body = await request.body()
        return JSONResponse({"status": "paid", "size": len(body)}, status_code=201)

    async def dummy_balance(request: Request) -> JSONResponse:
        return JSONResponse({"balance": 1000}, status_code=200)

    app = Starlette(
        routes=[
            Route("/healthz", dummy_healthz, methods=["GET"]),
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
# 1. ORDER PROOFS (Short-Circuit Call-Recorder Assertions)
# ---------------------------------------------------------------------------


async def test_order_unknown_agent_short_circuits() -> None:
    """Validate unknown agent fails at Stage 3: resolve called, gate NEVER invoked."""
    agent = make_test_agent()
    resolver = StubAgentResolver()  # Empty: will return None
    runner = StubGateRunner()
    frozen_clock = lambda: 1774483200.0  # noqa: E731
    settings = make_test_settings()
    app = create_test_app(resolver, runner, settings, frozen_clock)

    headers = make_signed_headers(agent, "GET", "/v1/balance", b"")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.get("/v1/balance", headers=headers)

    assert res.status_code == 401
    assert res.json()["error"]["code"] == "authentication_failed"
    # Order proof: resolver was asked to resolve, but gate was NEVER reached
    assert resolver.calls == [agent.agent_id]
    assert runner.calls == []


async def test_order_stale_timestamp_short_circuits() -> None:
    """Validate stale timestamp fails at Stage 4: resolve called, gate NOT called."""
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = StubGateRunner()
    now_ms = 1774483200000
    stale_ts_ms = now_ms - 31_000  # Outside 30s window
    frozen_clock = lambda: now_ms / 1000.0  # noqa: E731
    settings = make_test_settings(replay_window_ms=30_000)
    app = create_test_app(resolver, runner, settings, frozen_clock)

    headers = make_signed_headers(agent, "GET", "/v1/balance", b"", ts_ms=stale_ts_ms)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.get("/v1/balance", headers=headers)

    assert res.status_code == 401
    assert res.json()["error"]["code"] == "replay_detected"
    # Order proof: resolved ok, but rejected at Stage 4 before HMAC/gate
    assert resolver.calls == [agent.agent_id]
    assert runner.calls == []


async def test_order_hmac_failure_short_circuits() -> None:
    """Validate signature mismatch fails at Stage 5: resolve called, gate NOT called."""
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = StubGateRunner()
    frozen_clock = lambda: 1774483200.0  # noqa: E731
    settings = make_test_settings()
    app = create_test_app(resolver, runner, settings, frozen_clock)

    headers = make_signed_headers(agent, "GET", "/v1/balance", b"")
    # Tamper with signature
    headers[HEADER_AUTH] = f"FLXP1 {agent.agent_id}:" + "0" * 64

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.get("/v1/balance", headers=headers)

    assert res.status_code == 401
    assert res.json()["error"]["code"] == "authentication_failed"
    # Order proof: resolver called, Freshness passed, HMAC rejected -> Gate NEVER reached
    assert resolver.calls == [agent.agent_id]
    assert runner.calls == []


async def test_order_body_size_short_circuits_before_gate() -> None:
    """Validate oversized body fails at Stage 6: resolver called, gate NOT called."""
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = StubGateRunner()
    frozen_clock = lambda: 1774483200.0  # noqa: E731
    settings = make_test_settings()
    app = create_test_app(resolver, runner, settings, frozen_clock)

    # 64 KiB body = MAX_BODY_BYTES
    oversized_body = b"a" * MAX_BODY_BYTES
    headers = make_signed_headers(agent, "POST", "/v1/payments", oversized_body)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/v1/payments", headers=headers, content=oversized_body)

    assert res.status_code == 422
    assert res.json()["error"]["code"] == "validation_failed"
    # Order proof: HMAC was valid, but body size check rejected before gate
    assert resolver.calls == [agent.agent_id]
    assert runner.calls == []


# ---------------------------------------------------------------------------
# 2. ERROR MAPPING MATRIX & SANITIZATION
# ---------------------------------------------------------------------------


async def test_unexpected_resolver_exception_mapped_to_500_without_leak() -> None:
    """Validate unexpected resolver exception maps to internal_error without leaking details."""
    agent = make_test_agent()
    resolver = StubAgentResolver()
    resolver.raise_exc = ValueError("CRITICAL_DATABASE_SECRET_CREDENTIALS_EXPLODED")
    runner = StubGateRunner()
    frozen_clock = lambda: 1774483200.0  # noqa: E731
    settings = make_test_settings()
    app = create_test_app(resolver, runner, settings, frozen_clock)

    headers = make_signed_headers(agent, "GET", "/v1/balance", b"")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.get("/v1/balance", headers=headers)

    assert res.status_code == 500
    payload = res.json()
    assert payload == {
        "error": {
            "code": "internal_error",
            "message": "An internal server error occurred.",
            "retryable": False,
        }
    }
    # Security totality rule: raw exception string is ABSENT from payload
    assert "CRITICAL_DATABASE_SECRET" not in res.text


# ---------------------------------------------------------------------------
# 3. PASS-THROUGH SCOPE (/healthz vs /v1/)
# ---------------------------------------------------------------------------


async def test_pass_through_scope_unauthenticated() -> None:
    """Validate routes outside /v1/ pass through untouched without auth or gate calls."""
    resolver = StubAgentResolver()
    runner = StubGateRunner()
    frozen_clock = lambda: 1774483200.0  # noqa: E731
    settings = make_test_settings()
    app = create_test_app(resolver, runner, settings, frozen_clock)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.get("/healthz")

    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert resolver.calls == []
    assert runner.calls == []
    assert HEADER_REQUEST_ID in res.headers


# ---------------------------------------------------------------------------
# 4. QUERY STRING REJECTION RULE
# ---------------------------------------------------------------------------


async def test_query_string_rejection_even_with_valid_signature() -> None:
    """Validate query strings on /v1/ endpoints are rejected with 401."""
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = StubGateRunner()
    frozen_clock = lambda: 1774483200.0  # noqa: E731
    settings = make_test_settings()
    app = create_test_app(resolver, runner, settings, frozen_clock)

    headers = make_signed_headers(agent, "GET", "/v1/balance", b"")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.get("/v1/balance?filter=active", headers=headers)

    assert res.status_code == 401
    assert res.json()["error"]["code"] == "authentication_failed"
    assert resolver.calls == []
    assert runner.calls == []


# ---------------------------------------------------------------------------
# 5. FRESHNESS BOUNDARIES (== passes, strict > fails)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("offset_ms", "should_pass"),
    [
        (-29_999, True),  # Inside window
        (-30_000, True),  # Exact boundary: == window PASSES
        (-30_001, False),  # 1ms outside: FAILS
        (0, True),  # Exact match
        (29_999, True),  # Future inside window
        (30_000, True),  # Future exact boundary: == PASSES
        (30_001, False),  # Future 1ms outside: FAILS (symmetry)
    ],
)
async def test_freshness_boundaries_exact(offset_ms: int, should_pass: bool) -> None:
    """Validate freshness window boundary semantics with frozen clock."""
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = StubGateRunner()
    now_ms = 1774483200000
    frozen_clock = lambda: now_ms / 1000.0  # noqa: E731
    settings = make_test_settings(replay_window_ms=30_000)
    app = create_test_app(resolver, runner, settings, frozen_clock)

    req_ts_ms = now_ms + offset_ms
    headers = make_signed_headers(agent, "GET", "/v1/balance", b"", ts_ms=req_ts_ms)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.get("/v1/balance", headers=headers)

    if should_pass:
        assert res.status_code == 200
        assert res.json() == {"balance": 1000}
    else:
        assert res.status_code == 401
        assert res.json()["error"]["code"] == "replay_detected"


# ---------------------------------------------------------------------------
# 6. BODY SIZE BOUNDARIES (64 KiB vs 64 KiB - 1)
# ---------------------------------------------------------------------------


async def test_body_size_boundary_acceptance_and_rejection() -> None:
    """Validate body size: 64 KiB rejected (422), 64 KiB - 1 accepted (201)."""
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = StubGateRunner()
    frozen_clock = lambda: 1774483200.0  # noqa: E731
    settings = make_test_settings()
    app = create_test_app(resolver, runner, settings, frozen_clock)

    # 1. 64 KiB - 1 (65535 bytes) -> PASSES
    accepted_body = b"x" * (MAX_BODY_BYTES - 1)
    headers_ok = make_signed_headers(agent, "POST", "/v1/payments", accepted_body)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res_ok = await client.post("/v1/payments", headers=headers_ok, content=accepted_body)

    assert res_ok.status_code == 201
    assert res_ok.json()["size"] == MAX_BODY_BYTES - 1

    # 2. 64 KiB (65536 bytes) -> REJECTED (422)
    rejected_body = b"x" * MAX_BODY_BYTES
    headers_reject = make_signed_headers(agent, "POST", "/v1/payments", rejected_body)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res_reject = await client.post(
            "/v1/payments", headers=headers_reject, content=rejected_body
        )

    assert res_reject.status_code == 422
    assert res_reject.json()["error"]["code"] == "validation_failed"


# ---------------------------------------------------------------------------
# 7. POST IDEMPOTENCY PRESENCE
# ---------------------------------------------------------------------------


async def test_post_idempotency_presence_validation() -> None:
    """Validate presence and format requirements for X-FLX-Idempotency-Key on POST."""
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = StubGateRunner()
    frozen_clock = lambda: 1774483200.0  # noqa: E731
    settings = make_test_settings()
    app = create_test_app(resolver, runner, settings, frozen_clock)

    body = b'{"amount": 100}'

    # 1. Missing header on POST -> 422
    headers_no_key = make_signed_headers(agent, "POST", "/v1/payments", body)
    del headers_no_key[HEADER_IDEMPOTENCY]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/v1/payments", headers=headers_no_key, content=body)
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "validation_failed"

    # 2. Too short key (< 16 chars) -> 422
    headers_short = make_signed_headers(agent, "POST", "/v1/payments", body, idem_key="short-key")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/v1/payments", headers=headers_short, content=body)
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "validation_failed"

    # 3. Contains underscore (forbidden by canonical syntax) -> 422
    headers_underscore = make_signed_headers(
        agent, "POST", "/v1/payments", body, idem_key="valid-length_with_underscore-1234"
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/v1/payments", headers=headers_underscore, content=body)
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "validation_failed"

    # 4. Valid format -> 201
    headers_valid = make_signed_headers(
        agent, "POST", "/v1/payments", body, idem_key="valid-idempotency-key-0123"
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.post("/v1/payments", headers=headers_valid, content=body)
    assert res.status_code == 201


# ---------------------------------------------------------------------------
# 8. GATE RESULT MAPPING (Generic Client Surface)
# ---------------------------------------------------------------------------


async def test_gate_replayed_maps_to_401_replay_detected() -> None:
    """Validate gate returning replayed maps to 401 replay_detected."""
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = StubGateRunner(result=GateResult.from_code(-1, 0, 0))
    frozen_clock = lambda: 1774483200.0  # noqa: E731
    settings = make_test_settings()
    app = create_test_app(resolver, runner, settings, frozen_clock)

    headers = make_signed_headers(agent, "GET", "/v1/balance", b"")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.get("/v1/balance", headers=headers)

    assert res.status_code == 401
    payload = res.json()
    assert payload["error"]["code"] == "replay_detected"
    assert payload["error"]["retryable"] is False


async def test_gate_rate_limited_maps_to_429() -> None:
    """Validate gate returning rate_limited maps to 429 retryable."""
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = StubGateRunner(result=GateResult.from_code(-2, 11, 50))
    frozen_clock = lambda: 1774483200.0  # noqa: E731
    settings = make_test_settings()
    app = create_test_app(resolver, runner, settings, frozen_clock)

    headers = make_signed_headers(agent, "GET", "/v1/balance", b"")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.get("/v1/balance", headers=headers)

    assert res.status_code == 429
    payload = res.json()
    assert payload["error"]["code"] == "rate_limited"
    assert payload["error"]["retryable"] is True
    # Internal counts are NOT exposed to external client
    assert "11" not in res.text


async def test_gate_quota_exceeded_maps_to_429_generic() -> None:
    """Validate gate returning quota_exceeded maps to generic 429 rate_limited."""
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = StubGateRunner(result=GateResult.from_code(-3, 5, 101))
    frozen_clock = lambda: 1774483200.0  # noqa: E731
    settings = make_test_settings()
    app = create_test_app(resolver, runner, settings, frozen_clock)

    headers = make_signed_headers(agent, "GET", "/v1/balance", b"")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.get("/v1/balance", headers=headers)

    assert res.status_code == 429
    payload = res.json()
    # Financial policy details hidden: client sees generic rate_limited
    assert payload["error"]["code"] == "rate_limited"
    assert payload["error"]["retryable"] is True
    assert "quota" not in payload["error"]["message"].lower()


async def test_gate_unavailable_maps_to_503_retryable() -> None:
    """Validate GateUnavailable exception maps to 503 retryable fail-closed."""
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = StubGateRunner(exc=GateUnavailable(details={"reason": "connection_refused"}))
    frozen_clock = lambda: 1774483200.0  # noqa: E731
    settings = make_test_settings()
    app = create_test_app(resolver, runner, settings, frozen_clock)

    headers = make_signed_headers(agent, "GET", "/v1/balance", b"")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        res = await client.get("/v1/balance", headers=headers)

    assert res.status_code == 503
    payload = res.json()
    assert payload["error"]["code"] == "gate_unavailable"
    assert payload["error"]["retryable"] is True


# ---------------------------------------------------------------------------
# 9. CLOCK INJECTION PROOF (Zero Monkeypatching)
# ---------------------------------------------------------------------------


async def test_clock_injection_proves_no_time_monkeypatch() -> None:
    """Validate that swapping injected clock flips freshness verdict with NO monkeypatching."""
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = StubGateRunner()
    settings = make_test_settings(replay_window_ms=30_000)

    fixed_request_ts_ms = 1774483200000
    headers = make_signed_headers(agent, "GET", "/v1/balance", b"", ts_ms=fixed_request_ts_ms)

    # Clock 1: synchronized with request timestamp -> PASSES
    clock_sync = lambda: fixed_request_ts_ms / 1000.0  # noqa: E731
    app_sync = create_test_app(resolver, runner, settings, clock_sync)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_sync), base_url="http://test"
    ) as client:
        res_sync = await client.get("/v1/balance", headers=headers)
    assert res_sync.status_code == 200

    # Clock 2: 120 seconds in future -> FAILS (stale)
    clock_future = lambda: (fixed_request_ts_ms + 120_000) / 1000.0  # noqa: E731
    app_future = create_test_app(resolver, runner, settings, clock_future)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_future), base_url="http://test"
    ) as client:
        res_future = await client.get("/v1/balance", headers=headers)
    assert res_future.status_code == 401
    assert res_future.json()["error"]["code"] == "replay_detected"


# ---------------------------------------------------------------------------
# 10. REQUEST ID CORRELATION HEADER
# ---------------------------------------------------------------------------


async def test_request_id_present_on_success_and_all_error_codes() -> None:
    """Validate X-FLX-Request-Id header is unconditionally attached to all responses."""
    agent = make_test_agent()
    resolver = StubAgentResolver({agent.agent_id: agent})
    runner = StubGateRunner()
    frozen_clock = lambda: 1774483200.0  # noqa: E731
    settings = make_test_settings()
    app = create_test_app(resolver, runner, settings, frozen_clock)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Success (200)
        h_ok = make_signed_headers(agent, "GET", "/v1/balance", b"")
        res_ok = await client.get("/v1/balance", headers=h_ok)
        assert res_ok.status_code == 200
        assert HEADER_REQUEST_ID in res_ok.headers
        assert len(res_ok.headers[HEADER_REQUEST_ID]) == 32

        # 401 Unauthorized
        res_401 = await client.get("/v1/balance")
        assert res_401.status_code == 401
        assert HEADER_REQUEST_ID in res_401.headers

        # 422 Validation Error (missing idempotency key on POST)
        h_no_key = make_signed_headers(agent, "POST", "/v1/payments", b"{}")
        del h_no_key[HEADER_IDEMPOTENCY]
        res_422 = await client.post("/v1/payments", headers=h_no_key, content=b"{}")
        assert res_422.status_code == 422
        assert HEADER_REQUEST_ID in res_422.headers
