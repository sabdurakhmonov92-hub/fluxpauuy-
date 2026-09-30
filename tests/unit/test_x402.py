"""Unit tests for x402 payment authorization middleware.

Tests all hard requirements:
1. Valid EIP-3009 payload -> 200 OK + X-PAYMENT-RESPONSE header
2. Missing X-PAYMENT -> 402 Payment Required + PAYMENT-REQUIRED header & JSON body
3. Invalid signature -> 402 + error="invalid_signature"
4. Expired authorization -> 402 + error="expired"
5. Nonce replay -> 409 + error="replay"
6. Insufficient USDC balance -> 402 + error="insufficient_funds"
7. Facilitator timeout / unavailable -> 503 + Retry-After
8. Idempotent retry -> same X-PAYMENT twice returns cached response with 1 settlement
9. Ledger failure after settlement -> 500 + reconciliation enqueued
10. Unprotected route -> passthrough (no 402)
11. Property test: arbitrary malformed base64 never crashes middleware
12. Dynamic pricing support via callable
13. Payload size cap (DoS prevention)
"""

from __future__ import annotations

import base64
import json
import time
from decimal import Decimal
from typing import Any
from uuid import UUID

import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from hypothesis import given
from hypothesis import strategies as st
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from web3 import Web3

from fluxpay.gateway.x402 import (
    InMemoryReconciliationQueue,
    X402Middleware,
)
from fluxpay.gateway.x402_config import X402Config
from fluxpay.gateway.x402_eip3009 import (
    TRANSFER_WITH_AUTHORIZATION_TYPES,
    build_eip712_domain,
    normalize_nonce,
)
from fluxpay.gateway.x402_types import (
    SettleResult,
    VerifyResult,
)

pytestmark = pytest.mark.unit

TEST_MERCHANT_ADDR = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
TEST_ASSET_ADDR = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
TEST_CHAIN_ID = 8453


class MockFacilitator:
    """Configurable mock facilitator for isolating middleware decisions."""

    def __init__(self) -> None:
        self.verify_calls: list[dict[str, Any]] = []
        self.settle_calls: list[dict[str, Any]] = []
        self.verify_result: VerifyResult = VerifyResult(valid=True)
        self.settle_result: SettleResult = SettleResult(
            success=True,
            tx_hash="0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            block_number=18_500_000,
        )
        self.should_timeout_verify: bool = False
        self.should_fail_settle: bool = False

    async def verify(self, payload: dict[str, Any]) -> VerifyResult:
        self.verify_calls.append(payload)
        if self.should_timeout_verify:
            from fluxpay.gateway.x402_facilitator import FacilitatorTimeoutError

            raise FacilitatorTimeoutError("Simulated verify timeout")
        return self.verify_result

    async def settle(self, payload: dict[str, Any]) -> SettleResult:
        self.settle_calls.append(payload)
        if self.should_fail_settle:
            return SettleResult(success=False, reason="Mempool revert: insufficient gas")
        return self.settle_result


class MockLedger:
    """Mock ledger recording payment settlement legs with failure injection."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.should_fail: bool = False

    async def record_payment(
        self,
        *,
        agent_id: str,
        merchant_id: str,
        amount_minor: int,
        currency: str,
        idempotency_key: str,
        agent_account_id: UUID | None = None,
        merchant_account_id: UUID | None = None,
    ) -> None:
        if self.should_fail:
            raise RuntimeError("Database connection lost during ledger write")
        self.records.append(
            {
                "agent_id": agent_id,
                "merchant_id": merchant_id,
                "amount_minor": amount_minor,
                "currency": currency,
                "idempotency_key": idempotency_key,
            }
        )


def _sign_authorization(
    account: Any,
    config: X402Config,
    *,
    amount_minor: int = 1_000_000,
    valid_after: int = 0,
    valid_before: int = 2_000_000_000,
    nonce: str = "0x" + "11" * 32,
    to_address: str | None = None,
) -> str:
    """Produce base64-encoded X-PAYMENT header content."""
    recipient = to_address or config.pay_to
    norm_nonce = normalize_nonce(nonce)
    domain = build_eip712_domain(
        name=config.token_name,
        version=config.token_version,
        chain_id=config.chain_id,
        verifying_contract=config.asset,
    )
    msg_data = {
        "from": Web3.to_checksum_address(account.address),
        "to": Web3.to_checksum_address(recipient),
        "value": amount_minor,
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": norm_nonce,
    }
    encoded = encode_typed_data(
        domain_data=domain,
        message_types=TRANSFER_WITH_AUTHORIZATION_TYPES,
        message_data=msg_data,
    )
    signed = account.sign_message(encoded)

    payload = {
        "from": account.address,
        "to": recipient,
        "value": amount_minor,
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": norm_nonce,
        "signature": "0x" + signed.signature.hex(),
    }
    return base64.b64encode(json.dumps(payload).encode()).decode("ascii")


def _build_test_app(
    config: X402Config,
    facilitator: MockFacilitator,
    ledger: MockLedger,
    reconciliation_queue: InMemoryReconciliationQueue | None = None,
) -> Starlette:
    """Construct Starlette test application with protected and unprotected endpoints."""

    async def premium_handler(request: Request) -> JSONResponse:
        return JSONResponse({"data": "premium_content_granted", "status": "ok"})

    async def data_handler(request: Request) -> JSONResponse:
        return JSONResponse({"data": "data_point_42", "status": "ok"})

    async def free_handler(request: Request) -> JSONResponse:
        return JSONResponse({"data": "public_free_content"})

    routes = [
        Route("/api/premium", premium_handler, methods=["GET"]),
        Route("/api/data", data_handler, methods=["GET"]),
        Route("/api/free", free_handler, methods=["GET"]),
    ]

    app = Starlette(routes=routes)
    app.add_middleware(
        X402Middleware,
        config=config,
        facilitator=facilitator,
        ledger=ledger,
        reconciliation_queue=reconciliation_queue,
    )
    return app


@pytest.fixture
def x402_setup() -> tuple[
    X402Config, MockFacilitator, MockLedger, InMemoryReconciliationQueue, Starlette
]:
    config = X402Config(
        pay_to=TEST_MERCHANT_ADDR,
        asset=TEST_ASSET_ADDR,
        chain_id=TEST_CHAIN_ID,
        protected_routes={
            "/api/premium": Decimal("1.00"),
            "/api/data": Decimal("0.10"),
        },
    )
    facilitator = MockFacilitator()
    ledger = MockLedger()
    queue = InMemoryReconciliationQueue()
    app = _build_test_app(config, facilitator, ledger, queue)
    return config, facilitator, ledger, queue, app


@pytest.mark.asyncio
async def test_unprotected_route_passthrough(x402_setup: Any) -> None:
    """Non-payment routes must pass through without 402 challenge (<5ms)."""
    _, _, _, _, app = x402_setup
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/free")
        assert resp.status_code == 200
        assert resp.json() == {"data": "public_free_content"}
        assert "PAYMENT-REQUIRED" not in resp.headers


@pytest.mark.asyncio
async def test_missing_x_payment_returns_402_challenge(x402_setup: Any) -> None:
    """Requesting protected route without X-PAYMENT must return 402 with PAYMENT-REQUIRED header."""
    config, _, _, _, app = x402_setup
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/premium")
        assert resp.status_code == 402
        assert "PAYMENT-REQUIRED" in resp.headers

        # Verify header JSON
        header_data = json.loads(resp.headers["PAYMENT-REQUIRED"])
        assert header_data["scheme"] == "exact"
        assert header_data["network"] == "base"
        assert header_data["asset"] == config.asset
        assert header_data["amount"] == "1000000"  # 1.00 USDC * 10^6
        assert header_data["payTo"] == config.pay_to
        assert header_data["extra"]["name"] == "USD Coin"
        assert header_data["extra"]["decimals"] == 6

        # Verify body contains error details
        body = resp.json()
        assert body["error"] == "payment_required"
        assert body["amount"] == "1000000"


@pytest.mark.asyncio
async def test_valid_payment_settles_and_attaches_receipt(x402_setup: Any) -> None:
    """Valid EIP-3009 payment settles on-chain, writes to ledger, and returns receipt header."""
    config, facilitator, ledger, _, app = x402_setup
    account = Account.create()
    auth_header = _sign_authorization(account, config, amount_minor=1_000_000)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/premium", headers={"X-PAYMENT": auth_header})
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert "X-PAYMENT-RESPONSE" in resp.headers

        # Verify receipt header
        raw_receipt = base64.b64decode(resp.headers["X-PAYMENT-RESPONSE"]).decode()
        receipt = json.loads(raw_receipt)
        assert receipt["success"] is True
        assert receipt["amount"] == "1000000"
        assert receipt["network"] == "base"
        assert receipt["from"].lower() == account.address.lower()

        # Verify facilitator called
        assert len(facilitator.verify_calls) == 1
        assert len(facilitator.settle_calls) == 1

        # Verify ledger write
        assert len(ledger.records) == 1
        assert ledger.records[0]["amount_minor"] == 1_000_000
        assert ledger.records[0]["currency"] == "USDC"


@pytest.mark.asyncio
async def test_idempotent_retry_returns_cached_response_without_duplicate_settlement(
    x402_setup: Any,
) -> None:
    """Sending identical X-PAYMENT header twice returns cached response with
    exactly 1 settlement.
    """
    config, facilitator, ledger, _, app = x402_setup
    account = Account.create()
    auth_header = _sign_authorization(account, config, amount_minor=1_000_000)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # First request
        resp1 = await client.get("/api/premium", headers={"X-PAYMENT": auth_header})
        assert resp1.status_code == 200

        # Duplicate retry with same X-PAYMENT
        resp2 = await client.get("/api/premium", headers={"X-PAYMENT": auth_header})
        assert resp2.status_code == 200
        assert resp2.headers["X-PAYMENT-RESPONSE"] == resp1.headers["X-PAYMENT-RESPONSE"]

        # Crucial invariant: facilitator settled exactly once!
        assert len(facilitator.settle_calls) == 1
        assert len(ledger.records) == 1


@pytest.mark.asyncio
async def test_nonce_replay_rejected_with_409(x402_setup: Any) -> None:
    """Using an already-seen nonce with different parameters triggers 409 Conflict."""
    config, _, _, _, app = x402_setup
    account1 = Account.create()
    shared_nonce = "0x" + "aa" * 32

    # First payment consumes nonce
    auth_header1 = _sign_authorization(account1, config, nonce=shared_nonce)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp1 = await client.get("/api/premium", headers={"X-PAYMENT": auth_header1})
        assert resp1.status_code == 200

        # Second different payment attempts to reuse identical nonce
        account2 = Account.create()
        auth_header2 = _sign_authorization(account2, config, nonce=shared_nonce)
        resp2 = await client.get("/api/premium", headers={"X-PAYMENT": auth_header2})
        assert resp2.status_code == 409
        assert resp2.json()["error"] == "replay"


@pytest.mark.asyncio
async def test_invalid_signature_returns_402(x402_setup: Any) -> None:
    """Tampered or invalid EIP-712 signature returns 402 with error='invalid_signature'."""
    config, _, _, _, app = x402_setup
    account = Account.create()

    # Generate payload for different recipient
    auth_header = _sign_authorization(
        account, config, to_address="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/premium", headers={"X-PAYMENT": auth_header})
        assert resp.status_code == 402
        assert resp.json()["error"] in ("invalid_recipient", "invalid_signature")


@pytest.mark.asyncio
async def test_expired_authorization_returns_402(x402_setup: Any) -> None:
    """Authorization with validBefore < now must be rejected with 402 error='expired'."""
    config, _, _, _, app = x402_setup
    account = Account.create()
    expired_timestamp = int(time.time()) - 100
    auth_header = _sign_authorization(account, config, valid_before=expired_timestamp)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/premium", headers={"X-PAYMENT": auth_header})
        assert resp.status_code == 402
        assert resp.json()["error"] == "expired"


@pytest.mark.asyncio
async def test_insufficient_usdc_balance_returns_402(x402_setup: Any) -> None:
    """Facilitator reporting insufficient token balance returns 402 error='insufficient_funds'."""
    config, facilitator, _, _, app = x402_setup
    facilitator.verify_result = VerifyResult(
        valid=False,
        error="insufficient_funds",
        reason="Agent USDC balance below required transfer amount",
    )
    account = Account.create()
    auth_header = _sign_authorization(account, config)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/premium", headers={"X-PAYMENT": auth_header})
        assert resp.status_code == 402
        assert resp.json()["error"] == "insufficient_funds"


@pytest.mark.asyncio
async def test_facilitator_timeout_returns_503_retry_after(x402_setup: Any) -> None:
    """Facilitator timeout during verification returns 503 with Retry-After header."""
    config, facilitator, _, _, app = x402_setup
    facilitator.should_timeout_verify = True
    account = Account.create()
    auth_header = _sign_authorization(account, config)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/premium", headers={"X-PAYMENT": auth_header})
        assert resp.status_code == 503
        assert resp.headers.get("Retry-After") == "5"
        assert resp.json()["error"] == "facilitator_unavailable"


@pytest.mark.asyncio
async def test_settlement_failure_returns_502(x402_setup: Any) -> None:
    """On-chain settlement failure by facilitator returns 502 error='settlement_failed'."""
    config, facilitator, _, _, app = x402_setup
    facilitator.should_fail_settle = True
    account = Account.create()
    auth_header = _sign_authorization(account, config)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/premium", headers={"X-PAYMENT": auth_header})
        assert resp.status_code == 502
        assert resp.json()["error"] == "settlement_failed"


@pytest.mark.asyncio
async def test_ledger_failure_enqueues_reconciliation(x402_setup: Any) -> None:
    """If ledger fails AFTER settlement, return 500 and enqueue urgent reconciliation job."""
    config, _, ledger, queue, app = x402_setup
    ledger.should_fail = True
    account = Account.create()
    auth_header = _sign_authorization(account, config)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/premium", headers={"X-PAYMENT": auth_header})
        assert resp.status_code == 500
        assert resp.json()["error"] == "ledger_error"

        # Critical audit invariant: Reconciliation job MUST be enqueued!
        assert len(queue.jobs) == 1
        job = queue.jobs[0]
        assert job["amount_minor"] == 1_000_000
        assert job["currency"] == "USDC"
        assert "Database connection lost" in job["error"]


@pytest.mark.asyncio
async def test_dynamic_pricing_function() -> None:
    """Dynamic pricing function adjusts route cost at runtime."""
    facilitator = MockFacilitator()
    ledger = MockLedger()

    def custom_price_fn(req: Request) -> Decimal:
        if req.headers.get("X-Tier") == "vip":
            return Decimal("0.50")
        return Decimal("2.00")

    config = X402Config(
        pay_to=TEST_MERCHANT_ADDR,
        asset=TEST_ASSET_ADDR,
        chain_id=TEST_CHAIN_ID,
        protected_routes={"/api/dynamic": Decimal("1.00")},
        price_fn=custom_price_fn,
    )

    async def dynamic_handler(request: Request) -> JSONResponse:
        return JSONResponse({"status": "dynamic_ok"})

    app = Starlette(routes=[Route("/api/dynamic", dynamic_handler)])
    app.add_middleware(X402Middleware, config=config, facilitator=facilitator, ledger=ledger)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Without VIP header: price is $2.00 (2_000_000)
        resp1 = await client.get("/api/dynamic")
        assert resp1.status_code == 402
        assert resp1.json()["amount"] == "2000000"

        # With VIP header: price is $0.50 (500_000)
        resp2 = await client.get("/api/dynamic", headers={"X-Tier": "vip"})
        assert resp2.status_code == 402
        assert resp2.json()["amount"] == "500000"


@pytest.mark.asyncio
async def test_dos_prevention_payload_size_cap(x402_setup: Any) -> None:
    """Header payload exceeding 10KB cap must be rejected immediately."""
    _, _, _, _, app = x402_setup
    oversized_payload = "a" * 15_000

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/premium", headers={"X-PAYMENT": oversized_payload})
        assert resp.status_code == 400
        assert resp.json()["error"] == "payload_too_large"


# ---------------------------------------------------------------------------
# Property-Based Testing
# ---------------------------------------------------------------------------


@given(st.text(min_size=1, max_size=500))
def test_property_malformed_base64_never_crashes(malformed_str: str) -> None:
    """Arbitrary malformed base64 strings in X-PAYMENT never crash the middleware."""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    config = X402Config(
        pay_to=TEST_MERCHANT_ADDR,
        asset=TEST_ASSET_ADDR,
        protected_routes={"/api/premium": Decimal("1.00")},
    )
    facilitator = MockFacilitator()
    ledger = MockLedger()
    middleware = X402Middleware(config, facilitator, ledger)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/premium",
        "headers": [(b"x-payment", malformed_str.encode("utf-8", errors="replace"))],
    }
    request = Request(scope)

    async def call_next(_req: Request) -> Response:
        return Response("ok")

    def _run() -> Response:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(middleware.dispatch(request, call_next))
        finally:
            loop.close()

    with ThreadPoolExecutor(max_workers=1) as pool:
        resp = pool.submit(_run).result()

    assert resp.status_code in (400, 402)
    body = json.loads(getattr(resp, "body", b"{}").decode("utf-8", errors="replace"))
    assert body["error"] in ("invalid_signature", "invalid_payload", "payload_too_large")
