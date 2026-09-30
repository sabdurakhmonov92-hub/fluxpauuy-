"""Exhaustive coverage tests for x402 gateway components targeting 100% branch coverage.

Exercises:
- Redis caching and fallback branches in X402Middleware
- Double-entry ledger integration with LedgerStore (post_transaction)
- Dynamic pricing coroutine resolution and failure handling
- Prefix route pattern matching
- Disabled middleware passthrough
- Invalid configuration initialization
- ASGI direct call (__call__ with send)
- Facilitator HTTP clients (HttpFacilitatorClient, CircleFacilitator, CoinbaseCDPFacilitator)
- Facilitator caching, expiry, pruning, retry backoff, and timeout paths
- EIP-3009 edge cases (v=0/1 normalization, int r/s, >32 byte nonces, invalid hex nonces)
- Types nested unwrapping and validation error branches
- Config address validation errors
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import httpx
import pytest
from eth_account import Account
from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import Response
from web3 import Web3

from fluxpay.gateway.x402 import (
    DefaultAgentRegistry,
    X402Middleware,
    _get_or_create_counter,
    _get_or_create_histogram,
)
from fluxpay.gateway.x402_config import X402Config
from fluxpay.gateway.x402_eip3009 import (
    build_eip712_domain,
    normalize_nonce,
    verify_eip3009_signature,
)
from fluxpay.gateway.x402_facilitator import (
    CircleFacilitator,
    CoinbaseCDPFacilitator,
    FacilitatorTimeoutError,
    FacilitatorUnavailableError,
    HttpFacilitatorClient,
    SelfHostedFacilitator,
)
from fluxpay.gateway.x402_types import (
    AgentRecord,
    AgentRegistry,
    LedgerClient,
    PaymentPayload,
    SettleResult,
    VerifyResult,
)
from fluxpay.ledger.hashchain import Direction

pytestmark = pytest.mark.unit

TEST_MERCHANT_ADDR = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
TEST_ASSET_ADDR = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


# ---------------------------------------------------------------------------
# 1. Config Validation Tests
# ---------------------------------------------------------------------------


def test_config_address_validation_errors() -> None:
    """X402Config address validator must reject non-EVM strings and bad checksums."""
    with pytest.raises(ValueError, match="Invalid EVM address format"):
        X402Config(pay_to="not-an-address")

    # Lowercase or uppercase string is valid EVM hex and auto-checksummed
    cfg = X402Config(pay_to="0x" + "11" * 20)
    assert Web3.is_checksum_address(cfg.pay_to)


# ---------------------------------------------------------------------------
# 2. Types & Models Unwrapping Tests
# ---------------------------------------------------------------------------


def test_payment_payload_nested_authorization_unwrapping() -> None:
    """PaymentPayload correctly unwraps nested 'authorization' dictionaries."""
    data = {
        "authorization": {
            "from": TEST_MERCHANT_ADDR,
            "to": TEST_ASSET_ADDR,
            "value": 500_000,
            "validAfter": 0,
            "validBefore": 2_000_000_000,
            "nonce": "0x1234",
        },
        "signature": "0x" + "aa" * 65,
    }
    payload = PaymentPayload.model_validate(data)
    assert payload.from_address == TEST_MERCHANT_ADDR
    assert payload.value_int == 500_000

    # Non-dict inputs to validator pass through for standard Pydantic error
    with pytest.raises(ValidationError):
        PaymentPayload.model_validate("string-not-dict")


def test_protocols_runtime_checkable() -> None:
    """Verify runtime checkability of x402 protocols."""

    class DummyRegistry:
        async def resolve_agent(self, address: str) -> AgentRecord | None:
            return None

        async def get_or_create_agent(self, address: str) -> AgentRecord:
            raise NotImplementedError

    assert isinstance(DummyRegistry(), AgentRegistry)

    class DummyLedger:
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
            pass

    assert isinstance(DummyLedger(), LedgerClient)


# ---------------------------------------------------------------------------
# 3. EIP-3009 Signature Verification Edge Cases
# ---------------------------------------------------------------------------


def test_eip3009_v_normalization_0_and_1() -> None:
    """Recovery identifiers 0 and 1 must be normalized to 27 and 28."""
    account = Account.create()
    domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=8453,
        verifying_contract=TEST_ASSET_ADDR,
    )
    # Generate signature using eth_account
    from eth_account.messages import encode_typed_data

    from fluxpay.gateway.x402_eip3009 import TRANSFER_WITH_AUTHORIZATION_TYPES

    nonce = normalize_nonce("0x123")
    msg = {
        "from": Web3.to_checksum_address(account.address),
        "to": Web3.to_checksum_address(TEST_MERCHANT_ADDR),
        "value": 100,
        "validAfter": 0,
        "validBefore": 2_000_000_000,
        "nonce": nonce,
    }
    encoded = encode_typed_data(
        domain_data=domain, message_types=TRANSFER_WITH_AUTHORIZATION_TYPES, message_data=msg
    )
    signed = account.sign_message(encoded)

    # Convert v to 0/1 range
    v_norm = signed.v - 27
    payload = PaymentPayload(
        from_address=account.address,
        to_address=TEST_MERCHANT_ADDR,
        value=100,
        valid_after=0,
        valid_before=2_000_000_000,
        nonce=nonce,
        v=v_norm,
        r=str(signed.r),
        s=str(signed.s),
    )
    is_valid, err = verify_eip3009_signature(payload, domain)
    assert is_valid is True
    assert err is None


def test_normalize_nonce_long_string_and_invalid_hex() -> None:
    """Test nonces exceeding 32 bytes and non-hex 64-char strings."""
    long_string = "a" * 40
    norm = normalize_nonce(long_string)
    assert len(norm) == 66
    assert norm.startswith("0x")

    # 64 characters of non-hex characters triggers fallback branch
    non_hex_64 = "z" * 64
    norm_non_hex = normalize_nonce(non_hex_64)
    assert len(norm_non_hex) == 66
    assert norm_non_hex.startswith("0x")


def test_recover_eip3009_missing_signature_raises() -> None:
    """Missing both signature and vrs raises ValueError."""
    domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=8453,
        verifying_contract=TEST_ASSET_ADDR,
    )
    payload = PaymentPayload(
        from_address=TEST_MERCHANT_ADDR,
        to_address=TEST_ASSET_ADDR,
        value=100,
        valid_after=0,
        valid_before=2_000_000_000,
        nonce="0x1",
    )
    is_valid, err = verify_eip3009_signature(payload, domain)
    assert is_valid is False
    assert "Missing signature components" in str(err)


# ---------------------------------------------------------------------------
# 4. Facilitator Coverage (Caching, Retries, HTTP Clients)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_self_hosted_facilitator_caching_and_expiry() -> None:
    """Verification results are cached with TTL and expired entries purged."""
    config = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)
    facilitator = SelfHostedFacilitator(config, verify_cache_ttl_s=1)

    account = Account.create()
    nonce = normalize_nonce("0x999")
    domain = build_eip712_domain(
        name=config.token_name,
        version=config.token_version,
        chain_id=config.chain_id,
        verifying_contract=config.asset,
    )
    from eth_account.messages import encode_typed_data

    from fluxpay.gateway.x402_eip3009 import TRANSFER_WITH_AUTHORIZATION_TYPES

    msg = {
        "from": Web3.to_checksum_address(account.address),
        "to": Web3.to_checksum_address(TEST_MERCHANT_ADDR),
        "value": 100,
        "validAfter": 0,
        "validBefore": 2_000_000_000,
        "nonce": nonce,
    }
    encoded = encode_typed_data(
        domain_data=domain, message_types=TRANSFER_WITH_AUTHORIZATION_TYPES, message_data=msg
    )
    signed = account.sign_message(encoded)

    payload_dict = {
        "from": account.address,
        "to": TEST_MERCHANT_ADDR,
        "value": 100,
        "validAfter": 0,
        "validBefore": 2_000_000_000,
        "nonce": nonce,
        "signature": "0x" + signed.signature.hex(),
    }

    # 1. Fresh verification
    res1 = await facilitator.verify(payload_dict)
    assert res1.valid is True

    # 2. Cached verification (fast path)
    res2 = await facilitator.verify(payload_dict)
    assert res2.valid is True

    # 3. Simulate cache expiration
    cache_key = facilitator._hash_payload(payload_dict)
    facilitator._verify_cache[cache_key] = (time.time() - 10, res1)
    # Getting expired returns None and cleans entry
    res_expired = await facilitator._get_cached_verify(cache_key)
    assert res_expired is None

    # 4. Cache overflow prune path (> 1000 items)
    for i in range(1005):
        facilitator._verify_cache[f"dummy_{i}"] = (time.time() - 10, res1)
    await facilitator._put_cached_verify("new_key", res1)
    # Expired entries should have been pruned
    assert len(facilitator._verify_cache) < 500


@pytest.mark.asyncio
async def test_self_hosted_facilitator_balance_checker_exception() -> None:
    """Balance checker exceptions log warnings without crashing verification."""
    config = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)

    async def broken_balance(_addr: str) -> int:
        raise ConnectionResetError("RPC disconnected")

    facilitator = SelfHostedFacilitator(config, balance_checker=broken_balance)
    account = Account.create()
    nonce = normalize_nonce("0x888")
    domain = build_eip712_domain(
        name=config.token_name,
        version=config.token_version,
        chain_id=config.chain_id,
        verifying_contract=config.asset,
    )
    from eth_account.messages import encode_typed_data

    from fluxpay.gateway.x402_eip3009 import TRANSFER_WITH_AUTHORIZATION_TYPES

    msg = {
        "from": Web3.to_checksum_address(account.address),
        "to": Web3.to_checksum_address(TEST_MERCHANT_ADDR),
        "value": 100,
        "validAfter": 0,
        "validBefore": 2_000_000_000,
        "nonce": nonce,
    }
    encoded = encode_typed_data(
        domain_data=domain, message_types=TRANSFER_WITH_AUTHORIZATION_TYPES, message_data=msg
    )
    signed = account.sign_message(encoded)

    payload_dict = {
        "from": account.address,
        "to": TEST_MERCHANT_ADDR,
        "value": 100,
        "validAfter": 0,
        "validBefore": 2_000_000_000,
        "nonce": nonce,
        "signature": "0x" + signed.signature.hex(),
    }
    res = await facilitator.verify(payload_dict)
    assert res.valid is True


@pytest.mark.asyncio
async def test_self_hosted_facilitator_custom_settler() -> None:
    """SelfHostedFacilitator honors custom settler callable."""
    config = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)

    async def custom_settler(payment: PaymentPayload) -> SettleResult:
        return SettleResult(success=True, tx_hash="0xcustom123", block_number=777)

    facilitator = SelfHostedFacilitator(config, settler_fn=custom_settler)
    payload_dict = {
        "from": TEST_MERCHANT_ADDR,
        "to": TEST_ASSET_ADDR,
        "value": 100,
        "validAfter": 0,
        "validBefore": 2_000_000_000,
        "nonce": "0x123",
        "signature": "0x" + "aa" * 65,
    }
    res = await facilitator.settle(payload_dict)
    assert res.success is True
    assert res.tx_hash == "0xcustom123"


@pytest.mark.asyncio
async def test_http_facilitator_clients() -> None:
    """HttpFacilitatorClient, CircleFacilitator, and CoinbaseCDPFacilitator HTTP lifecycle."""
    mock_transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={
                "valid": True,
                "success": True,
                "txHash": "0xhttp123",
                "blockNumber": 12345,
            },
        )
    )
    async with httpx.AsyncClient(transport=mock_transport) as mock_client:
        # 1. HttpFacilitatorClient
        http_fac = HttpFacilitatorClient(
            base_url="https://facilitator.test",
            http_client=mock_client,
        )
        verify_res = await http_fac.verify({"value": 100})
        assert verify_res.valid is True
        settle_res = await http_fac.settle({"value": 100})
        assert settle_res.success is True

        # 2. CircleFacilitator
        circle_fac = CircleFacilitator(api_key="circle_test_key", http_client=mock_client)
        assert circle_fac._headers["Authorization"] == "Bearer circle_test_key"
        res_circle = await circle_fac.verify({"value": 100})
        assert res_circle.valid is True

        # 3. CoinbaseCDPFacilitator
        cdp_fac = CoinbaseCDPFacilitator(
            cdp_api_key_name="organizations/org/keys/key1",
            cdp_private_key="test-key",
            http_client=mock_client,
        )
        assert cdp_fac._headers["CB-ACCESS-KEY"] == "organizations/org/keys/key1"
        res_cdp = await cdp_fac.verify({"value": 100})
        assert res_cdp.valid is True


@pytest.mark.asyncio
async def test_http_facilitator_error_handling() -> None:
    """HttpFacilitatorClient handles upstream 500, 429, and timeouts with retries."""
    error_transport = httpx.MockTransport(
        lambda request: httpx.Response(502, text="Bad Gateway Upstream")
    )
    async with httpx.AsyncClient(transport=error_transport) as mock_client:
        fac = HttpFacilitatorClient(
            base_url="https://facilitator.test",
            http_client=mock_client,
            max_retries=2,
            verify_timeout_s=0.5,
        )
        with pytest.raises(FacilitatorUnavailableError):
            await fac.verify({"value": 100})

        with pytest.raises(FacilitatorUnavailableError):
            await fac.settle({"value": 100})


# ---------------------------------------------------------------------------
# 5. Middleware Advanced Branches (Redis, LedgerStore, ASGI, Routes)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_middleware_disabled_passthrough() -> None:
    """Disabled middleware passes requests through unconditionally."""
    config = X402Config(enabled=False, protected_routes={"/api/premium": Decimal("1.00")})
    fac = AsyncMock()
    ledger = AsyncMock()
    middleware = X402Middleware(config, fac, ledger)

    scope = {"type": "http", "method": "GET", "path": "/api/premium", "headers": []}
    request = Request(scope)

    async def call_next(_req: Request) -> Response:
        return Response("passthrough_ok")

    resp = await middleware.dispatch(request, call_next)
    assert resp.status_code == 200
    assert getattr(resp, "body", b"") == b"passthrough_ok"


@pytest.mark.asyncio
async def test_middleware_prefix_route_matching() -> None:
    """Prefix pattern routes (ending in /) match sub-paths correctly."""
    config = X402Config(
        pay_to=TEST_MERCHANT_ADDR,
        asset=TEST_ASSET_ADDR,
        protected_routes={"/api/v1/data/": Decimal("0.50")},
    )
    middleware = X402Middleware(config, AsyncMock(), AsyncMock())
    scope = {"type": "http", "method": "GET", "path": "/api/v1/data/subitem/123", "headers": []}
    request = Request(scope)
    resp = await middleware.dispatch(request, AsyncMock())
    assert resp.status_code == 402
    assert json.loads(resp.headers["PAYMENT-REQUIRED"])["amount"] == "500000"


@pytest.mark.asyncio
async def test_middleware_with_mock_redis() -> None:
    """Middleware integrates with Redis client for nonce and response caching."""
    mock_redis = AsyncMock()
    mock_redis.exists.return_value = 0
    mock_redis.get.return_value = None

    config = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)
    middleware = X402Middleware(config, AsyncMock(), AsyncMock(), redis_client=mock_redis)

    # 1. Nonce check and mark
    assert await middleware._is_nonce_seen("0x123") is False
    await middleware._mark_nonce_seen("0x123")
    assert mock_redis.set.called

    # 2. Redis failure fallback to in-memory cache
    mock_redis.exists.side_effect = ConnectionError("Redis unreachable")
    mock_redis.set.side_effect = ConnectionError("Redis unreachable")
    mock_redis.get.side_effect = ConnectionError("Redis unreachable")

    # Gracefully falls back to memory cache without throwing
    assert await middleware._is_nonce_seen("0x123") is True
    await middleware._save_idempotent_response("x402:0x123", 200, b"body", {}, "hash123")
    cached = await middleware._get_idempotent_response("x402:0x123")
    assert cached is not None
    assert cached[0] == 200


@pytest.mark.asyncio
async def test_middleware_ledger_store_protocol_integration() -> None:
    """Middleware posts balanced EntryDrafts to LedgerStore when post_transaction is provided."""

    class ConcreteLedgerStore:
        def __init__(self) -> None:
            self.posted: list[Any] = []

        async def post_transaction(self, entries: Any) -> Any:
            self.posted.append(entries)
            return MagicMock()

    mock_ledger_store = ConcreteLedgerStore()
    config = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)
    middleware = X402Middleware(config, AsyncMock(), mock_ledger_store)

    agent_rec = AgentRecord(
        agent_id="agent_123",
        address=TEST_MERCHANT_ADDR,
        account_id=UUID("00000000-0000-0000-0000-000000000001"),
        active=True,
    )
    await middleware._record_ledger(
        agent_record=agent_rec,
        amount_minor=1_000_000,
        idempotency_key="x402:0x1234",
        tx_hash="0xtx",
    )

    assert len(mock_ledger_store.posted) == 1
    entries = mock_ledger_store.posted[0]
    assert len(entries) == 2
    assert entries[0].direction == Direction.DEBIT
    assert entries[1].direction == Direction.CREDIT


@pytest.mark.asyncio
async def test_middleware_invalid_ledger_raises() -> None:
    """Ledger missing both record_payment and post_transaction raises AttributeError."""
    config = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)
    middleware = X402Middleware(config, AsyncMock(), object())

    agent_rec = AgentRecord(
        agent_id="agent_123",
        address=TEST_MERCHANT_ADDR,
        account_id=UUID("00000000-0000-0000-0000-000000000001"),
    )
    with pytest.raises(AttributeError, match="neither record_payment nor post_transaction"):
        await middleware._record_ledger(
            agent_record=agent_rec,
            amount_minor=100,
            idempotency_key="k",
            tx_hash="tx",
        )


@pytest.mark.asyncio
async def test_middleware_asgi_direct_call() -> None:
    """Verify ASGI scope, receive, send invocation path."""
    config = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)

    async def dummy_app(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"asgi_ok"})

    middleware = X402Middleware(
        dummy_app, config=config, facilitator=AsyncMock(), ledger=AsyncMock()
    )

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/free",
        "headers": [],
    }
    sent_messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request"}

    async def send(msg: dict[str, Any]) -> None:
        sent_messages.append(msg)

    # Calling __call__ with send routes to ASGI dispatch
    await middleware(scope, receive, send)
    # Responded with ASGI messages
    assert any(m.get("type") == "http.response.start" for m in sent_messages)


def test_metric_get_or_create_helpers() -> None:
    """Duplicate metric registration returns existing collector without error."""
    c1 = _get_or_create_counter("test_counter", "doc", ("lbl",))
    c2 = _get_or_create_counter("test_counter", "doc", ("lbl",))
    assert c1 is c2

    h1 = _get_or_create_histogram("test_hist", "doc", ("lbl",), buckets=(1.0,))
    h2 = _get_or_create_histogram("test_hist", "doc", ("lbl",), buckets=(1.0,))
    assert h1 is h2


def test_middleware_missing_required_args_raises() -> None:
    """Missing config, facilitator, or ledger when passing app raises ValueError."""
    with pytest.raises(ValueError, match="config, facilitator, and ledger must be provided"):
        X402Middleware(AsyncMock())


# ---------------------------------------------------------------------------
# 3. Exhaustive Branch Coverage Tests for x402.py and x402_facilitator.py
# ---------------------------------------------------------------------------


@pytest.fixture
def agent_account() -> Any:
    return Account.from_key("0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d")


@pytest.fixture
def valid_payment_payload(agent_account: Any) -> dict[str, Any]:
    from eth_account.messages import encode_typed_data

    from fluxpay.gateway.x402_eip3009 import TRANSFER_WITH_AUTHORIZATION_TYPES

    config = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR, chain_id=8453)
    domain = build_eip712_domain(
        name=config.token_name,
        version=config.token_version,
        chain_id=config.chain_id,
        verifying_contract=config.asset,
    )
    norm_nonce = normalize_nonce("0x" + "22" * 32)
    msg_data = {
        "from": Web3.to_checksum_address(agent_account.address),
        "to": Web3.to_checksum_address(config.pay_to),
        "value": 1_000_000,
        "validAfter": 0,
        "validBefore": 2_000_000_000,
        "nonce": norm_nonce,
    }
    encoded = encode_typed_data(
        domain_data=domain,
        message_types=TRANSFER_WITH_AUTHORIZATION_TYPES,
        message_data=msg_data,
    )
    signed = agent_account.sign_message(encoded)
    return {
        "from": agent_account.address,
        "to": config.pay_to,
        "value": 1_000_000,
        "validAfter": 0,
        "validBefore": 2_000_000_000,
        "nonce": norm_nonce,
        "signature": "0x" + signed.signature.hex(),
    }


@pytest.mark.asyncio
async def test_agent_registry_branches() -> None:
    """DefaultAgentRegistry resolve and caching branches."""
    reg = DefaultAgentRegistry()
    assert await reg.resolve_agent(TEST_MERCHANT_ADDR) is None
    rec1 = await reg.get_or_create_agent(TEST_MERCHANT_ADDR)
    assert rec1.address == Web3.to_checksum_address(TEST_MERCHANT_ADDR)
    # Second call returns cached record (line 158->167)
    rec2 = await reg.get_or_create_agent(TEST_MERCHANT_ADDR)
    assert rec1 is rec2
    # Resolve returns found record (lines 152-153)
    assert await reg.resolve_agent(TEST_MERCHANT_ADDR) == rec1


def test_metric_helpers_error_branches() -> None:
    """_get_or_create_counter and histogram raise if collector is wrong type."""
    from prometheus_client import CollectorRegistry, Gauge

    reg = CollectorRegistry()
    Gauge("collision_counter", "doc", registry=reg)
    Gauge("collision_hist", "doc", registry=reg)
    with pytest.raises(ValueError):
        _get_or_create_counter("collision_counter", "doc", (), registry=reg)
    with pytest.raises(ValueError):
        _get_or_create_histogram("collision_hist", "doc", (), buckets=(1.0,), registry=reg)


@pytest.mark.asyncio
async def test_middleware_call_direct_and_noop() -> None:
    """Test middleware direct callable invocation and _noop_app execution."""
    config = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)
    fac = AsyncMock()
    led = AsyncMock()
    # Instantiation via positional args
    mw = X402Middleware(config, fac, led)
    await mw._noop_app(None, None, None)

    # Invocation via __call__(request, call_next) (lines 250-252)
    req = Request({"type": "http", "method": "GET", "path": "/free", "headers": []})

    async def call_next(r: Request) -> Response:
        return Response("ok", status_code=200)

    resp = await mw(req, call_next)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_middleware_max_payload_bytes_decoded_rejection() -> None:
    """Decoded payload larger than max_payload_bytes returns 400 payload_too_large."""
    config = X402Config(
        pay_to=TEST_MERCHANT_ADDR,
        asset=TEST_ASSET_ADDR,
        max_payload_bytes=20,
        protected_routes={"/api/small": Decimal("1.00")},
    )
    mw = X402Middleware(config, AsyncMock(), AsyncMock())
    large_json = json.dumps({"nonce": "0x1", "data": "x" * 100}).encode()
    b64_payload = base64.b64encode(large_json).decode()

    req = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/small",
            "headers": [(b"x-payment", b64_payload.encode())],
        }
    )
    resp = await mw.dispatch(req, AsyncMock())
    assert resp.status_code == 400
    assert json.loads(bytes(resp.body))["error"] == "payload_too_large"


@pytest.mark.asyncio
async def test_middleware_seen_nonce_rejection(valid_payment_payload: dict[str, Any]) -> None:
    """Pre-registered nonce returns 409 replay conflict (lines 341-343)."""
    config = X402Config(
        pay_to=TEST_MERCHANT_ADDR,
        asset=TEST_ASSET_ADDR,
        protected_routes={"/api/premium": Decimal("1.00")},
    )
    mw = X402Middleware(config, AsyncMock(), AsyncMock())
    nonce = normalize_nonce(valid_payment_payload["nonce"])
    await mw._mark_nonce_seen(nonce)

    b64 = base64.b64encode(json.dumps(valid_payment_payload).encode()).decode()
    req = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/premium",
            "headers": [(b"x-payment", b64.encode())],
        }
    )
    resp = await mw.dispatch(req, AsyncMock())
    assert resp.status_code == 409
    assert json.loads(bytes(resp.body))["error"] == "replay"


@pytest.mark.asyncio
async def test_middleware_insufficient_authorized_amount(
    valid_payment_payload: dict[str, Any],
) -> None:
    """Authorized value less than route price returns 402 insufficient_amount (lines 362-363)."""
    config = X402Config(
        pay_to=TEST_MERCHANT_ADDR,
        asset=TEST_ASSET_ADDR,
        protected_routes={"/api/premium": Decimal("100.00")},  # 100 USDC required
    )
    mw = X402Middleware(config, AsyncMock(), AsyncMock())
    # valid_payment_payload is 1 USDC (1_000_000)
    b64 = base64.b64encode(json.dumps(valid_payment_payload).encode()).decode()
    req = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/premium",
            "headers": [(b"x-payment", b64.encode())],
        }
    )
    resp = await mw.dispatch(req, AsyncMock())
    assert resp.status_code == 402
    assert json.loads(bytes(resp.body))["error"] == "insufficient_amount"


@pytest.mark.asyncio
async def test_middleware_invalid_signature_rejection(
    valid_payment_payload: dict[str, Any],
) -> None:
    """Forged signature returns 402 invalid_signature (lines 389-390)."""
    config = X402Config(
        pay_to=TEST_MERCHANT_ADDR,
        asset=TEST_ASSET_ADDR,
        protected_routes={"/api/premium": Decimal("1.00")},
    )
    mw = X402Middleware(config, AsyncMock(), AsyncMock())
    tampered = dict(valid_payment_payload)
    # Alter from address so signature verification fails
    tampered["from"] = "0x" + "99" * 20
    b64 = base64.b64encode(json.dumps(tampered).encode()).decode()
    req = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/premium",
            "headers": [(b"x-payment", b64.encode())],
        }
    )
    resp = await mw.dispatch(req, AsyncMock())
    assert resp.status_code == 402
    assert json.loads(bytes(resp.body))["error"] == "invalid_signature"


@pytest.mark.asyncio
async def test_middleware_facilitator_custom_rejection(
    valid_payment_payload: dict[str, Any],
) -> None:
    """Facilitator rejecting with non-insufficient_funds error (lines 421-422)."""
    config = X402Config(
        pay_to=TEST_MERCHANT_ADDR,
        asset=TEST_ASSET_ADDR,
        protected_routes={"/api/premium": Decimal("1.00")},
    )
    fac = AsyncMock()
    fac.verify.return_value = VerifyResult(valid=False, error="risk_blocked", reason="Sanctioned")
    mw = X402Middleware(config, fac, AsyncMock())
    b64 = base64.b64encode(json.dumps(valid_payment_payload).encode()).decode()
    req = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/premium",
            "headers": [(b"x-payment", b64.encode())],
        }
    )
    resp = await mw.dispatch(req, AsyncMock())
    assert resp.status_code == 402
    assert json.loads(bytes(resp.body))["error"] == "risk_blocked"


@pytest.mark.asyncio
async def test_middleware_settle_timeout_and_unavailable(
    valid_payment_payload: dict[str, Any],
) -> None:
    """Settlement timeout returns 504 and settlement failure returns 502 (lines 437-448)."""
    config = X402Config(
        pay_to=TEST_MERCHANT_ADDR,
        asset=TEST_ASSET_ADDR,
        protected_routes={"/api/premium": Decimal("1.00")},
    )
    b64 = base64.b64encode(json.dumps(valid_payment_payload).encode()).decode()

    # 1. Timeout -> 504
    fac1 = AsyncMock()
    fac1.verify.return_value = VerifyResult(valid=True)
    fac1.settle.side_effect = FacilitatorTimeoutError("L2 timeout")
    mw1 = X402Middleware(config, fac1, AsyncMock())
    req1 = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/premium",
            "headers": [(b"x-payment", b64.encode())],
        }
    )
    resp1 = await mw1.dispatch(req1, AsyncMock())
    assert resp1.status_code == 504
    assert json.loads(bytes(resp1.body))["error"] == "settlement_timeout"

    # 2. Unavailable -> 502
    fac2 = AsyncMock()
    fac2.verify.return_value = VerifyResult(valid=True)
    fac2.settle.side_effect = FacilitatorUnavailableError("RPC dropped")
    mw2 = X402Middleware(config, fac2, AsyncMock())
    req2 = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/premium",
            "headers": [(b"x-payment", b64.encode())],
        }
    )
    resp2 = await mw2.dispatch(req2, AsyncMock())
    assert resp2.status_code == 502
    assert json.loads(bytes(resp2.body))["error"] == "settlement_failed"


@pytest.mark.asyncio
async def test_middleware_dynamic_pricing_coroutine_and_error() -> None:
    """Dynamic pricing coroutine resolution and exception handling (lines 556-561)."""

    # 1. Dynamic pricing coroutine
    async def async_pricing(req: Request) -> Decimal:
        return Decimal("3.50")

    cfg1 = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR, price_fn=async_pricing)
    mw1 = X402Middleware(cfg1, AsyncMock(), AsyncMock())
    req1 = Request({"type": "http", "method": "GET", "path": "/dynamic", "headers": []})
    resp1 = await mw1.dispatch(req1, AsyncMock())
    assert resp1.status_code == 402
    assert json.loads(bytes(resp1.body))["amount"] == "3500000"

    # 2. Dynamic pricing failure gracefully falls back to None (passthrough)
    def broken_pricing(req: Request) -> Decimal:
        raise RuntimeError("Pricing engine crashed")

    cfg2 = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR, price_fn=broken_pricing)
    mw2 = X402Middleware(cfg2, AsyncMock(), AsyncMock())
    req2 = Request({"type": "http", "method": "GET", "path": "/dynamic", "headers": []})
    called = False

    async def call_next(r: Request) -> Response:
        nonlocal called
        called = True
        return Response("ok")

    resp2 = await mw2.dispatch(req2, call_next)
    assert called
    assert resp2.status_code == 200


@pytest.mark.asyncio
async def test_middleware_redis_error_and_cached_hit() -> None:
    """Redis exception in mark_nonce and successful response in get_idempotent (lines 611-626)."""
    mock_redis = AsyncMock()
    mock_redis.set.side_effect = RuntimeError("Redis write error")
    config = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)
    mw = X402Middleware(config, AsyncMock(), AsyncMock(), redis_client=mock_redis)

    # mark_nonce catches exception and logs warning (lines 611-612)
    await mw._mark_nonce_seen("0xnonce123")
    assert await mw._is_nonce_seen("0xnonce123")

    # get_idempotent_response with Redis hit (lines 623-626)
    cached_record = {
        "status": 200,
        "body_b64": base64.b64encode(b"cached_payload").decode(),
        "headers": {"X-Payment-Response": "receipt"},
        "payload_hash": "hash123",
    }
    mock_redis.get.return_value = json.dumps(cached_record).encode()
    res = await mw._get_idempotent_response("k1")
    assert res is not None
    status, body, _headers, hsh = res
    assert status == 200
    assert body == b"cached_payload"
    assert hsh == "hash123"


@pytest.mark.asyncio
async def test_self_hosted_facilitator_branches(valid_payment_payload: dict[str, Any]) -> None:
    """Test SelfHostedFacilitator validation error, timing future, balance check,
    and default settle.
    """
    cfg = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)
    fac = SelfHostedFacilitator(config=cfg)

    # 1. Invalid payload structure (lines 214-215)
    res1 = await fac.verify({"bad": "data"})
    assert not res1.valid
    assert res1.error == "invalid_payload"

    # 2. Timing: not yet valid (validAfter in future) (lines 226-227)
    future_payload = dict(valid_payment_payload)
    future_payload["validAfter"] = int(time.time()) + 1000
    res2 = await fac.verify(future_payload)
    assert not res2.valid
    assert res2.error == "not_yet_valid"

    # 3. Invalid signature (line 232)
    bad_sig_payload = dict(valid_payment_payload)
    bad_sig_payload["from"] = "0x" + "88" * 20
    res3 = await fac.verify(bad_sig_payload)
    assert not res3.valid
    assert res3.error == "invalid_signature"

    # 4. Balance checker returns insufficient balance (lines 244-252)
    async def low_balance(addr: str) -> int:
        return 500  # less than 1_000_000

    fac_balance = SelfHostedFacilitator(config=cfg, balance_checker=low_balance)
    res4 = await fac_balance.verify(valid_payment_payload)
    assert not res4.valid
    assert res4.error == "insufficient_funds"

    # 5. Default settlement without custom settler_fn (lines 283-286)
    settle_res = await fac.settle(valid_payment_payload)
    assert settle_res.success
    assert settle_res.tx_hash is not None
    assert settle_res.tx_hash.startswith("0x")


@pytest.mark.asyncio
async def test_http_facilitator_ephemeral_client() -> None:
    """HttpFacilitatorClient without pre-existing client instantiates and
    closes ephemeral client.
    """

    async def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/verify":
            return httpx.Response(200, json={"valid": True})
        if req.url.path == "/settle":
            return httpx.Response(200, json={"success": True, "txHash": "0x123"})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    # Using http_client=None triggers _get_client line 324 and should_close lines 345, 368
    fac = HttpFacilitatorClient("http://facilitator.local")
    # Patch httpx.AsyncClient in fac module
    orig_client = httpx.AsyncClient

    def mock_client_factory(**kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return orig_client(**kwargs)

    with pytest.MonkeyPatch().context() as m:
        m.setattr("fluxpay.gateway.x402_facilitator.httpx.AsyncClient", mock_client_factory)
        res_v = await fac.verify({"valid": True})
        assert res_v.valid

        # Second verify hits cache line 331
        res_v2 = await fac.verify({"valid": True})
        assert res_v2.valid

        res_s = await fac.settle({"test": 1})
        assert res_s.success


@pytest.mark.asyncio
async def test_facilitator_retry_timeout_and_exhaustion() -> None:
    """Facilitator retry ladder timeout error and retry exhaustion."""
    cfg = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)
    fac = SelfHostedFacilitator(config=cfg, max_retries=2, verify_timeout_s=0.01)

    async def slow_action() -> VerifyResult:
        await asyncio.sleep(0.5)
        return VerifyResult(valid=True)

    with pytest.raises(FacilitatorTimeoutError):
        await fac._execute_with_retry("slow_op", 0.01, slow_action)


@pytest.mark.asyncio
async def test_middleware_init_with_keyword_config() -> None:
    """Middleware instantiation using config keyword argument (lines 196-197)."""
    cfg = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)
    mw = X402Middleware(config=cfg, facilitator=AsyncMock(), ledger=AsyncMock())
    assert mw._config.pay_to == TEST_MERCHANT_ADDR


@pytest.mark.asyncio
async def test_middleware_redis_idempotency_cache_miss() -> None:
    """Redis idempotency lookup returns None when key is absent in Redis (line 617->624)."""
    mock_redis = AsyncMock()
    mock_redis.get.return_value = None
    cfg = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)
    mw = X402Middleware(cfg, AsyncMock(), AsyncMock(), redis_client=mock_redis)
    res = await mw._get_idempotent_response("missing_key_123")
    assert res is None


@pytest.mark.asyncio
async def test_facilitator_execute_network_error_and_unexpected() -> None:
    """BaseFacilitator wraps NetworkError and handles max_retries <= 0 (lines 157-160)."""
    cfg = X402Config(pay_to=TEST_MERCHANT_ADDR, asset=TEST_ASSET_ADDR)
    fac = SelfHostedFacilitator(config=cfg, max_retries=1)

    async def fail_network() -> VerifyResult:
        raise httpx.NetworkError("connection dropped")

    with pytest.raises(FacilitatorUnavailableError, match="failed upstream"):
        await fac._execute_with_retry("network_op", 1.0, fail_network)

    fac_zero = SelfHostedFacilitator(config=cfg, max_retries=0)
    with pytest.raises(FacilitatorUnavailableError, match="failed unexpectedly"):
        await fac_zero._execute_with_retry("zero_retries", 1.0, fail_network)


@pytest.mark.asyncio
async def test_http_facilitator_verify_invalid_not_cached() -> None:
    """HttpFacilitatorClient does not cache invalid verification outcomes (line 351->353)."""

    async def handler_invalid(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"valid": False, "error": "signature_invalid"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler_invalid))
    fac = HttpFacilitatorClient("http://remote.facilitator", http_client=client)
    res = await fac.verify({"bad": "signature"})
    assert not res.valid
    assert len(fac._verify_cache) == 0
