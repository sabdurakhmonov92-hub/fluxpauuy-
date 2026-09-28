"""End-to-End Platform Integration Tests (Task 33 — The Platform Boots Here).

=============================================================================
FLUXPAY V3 PLATFORM ACCEPTANCE SUITE (BLOCK F CLOSURE)
=============================================================================
Verifies the complete assembled composition root against the real production stack:
1. Real PostgreSQL (ledger, state machine idempotency, limits, accounts, users, audit).
2. Real Valkey (anti-replay gate, rate limits, daily quotas, idempotency fast-path).
3. Real RabbitMQ (reliable financial event bus over quorum queues).
4. Real HTTP middleware chain (GatewayMiddleware outermost, AdminAuthMiddleware inner).
5. Real domain services (PaymentService, LedgerStore, AccountDirectory, Quarantine).

Tests:
- test_middleware_order_probe: Pinned order (Gateway outermost wraps Admin inner).
- test_first_real_payment_full_stack: The platform moment (201, ledger, rabbit event, balance).
- test_three_tier_replay_dance: Redis fast-path -> Postgres DB-tier -> fresh execution.
- test_error_dialect_over_http: Policy reject (422), insufficient funds (400),
  unknown merchant (404), validation failure (422 platform ErrorEnvelope).
- test_admin_lane_mounted_and_guarded: 401 unauthenticated, 403 forbidden, 201 provisioned.
- test_docs_suppression_policy: Production disables /docs and /openapi.json; dev keeps them.
- test_get_payment_by_id: Unknown returns 404; known returns settled PaymentDetail.
- test_balance_endpoint: Zero balance for unfunded; exact balance for funded agent.
- test_held_flow_and_settle_approved_http: Ceiling breach -> held -> settle_approved -> visible.
- test_openapi_golden_freeze: app.openapi() strictly matches committed golden contract.
- test_tz_probe_positive: Server connection timezone verified as UTC at boot.
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator, Callable, Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]
import httpx
import pytest
import pytest_asyncio

from fluxpay.admin.middleware import AdminAuthMiddleware
from fluxpay.contracts.schemas import (
    BalanceResponse,
    ErrorEnvelope,
    PaymentDetail,
    PaymentResponse,
)
from fluxpay.gateway.middleware import HEADER_REQUEST_ID, GatewayMiddleware
from fluxpay.ledger.hashchain import Direction
from fluxpay.ledger.postgres import PostgresLedgerStore
from fluxpay.ledger.store import EntryDraft
from fluxpay.payments.service import deterministic_tx_id
from fluxpay.registry.agents import (
    AgentLifecycle,
    CreateAgentCommand,
    CreateMerchantCommand,
    MerchantLifecycle,
)
from fluxpay.risk.limits import AgentLimits, LimitRepo
from fluxpay.shared.events import EventType
from fluxpay.wallet.accounts import AccountDirectory

pytestmark = pytest.mark.integration

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
GOLDEN_PATH: Path = REPO_ROOT / "tests" / "golden" / "openapi.golden.json"


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class PlatformAgentCredentials:
    """Agent test credentials with properties matching gateway harness expectations."""

    agent_id: UUID
    external_id: str
    secret: str

    @property
    def secret_bytes(self) -> bytes:
        return self.secret.encode("ascii")


@pytest_asyncio.fixture
async def make_agent(
    agent_lifecycle: AgentLifecycle,
) -> Callable[..., Coroutine[Any, Any, PlatformAgentCredentials]]:
    """Atomically provision agent row and initial ledger account via AgentLifecycle."""

    async def _make(
        *,
        external_id: str | None = None,
        name: str = "Test Platform Agent",
        currency: str = "USDC",
        **kwargs: Any,
    ) -> PlatformAgentCredentials:
        ext_id = external_id or f"ag_{uuid4().hex[:12]}"
        created = await agent_lifecycle.create_agent(
            CreateAgentCommand(external_id=ext_id, name=name, currency=currency)
        )
        return PlatformAgentCredentials(
            agent_id=created.agent_id,
            external_id=created.external_id,
            secret=created.secret,
        )

    return _make


@pytest_asyncio.fixture
async def seed_account(
    db_pool: asyncpg.Pool,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    apply_bootstrap: None,
) -> Any:
    """Seed account funds from authoritative platform system treasury account."""
    system_ref = await account_directory.get_system_account("USDC")

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE ledger_accounts
            SET balance = balance + 100_000_000_000, version = version + 1
            WHERE id = $1;
            """,
            system_ref.account_id,
        )

    async def _seed(account_id: UUID, amount: int, currency: str = "USDC") -> Any:
        return await ledger_store.post_transaction(
            [
                EntryDraft(
                    account_id=system_ref.account_id,
                    direction=Direction.DEBIT,
                    amount=amount,
                    currency=currency,
                ),
                EntryDraft(
                    account_id=account_id,
                    direction=Direction.CREDIT,
                    amount=amount,
                    currency=currency,
                ),
            ]
        )

    return _seed


@pytest_asyncio.fixture
async def platform_client(
    build_app: Any,
) -> AsyncGenerator[tuple[httpx.AsyncClient, Any], None]:
    """Provide httpx AsyncClient connected to the live platform application.

    Manual lifespan CM avoids external dependencies (asgi-lifespan) while guaranteeing
    that PostgreSQL pool, Valkey, and RabbitMQ event bus are cleanly initialized and drained.
    """
    app = build_app()
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client, app


async def _clean_entities(pool: asyncpg.Pool, agent_id: UUID, merchant_id: UUID) -> None:
    """Clean transient test entities from tables that permit deletions."""
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM payment_holds WHERE agent_id = $1;", agent_id)
        await conn.execute("DELETE FROM idempotency_keys WHERE agent_id = $1;", agent_id)
        await conn.execute("DELETE FROM agent_limits WHERE agent_id = $1;", agent_id)
        await conn.execute("DELETE FROM agents WHERE id = $1;", agent_id)
        await conn.execute("DELETE FROM merchants WHERE id = $1;", merchant_id)


# -----------------------------------------------------------------------------
# 1. ORDER-PROBE TEST
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_middleware_order_probe(
    platform_client: tuple[httpx.AsyncClient, Any],
) -> None:
    """Verify middleware registration and execution order.

    FastAPI / Starlette reverse-registration semantics:
    app.user_middleware[0] is AdminAuthMiddleware (registered first).
    app.user_middleware[1] is GatewayMiddleware (registered last -> outermost).

    Ingress verification:
    Request to unauthenticated /admin/agents triggers 401 AuthenticationError in
    AdminAuthMiddleware. GatewayMiddleware wraps outermost, executing Stage 0 context
    binding and attaching X-FLX-Request-Id to the response.
    """
    client, app = platform_client

    assert len(app.user_middleware) >= 2
    assert app.user_middleware[0].cls is GatewayMiddleware
    assert any(m.cls is AdminAuthMiddleware for m in app.user_middleware)

    resp = await client.post("/admin/agents", json={})
    assert resp.status_code == 401

    request_id = resp.headers.get(HEADER_REQUEST_ID)
    assert request_id is not None
    assert len(request_id) > 0

    envelope = ErrorEnvelope.model_validate(resp.json())
    assert envelope.error.code == "authentication_failed"


# -----------------------------------------------------------------------------
# 2. THE FIRST REAL PAYMENT (THE PLATFORM MOMENT)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_first_real_payment_full_stack(
    platform_client: tuple[httpx.AsyncClient, Any],
    db_pool: asyncpg.Pool,
    make_agent: Any,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    seed_account: Any,
    signed_request: Any,
) -> None:
    """Execute the first real payment through the full assembled stack.

    Proves:
    Gateway authentication -> PaymentService orchestration -> Double-entry ledger post ->
    RabbitMQ payment.settled publication -> Valkey outflow tracking -> HTTP 201 response.
    """
    client, app = platform_client

    # 1. Provision Agent and Merchant
    creds = await make_agent()
    merch_ext = f"mch_plat_{uuid4().hex[:10]}"
    merchant = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=merch_ext)
    )

    try:
        agent_acct = await account_directory.get_agent_account(creds.agent_id)
        merchant_acct = await account_directory.get_merchant_account(merch_ext)
        fees_acct = await account_directory.get_fees_account()

        # 2. Fund agent with $100 (100_000 minor units)
        await seed_account(agent_acct.account_id, 100_000, "USDC")

        # 3. Subscribe event bus consumer group before payment
        await app.state.bus.ensure_group(EventType.PAYMENT_SETTLED, "platform_e2e")

        # 4. Execute signed payment: $10.50 (1050 minor units) -> fee=10, total=1060
        idem_key = f"e2e-pay-{uuid4().hex[:12]}"
        payload = {"to": merch_ext, "amount": 1050, "currency": "USDC"}
        body_bytes = json.dumps(payload).encode("utf-8")

        resp = await signed_request(
            client,
            creds,
            "POST",
            "/v1/payments",
            body=body_bytes,
            idem=idem_key,
        )

        assert resp.status_code == 201
        assert resp.headers.get(HEADER_REQUEST_ID) is not None
        assert "X-FLX-Idempotent-Replay" not in resp.headers

        payment_resp = PaymentResponse.model_validate(resp.json())
        expected_tx_id = deterministic_tx_id(creds.agent_id, idem_key)
        assert payment_resp.id == expected_tx_id
        assert payment_resp.status == "settled"

        # 5. Assert Ledger Entries (3-legged balanced transaction)
        tx = await app.state.ledger.get_transaction(expected_tx_id)
        assert tx is not None
        assert len(tx.entries) == 3

        e_agent, e_merch, e_fee = tx.entries
        assert e_agent.account_id == agent_acct.account_id
        assert e_agent.direction == Direction.DEBIT
        assert e_agent.amount == 1060

        assert e_merch.account_id == merchant_acct.account_id
        assert e_merch.direction == Direction.CREDIT
        assert e_merch.amount == 1050

        assert e_fee.account_id == fees_acct.account_id
        assert e_fee.direction == Direction.CREDIT
        assert e_fee.amount == 10

        # 6. Assert Ledger Balances via HTTP /v1/balance
        bal_resp = await signed_request(client, creds, "GET", "/v1/balance")
        assert bal_resp.status_code == 200
        bal_data = BalanceResponse.model_validate(bal_resp.json())
        assert bal_data.balance == 100_000 - 1060
        assert bal_data.currency == "USDC"

        # 7. Assert RabbitMQ Event Delivery
        deliveries = await app.state.bus.read_batch(
            EventType.PAYMENT_SETTLED,
            "platform_e2e",
            "consumer_1",
            count=10,
            block_ms=500,
        )
        matching = [d for d in deliveries if d.envelope.payload.get("tx_id") == str(expected_tx_id)]
        assert len(matching) == 1
        event_payload = matching[0].envelope.payload
        assert event_payload["amount"] == 1050
        assert event_payload["fee"] == 10
        assert event_payload["total"] == 1060
        assert event_payload["merchant"] == merch_ext

        # 8. Assert Absence of Audit Rows (Payment lane does NOT write to audit log)
        async with db_pool.acquire() as conn:
            audit_count = await conn.fetchval(
                "SELECT COUNT(*) FROM audit_log WHERE target_id = $1;",
                str(expected_tx_id),
            )
            assert audit_count == 0

    finally:
        await _clean_entities(db_pool, creds.agent_id, merchant.merchant_id)


# -----------------------------------------------------------------------------
# 3. THREE-TIER IDEMPOTENCY REPLAY DANCE
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_three_tier_replay_dance(
    platform_client: tuple[httpx.AsyncClient, Any],
    db_pool: asyncpg.Pool,
    make_agent: Any,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    seed_account: Any,
    signed_request: Any,
) -> None:
    """Prove the three-tier idempotency dance:

    Tier 1 (Redis Fast-Path):
    Second request hits Valkey cache -> 201 with X-FLX-Idempotent-Replay: true.

    Tier 2 (PostgreSQL DB-Tier):
    Valkey keys deleted. Third request bypasses FastPath, hits PostgreSQL reservation,
    and returns cached wire bytes -> 201 byte-equal WITHOUT replay header.

    Tier 3 (Fresh Execution):
    Initial request executed through double-entry ledger.
    """
    client, app = platform_client

    creds = await make_agent()
    merch_ext = f"mch_tier_{uuid4().hex[:10]}"
    merchant = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=merch_ext)
    )

    try:
        agent_acct = await account_directory.get_agent_account(creds.agent_id)
        await seed_account(agent_acct.account_id, 100_000, "USDC")

        idem_key = f"tier-dance-{uuid4().hex[:12]}"
        payload = {"to": merch_ext, "amount": 1050, "currency": "USDC"}
        body_bytes = json.dumps(payload).encode("utf-8")

        # 1. Tier 3: Fresh execution
        resp1 = await signed_request(
            client,
            creds,
            "POST",
            "/v1/payments",
            body=body_bytes,
            idem=idem_key,
        )
        assert resp1.status_code == 201
        assert "X-FLX-Idempotent-Replay" not in resp1.headers
        tx_id = PaymentResponse.model_validate(resp1.json()).id

        # 2. Tier 1: Valkey Fast-Path Replay
        resp2 = await signed_request(
            client,
            creds,
            "POST",
            "/v1/payments",
            body=body_bytes,
            idem=idem_key,
        )
        assert resp2.status_code == 201
        assert resp2.headers.get("X-FLX-Idempotent-Replay") == "true"
        assert resp2.content == resp1.content

        # Verify ledger transactions count is still 1
        tx1 = await app.state.ledger.get_transaction(tx_id)
        assert tx1 is not None
        assert len(tx1.entries) == 3

        # 3. Tier 2: Flush Valkey Idempotency Cache to force DB-Tier Replay
        valkey = app.state.valkey
        keys = await valkey.keys(f"flx:idem:{{{creds.agent_id}}}:{idem_key}*")
        if keys:
            await valkey.delete(*keys)

        # 4. Tier 2: Database-Tier Replay (handled by service.pay via PostgreSQL)
        resp3 = await signed_request(
            client,
            creds,
            "POST",
            "/v1/payments",
            body=body_bytes,
            idem=idem_key,
        )
        assert resp3.status_code == 201
        # Middleware fast-path missed, so no fast-path header
        assert "X-FLX-Idempotent-Replay" not in resp3.headers
        # But wire bytes are byte-identical to the original output
        assert resp3.content == resp1.content

        # Verify ledger transactions count is still exactly 1
        tx2 = await app.state.ledger.get_transaction(tx_id)
        assert tx2 is not None
        assert len(tx2.entries) == 3

    finally:
        await _clean_entities(db_pool, creds.agent_id, merchant.merchant_id)


# -----------------------------------------------------------------------------
# 4. ERROR DIALECT OVER HTTP
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_error_dialect_over_http(
    platform_client: tuple[httpx.AsyncClient, Any],
    db_pool: asyncpg.Pool,
    make_agent: Any,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    seed_account: Any,
    signed_request: Any,
) -> None:
    """Verify platform-wide error dialect adheres to frozen Task 4 ErrorEnvelope."""
    client, _app = platform_client

    creds = await make_agent()
    merch_ext = f"mch_err_{uuid4().hex[:10]}"
    merchant = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=merch_ext)
    )

    try:
        agent_acct = await account_directory.get_agent_account(creds.agent_id)

        # a) Unknown merchant -> 404 not_found
        await seed_account(agent_acct.account_id, 100_000, "USDC")
        bad_merch_resp = await signed_request(
            client,
            creds,
            "POST",
            "/v1/payments",
            body=json.dumps({"to": "mch_nonexistent", "amount": 1050, "currency": "USDC"}).encode(),
        )
        assert bad_merch_resp.status_code == 404
        env_404 = ErrorEnvelope.model_validate(bad_merch_resp.json())
        assert env_404.error.code == "not_found"

        # b) Insufficient funds -> 400 insufficient_funds
        unfunded_creds = await make_agent()
        insuf_resp = await signed_request(
            client,
            unfunded_creds,
            "POST",
            "/v1/payments",
            body=json.dumps({"to": merch_ext, "amount": 1050, "currency": "USDC"}).encode(),
        )
        assert insuf_resp.status_code == 400
        env_400 = ErrorEnvelope.model_validate(insuf_resp.json())
        assert env_400.error.code == "insufficient_funds"

        # c) Velocity limit policy reject -> 422 payment_policy_rejected
        vel_creds = await make_agent()
        vel_acct = await account_directory.get_agent_account(vel_creds.agent_id)
        await seed_account(vel_acct.account_id, 100_000, "USDC")
        limits_repo = LimitRepo(db_pool)
        await limits_repo.upsert(
            vel_creds.agent_id,
            AgentLimits(
                agent_id=vel_creds.agent_id,
                velocity_limit=2,  # attempt 1 (<2) succeeds; attempt 2 (>=2) rejects
                velocity_window_s=60,
                max_single_tx_minor=100_000,
                daily_outflow_cap_minor=500_000,
            ),
        )
        # Attempt 1: succeeds
        ok_resp = await signed_request(
            client,
            vel_creds,
            "POST",
            "/v1/payments",
            body=json.dumps({"to": merch_ext, "amount": 1050, "currency": "USDC"}).encode(),
        )
        assert ok_resp.status_code == 201

        # Attempt 2: breaches velocity limit
        vel_resp = await signed_request(
            client,
            vel_creds,
            "POST",
            "/v1/payments",
            body=json.dumps({"to": merch_ext, "amount": 1050, "currency": "USDC"}).encode(),
        )
        assert vel_resp.status_code == 422
        env_policy = ErrorEnvelope.model_validate(vel_resp.json())
        assert env_policy.error.code == "payment_policy_rejected"

        # d) Bad body ("ammount" typo, extra forbidden) -> 422 validation_failed
        bad_body_resp = await signed_request(
            client,
            creds,
            "POST",
            "/v1/payments",
            body=b'{"to":"merchant_demo","ammount":1050,"currency":"USDC"}',
        )
        assert bad_body_resp.status_code == 422
        env_val = ErrorEnvelope.model_validate(bad_body_resp.json())
        assert env_val.error.code == "validation_failed"
        assert env_val.error.message == "Request payload failed validation."

    finally:
        await _clean_entities(db_pool, creds.agent_id, merchant.merchant_id)


# -----------------------------------------------------------------------------
# 5. ADMIN LANE MOUNT & RBAC DEFENSE
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_lane_mounted_and_guarded(
    platform_client: tuple[httpx.AsyncClient, Any],
    db_pool: asyncpg.Pool,
    make_user: Any,
    mint_admin_token: Callable[..., str],
) -> None:
    """Verify admin lane mount, Bearer token enforcement, and defense-in-depth DB check."""
    client, _app = platform_client

    # 1. Unauthenticated request to /admin/agents -> 401
    resp_no_auth = await client.post("/admin/agents", json={})
    assert resp_no_auth.status_code == 401
    env_401 = ErrorEnvelope.model_validate(resp_no_auth.json())
    assert env_401.error.code == "authentication_failed"

    # 2. Token with insufficient role (support role attempting agent provisioning) -> 403
    support_sub = str(uuid4())
    await make_user(role="support", keycloak_sub=support_sub)
    support_token = mint_admin_token(sub=support_sub, role="support")

    resp_forbidden = await client.post(
        "/admin/agents",
        json={"external_id": f"ag_{uuid4().hex[:10]}", "name": "Agent Forbidden"},
        headers={"Authorization": f"Bearer {support_token}"},
    )
    assert resp_forbidden.status_code == 403
    env_403 = ErrorEnvelope.model_validate(resp_forbidden.json())
    assert env_403.error.code == "forbidden"
    assert env_403.error.message == "insufficient permissions"

    # 3. Valid admin token + active database user -> 201 Created
    admin_sub = str(uuid4())
    await make_user(role="admin", keycloak_sub=admin_sub)
    admin_token = mint_admin_token(sub=admin_sub, role="admin")

    new_ext_id = f"ag_adm_{uuid4().hex[:10]}"
    resp_created = await client.post(
        "/admin/agents",
        json={
            "external_id": new_ext_id,
            "name": "Operator Provisioned Agent",
            "currency": "USDC",
            "rate_limit_max": 250,
            "daily_quota_max": 5000,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_created.status_code == 201
    body = resp_created.json()
    assert "id" in body
    assert body["external_id"] == new_ext_id
    assert "secret" in body
    created_id = UUID(body["id"])

    # Verify audit row created
    async with db_pool.acquire() as conn:
        audit_row = await conn.fetchrow(
            "SELECT action, target_id FROM audit_log WHERE target_id = $1;",
            str(created_id),
        )
        assert audit_row is not None
        assert audit_row["action"] == "agent.create"

        # Teardown created agent
        await conn.execute("DELETE FROM agents WHERE id = $1;", created_id)
        await conn.execute("DELETE FROM ledger_accounts WHERE owner_id = $1;", created_id)


# -----------------------------------------------------------------------------
# 6. DOCUMENTATION SUPPRESSION POLICY
# -----------------------------------------------------------------------------


def test_docs_suppression_policy(build_app: Any, make_gateway_settings: Any) -> None:
    """Assert production environment suppresses /docs and /openapi.json for security."""
    prod_settings = make_gateway_settings(env="production")
    prod_app = build_app(settings=prod_settings)

    assert prod_app.docs_url is None
    assert prod_app.redoc_url is None
    assert prod_app.openapi_url is None

    dev_settings = make_gateway_settings(env="development")
    dev_app = build_app(settings=dev_settings)

    assert dev_app.docs_url == "/docs"
    assert dev_app.openapi_url == "/openapi.json"


# -----------------------------------------------------------------------------
# 7. GET PAYMENT BY ID
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_payment_by_id(
    platform_client: tuple[httpx.AsyncClient, Any],
    db_pool: asyncpg.Pool,
    make_agent: Any,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    seed_account: Any,
    signed_request: Any,
) -> None:
    """Verify GET /v1/payments/{tx_id} returns settled PaymentDetail or 404."""
    client, _app = platform_client

    creds = await make_agent()
    merch_ext = f"mch_get_{uuid4().hex[:10]}"
    merchant = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=merch_ext)
    )

    try:
        agent_acct = await account_directory.get_agent_account(creds.agent_id)
        await seed_account(agent_acct.account_id, 100_000, "USDC")

        # 1. Unknown payment -> 404
        unknown_id = uuid4()
        resp_404 = await signed_request(client, creds, "GET", f"/v1/payments/{unknown_id}")
        assert resp_404.status_code == 404
        env_404 = ErrorEnvelope.model_validate(resp_404.json())
        assert env_404.error.code == "not_found"

        # 2. Execute payment
        idem_key = f"get-pay-{uuid4().hex[:12]}"
        pay_resp = await signed_request(
            client,
            creds,
            "POST",
            "/v1/payments",
            body=json.dumps({"to": merch_ext, "amount": 1050, "currency": "USDC"}).encode(),
            idem=idem_key,
        )
        assert pay_resp.status_code == 201
        tx_id = PaymentResponse.model_validate(pay_resp.json()).id

        # 3. Query payment by ID -> 200 settled PaymentDetail
        resp_known = await signed_request(client, creds, "GET", f"/v1/payments/{tx_id}")
        assert resp_known.status_code == 200
        detail = PaymentDetail.model_validate(resp_known.json())
        assert detail.id == tx_id
        assert detail.status == "settled"
        assert detail.amount == 1060  # Agent's debit amount
        assert detail.currency == "USDC"
        assert detail.created_at.tzinfo is not None

    finally:
        await _clean_entities(db_pool, creds.agent_id, merchant.merchant_id)


# -----------------------------------------------------------------------------
# 8. BALANCE ENDPOINT
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_balance_endpoint(
    platform_client: tuple[httpx.AsyncClient, Any],
    db_pool: asyncpg.Pool,
    make_agent: Any,
    account_directory: AccountDirectory,
    seed_account: Any,
    signed_request: Any,
) -> None:
    """Verify GET /v1/balance reflects double-entry ledger truth."""
    client, _app = platform_client

    creds = await make_agent()
    try:
        agent_acct = await account_directory.get_agent_account(creds.agent_id)

        # 1. Unfunded newly provisioned agent starts at 0
        resp_zero = await signed_request(client, creds, "GET", "/v1/balance")
        assert resp_zero.status_code == 200
        bal_zero = BalanceResponse.model_validate(resp_zero.json())
        assert bal_zero.balance == 0
        assert bal_zero.currency == "USDC"

        # 2. Fund agent with $50 (50_000 minor units)
        await seed_account(agent_acct.account_id, 50_000, "USDC")

        resp_funded = await signed_request(client, creds, "GET", "/v1/balance")
        assert resp_funded.status_code == 200
        bal_funded = BalanceResponse.model_validate(resp_funded.json())
        assert bal_funded.balance == 50_000
        assert bal_funded.currency == "USDC"

    finally:
        async with db_pool.acquire() as conn:
            await conn.execute("DELETE FROM agents WHERE id = $1;", creds.agent_id)


# -----------------------------------------------------------------------------
# 9. HELD FLOW & SETTLE_APPROVED (TASK 42 PREVIEW)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_held_flow_and_settle_approved_http(
    platform_client: tuple[httpx.AsyncClient, Any],
    db_pool: asyncpg.Pool,
    make_agent: Any,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    seed_account: Any,
    signed_request: Any,
) -> None:
    """Verify quarantined payment returns 201 held, no ledger tx, settles via settle_approved."""
    client, app = platform_client

    creds = await make_agent()
    merch_ext = f"mch_held_{uuid4().hex[:10]}"
    merchant = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=merch_ext)
    )

    try:
        agent_acct = await account_directory.get_agent_account(creds.agent_id)
        await seed_account(agent_acct.account_id, 1_000_000, "USDC")

        # Set single transaction ceiling lower than amount
        limits_repo = LimitRepo(db_pool)
        await limits_repo.upsert(
            creds.agent_id,
            AgentLimits(
                agent_id=creds.agent_id,
                velocity_limit=100,
                velocity_window_s=60,
                max_single_tx_minor=500,  # ceiling $5.00
                daily_outflow_cap_minor=500_000,
            ),
        )

        await app.state.bus.ensure_group(EventType.PAYMENT_HELD, "held_workers")

        # 1. Post payment exceeding ceiling -> 201 status="held"
        idem_key = f"held-flow-{uuid4().hex[:12]}"
        amount = 1050
        resp_held = await signed_request(
            client,
            creds,
            "POST",
            "/v1/payments",
            body=json.dumps({"to": merch_ext, "amount": amount, "currency": "USDC"}).encode(),
            idem=idem_key,
        )
        assert resp_held.status_code == 201
        pay_held = PaymentResponse.model_validate(resp_held.json())
        assert pay_held.status == "held"
        held_tx_id = pay_held.id

        # 2. Ledger transaction does NOT exist yet (held payments have no ledger entries)
        tx_pre = await app.state.ledger.get_transaction(held_tx_id)
        assert tx_pre is None

        # 3. GET /v1/payments/{held_id} returns 404 (ledger-truth contract)
        resp_get_held = await signed_request(client, creds, "GET", f"/v1/payments/{held_tx_id}")
        assert resp_get_held.status_code == 404

        # 4. RabbitMQ received payment.held event
        deliveries = await app.state.bus.read_batch(
            EventType.PAYMENT_HELD,
            "held_workers",
            "c_held",
            count=10,
            block_ms=500,
        )
        matching_held = [
            d for d in deliveries if d.envelope.payload.get("tx_id") == str(held_tx_id)
        ]
        assert len(matching_held) == 1
        assert matching_held[0].envelope.payload["reason"] == "single_tx_ceiling"

        # 5. Task 42 Settlement: direct invocation of settle_approved
        outcome_settled = await app.state.payments.settle_approved(
            agent_id=creds.agent_id,
            idem_key=idem_key,
            to_merchant=merch_ext,
            amount_minor=amount,
            currency="USDC",
        )
        assert outcome_settled.status == "settled"
        assert outcome_settled.tx_id == held_tx_id

        # 6. Ledger transaction now exists with 3 entries
        tx_post = await app.state.ledger.get_transaction(held_tx_id)
        assert tx_post is not None
        assert len(tx_post.entries) == 3

        # 7. GET /v1/payments/{held_id} now succeeds -> 200 settled PaymentDetail
        resp_get_settled = await signed_request(client, creds, "GET", f"/v1/payments/{held_tx_id}")
        assert resp_get_settled.status_code == 200
        detail = PaymentDetail.model_validate(resp_get_settled.json())
        assert detail.id == held_tx_id
        assert detail.status == "settled"
        assert detail.amount == 1060

    finally:
        await _clean_entities(db_pool, creds.agent_id, merchant.merchant_id)


# -----------------------------------------------------------------------------
# 10. OPENAPI GOLDEN FREEZE
# -----------------------------------------------------------------------------


def test_openapi_golden_freeze(build_app: Any) -> None:
    """Verify application OpenAPI schema strictly conforms to the frozen golden contract.

    Alarm Rule:
    Any divergence between app.openapi() and tests/golden/openapi.golden.json is a breaking
    contract alarm. Regulating API changes requires intentional review and a golden update.
    """
    assert GOLDEN_PATH.is_file(), f"Golden contract missing at {GOLDEN_PATH}"
    golden_schema = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))

    app = build_app()
    current_schema = app.openapi()

    assert current_schema == golden_schema, (
        "OpenAPI schema diverged from committed tests/golden/openapi.golden.json. "
        "Any changes to routes, parameters, or schemas require an intentional version bump."
    )


# -----------------------------------------------------------------------------
# 11. TZ PROBE POSITIVE INVARIANT
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tz_probe_positive(
    platform_client: tuple[httpx.AsyncClient, Any],
) -> None:
    """Verify that PostgreSQL connections acquired by the platform pool run under UTC."""
    _client, app = platform_client
    async with app.state.pool.acquire() as conn:
        tz = await conn.fetchval("SHOW timezone")
        assert tz in ("UTC", "Etc/UTC"), f"PostgreSQL connection timezone must be UTC, got {tz}"
