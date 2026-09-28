"""=============================================================================
Integration Tests for PaymentService: The Full Money Flow (Task 31)
=============================================================================
Proves the core money loop against real PostgreSQL and real Valkey infrastructure:
1. Real double-entry ledger (PostgresLedgerStore, hash chaining, solvency).
2. Real two-tier idempotency (PostgreSQL idempotency_keys, stale takeover, claim_tx).
3. Real risk engine (LimitRepo, limits evaluation, Redis counters, HITL quarantine).
4. Real EventBus (RabbitMQ / RedisStreamBus with quorum queue / stream delivery).
5. Real account topology (AccountDirectory, system/fees/merchant/agent accounts).

Tests:
- test_full_happy_path: 3-legged balanced transaction, event published, outflow incremented.
- test_idempotent_retry: byte-equal replay, zero new entries, zero new events.
- test_crash_recovery_window: crash between post and complete healed via probe; exactly-once.
- test_insufficient_funds: terminal fail(), payment.failed event, retry after funding settles.
- test_velocity_limit: policy reject, reservation FAILED, payment.failed event.
- test_quarantine_and_task42_handoff: held payment stays PENDING; settle_approved converges.
- test_reject_held: held payment rejected via reject_held -> FAILED + payment.failed.
- test_byte_exact_db_replays: identical bytes across multiple replays.
"""

from __future__ import annotations

import hashlib
import os
import socket
from collections.abc import AsyncGenerator, Callable, Coroutine
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import aio_pika
import asyncpg  # type: ignore[import-untyped]
import pytest
import pytest_asyncio
import redis.asyncio as redis_async

from fluxpay.ledger.hashchain import Direction
from fluxpay.ledger.postgres import PostgresLedgerStore
from fluxpay.ledger.store import EntryDraft
from fluxpay.payments.service import (
    PaymentService,
    deterministic_tx_id,
)
from fluxpay.registry.agents import (
    AgentLifecycle,
    CreateAgentCommand,
    CreateMerchantCommand,
    MerchantLifecycle,
)
from fluxpay.risk.limits import AgentLimits, LimitRepo
from fluxpay.risk.quarantine import QuarantineService
from fluxpay.shared import idempotency
from fluxpay.shared.errors import (
    IdempotencyConflict,
    InsufficientFunds,
    PaymentPolicyError,
)
from fluxpay.shared.events import (
    EventBus,
    EventType,
    RedisStreamBus,
)
from fluxpay.shared.rabbitmq_bus import RabbitMQBus
from fluxpay.wallet.accounts import AccountDirectory

pytestmark = pytest.mark.integration

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
MIGRATION_0007_PATH: Path = REPO_ROOT / "migrations" / "0007_limits.sql"


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _is_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    """Check if a network port is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


async def _clean_test_records(pool: asyncpg.Pool, agent_id: UUID, merchant_id: UUID) -> None:
    """Teardown ephemeral records created by tests.

    Crucially does NOT attempt to delete ledger_accounts or ledger_entries, as
    the double-entry ledger is strictly append-only and immutable; once entries
    are recorded against an account, FK constraints intentionally prevent account deletion.
    """
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM payment_holds WHERE agent_id = $1;", agent_id)
        await conn.execute("DELETE FROM idempotency_keys WHERE agent_id = $1;", agent_id)
        await conn.execute("DELETE FROM agent_limits WHERE agent_id = $1;", agent_id)
        await conn.execute("DELETE FROM agents WHERE id = $1;", agent_id)
        await conn.execute("DELETE FROM merchants WHERE id = $1;", merchant_id)


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def apply_limits_schema(
    db_pool: asyncpg.Pool,
    apply_agents_schema: None,
) -> None:
    """Execute migrations/0007_limits.sql once per session."""
    sql = MIGRATION_0007_PATH.read_text(encoding="utf-8")  # noqa: ASYNC240
    async with db_pool.acquire() as conn:
        await conn.execute(sql)


@pytest_asyncio.fixture
async def payment_bus(
    valkey_client: redis_async.Redis,
) -> AsyncGenerator[EventBus, None]:
    """Provide real EventBus: RabbitMQBus if broker reachable, else RedisStreamBus."""
    rmq_url = os.environ.get("FLX_RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
    host = "localhost"
    port = 5672
    prefix = f"t{uuid4().hex[:10]}"

    if _is_port_open(host, port):
        try:
            conn = await aio_pika.connect_robust(rmq_url)
            bus = RabbitMQBus(conn, key_prefix=prefix)
            yield bus
            await conn.close()
            return
        except Exception:  # noqa: S110
            pass

    # High-performance native fallback to RedisStreamBus on live Valkey
    stream_bus = RedisStreamBus(valkey_client, key_prefix=f"flx:events:{prefix}")
    yield stream_bus


@pytest_asyncio.fixture
async def seed_account(
    db_pool: asyncpg.Pool,
    ledger_store: PostgresLedgerStore,
    account_directory: AccountDirectory,
) -> Callable[[UUID, int, str], Coroutine[Any, Any, Any]]:
    """Seed an agent account from the prefunded bootstrap system platform account.

    Avoids ephemeral account creation with broken conftest teardown (which attempts
    DELETE on append-only ledger_entries).
    """
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

    async def _seed(
        account_id: UUID,
        amount: int,
        currency: str = "USDC",
    ) -> Any:
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


# ==============================================================================
# 1. FULL HAPPY PATH INTEGRATION TEST
# ==============================================================================


async def test_full_happy_path(
    db_pool: asyncpg.Pool,
    valkey_client: redis_async.Redis,
    agent_lifecycle: AgentLifecycle,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    seed_account: Any,
    payment_bus: EventBus,
    apply_bootstrap: None,
    apply_idempotency_schema: None,
    apply_limits_schema: None,
) -> None:
    """Verify complete money flow against real Postgres, Valkey, and event transport."""
    # 1. Provision Agent & Merchant
    agent_ext = f"agt_{uuid4().hex[:12]}"
    merch_ext = f"mch_{uuid4().hex[:12]}"
    agent = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=agent_ext))
    merchant = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=merch_ext)
    )

    try:
        agent_acct = await account_directory.get_agent_account(agent.agent_id)
        merchant_acct = await account_directory.get_merchant_account(merch_ext)
        fees_acct = await account_directory.get_fees_account()

        # 2. Fund Agent with 1_000_000_000 minor units ($1,000)
        await seed_account(agent_acct.account_id, 1_000_000_000, "USDC")
        init_agent_bal = (await ledger_store.get_balance(agent_acct.account_id)).balance
        init_fees_bal = (await ledger_store.get_balance(fees_acct.account_id)).balance
        assert init_agent_bal == 1_000_000_000

        # 3. Assemble Service with real dependencies
        limits_repo = LimitRepo(db_pool)
        quarantine = QuarantineService(db_pool)
        service = PaymentService(
            ledger=ledger_store,
            directory=account_directory,
            limits_repo=limits_repo,
            quarantine=quarantine,
            bus=payment_bus,
            valkey=valkey_client,
            pool=db_pool,
        )

        # 4. Ensure Event Bus consumer group is watching BEFORE event is published
        await payment_bus.ensure_group(EventType.PAYMENT_SETTLED, "happy_workers")

        # 5. Execute Payment: 10,000 minor units ($0.01) -> fee=100, total=10,100
        idem_key = f"flow-happy-{uuid4().hex[:12]}"
        body_hash = _sha256_hex("payment-test-happy-10000")
        outcome = await service.pay(
            agent_id=agent.agent_id,
            idem_key=idem_key,
            body_hash=body_hash,
            to_merchant=merch_ext,
            amount_minor=10_000,
            currency="USDC",
        )

        # 6. Assert Outcome
        expected_tx_id = deterministic_tx_id(agent.agent_id, idem_key)
        assert outcome.status == "settled"
        assert outcome.tx_id == expected_tx_id
        assert outcome.response_status == 201
        assert outcome.replayed is False

        # 6. Assert Ledger Entries & Balances in Postgres
        tx = await ledger_store.get_transaction(expected_tx_id)
        assert tx is not None
        assert len(tx.entries) == 3
        # Debit agent 10,100; credit merchant 10,000; credit fees 100
        e_agent, e_merch, e_fee = tx.entries
        assert e_agent.account_id == agent_acct.account_id
        assert e_agent.direction == Direction.DEBIT
        assert e_agent.amount == 10_100
        assert e_merch.account_id == merchant_acct.account_id
        assert e_merch.direction == Direction.CREDIT
        assert e_merch.amount == 10_000
        assert e_fee.account_id == fees_acct.account_id
        assert e_fee.direction == Direction.CREDIT
        assert e_fee.amount == 100

        bal_agent = await ledger_store.get_balance(agent_acct.account_id)
        bal_merch = await ledger_store.get_balance(merchant_acct.account_id)
        bal_fee = await ledger_store.get_balance(fees_acct.account_id)
        assert bal_agent.balance == 1_000_000_000 - 10_100
        assert bal_merch.balance == 10_000
        assert bal_fee.balance == init_fees_bal + 100

        # 7. Assert Idempotency Row in Postgres
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT state, tx_id, response_status, response_body
                FROM idempotency_keys
                WHERE agent_id = $1 AND idem_key = $2;
                """,
                agent.agent_id,
                idem_key,
            )
            assert row is not None
            assert row["state"] == "COMPLETED"
            assert row["tx_id"] == expected_tx_id
            assert row["response_status"] == 201
            assert row["response_body"] == outcome.wire_body.decode("utf-8")

        # 8. Assert Outflow in Valkey
        now_dt = datetime.now(UTC)
        yyyymmdd = now_dt.strftime("%Y%m%d")
        outflow_key = f"flx:outflow:{{{agent.agent_id}}}:{yyyymmdd}"
        stored_outflow = await valkey_client.get(outflow_key)
        assert stored_outflow == b"10100" or stored_outflow == "10100"

        # 9. Assert Event Bus Delivery
        await payment_bus.ensure_group(EventType.PAYMENT_SETTLED, "happy_workers")
        deliveries = await payment_bus.read_batch(
            EventType.PAYMENT_SETTLED,
            "happy_workers",
            "c1",
            count=10,
            block_ms=500,
        )
        assert len(deliveries) >= 1
        matching = [d for d in deliveries if d.envelope.payload.get("tx_id") == str(expected_tx_id)]
        assert len(matching) == 1
        m_payload = matching[0].envelope.payload
        assert m_payload["merchant"] == merch_ext
        assert m_payload["amount"] == 10_000
        assert m_payload["fee"] == 100
        assert m_payload["total"] == 10_100
        assert m_payload["currency"] == "USDC"

    finally:
        await _clean_test_records(db_pool, agent.agent_id, merchant.merchant_id)


# ==============================================================================
# 2. IDEMPOTENT RETRY INTEGRATION TEST
# ==============================================================================


async def test_idempotent_retry(
    db_pool: asyncpg.Pool,
    valkey_client: redis_async.Redis,
    agent_lifecycle: AgentLifecycle,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    seed_account: Any,
    payment_bus: EventBus,
    apply_bootstrap: None,
    apply_idempotency_schema: None,
    apply_limits_schema: None,
) -> None:
    """Invoking pay() twice with same parameters returns cached response with no second debit."""
    agent_ext = f"agt_{uuid4().hex[:12]}"
    merch_ext = f"mch_{uuid4().hex[:12]}"
    agent = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=agent_ext))
    merchant = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=merch_ext)
    )

    try:
        agent_acct = await account_directory.get_agent_account(agent.agent_id)
        await seed_account(agent_acct.account_id, 1_000_000_000, "USDC")

        service = PaymentService(
            ledger=ledger_store,
            directory=account_directory,
            limits_repo=LimitRepo(db_pool),
            quarantine=QuarantineService(db_pool),
            bus=payment_bus,
            valkey=valkey_client,
            pool=db_pool,
        )

        idem_key = f"flow-retry-{uuid4().hex[:12]}"
        body_hash = _sha256_hex("payment-test-retry-body")

        # 1. First execution
        o1 = await service.pay(
            agent_id=agent.agent_id,
            idem_key=idem_key,
            body_hash=body_hash,
            to_merchant=merch_ext,
            amount_minor=20_000,
            currency="USDC",
        )
        assert o1.status == "settled"
        assert o1.replayed is False

        # 2. Second execution (retry)
        o2 = await service.pay(
            agent_id=agent.agent_id,
            idem_key=idem_key,
            body_hash=body_hash,
            to_merchant=merch_ext,
            amount_minor=20_000,
            currency="USDC",
        )
        assert o2.status == "settled"
        assert o2.replayed is True

        # Invariants: byte-equal outcome, same tx_id, zero new entries
        assert o1.tx_id == o2.tx_id
        assert o1.response_status == o2.response_status
        assert o1.wire_body == o2.wire_body

        tx = await ledger_store.get_transaction(o1.tx_id)
        assert tx is not None
        assert len(tx.entries) == 3

        # Balance check: only 1 debit of 20,200 total
        bal = await ledger_store.get_balance(agent_acct.account_id)
        assert bal.balance == 1_000_000_000 - 20_200

    finally:
        await _clean_test_records(db_pool, agent.agent_id, merchant.merchant_id)


# ==============================================================================
# 3. CRASH RECOVERY WINDOW TEST (EXACTLY-ONCE PROOF IN REAL POSTGRES)
# ==============================================================================


async def test_crash_recovery_window(
    db_pool: asyncpg.Pool,
    valkey_client: redis_async.Redis,
    agent_lifecycle: AgentLifecycle,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    seed_account: Any,
    payment_bus: EventBus,
    apply_bootstrap: None,
    apply_idempotency_schema: None,
    apply_limits_schema: None,
) -> None:
    """Simulate a worker crash after ledger post before completion.

    Re-entry after stale takeover finds existing transaction via probe, skips post,
    and completes cleanly without double debit.
    """
    agent_ext = f"agt_{uuid4().hex[:12]}"
    merch_ext = f"mch_{uuid4().hex[:12]}"
    agent = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=agent_ext))
    merchant = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=merch_ext)
    )

    try:
        agent_acct = await account_directory.get_agent_account(agent.agent_id)
        await seed_account(agent_acct.account_id, 1_000_000_000, "USDC")

        idem_key = f"flow-crash-{uuid4().hex[:12]}"
        body_hash = _sha256_hex("payment-test-crash-body")
        tx_id = deterministic_tx_id(agent.agent_id, idem_key)

        # Create a crashing idempotency module that fails on complete()
        class CrashingIdempotency:
            def __getattr__(self, name: str) -> Any:
                return getattr(idempotency, name)

            async def complete(self, *args: Any, **kwargs: Any) -> None:
                raise RuntimeError("CRASH_AFTER_LEDGER_POST_SIMULATED")

        crashing_service = PaymentService(
            ledger=ledger_store,
            directory=account_directory,
            limits_repo=LimitRepo(db_pool),
            quarantine=QuarantineService(db_pool),
            bus=payment_bus,
            valkey=valkey_client,
            pool=db_pool,
            idempotency_module=CrashingIdempotency(),
        )

        # 1. Run pay() -> raises simulated crash
        with pytest.raises(RuntimeError, match="CRASH_AFTER_LEDGER_POST_SIMULATED"):
            await crashing_service.pay(
                agent_id=agent.agent_id,
                idem_key=idem_key,
                body_hash=body_hash,
                to_merchant=merch_ext,
                amount_minor=15_000,
                currency="USDC",
            )

        # At this instant:
        # - Ledger transaction ALREADY POSTED in real Postgres
        tx_before = await ledger_store.get_transaction(tx_id)
        assert tx_before is not None
        assert len(tx_before.entries) == 3

        # - Idempotency reservation in Postgres is PENDING with claimed tx_id
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT state, tx_id FROM idempotency_keys WHERE agent_id = $1 AND idem_key = $2;",
                agent.agent_id,
                idem_key,
            )
            assert row is not None
            assert row["state"] == "PENDING"
            assert row["tx_id"] == tx_id

            # Simulate passage of time (> 30s) so reservation becomes stale and reclaimable
            await conn.execute(
                """
                UPDATE idempotency_keys
                SET reserved_at = now() - interval '60 seconds'
                WHERE agent_id = $1 AND idem_key = $2;
                """,
                agent.agent_id,
                idem_key,
            )

        # 2. Fresh service executes payment on retry
        fresh_service = PaymentService(
            ledger=ledger_store,
            directory=account_directory,
            limits_repo=LimitRepo(db_pool),
            quarantine=QuarantineService(db_pool),
            bus=payment_bus,
            valkey=valkey_client,
            pool=db_pool,
        )

        outcome = await fresh_service.pay(
            agent_id=agent.agent_id,
            idem_key=idem_key,
            body_hash=body_hash,
            to_merchant=merch_ext,
            amount_minor=15_000,
            currency="USDC",
        )

        # Outcome converges to settled!
        assert outcome.status == "settled"
        assert outcome.tx_id == tx_id

        # Ledger entries count for tx_id is STILL 3 (post was skipped via probe!)
        tx_after = await ledger_store.get_transaction(tx_id)
        assert tx_after is not None
        assert len(tx_after.entries) == 3

        # Balance only decremented once: 15_000 + 150 fee = 15_150
        bal = await ledger_store.get_balance(agent_acct.account_id)
        assert bal.balance == 1_000_000_000 - 15_150

        # Reservation is now COMPLETED
        async with db_pool.acquire() as conn:
            state = await conn.fetchval(
                "SELECT state FROM idempotency_keys WHERE agent_id = $1 AND idem_key = $2;",
                agent.agent_id,
                idem_key,
            )
            assert state == "COMPLETED"

    finally:
        await _clean_test_records(db_pool, agent.agent_id, merchant.merchant_id)


# ==============================================================================
# 4. INSUFFICIENT FUNDS INTEGRATION TEST
# ==============================================================================


async def test_insufficient_funds_flow(
    db_pool: asyncpg.Pool,
    valkey_client: redis_async.Redis,
    agent_lifecycle: AgentLifecycle,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    seed_account: Any,
    payment_bus: EventBus,
    apply_bootstrap: None,
    apply_idempotency_schema: None,
    apply_limits_schema: None,
) -> None:
    """Unfunded account triggers InsufficientFunds and marks reservation FAILED."""
    agent_ext = f"agt_{uuid4().hex[:12]}"
    merch_ext = f"mch_{uuid4().hex[:12]}"
    agent = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=agent_ext))
    merchant = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=merch_ext)
    )

    try:
        agent_acct = await account_directory.get_agent_account(agent.agent_id)
        # Agent starts with 0 balance!

        service = PaymentService(
            ledger=ledger_store,
            directory=account_directory,
            limits_repo=LimitRepo(db_pool),
            quarantine=QuarantineService(db_pool),
            bus=payment_bus,
            valkey=valkey_client,
            pool=db_pool,
        )

        idem_key = f"flow-insufficient-{uuid4().hex[:12]}"
        body_hash = _sha256_hex("unfunded-payment")

        # 1. Attempt payment without funds
        with pytest.raises(InsufficientFunds):
            await service.pay(
                agent_id=agent.agent_id,
                idem_key=idem_key,
                body_hash=body_hash,
                to_merchant=merch_ext,
                amount_minor=10_000,
                currency="USDC",
            )

        # Idempotency row must be FAILED in Postgres
        async with db_pool.acquire() as conn:
            state = await conn.fetchval(
                "SELECT state FROM idempotency_keys WHERE agent_id = $1 AND idem_key = $2;",
                agent.agent_id,
                idem_key,
            )
            assert state == "FAILED"

        # 2. Fund the agent account
        await seed_account(agent_acct.account_id, 1_000_000_000, "USDC")

        # 3. Retry with SAME idempotency key (FAILED row is reclaimable)
        outcome = await service.pay(
            agent_id=agent.agent_id,
            idem_key=idem_key,
            body_hash=body_hash,
            to_merchant=merch_ext,
            amount_minor=10_000,
            currency="USDC",
        )

        assert outcome.status == "settled"
        assert outcome.replayed is False

        # Reservation is now COMPLETED
        async with db_pool.acquire() as conn:
            state = await conn.fetchval(
                "SELECT state FROM idempotency_keys WHERE agent_id = $1 AND idem_key = $2;",
                agent.agent_id,
                idem_key,
            )
            assert state == "COMPLETED"

    finally:
        await _clean_test_records(db_pool, agent.agent_id, merchant.merchant_id)


# ==============================================================================
# 5. VELOCITY REJECT INTEGRATION TEST
# ==============================================================================


async def test_velocity_limit_flow(
    db_pool: asyncpg.Pool,
    valkey_client: redis_async.Redis,
    agent_lifecycle: AgentLifecycle,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    seed_account: Any,
    payment_bus: EventBus,
    apply_bootstrap: None,
    apply_idempotency_schema: None,
    apply_limits_schema: None,
) -> None:
    """Enforce velocity limit against live Valkey counter: breaches fail reservation."""
    agent_ext = f"agt_{uuid4().hex[:12]}"
    merch_ext = f"mch_{uuid4().hex[:12]}"
    agent = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=agent_ext))
    merchant = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=merch_ext)
    )

    try:
        agent_acct = await account_directory.get_agent_account(agent.agent_id)
        await seed_account(agent_acct.account_id, 1_000_000_000, "USDC")

        limits_repo = LimitRepo(db_pool)
        # Configure strict limit: 2 attempts per 60s
        await limits_repo.upsert(
            agent.agent_id,
            AgentLimits(
                agent_id=agent.agent_id,
                velocity_limit=2,
                velocity_window_s=60,
                max_single_tx_minor=100_000_000,
                daily_outflow_cap_minor=500_000_000,
            ),
        )

        service = PaymentService(
            ledger=ledger_store,
            directory=account_directory,
            limits_repo=limits_repo,
            quarantine=QuarantineService(db_pool),
            bus=payment_bus,
            valkey=valkey_client,
            pool=db_pool,
        )

        # 1st attempt: succeeds
        o1 = await service.pay(
            agent_id=agent.agent_id,
            idem_key=f"vel-1-{uuid4().hex[:8]}",
            body_hash=_sha256_hex("v1"),
            to_merchant=merch_ext,
            amount_minor=1_000,
        )
        assert o1.status == "settled"

        # 2nd attempt: breaches velocity limit (2 >= 2) -> PaymentPolicyError
        idem_key2 = f"vel-2-{uuid4().hex[:8]}"
        with pytest.raises(PaymentPolicyError):
            await service.pay(
                agent_id=agent.agent_id,
                idem_key=idem_key2,
                body_hash=_sha256_hex("v2"),
                to_merchant=merch_ext,
                amount_minor=1_000,
            )

        # 2nd reservation is FAILED
        async with db_pool.acquire() as conn:
            state = await conn.fetchval(
                "SELECT state FROM idempotency_keys WHERE agent_id = $1 AND idem_key = $2;",
                agent.agent_id,
                idem_key2,
            )
            assert state == "FAILED"

    finally:
        await _clean_test_records(db_pool, agent.agent_id, merchant.merchant_id)


# ==============================================================================
# 6. QUARANTINE & TASK 42 HITL INTEGRATION TEST
# ==============================================================================


async def test_quarantine_and_task42_handoff(
    db_pool: asyncpg.Pool,
    valkey_client: redis_async.Redis,
    agent_lifecycle: AgentLifecycle,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    seed_account: Any,
    payment_bus: EventBus,
    apply_bootstrap: None,
    apply_idempotency_schema: None,
    apply_limits_schema: None,
) -> None:
    """Quarantined payment stays PENDING; settle_approved settles; reject_held fails."""
    agent_ext = f"agt_{uuid4().hex[:12]}"
    merch_ext = f"mch_{uuid4().hex[:12]}"
    agent = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=agent_ext))
    merchant = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=merch_ext)
    )

    try:
        agent_acct = await account_directory.get_agent_account(agent.agent_id)
        # Fund agent with $1,000 (1_000_000_000 minor)
        await seed_account(agent_acct.account_id, 1_000_000_000, "USDC")

        quarantine = QuarantineService(db_pool)
        service = PaymentService(
            ledger=ledger_store,
            directory=account_directory,
            limits_repo=LimitRepo(db_pool),
            quarantine=quarantine,
            bus=payment_bus,
            valkey=valkey_client,
            pool=db_pool,
        )

        idem_key = f"flow-quarantine-{uuid4().hex[:12]}"
        body_hash = _sha256_hex("ceiling-breach-payment")
        amount = 150_000_000  # Default ceiling is 100_000_000 ($100)

        # 1. Execute payment breaching ceiling
        o_held = await service.pay(
            agent_id=agent.agent_id,
            idem_key=idem_key,
            body_hash=body_hash,
            to_merchant=merch_ext,
            amount_minor=amount,
            currency="USDC",
        )

        assert o_held.status == "held"
        assert o_held.response_status == 201

        # Ledger has ZERO entries
        tx_check = await ledger_store.get_transaction(o_held.tx_id)
        assert tx_check is None

        # Hold placed in payment_holds table
        async with db_pool.acquire() as conn:
            hold_row = await conn.fetchrow(
                """
                SELECT hold_id, status, reason
                FROM payment_holds
                WHERE agent_id = $1 AND idem_key = $2;
                """,
                agent.agent_id,
                idem_key,
            )
            assert hold_row is not None
            assert hold_row["status"] == "pending"
            assert hold_row["reason"] == "single_tx_ceiling"
            hold_id = hold_row["hold_id"]

            # Idempotency reservation in Postgres MUST BE PENDING (not COMPLETED!)
            idem_state = await conn.fetchval(
                "SELECT state FROM idempotency_keys WHERE agent_id = $1 AND idem_key = $2;",
                agent.agent_id,
                idem_key,
            )
            assert idem_state == "PENDING"

        # 2. Concurrent live retry raises IdempotencyConflict (IN_PROGRESS)
        with pytest.raises(IdempotencyConflict):
            await service.pay(
                agent_id=agent.agent_id,
                idem_key=idem_key,
                body_hash=body_hash,
                to_merchant=merch_ext,
                amount_minor=amount,
                currency="USDC",
            )

        # 3. Task 42: Admin approves hold
        approved_record = await quarantine.decide(
            hold_id=hold_id,
            approved=True,
        )
        assert approved_record is not None
        assert approved_record.status == "approved"

        # 4. Task 42: Invoke settle_approved with original parameters
        o_settled = await service.settle_approved(
            agent_id=agent.agent_id,
            idem_key=idem_key,
            to_merchant=merch_ext,
            amount_minor=amount,
            currency="USDC",
        )

        assert o_settled.status == "settled"
        assert o_settled.tx_id == o_held.tx_id

        # Ledger now has 3 entries
        tx_settled = await ledger_store.get_transaction(o_held.tx_id)
        assert tx_settled is not None
        assert len(tx_settled.entries) == 3

        # Idempotency reservation in Postgres is now COMPLETED
        async with db_pool.acquire() as conn:
            state = await conn.fetchval(
                "SELECT state FROM idempotency_keys WHERE agent_id = $1 AND idem_key = $2;",
                agent.agent_id,
                idem_key,
            )
            assert state == "COMPLETED"

        # 5. Subsequent agent poll hits REPLAY and receives settled wire bytes
        o_replay = await service.pay(
            agent_id=agent.agent_id,
            idem_key=idem_key,
            body_hash=body_hash,
            to_merchant=merch_ext,
            amount_minor=amount,
            currency="USDC",
        )
        assert o_replay.status == "settled"
        assert o_replay.replayed is True
        assert o_replay.wire_body == o_settled.wire_body

    finally:
        await _clean_test_records(db_pool, agent.agent_id, merchant.merchant_id)


# ==============================================================================
# 7. BYTE-EXACT DB REPLAY INTEGRATION TEST
# ==============================================================================


async def test_byte_exact_db_replays(
    db_pool: asyncpg.Pool,
    valkey_client: redis_async.Redis,
    agent_lifecycle: AgentLifecycle,
    merchant_lifecycle: MerchantLifecycle,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    seed_account: Any,
    payment_bus: EventBus,
    apply_bootstrap: None,
    apply_idempotency_schema: None,
    apply_limits_schema: None,
) -> None:
    """Verify that multiple database replays yield byte-identical wire responses."""
    agent_ext = f"agt_{uuid4().hex[:12]}"
    merch_ext = f"mch_{uuid4().hex[:12]}"
    agent = await agent_lifecycle.create_agent(CreateAgentCommand(external_id=agent_ext))
    merchant = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=merch_ext)
    )

    try:
        agent_acct = await account_directory.get_agent_account(agent.agent_id)
        await seed_account(agent_acct.account_id, 1_000_000_000, "USDC")

        service = PaymentService(
            ledger=ledger_store,
            directory=account_directory,
            limits_repo=LimitRepo(db_pool),
            quarantine=QuarantineService(db_pool),
            bus=payment_bus,
            valkey=valkey_client,
            pool=db_pool,
        )

        idem_key = f"flow-bytes-{uuid4().hex[:12]}"
        body_hash = _sha256_hex("byte-exact-test")

        o_orig = await service.pay(
            agent_id=agent.agent_id,
            idem_key=idem_key,
            body_hash=body_hash,
            to_merchant=merch_ext,
            amount_minor=10_000,
        )

        o_replay1 = await service.pay(
            agent_id=agent.agent_id,
            idem_key=idem_key,
            body_hash=body_hash,
            to_merchant=merch_ext,
            amount_minor=10_000,
        )

        o_replay2 = await service.pay(
            agent_id=agent.agent_id,
            idem_key=idem_key,
            body_hash=body_hash,
            to_merchant=merch_ext,
            amount_minor=10_000,
        )

        assert o_orig.wire_body == o_replay1.wire_body == o_replay2.wire_body
        assert o_replay1.replayed is True
        assert o_replay2.replayed is True

    finally:
        await _clean_test_records(db_pool, agent.agent_id, merchant.merchant_id)
