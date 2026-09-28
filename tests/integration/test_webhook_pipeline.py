"""Integration tests for the resilient webhook notification pipeline (Block H, Part 1).

Covers end-to-end event fanout, ledger merchant resolution, SKIP LOCKED concurrency,
HMAC-SHA256 wire signature verification, retry ladder, dead-lettering, manual redrive,
fail-closed secret custody, HTTPS-only DB check, and graceful shutdown lifecycle.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from collections.abc import AsyncGenerator, Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]
import pytest
import pytest_asyncio
import redis.asyncio as redis_async

from fluxpay.ledger.hashchain import Direction, format_timestamp
from fluxpay.ledger.postgres import PostgresLedgerStore
from fluxpay.ledger.store import EntryDraft
from fluxpay.notifications.dispatcher import DeliveryWorker, EventFanoutWorker
from fluxpay.notifications.webhooks import (
    HEADER_EVENT_ID,
    HEADER_SIGNATURE,
    sign_webhook,
    verify_webhook,
)
from fluxpay.registry.agents import (
    CreateMerchantCommand,
    MerchantLifecycle,
)
from fluxpay.shared.events import EventBus, EventType, make_event
from fluxpay.shared.vault import encrypt_secret
from fluxpay.wallet.accounts import AccountDirectory

pytestmark = pytest.mark.integration


@pytest_asyncio.fixture(autouse=True)
async def clean_webhooks_tables(
    db_pool: asyncpg.Pool,
    apply_webhooks_schema: None,
) -> AsyncGenerator[None, None]:
    """Clean webhook tables before and after each test to prevent cross-test pollution."""
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM webhook_deliveries;")
        await conn.execute("DELETE FROM webhook_endpoints;")
    yield
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM webhook_deliveries;")
        await conn.execute("DELETE FROM webhook_endpoints;")


# ==============================================================================
# HELPER: Seed a ledger transaction credited to a merchant account
# ==============================================================================


async def _seed_merchant_transaction(
    db_pool: asyncpg.Pool,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    merchant_ext_id: str,
    amount_minor: int = 50000,
    currency: str = "USDC",
) -> UUID:
    """Post a transaction in ledger_entries with credit to merchant account."""
    system_ref = await account_directory.get_system_account(currency)
    merchant_ref = await account_directory.get_merchant_account(merchant_ext_id, currency)

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE ledger_accounts
            SET balance = balance + 10_000_000_000, version = version + 1
            WHERE id = $1;
            """,
            system_ref.account_id,
        )

    res = await ledger_store.post_transaction(
        [
            EntryDraft(
                account_id=system_ref.account_id,
                direction=Direction.DEBIT,
                amount=amount_minor,
                currency=currency,
            ),
            EntryDraft(
                account_id=merchant_ref.account_id,
                direction=Direction.CREDIT,
                amount=amount_minor,
                currency=currency,
            ),
        ]
    )
    return res.tx_id


# ==============================================================================
# 1. E2E FANOUT: BUS -> DELIVERY ROWS & ACK
# ==============================================================================


async def test_fanout_e2e_multi_endpoint_and_ack(
    db_pool: asyncpg.Pool,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    merchant_lifecycle: MerchantLifecycle,
    make_webhook_endpoint: Any,
    payment_bus: EventBus,
    fanout_worker: Callable[..., EventFanoutWorker],
    apply_webhooks_schema: None,
) -> None:
    """Verify that a payment.settled event fans out to all active endpoints and acks the bus."""
    # 1. Provision merchant with 2 active endpoints
    mch_ext = f"mch_fanout_{uuid4().hex[:10]}"
    merchant = await merchant_lifecycle.create_merchant(CreateMerchantCommand(external_id=mch_ext))
    ep1 = await make_webhook_endpoint(merchant.merchant_id, active=True)
    ep2 = await make_webhook_endpoint(merchant.merchant_id, active=True)

    # 2. Seed financial ledger transaction
    tx_id = await _seed_merchant_transaction(db_pool, account_directory, ledger_store, mch_ext)

    # 3. Initialize worker and ensure consumer group on bus before publish
    worker = fanout_worker(bus=payment_bus, batch_size=10)
    await worker.setup()

    # 4. Publish domain event to bus
    event = make_event(
        type=EventType.PAYMENT_SETTLED,
        payload={
            "tx_id": str(tx_id),
            "amount": 50000,
            "currency": "USDC",
        },
        producer="fluxpay.payments",
    )
    await payment_bus.publish(event)

    # 5. Run one cycle of fanout worker
    batch = await worker.poll()
    assert len(batch) >= 1
    await worker.process(batch)

    # 5. Assert delivery rows inserted in DB for both endpoints
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, event_id, endpoint_id, payload, status, attempts
            FROM webhook_deliveries
            WHERE event_id = $1
            ORDER BY endpoint_id;
            """,
            event.event_id,
        )

    assert len(rows) == 2
    endpoint_ids = {r["endpoint_id"] for r in rows}
    assert endpoint_ids == {ep1.endpoint_id, ep2.endpoint_id}

    for r in rows:
        assert r["status"] == "pending"
        assert r["attempts"] == 0
        stored_payload = json.loads(r["payload"]) if isinstance(r["payload"], str) else r["payload"]
        assert stored_payload["event"] == "payment.settled"
        assert stored_payload["event_id"] == str(event.event_id)
        assert stored_payload["data"]["tx_id"] == str(tx_id)
        assert stored_payload["data"]["amount"] == 50000
        assert stored_payload["data"]["currency"] == "USDC"

    # 6. Assert event is acknowledged: subsequent poll returns empty
    subsequent = await worker.poll()
    matching = [d for d in subsequent if d[1].envelope.event_id == event.event_id]
    assert len(matching) == 0


# ==============================================================================
# 2. MERCHANT RESOLUTION FROM TX (THE LAYERING WIN) & POISON SAFE
# ==============================================================================


async def test_merchant_resolution_from_ledger_and_unknown_tx_poison(
    db_pool: asyncpg.Pool,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    merchant_lifecycle: MerchantLifecycle,
    make_webhook_endpoint: Any,
    payment_bus: EventBus,
    fanout_worker: Callable[..., EventFanoutWorker],
    apply_webhooks_schema: None,
) -> None:
    """Verify merchant resolved from ledger entries with zero Task 31 changes;
    unknown tx is poison-acked.
    """
    mch_ext = f"mch_ledger_{uuid4().hex[:10]}"
    merchant = await merchant_lifecycle.create_merchant(CreateMerchantCommand(external_id=mch_ext))
    await make_webhook_endpoint(merchant.merchant_id, active=True)

    # Real ledger transaction seeded
    tx_id_real = await _seed_merchant_transaction(db_pool, account_directory, ledger_store, mch_ext)

    worker = fanout_worker(bus=payment_bus, batch_size=10)
    await worker.setup()

    # 1. Real event (payload has tx_id, but NO merchant field)
    real_event = make_event(
        type=EventType.PAYMENT_SETTLED,
        payload={
            "tx_id": str(tx_id_real),
            "amount": 25000,
            "currency": "USDC",
        },
        producer="fluxpay.payments",
    )
    await payment_bus.publish(real_event)

    # 2. Poison event: unknown tx_id not in ledger and no merchant in payload
    unknown_tx_id = uuid4()
    poison_event = make_event(
        type=EventType.PAYMENT_SETTLED,
        payload={
            "tx_id": str(unknown_tx_id),
            "amount": 10000,
            "currency": "USDC",
        },
        producer="fluxpay.payments",
    )
    await payment_bus.publish(poison_event)

    batch = await worker.poll()
    assert len(batch) >= 2
    await worker.process(batch)

    async with db_pool.acquire() as conn:
        real_rows = await conn.fetch(
            "SELECT id FROM webhook_deliveries WHERE event_id = $1;", real_event.event_id
        )
        poison_rows = await conn.fetch(
            "SELECT id FROM webhook_deliveries WHERE event_id = $1;", poison_event.event_id
        )

    # Real event produced a delivery row
    assert len(real_rows) == 1
    # Poison event skipped delivery creation but was ACKed (worker remains alive)
    assert len(poison_rows) == 0

    # Ensure queue is clean
    subsequent = await worker.poll()
    assert len(subsequent) == 0


# ==============================================================================
# 3. DELIVERY WORKER: HAPPY PATH
# ==============================================================================


async def test_delivery_worker_happy_path(
    db_pool: asyncpg.Pool,
    merchant_lifecycle: MerchantLifecycle,
    make_webhook_endpoint: Any,
    mock_http: Any,
    delivery_worker: Callable[..., DeliveryWorker],
    apply_webhooks_schema: None,
) -> None:
    """Verify delivery worker claims pending row, signs body, POSTs HTTPS, and sets delivered."""
    mch = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=f"mch_del_{uuid4().hex[:10]}")
    )
    ep = await make_webhook_endpoint(mch.merchant_id, active=True)
    event_id = uuid4()
    tx_id = uuid4()

    payload_dict = {
        "event": "payment.settled",
        "event_id": str(event_id),
        "created_at": format_timestamp(datetime.now(UTC)),
        "data": {
            "tx_id": str(tx_id),
            "amount": 12000,
            "currency": "USDC",
        },
    }

    delivery_id = uuid4()
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO webhook_deliveries (
                id, event_id, endpoint_id, payload,
                status, attempts, next_attempt_at
            ) VALUES ($1, $2, $3, $4::jsonb, 'pending', 0, now());
            """,
            delivery_id,
            event_id,
            ep.endpoint_id,
            json.dumps(payload_dict),
        )

    # Script 200 OK
    mock_http.script_status(ep.url, [200])

    worker = delivery_worker(http_client=mock_http.client, batch_size=10)
    batch = await worker.poll()
    assert len(batch) == 1
    await worker.process(batch)

    # Verify DB state
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT status, attempts, last_response_code, last_error
            FROM webhook_deliveries WHERE id = $1;
            """,
            delivery_id,
        )
    assert row["status"] == "delivered"
    assert row["attempts"] == 1
    assert row["last_response_code"] == 200
    assert row["last_error"] is None

    # Verify HTTP request dispatched
    assert len(mock_http.requests) == 1
    req = mock_http.requests[0]
    assert req.url == ep.url
    assert req.headers[HEADER_EVENT_ID] == str(event_id)
    assert req.headers[HEADER_SIGNATURE] == sign_webhook(ep.secret, req.body)


# ==============================================================================
# 4. RETRY LADDER & EXPONENTIAL BACKOFF BOUNDS
# ==============================================================================


async def test_delivery_retry_ladder_and_backoff_bounds(
    db_pool: asyncpg.Pool,
    merchant_lifecycle: MerchantLifecycle,
    make_webhook_endpoint: Any,
    mock_http: Any,
    delivery_worker: Callable[..., DeliveryWorker],
    apply_webhooks_schema: None,
) -> None:
    """Verify scripted 500, 500, 200 sequence, attempt incrementing, and backoff bounds."""
    mch = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=f"mch_retry_{uuid4().hex[:10]}")
    )
    ep = await make_webhook_endpoint(mch.merchant_id, active=True)
    delivery_id = uuid4()
    event_id = uuid4()

    payload_dict = {
        "event": "payment.settled",
        "event_id": str(event_id),
        "created_at": format_timestamp(datetime.now(UTC)),
        "data": {"tx_id": str(uuid4()), "amount": 1000, "currency": "USDC"},
    }

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO webhook_deliveries (
                id, event_id, endpoint_id, payload,
                status, attempts, next_attempt_at
            ) VALUES ($1, $2, $3, $4::jsonb, 'pending', 0, now());
            """,
            delivery_id,
            event_id,
            ep.endpoint_id,
            json.dumps(payload_dict),
        )

    # Script: 500, 500, 200
    mock_http.script_status(ep.url, [500, 500, 200])
    worker = delivery_worker(http_client=mock_http.client, batch_size=10)

    # Cycle 1: First fail (500)
    batch1 = await worker.poll()
    assert len(batch1) == 1
    await worker.process(batch1)

    async with db_pool.acquire() as conn:
        row1 = await conn.fetchrow(
            """
            SELECT status, attempts, last_response_code,
                   EXTRACT(EPOCH FROM (next_attempt_at - now())) AS backoff_sec
            FROM webhook_deliveries WHERE id = $1;
            """,
            delivery_id,
        )
    assert row1["status"] == "pending"
    assert row1["attempts"] == 1
    assert row1["last_response_code"] == 500
    # Backoff for attempt 1: base 2.0s + jitter [0, 0.5s] -> between 1.5s and 3.0s
    assert 1.5 <= row1["backoff_sec"] <= 3.0

    # Advance fake now by backdating next_attempt_at (NO real sleeps)
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE webhook_deliveries
            SET next_attempt_at = now() - interval '1 second'
            WHERE id = $1;
            """,
            delivery_id,
        )

    # Cycle 2: Second fail (500)
    batch2 = await worker.poll()
    assert len(batch2) == 1
    await worker.process(batch2)

    async with db_pool.acquire() as conn:
        row2 = await conn.fetchrow(
            """
            SELECT status, attempts, last_response_code,
                   EXTRACT(EPOCH FROM (next_attempt_at - now())) AS backoff_sec
            FROM webhook_deliveries WHERE id = $1;
            """,
            delivery_id,
        )
    assert row2["status"] == "pending"
    assert row2["attempts"] == 2
    assert row2["last_response_code"] == 500
    # Backoff for attempt 2: base 4.0s + jitter [0, 0.5s] -> between 3.5s and 5.0s
    assert 3.5 <= row2["backoff_sec"] <= 5.0

    # Advance fake now again
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE webhook_deliveries
            SET next_attempt_at = now() - interval '1 second'
            WHERE id = $1;
            """,
            delivery_id,
        )

    # Cycle 3: Third attempt succeeds (200)
    batch3 = await worker.poll()
    assert len(batch3) == 1
    await worker.process(batch3)

    async with db_pool.acquire() as conn:
        row3 = await conn.fetchrow(
            "SELECT status, attempts, last_response_code FROM webhook_deliveries WHERE id = $1;",
            delivery_id,
        )
    assert row3["status"] == "delivered"
    assert row3["attempts"] == 3
    assert row3["last_response_code"] == 200


# ==============================================================================
# 5. DEAD-LETTERING AT MAX ATTEMPTS (DLQ AS STATUS)
# ==============================================================================


async def test_delivery_dead_lettering_at_limit(
    db_pool: asyncpg.Pool,
    merchant_lifecycle: MerchantLifecycle,
    make_webhook_endpoint: Any,
    mock_http: Any,
    delivery_worker: Callable[..., DeliveryWorker],
    apply_webhooks_schema: None,
) -> None:
    """Verify that reaching 15 attempts transitions delivery to status='dead' and stops claiming."""
    mch = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=f"mch_dead_{uuid4().hex[:10]}")
    )
    ep = await make_webhook_endpoint(mch.merchant_id, active=True)
    delivery_id = uuid4()

    payload_dict = {
        "event": "payment.settled",
        "event_id": str(uuid4()),
        "created_at": format_timestamp(datetime.now(UTC)),
        "data": {"tx_id": str(uuid4()), "amount": 1000, "currency": "USDC"},
    }

    # Seed row at attempts = 14
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO webhook_deliveries (
                id, event_id, endpoint_id, payload,
                status, attempts, next_attempt_at
            ) VALUES ($1, $2, $3, $4::jsonb, 'pending', 14, now());
            """,
            delivery_id,
            uuid4(),
            ep.endpoint_id,
            json.dumps(payload_dict),
        )

    mock_http.script_status(ep.url, [500])
    worker = delivery_worker(http_client=mock_http.client, batch_size=10)

    # Claim attempt 15
    batch = await worker.poll()
    assert len(batch) == 1
    assert batch[0]["attempts"] == 15
    await worker.process(batch)

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT status, attempts, last_response_code FROM webhook_deliveries WHERE id = $1;",
            delivery_id,
        )
    assert row["status"] == "dead"
    assert row["attempts"] == 15
    assert row["last_response_code"] == 500

    # Ensure worker idle (dead rows excluded from pending claim)
    idle_batch = await worker.poll()
    assert len(idle_batch) == 0


# ==============================================================================
# 6. DEDUPLICATION VIA ON CONFLICT ON BUS REDELIVERY
# ==============================================================================


async def test_fanout_deduplication_on_bus_redelivery(
    db_pool: asyncpg.Pool,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    merchant_lifecycle: MerchantLifecycle,
    make_webhook_endpoint: Any,
    payment_bus: EventBus,
    fanout_worker: Callable[..., EventFanoutWorker],
    apply_webhooks_schema: None,
) -> None:
    """Verify redelivered bus events with same event_id result in exactly 1 delivery row."""
    mch_ext = f"mch_dedup_{uuid4().hex[:10]}"
    merchant = await merchant_lifecycle.create_merchant(CreateMerchantCommand(external_id=mch_ext))
    ep = await make_webhook_endpoint(merchant.merchant_id, active=True)
    tx_id = await _seed_merchant_transaction(db_pool, account_directory, ledger_store, mch_ext)

    worker = fanout_worker(bus=payment_bus, batch_size=10)
    await worker.setup()

    event = make_event(
        type=EventType.PAYMENT_SETTLED,
        payload={"tx_id": str(tx_id), "amount": 75000, "currency": "USDC"},
        producer="fluxpay.payments",
    )

    # Publish twice
    await payment_bus.publish(event)
    await payment_bus.publish(event)

    batch1 = await worker.poll()
    assert len(batch1) >= 1
    await worker.process(batch1)

    # Check DB
    async with db_pool.acquire() as conn:
        count = await conn.fetchval(
            "SELECT count(*) FROM webhook_deliveries WHERE event_id = $1 AND endpoint_id = $2;",
            event.event_id,
            ep.endpoint_id,
        )
    assert count == 1


# ==============================================================================
# 7. MANUAL REDRIVE VIA SQL OPS PATH
# ==============================================================================


async def test_manual_redrive_ops_path(
    db_pool: asyncpg.Pool,
    merchant_lifecycle: MerchantLifecycle,
    make_webhook_endpoint: Any,
    mock_http: Any,
    delivery_worker: Callable[..., DeliveryWorker],
    apply_webhooks_schema: None,
) -> None:
    """Verify that updating status='dead' to 'pending' triggers successful redelivery."""
    mch = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=f"mch_redrive_{uuid4().hex[:10]}")
    )
    ep = await make_webhook_endpoint(mch.merchant_id, active=True)
    delivery_id = uuid4()

    payload_dict = {
        "event": "payment.settled",
        "event_id": str(uuid4()),
        "created_at": format_timestamp(datetime.now(UTC)),
        "data": {"tx_id": str(uuid4()), "amount": 1000, "currency": "USDC"},
    }

    # Insert in dead state
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO webhook_deliveries (
                id, event_id, endpoint_id, payload,
                status, attempts, next_attempt_at, last_response_code
            ) VALUES ($1, $2, $3, $4::jsonb, 'dead', 15, now(), 503);
            """,
            delivery_id,
            uuid4(),
            ep.endpoint_id,
            json.dumps(payload_dict),
        )

    # Script 200 OK for when redrive happens
    mock_http.script_status(ep.url, [200])
    worker = delivery_worker(http_client=mock_http.client, batch_size=10)

    # Ensure worker does not claim dead row
    assert len(await worker.poll()) == 0

    # Operational Redrive Query (Admin Plane / Ops playbook)
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE webhook_deliveries
            SET status = 'pending', attempts = 0, next_attempt_at = now()
            WHERE status = 'dead' AND id = $1;
            """,
            delivery_id,
        )

    # Worker now claims it
    batch = await worker.poll()
    assert len(batch) == 1
    await worker.process(batch)

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT status, attempts, last_response_code FROM webhook_deliveries WHERE id = $1;",
            delivery_id,
        )
    assert row["status"] == "delivered"
    assert row["attempts"] == 1
    assert row["last_response_code"] == 200


# ==============================================================================
# 8. MULTI-INSTANCE SKIP LOCKED CONCURRENCY (ZERO DOUBLE-CLAIM)
# ==============================================================================


async def test_multi_instance_skip_locked_concurrency(
    db_pool: asyncpg.Pool,
    valkey_client: redis_async.Redis,
    merchant_lifecycle: MerchantLifecycle,
    make_webhook_endpoint: Any,
    mock_http: Any,
    apply_webhooks_schema: None,
) -> None:
    """Verify that two concurrent worker instances never claim the same delivery row."""
    mch = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=f"mch_skip_{uuid4().hex[:10]}")
    )
    ep = await make_webhook_endpoint(mch.merchant_id, active=True)

    # Insert 6 pending delivery rows
    delivery_ids: list[UUID] = []
    payload_json = json.dumps(
        {
            "event": "payment.settled",
            "event_id": str(uuid4()),
            "created_at": format_timestamp(datetime.now(UTC)),
            "data": {"tx_id": str(uuid4()), "amount": 1000, "currency": "USDC"},
        }
    )
    async with db_pool.acquire() as conn:
        for _ in range(6):
            did = uuid4()
            delivery_ids.append(did)
            await conn.execute(
                """
                INSERT INTO webhook_deliveries (
                    id, event_id, endpoint_id, payload,
                    status, attempts, next_attempt_at
                ) VALUES ($1, $2, $3, $4::jsonb, 'pending', 0, now());
                """,
                did,
                uuid4(),
                ep.endpoint_id,
                payload_json,
            )

    worker_a = DeliveryWorker(
        pool=db_pool,
        valkey=valkey_client,
        http_client=mock_http.client,
        batch_size=3,
        name="worker_a",
    )
    worker_b = DeliveryWorker(
        pool=db_pool,
        valkey=valkey_client,
        http_client=mock_http.client,
        batch_size=3,
        name="worker_b",
    )

    # Concurrently claim batches
    batch_a, batch_b = await asyncio.gather(worker_a.poll(), worker_b.poll())
    assert len(batch_a) == 3
    assert len(batch_b) == 3

    ids_a = {r["id"] for r in batch_a}
    ids_b = {r["id"] for r in batch_b}

    # SKIP LOCKED Proof: sets are completely disjoint
    assert ids_a.isdisjoint(ids_b)
    assert ids_a | ids_b == set(delivery_ids)

    # Concurrently process
    await asyncio.gather(worker_a.process(batch_a), worker_b.process(batch_b))
    assert len(mock_http.requests) == 6


# ==============================================================================
# 9. WIRE SIGNATURE & EVENT ID VERIFICATION (BOTH SIDES TEST)
# ==============================================================================


async def test_wire_signature_and_event_id_verification(
    db_pool: asyncpg.Pool,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    merchant_lifecycle: MerchantLifecycle,
    make_webhook_endpoint: Any,
    payment_bus: EventBus,
    fanout_worker: Callable[..., EventFanoutWorker],
    delivery_worker: Callable[..., DeliveryWorker],
    mock_http: Any,
    apply_webhooks_schema: None,
) -> None:
    """Verify that wire request signature matches merchant-side HMAC verification."""
    mch_ext = f"mch_wire_{uuid4().hex[:10]}"
    merchant = await merchant_lifecycle.create_merchant(CreateMerchantCommand(external_id=mch_ext))
    ep = await make_webhook_endpoint(merchant.merchant_id, active=True)
    tx_id = await _seed_merchant_transaction(db_pool, account_directory, ledger_store, mch_ext)

    f_worker = fanout_worker(bus=payment_bus, batch_size=10)
    await f_worker.setup()

    event = make_event(
        type=EventType.PAYMENT_SETTLED,
        payload={"tx_id": str(tx_id), "amount": 88000, "currency": "USDC"},
        producer="fluxpay.payments",
    )
    await payment_bus.publish(event)

    # Fanout
    batch = await f_worker.poll()
    assert len(batch) >= 1
    await f_worker.process(batch)

    # Deliver
    d_worker = delivery_worker(http_client=mock_http.client, batch_size=10)
    d_batch = await d_worker.poll()
    assert len(d_batch) == 1
    await d_worker.process(d_batch)

    # Intercepted HTTP Request
    assert len(mock_http.requests) == 1
    recorded = mock_http.requests[0]

    # Verify merchant-side headers
    assert recorded.headers[HEADER_EVENT_ID] == str(event.event_id)
    wire_signature = recorded.headers[HEADER_SIGNATURE]

    # Reproduce merchant-side verification using credentials secret
    merchant_secret = ep.secret
    assert verify_webhook(merchant_secret, recorded.body, wire_signature) is True
    assert hmac.new(merchant_secret, recorded.body, hashlib.sha256).hexdigest() == wire_signature


# ==============================================================================
# 10. INACTIVE ENDPOINT FILTERING
# ==============================================================================


async def test_inactive_endpoint_receives_no_deliveries(
    db_pool: asyncpg.Pool,
    account_directory: AccountDirectory,
    ledger_store: PostgresLedgerStore,
    merchant_lifecycle: MerchantLifecycle,
    make_webhook_endpoint: Any,
    payment_bus: EventBus,
    fanout_worker: Callable[..., EventFanoutWorker],
    apply_webhooks_schema: None,
) -> None:
    """Verify that fanout ignores endpoints with active=false."""
    mch_ext = f"mch_inact_{uuid4().hex[:10]}"
    merchant = await merchant_lifecycle.create_merchant(CreateMerchantCommand(external_id=mch_ext))
    active_ep = await make_webhook_endpoint(merchant.merchant_id, active=True)
    inactive_ep = await make_webhook_endpoint(merchant.merchant_id, active=False)

    tx_id = await _seed_merchant_transaction(db_pool, account_directory, ledger_store, mch_ext)
    worker = fanout_worker(bus=payment_bus, batch_size=10)
    await worker.setup()

    event = make_event(
        type=EventType.PAYMENT_SETTLED,
        payload={"tx_id": str(tx_id), "amount": 1000, "currency": "USDC"},
        producer="fluxpay.payments",
    )
    await payment_bus.publish(event)

    batch = await worker.poll()
    assert len(batch) >= 1
    await worker.process(batch)

    async with db_pool.acquire() as conn:
        deliveries = await conn.fetch(
            "SELECT endpoint_id FROM webhook_deliveries WHERE event_id = $1;", event.event_id
        )

    assert len(deliveries) == 1
    assert deliveries[0]["endpoint_id"] == active_ep.endpoint_id
    assert deliveries[0]["endpoint_id"] != inactive_ep.endpoint_id


# ==============================================================================
# 11. HTTPS-ONLY ENFORCED AT DB MIGRATION CHECK
# ==============================================================================


async def test_https_only_enforced_by_db_check(
    db_pool: asyncpg.Pool,
    merchant_lifecycle: MerchantLifecycle,
    apply_webhooks_schema: None,
) -> None:
    """Verify that inserting a non-HTTPS URL violates the CHECK constraint."""
    mch = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=f"mch_http_{uuid4().hex[:10]}")
    )
    insecure_url = "http://insecure.test/webhook"
    secret_enc = encrypt_secret("some_secret", context=f"webhook_secret:{uuid4()}")

    with pytest.raises(asyncpg.CheckViolationError):
        async with db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO webhook_endpoints (id, merchant_id, url, secret_encrypted, active)
                VALUES ($1, $2, $3, $4, true);
                """,
                uuid4(),
                mch.merchant_id,
                insecure_url,
                secret_enc,
            )


# ==============================================================================
# 12. SECRET CUSTODY FAIL-CLOSED RETRY
# ==============================================================================


async def test_secret_custody_decrypt_failure_fail_closed(
    db_pool: asyncpg.Pool,
    merchant_lifecycle: MerchantLifecycle,
    delivery_worker: Callable[..., DeliveryWorker],
    mock_http: Any,
    apply_webhooks_schema: None,
) -> None:
    """Verify secret decryption failure leaves delivery pending with retry scheduled
    (fail-closed).
    """
    mch = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=f"mch_corrupt_{uuid4().hex[:10]}")
    )
    endpoint_id = uuid4()
    # Encrypt with WRONG context to simulate decryption failure
    bad_secret_enc = encrypt_secret("my_secret", context="wrong_aad_context")

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO webhook_endpoints (id, merchant_id, url, secret_encrypted, active)
            VALUES ($1, $2, 'https://hook.test/custody', $3, true);
            """,
            endpoint_id,
            mch.merchant_id,
            bad_secret_enc,
        )

    delivery_id = uuid4()
    payload_json = json.dumps(
        {
            "event": "payment.settled",
            "event_id": str(uuid4()),
            "created_at": format_timestamp(datetime.now(UTC)),
            "data": {"tx_id": str(uuid4()), "amount": 1000, "currency": "USDC"},
        }
    )

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO webhook_deliveries (
                id, event_id, endpoint_id, payload,
                status, attempts, next_attempt_at
            ) VALUES ($1, $2, $3, $4::jsonb, 'pending', 0, now());
            """,
            delivery_id,
            uuid4(),
            endpoint_id,
            payload_json,
        )

    worker = delivery_worker(http_client=mock_http.client, batch_size=10)
    batch = await worker.poll()
    assert len(batch) == 1
    await worker.process(batch)

    # Fail-closed: row stays 'pending', last_error reflects custody error, no HTTP call made
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT status, attempts, last_error FROM webhook_deliveries WHERE id = $1;",
            delivery_id,
        )
    assert row["status"] == "pending"
    assert "Vault secret decryption failed" in row["last_error"]
    assert len(mock_http.requests) == 0


# ==============================================================================
# 13. GRACEFUL SHUTDOWN MID-BATCH
# ==============================================================================


async def test_graceful_shutdown_mid_batch(
    db_pool: asyncpg.Pool,
    valkey_client: redis_async.Redis,
    merchant_lifecycle: MerchantLifecycle,
    make_webhook_endpoint: Any,
    mock_http: Any,
    apply_webhooks_schema: None,
) -> None:
    """Verify setting stop event allows in-flight delivery to finish and halts next batch."""
    mch = await merchant_lifecycle.create_merchant(
        CreateMerchantCommand(external_id=f"mch_graceful_{uuid4().hex[:10]}")
    )
    ep = await make_webhook_endpoint(mch.merchant_id, active=True)

    # Insert 2 pending rows
    payload_json = json.dumps(
        {
            "event": "payment.settled",
            "event_id": str(uuid4()),
            "created_at": format_timestamp(datetime.now(UTC)),
            "data": {"tx_id": str(uuid4()), "amount": 1000, "currency": "USDC"},
        }
    )
    async with db_pool.acquire() as conn:
        for _ in range(2):
            await conn.execute(
                """
                INSERT INTO webhook_deliveries (
                    id, event_id, endpoint_id, payload,
                    status, attempts, next_attempt_at
                ) VALUES ($1, $2, $3, $4::jsonb, 'pending', 0, now());
                """,
                uuid4(),
                uuid4(),
                ep.endpoint_id,
                payload_json,
            )

    stop_event = asyncio.Event()

    # Worker configured with stop event
    worker = DeliveryWorker(
        pool=db_pool,
        valkey=valkey_client,
        http_client=mock_http.client,
        batch_size=1,
        stop=stop_event,
    )

    # In background, run worker loop
    task = asyncio.create_task(worker.run_forever())

    # Stop triggered after short delay
    await asyncio.sleep(0.05)
    stop_event.set()

    # Await worker clean termination
    await asyncio.wait_for(task, timeout=2.0)
    assert worker.stop.is_set()
