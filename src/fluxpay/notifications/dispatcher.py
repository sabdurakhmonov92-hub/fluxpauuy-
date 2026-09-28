"""Resilient webhook notification dispatcher workers (Block H, Part 1).

==============================================================================
CONCURRENCY WEAPON 1: POSTGRES FOR UPDATE SKIP LOCKED (WHY SKIP LOCKED)
==============================================================================
Traditional polling workers in multi-instance architectures suffer from either
severe contention (pessimistic table locks blocking concurrent workers) or double-
delivery races (two workers reading the same 'pending' rows simultaneously).
Postgres 9.5+ `FOR UPDATE SKIP LOCKED` transforms standard relational tables into
high-throughput, zero-contention FIFO work queues:
1. Atomicity: In a single atomic statement, the worker queries candidates ordered by
   `next_attempt_at`, acquires row-level exclusive locks on eligible rows, and silently
   skips any rows locked by concurrent sibling workers.
2. Contention-Free Scale: N worker instances running against the same database cluster
   partition the backlog without inter-worker coordination or distributed Redis locks.
3. Multi-Instance Safe Claim: The claim UPDATE immediately advances `next_attempt_at`
   and increments `attempts`. Even if the claiming worker crashes or hangs, the row
   remains lease-locked into the future before becoming eligible for automatic recovery.

==============================================================================
CONCURRENCY WEAPON 2: ON CONFLICT (event_id, endpoint_id) DO NOTHING
==============================================================================
Event buses (both Redis Streams and RabbitMQ quorum queues) operate under at-least-
once delivery semantics. On consumer restart, network partition, or unacknowledged
broker timeout, events are redelivered (indicated by delivery_count > 1).
Database-level deduplication via `ON CONFLICT (event_id, endpoint_id) DO NOTHING`
guarantees that regardless of how many times the fanout worker receives an event from
the broker, exactly one delivery record is ever inserted for that endpoint. The bus
acknowledges the duplicate, and downstream merchants never receive duplicated fanout.

==============================================================================
DECISION: PAYLOAD FROZEN AT INSERTION (SCHEMA & EVENT LOG IMMUTABILITY)
==============================================================================
Rather than storing merely the event ID and dynamically re-serializing the event at
HTTP dispatch time, `webhook_deliveries` stores `payload JSONB NOT NULL`, frozen at
the moment of fanout.
RATIONALE:
1. Schema vs Event-Log Drift Immunity: Domain event definitions and serialization schemas
   evolve over time. If a delivery fails and retries over 24 hours (or is manually redriven
   weeks later from the dead-letter queue), re-evaluating the event against updated code
   could alter payload structure or fail validation.
2. Retention & Replay Faithfulness: In high-volume systems, event streams (Redis Streams /
   RabbitMQ) enforce retention limits and discard historical messages. A dead-lettered
   delivery row in Postgres contains everything required for standalone redelivery without
   relying on upstream event stream availability.
3. Cryptographic Signature Consistency: The merchant signature is computed over the exact
   payload generated at event time. Storing the payload ensures idempotent replay yields
   byte-identical wire representations.

==============================================================================
THE LAYERING WIN: ZERO PRODUCER CONTRACT CHANGES VIA LEDGER TRUTH
==============================================================================
Task 31's payment engine emits domain events (payment.settled, payment.held, payment.failed).
While some events may omit merchant metadata, the payment engine strictly records financial
truth into `ledger_entries`.
Instead of modifying frozen Task 31 code or expanding event schemas across existing tests,
the fanout worker queries the financial ledger:
  `ledger_entries (tx_id) -> ledger_accounts (owner_type='merchant') -> owner_id (merchants.id)`
RATIONALE:
1. Producer Contract Purity: Producers remain focused on payment execution without carrying
   downstream notification routing metadata.
2. Ledger as Authoritative Truth: Financial settlement in the double-entry ledger is the
   ultimate source of truth. If a transaction settled, its ledger entry indisputably identifies
   the recipient merchant account.
3. Layering Cleanliness: Zero modification to Task 31 services or tests; notification routing
   is decoupled from the financial settlement engine.

==============================================================================
DEAD-LETTERING AS STATUS + OPS MANUAL REDRIVE
==============================================================================
Unlike the event bus (where poison messages enter a RabbitMQ DLQ queue), webhook deliveries
are database-queued. Storing dead-lettered deliveries as `status = 'dead'` directly within
`webhook_deliveries` creates an inspectable, SQL-queryable operational work ledger:
1. Query Dead Deliveries:
     SELECT id, event_id, endpoint_id, attempts, last_response_code, last_error
     FROM webhook_deliveries WHERE status = 'dead';
2. Manual Redrive (Admin Phase 2 / Task 42):
     UPDATE webhook_deliveries
     SET status = 'pending', attempts = 0, next_attempt_at = now()
     WHERE status = 'dead' AND id = :delivery_id;
Once reset to 'pending', the delivery worker's next polling cycle immediately claims it.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Callable, Coroutine, Sequence
from datetime import datetime
from typing import Any, Final
from urllib.parse import urlsplit
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import httpx
import orjson

from fluxpay.notifications.webhooks import (
    HEADER_EVENT_ID,
    HEADER_SIGNATURE,
    build_payload,
    sign_webhook,
    webhook_secret_context,
)
from fluxpay.shared.errors import VaultError
from fluxpay.shared.events import Delivery, EventBus, EventEnvelope, EventType
from fluxpay.shared.logging import get_logger
from fluxpay.shared.vault import decrypt_secret
from fluxpay.workers.base import Worker

logger = get_logger("fluxpay.notifications.dispatcher")

__all__ = [
    "DEFAULT_BATCH_SIZE",
    "DEFAULT_HTTP_TIMEOUT_S",
    "DEFAULT_POLL_INTERVAL_S",
    "MAX_DELIVERY_ATTEMPTS",
    "DeliveryWorker",
    "EventFanoutWorker",
    "WebhookDispatcherWorker",
    "compute_backoff",
]

DEFAULT_POLL_INTERVAL_S: Final[float] = 1.0
DEFAULT_BATCH_SIZE: Final[int] = 10
DEFAULT_HTTP_TIMEOUT_S: Final[float] = 5.0
MAX_DELIVERY_ATTEMPTS: Final[int] = 15

FANOUT_EVENT_TYPES: Final[tuple[EventType, ...]] = (
    EventType.PAYMENT_SETTLED,
    EventType.PAYMENT_HELD,
    EventType.PAYMENT_FAILED,
)


def compute_backoff(attempts: int) -> float:
    """Compute exponential backoff with jitter: base 2s * 2^(attempts-1) + jitter 0-500ms, cap 1h.

    Args:
        attempts: 1-based attempt count of the failed delivery.
            1st fail (attempts=1): 2s * 2^0 + [0, 0.5] = 2.0s - 2.5s.
            2nd fail (attempts=2): 2s * 2^1 + [0, 0.5] = 4.0s - 4.5s.
            3rd fail (attempts=3): 2s * 2^2 + [0, 0.5] = 8.0s - 8.5s.
            ...
            Capped at 3600.0s (1 hour).
    """
    exp_factor = 2.0 * (2 ** max(0, attempts - 1))
    jitter = random.uniform(0.0, 0.5)  # noqa: S311 (retry jitter does not require cryptographic security)
    return float(min(3600.0, float(exp_factor)) + jitter)


# ==============================================================================
# 1. EVENT FANOUT WORKER (Event Bus -> Webhook Delivery Rows)
# ==============================================================================


class EventFanoutWorker(Worker):
    """Subscribes to domain events on the bus and fans out delivery rows per active endpoint.

    Decoupled from HTTP dispatch to isolate event transport failures from endpoint outages.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        valkey: Any,
        bus: EventBus,
        *,
        name: str = "webhook_fanout",
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
        batch_size: int = DEFAULT_BATCH_SIZE,
        stop: asyncio.Event | None = None,
        sleeper: Callable[[float], Coroutine[Any, Any, None]] = asyncio.sleep,
    ) -> None:
        super().__init__(
            name=name,
            pool=pool,
            valkey=valkey,
            bus=bus,
            poll_interval_s=poll_interval_s,
            batch_size=batch_size,
            stop=stop,
            sleeper=sleeper,
        )
        self._consumer_id = f"fanout_{self.name}"
        self._groups_ensured: set[str] = set()

    async def _ensure_groups(self) -> None:
        """Ensure consumer groups exist for all monitored event types."""
        for event_type in FANOUT_EVENT_TYPES:
            group_key = f"{event_type.value}:webhooks"
            if group_key not in self._groups_ensured:
                await self.bus.ensure_group(event_type, group="webhooks")
                self._groups_ensured.add(group_key)

    async def setup(self) -> None:
        """Explicitly ensure consumer groups are created on the bus."""
        await self._ensure_groups()

    async def poll(self) -> Sequence[tuple[EventType, Delivery]]:
        """Poll incoming domain events from the event bus across monitored event types."""
        await self._ensure_groups()
        polled: list[tuple[EventType, Delivery]] = []
        remaining = self.batch_size

        for event_type in FANOUT_EVENT_TYPES:
            if remaining <= 0 or self.stop.is_set():
                break
            deliveries = await self.bus.read_batch(
                event_type,
                group="webhooks",
                consumer=self._consumer_id,
                count=remaining,
                block_ms=0,
            )
            for d in deliveries:
                polled.append((event_type, d))
            remaining -= len(deliveries)

        return polled

    async def _resolve_merchant_id(self, envelope: EventEnvelope) -> UUID | None:
        """Resolve destination merchant UUID from financial ledger entries or payload metadata."""
        tx_id_raw = envelope.payload.get("tx_id")
        if tx_id_raw:
            try:
                tx_uuid = UUID(str(tx_id_raw))
            except (ValueError, TypeError):
                tx_uuid = None

            if tx_uuid is not None:
                # 1. Primary: Resolve merchant from ledger transaction entries (The Layering Win)
                async with self.pool.acquire() as conn:
                    row = await conn.fetchrow(
                        """
                        SELECT DISTINCT la.owner_id AS merchant_id
                        FROM ledger_entries le
                        JOIN ledger_accounts la ON la.id = le.account_id
                        WHERE le.tx_id = $1 AND la.owner_type = 'merchant'
                        LIMIT 1;
                        """,
                        tx_uuid,
                    )
                    if row is not None:
                        return UUID(str(row["merchant_id"]))

        # 2. Secondary fallback: Check payload merchant external_id for non-ledger events
        merchant_raw = envelope.payload.get("merchant")
        if merchant_raw and isinstance(merchant_raw, str):
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT id FROM merchants WHERE external_id = $1 LIMIT 1;",
                    merchant_raw,
                )
                if row is not None:
                    return UUID(str(row["id"]))

        return None

    async def process(self, batch: Sequence[Any]) -> None:
        """Process event batch, inserting delivery rows and acknowledging bus."""
        for item in batch:
            event_type, delivery = item
            envelope = delivery.envelope
            event_id = envelope.event_id

            # 1. Validate and build frozen merchant webhook payload contract
            try:
                webhook_payload = build_payload(envelope)
            except Exception as exc:
                logger.warning(
                    "webhook_fanout_poison_payload_skipped",
                    event_id=str(event_id),
                    event_type=envelope.type.value,
                    error=str(exc),
                )
                # Poison entry policy (Task 10): ack malformed message so it does not wedge queue
                await self.bus.ack(event_type, "webhooks", delivery.delivery_id)
                continue

            # 2. Resolve merchant identity from financial ledger truth
            merchant_id = await self._resolve_merchant_id(envelope)
            if merchant_id is None:
                logger.warning(
                    "webhook_fanout_merchant_unresolved_poison_skipped",
                    event_id=str(event_id),
                    event_type=envelope.type.value,
                    tx_id=str(envelope.payload.get("tx_id")),
                )
                # Unknown transaction / merchant: ack and skip per poison policy
                await self.bus.ack(event_type, "webhooks", delivery.delivery_id)
                continue

            # 3. Retrieve all active webhook endpoints for the merchant
            async with self.pool.acquire() as conn:
                endpoints = await conn.fetch(
                    """
                    SELECT id
                    FROM webhook_endpoints
                    WHERE merchant_id = $1 AND active = true;
                    """,
                    merchant_id,
                )

            if not endpoints:
                logger.info(
                    "webhook_fanout_no_active_endpoints",
                    merchant_id=str(merchant_id),
                    event_id=str(event_id),
                )
                await self.bus.ack(event_type, "webhooks", delivery.delivery_id)
                continue

            # 4. Atomically insert pending delivery rows with frozen payload
            payload_json = orjson.dumps(webhook_payload).decode("utf-8")
            async with self.pool.acquire() as conn:
                async with conn.transaction():
                    for ep in endpoints:
                        await conn.execute(
                            """
                            INSERT INTO webhook_deliveries (
                                id, event_id, endpoint_id, payload,
                                status, attempts, next_attempt_at
                            ) VALUES (
                                gen_random_uuid(), $1, $2, $3::jsonb, 'pending', 0, now()
                            )
                            ON CONFLICT (event_id, endpoint_id) DO NOTHING;
                            """,
                            event_id,
                            ep["id"],
                            payload_json,
                        )

            # 5. Acknowledge bus transport delivery after successful DB commit
            await self.bus.ack(event_type, "webhooks", delivery.delivery_id)

            # Check shutdown event between deliveries
            if self.stop.is_set():
                break


# ==============================================================================
# 2. DELIVERY WORKER (Pending DB Rows -> Signed HTTPS POST)
# ==============================================================================


class DeliveryWorker(Worker):
    """Claims pending webhook deliveries via SKIP LOCKED and dispatches signed HTTP POST."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        valkey: Any = None,
        bus: Any = None,
        *,
        name: str = "webhook_delivery",
        http_client: httpx.AsyncClient | None = None,
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
        batch_size: int = DEFAULT_BATCH_SIZE,
        stop: asyncio.Event | None = None,
        sleeper: Callable[[float], Coroutine[Any, Any, None]] = asyncio.sleep,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(
            name=name,
            pool=pool,
            valkey=valkey,
            bus=bus,
            poll_interval_s=poll_interval_s,
            batch_size=batch_size,
            stop=stop,
            sleeper=sleeper,
        )
        self._own_client = http_client is None
        self.http_client = (
            http_client
            if http_client is not None
            else httpx.AsyncClient(timeout=httpx.Timeout(DEFAULT_HTTP_TIMEOUT_S), http2=True)
        )
        self.clock = clock

    async def poll(self) -> Sequence[asyncpg.Record]:
        """Claim a batch of pending deliveries using FOR UPDATE SKIP LOCKED.

        Atomically claims rows, increments attempts, and advances next_attempt_at into the future
        to establish a safety lease during HTTP dispatch.
        """
        async with self.pool.acquire() as conn:
            records = await conn.fetch(
                """
                UPDATE webhook_deliveries d
                SET next_attempt_at = now() + interval '60 seconds',
                    attempts = d.attempts + 1,
                    updated_at = now()
                FROM webhook_endpoints e
                WHERE d.endpoint_id = e.id
                  AND d.id IN (
                      SELECT sub.id
                      FROM webhook_deliveries sub
                      WHERE sub.status = 'pending'
                        AND sub.next_attempt_at <= now()
                      ORDER BY sub.next_attempt_at
                      FOR UPDATE SKIP LOCKED
                      LIMIT $1
                  )
                RETURNING d.id, d.event_id, d.endpoint_id, d.payload, d.attempts,
                          e.url, e.secret_encrypted;
                """,
                self.batch_size,
            )
            return list(records)

    async def process(self, batch: Sequence[Any]) -> None:
        """Dispatch signed HTTP POST requests for each claimed delivery row."""
        for row in batch:
            delivery_id = row["id"]
            endpoint_id = row["endpoint_id"]
            event_id = row["event_id"]
            attempts = row["attempts"]
            url = row["url"]
            secret_encrypted = row["secret_encrypted"]
            raw_payload = row["payload"]

            # Log pathless origin only to prevent leaking credential tokens in URL paths/queries
            parsed = urlsplit(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"

            # 1. Resolve payload raw bytes
            if isinstance(raw_payload, str):
                body_bytes = raw_payload.encode("utf-8")
            elif isinstance(raw_payload, bytes):
                body_bytes = raw_payload
            else:
                body_bytes = orjson.dumps(raw_payload)

            # 2. Decrypt endpoint signing secret from AES-256-GCM vault envelope
            context = webhook_secret_context(endpoint_id)
            try:
                secret_bytes = decrypt_secret(secret_encrypted, context=context)
            except (VaultError, Exception) as exc:
                logger.error(
                    "webhook_delivery_secret_custody_alarm",
                    endpoint_id=str(endpoint_id),
                    event_id=str(event_id),
                    attempt=attempts,
                    error=str(exc),
                )
                # Fail-closed: Leave pending with backoff so manual intervention
                # or key fix can recover
                backoff_s = compute_backoff(attempts)
                async with self.pool.acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE webhook_deliveries
                        SET next_attempt_at = now() + $2 * interval '1 second',
                            last_error = $3,
                            updated_at = now()
                        WHERE id = $1;
                        """,
                        delivery_id,
                        backoff_s,
                        f"Vault secret decryption failed: {exc}",
                    )
                if self.stop.is_set():
                    break
                continue

            # 3. Compute HMAC-SHA256 signature and immediately wipe RAM secret
            try:
                signature = sign_webhook(bytes(secret_bytes), body_bytes)
            finally:
                secret_bytes.wipe()

            # 4. Construct wire request
            headers = {
                "Content-Type": "application/json",
                HEADER_SIGNATURE: signature,
                HEADER_EVENT_ID: str(event_id),
            }

            # 5. Dispatch HTTP POST request
            resp_code: int | None = None
            error_msg: str | None = None
            delivered = False

            try:
                resp = await self.http_client.post(
                    url,
                    content=body_bytes,
                    headers=headers,
                    timeout=DEFAULT_HTTP_TIMEOUT_S,
                )
                resp_code = resp.status_code
                if 200 <= resp_code < 300:
                    delivered = True
                else:
                    error_msg = f"HTTP {resp_code}: {resp.text[:200]}"
            except httpx.RequestError as exc:
                error_msg = f"HTTP request error: {exc}"
            except Exception as exc:
                error_msg = f"Unexpected delivery error: {exc}"

            # 6. Record delivery outcome or schedule retry
            if delivered:
                logger.info(
                    "webhook_delivered",
                    endpoint_id=str(endpoint_id),
                    event_id=str(event_id),
                    attempt=attempts,
                    response_code=resp_code,
                    origin=origin,
                )
                async with self.pool.acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE webhook_deliveries
                        SET status = 'delivered',
                            last_response_code = $2,
                            last_error = NULL,
                            updated_at = now()
                        WHERE id = $1;
                        """,
                        delivery_id,
                        resp_code,
                    )
            else:
                if attempts >= MAX_DELIVERY_ATTEMPTS:
                    logger.error(
                        "webhook_delivery_dead",
                        endpoint_id=str(endpoint_id),
                        event_id=str(event_id),
                        attempts=attempts,
                        last_response_code=resp_code,
                        last_error=error_msg,
                        origin=origin,
                    )
                    async with self.pool.acquire() as conn:
                        await conn.execute(
                            """
                            UPDATE webhook_deliveries
                            SET status = 'dead',
                                last_response_code = $2,
                                last_error = $3,
                                updated_at = now()
                            WHERE id = $1;
                            """,
                            delivery_id,
                            resp_code,
                            error_msg,
                        )
                else:
                    backoff_s = compute_backoff(attempts)
                    logger.warning(
                        "webhook_delivery_retry_scheduled",
                        endpoint_id=str(endpoint_id),
                        event_id=str(event_id),
                        attempt=attempts,
                        next_backoff_s=round(backoff_s, 2),
                        last_response_code=resp_code,
                        origin=origin,
                    )
                    async with self.pool.acquire() as conn:
                        await conn.execute(
                            """
                            UPDATE webhook_deliveries
                            SET status = 'pending',
                                next_attempt_at = now() + $2 * interval '1 second',
                                last_response_code = $3,
                                last_error = $4,
                                updated_at = now()
                            WHERE id = $1;
                            """,
                            delivery_id,
                            backoff_s,
                            resp_code,
                            error_msg,
                        )

            # Check shutdown event between deliveries
            if self.stop.is_set():
                break

    async def close(self) -> None:
        """Close worker resources and internal HTTP client if owned."""
        if self._own_client and hasattr(self.http_client, "aclose"):
            await self.http_client.aclose()
        await super().close()


# Alias WebhookDispatcherWorker to DeliveryWorker for backward/forward naming compatibility
WebhookDispatcherWorker = DeliveryWorker
