"""Integration tests verifying RabbitMQ event bus transport invariants against live RabbitMQ.

Covers publication, competing consumers, crash recovery via channel closure,
poison message dead-lettering, garbage byte skipping with auto-ACK, idempotent ACKs,
and per-type queue isolation per Blueprint §6.
"""

import aio_pika
import aio_pika.abc
import pytest

from fluxpay.shared.events import (
    EventType,
    JsonValue,
    make_event,
)
from fluxpay.shared.rabbitmq_bus import RabbitMQBus

pytestmark = pytest.mark.integration


async def test_rabbitmq_bus_roundtrip(
    rabbit_connection: aio_pika.abc.AbstractRobustConnection,
    bus_prefix: str,
) -> None:
    """Validate full publication, delivery, payload equality, and ack lifecycle.

    Flow:
    1. publish event
    2. ensure_group on queue (idempotent topology declaration)
    3. read_batch with block_ms=250 returns exactly 1 Delivery matching original
    4. ack delivery
    5. subsequent read_batch returns empty list
    """
    bus = RabbitMQBus(rabbit_connection, key_prefix=bus_prefix)
    try:
        event_type = EventType.PAYMENT_SETTLED
        payload: dict[str, JsonValue] = {
            "payment_id": "pay_rmq_123",
            "account_id": "acc_agent_456",
            "amount_cents": 5000,
            "success": True,
            "memo": None,
        }
        event = make_event(event_type, payload, "payments_service")

        await bus.publish(event)
        await bus.ensure_group(event_type, "settlement_workers")

        deliveries = await bus.read_batch(
            event_type,
            "settlement_workers",
            "worker_1",
            count=10,
            block_ms=250,
        )
        assert len(deliveries) == 1

        delivery = deliveries[0]
        assert delivery.envelope.event_id == event.event_id
        assert delivery.envelope.type == event.type
        assert delivery.envelope.producer == event.producer
        assert delivery.envelope.schema_version == event.schema_version
        assert delivery.envelope.payload == payload
        assert delivery.delivery_count == 1

        # Acknowledge delivery
        await bus.ack(event_type, "settlement_workers", delivery.delivery_id)

        # Read again on the same queue — must be empty
        subsequent = await bus.read_batch(
            event_type,
            "settlement_workers",
            "worker_1",
            count=10,
            block_ms=200,
        )
        assert subsequent == []
    finally:
        await bus.close()


async def test_empty_non_blocking_read(
    rabbit_connection: aio_pika.abc.AbstractRobustConnection,
    bus_prefix: str,
) -> None:
    """Validate that read_batch on a fresh queue returns [] without hanging."""
    bus = RabbitMQBus(rabbit_connection, key_prefix=bus_prefix)
    try:
        event_type = EventType.PAYMENT_HELD
        await bus.ensure_group(event_type, "workers")

        deliveries = await bus.read_batch(
            event_type,
            "workers",
            "fast_worker",
            count=10,
            block_ms=200,
        )
        assert deliveries == []
    finally:
        await bus.close()


async def test_load_balance_competing_consumers(
    rabbit_connection: aio_pika.abc.AbstractRobustConnection,
    bus_prefix: str,
) -> None:
    """Validate competing consumers on a single queue with disjoint delivery sets.

    Publishes 10 events. Two independent bus instances (two subscriber channels)
    read from the same queue. Asserts that the delivery sets are disjoint, their union
    contains all 10 events, and all are acknowledged.
    """
    bus1 = RabbitMQBus(rabbit_connection, key_prefix=bus_prefix)
    bus2 = RabbitMQBus(rabbit_connection, key_prefix=bus_prefix)
    try:
        event_type = EventType.PAYMENT_SETTLED

        # Publish 10 events
        published_events = [
            make_event(event_type, {"idx": i, "batch": "load"}, "load_producer") for i in range(10)
        ]
        for ev in published_events:
            await bus1.publish(ev)

        # Competing consumers read batches
        batch1 = await bus1.read_batch(event_type, "workers", "c1", count=5, block_ms=250)
        batch2 = await bus2.read_batch(event_type, "workers", "c2", count=10, block_ms=250)

        ids1 = {d.envelope.event_id for d in batch1}
        ids2 = {d.envelope.event_id for d in batch2}

        # Delivery sets must be disjoint (no double-delivery across competing consumers)
        assert ids1.isdisjoint(ids2)
        assert len(ids1 | ids2) == 10
        assert ids1 | ids2 == {ev.event_id for ev in published_events}

        # Ack all deliveries across their respective channels
        for d in batch1:
            await bus1.ack(event_type, "workers", d.delivery_id)
        for d in batch2:
            await bus2.ack(event_type, "workers", d.delivery_id)
    finally:
        await bus1.close()
        await bus2.close()


async def test_broker_native_crash_recovery(
    rabbit_connection: aio_pika.abc.AbstractRobustConnection,
    bus_prefix: str,
) -> None:
    """Validate broker-native crash recovery via channel death and x-delivery-count tracking.

    consumerA reads an event but crashes before calling ack (bus.close() simulating channel death).
    RabbitMQ natively requeues the unacked message.
    consumerB reads the message: delivery_count >= 2 (at-least-once proof via x-delivery-count).
    """
    bus1 = RabbitMQBus(rabbit_connection, key_prefix=bus_prefix)
    bus2 = RabbitMQBus(rabbit_connection, key_prefix=bus_prefix)
    try:
        event_type = EventType.PAYMENT_FAILED
        event = make_event(
            event_type,
            {"error": "timeout", "order_id": "ord_crash"},
            "crash_producer",
        )
        await bus1.publish(event)

        # consumerA reads the event but DOES NOT ack (simulating crash)
        deliveries1 = await bus1.read_batch(event_type, "workers", "c1", count=10, block_ms=250)
        assert len(deliveries1) == 1
        assert deliveries1[0].envelope.event_id == event.event_id
        assert deliveries1[0].delivery_count == 1

        # Channel death: closing bus1 drops the channel without acking
        await bus1.close()

        # consumerB reads from a new bus instance
        deliveries2 = await bus2.read_batch(event_type, "workers", "c2", count=10, block_ms=250)
        assert len(deliveries2) == 1
        recovered = deliveries2[0]
        assert recovered.envelope.event_id == event.event_id
        # Redelivered message must reflect delivery_count >= 2
        assert recovered.delivery_count >= 2

        # consumerB successfully acks
        await bus2.ack(event_type, "workers", recovered.delivery_id)

        # Queue is now drained
        subsequent = await bus2.read_batch(event_type, "workers", "c2", count=10, block_ms=100)
        assert subsequent == []
    finally:
        await bus1.close()
        await bus2.close()


async def test_poison_message_exhausts_delivery_limit_to_dlq(
    rabbit_connection: aio_pika.abc.AbstractRobustConnection,
    bus_prefix: str,
) -> None:
    """Validate that repeated rejections route poison messages to the DLQ after delivery-limit.

    Scenario:
    1. Publish 1 event.
    2. Read and reject(requeue=True) 5 times (exhausting delivery_limit=5).
    3. Verify the main queue is now empty.
    4. Verify dlq_get() returns the intact envelope, preserving payload equality.
    """
    bus = RabbitMQBus(rabbit_connection, key_prefix=bus_prefix, delivery_limit=5)
    try:
        event_type = EventType.PAYMENT_FAILED
        payload: dict[str, JsonValue] = {"poison": True, "reason": "unhandled_business_error"}
        event = make_event(event_type, payload, "poison_producer")
        await bus.publish(event)

        # Reject with requeue 5 times (delivery_limit=5)
        for _ in range(5):
            deliveries = await bus.read_batch(
                event_type, "workers", "worker", count=1, block_ms=250
            )
            assert len(deliveries) == 1
            assert deliveries[0].envelope.event_id == event.event_id
            await bus.reject(deliveries[0].delivery_id, requeue=True)

        # Main queue must now be empty (broker dead-lettered the message)
        main_empty = await bus.read_batch(event_type, "workers", "worker", count=1, block_ms=200)
        assert main_empty == []

        # DLQ must contain the intact envelope
        dlq_envelopes = await bus.dlq_get(event_type, count=10)
        assert len(dlq_envelopes) == 1
        dead_lettered = dlq_envelopes[0]
        assert dead_lettered.event_id == event.event_id
        assert dead_lettered.type == event.type
        assert dead_lettered.producer == event.producer
        assert dead_lettered.payload == payload
    finally:
        await bus.close()


async def test_poison_bytes_skipped_and_auto_acked(
    rabbit_connection: aio_pika.abc.AbstractRobustConnection,
    bus_prefix: str,
) -> None:
    """Validate that unparseable raw garbage bytes are logged, auto-ACKed, and skipped.

    A poison message with undecodable payload must never wedge the queue.
    """
    bus = RabbitMQBus(rabbit_connection, key_prefix=bus_prefix)
    try:
        event_type = EventType.PAYMENT_SETTLED
        await bus.ensure_group(event_type, "workers")

        # Inject raw garbage bytes directly into the queue
        queue_name = f"{bus_prefix}:{event_type.value}"
        channel = await rabbit_connection.channel()
        garbage_msg = aio_pika.Message(
            body=b"NOT_A_VALID_JSON_ENVELOPE_GARBAGE_BYTES",
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        )
        await channel.default_exchange.publish(garbage_msg, routing_key=queue_name)
        await channel.close()

        # read_batch skips and auto-ACKs the poison message
        deliveries = await bus.read_batch(
            event_type, "workers", "resilient_worker", count=10, block_ms=250
        )
        assert deliveries == []

        # Subsequent read verifies queue is completely empty
        subsequent = await bus.read_batch(
            event_type, "workers", "resilient_worker", count=10, block_ms=100
        )
        assert subsequent == []
    finally:
        await bus.close()


async def test_idempotent_ack(
    rabbit_connection: aio_pika.abc.AbstractRobustConnection,
    bus_prefix: str,
) -> None:
    """Validate that acking an unknown or already-acked delivery_id raises no exception."""
    bus = RabbitMQBus(rabbit_connection, key_prefix=bus_prefix)
    try:
        await bus.ack(EventType.PAYMENT_SETTLED, "workers", "unknown_delivery_id_999")
    finally:
        await bus.close()


async def test_ensure_group_idempotent(
    rabbit_connection: aio_pika.abc.AbstractRobustConnection,
    bus_prefix: str,
) -> None:
    """Validate that calling ensure_group multiple times is safe and raises no exceptions."""
    bus = RabbitMQBus(rabbit_connection, key_prefix=bus_prefix)
    try:
        await bus.ensure_group(EventType.PAYMENT_HELD, "workers")
        await bus.ensure_group(EventType.PAYMENT_HELD, "workers")
    finally:
        await bus.close()


async def test_per_type_isolation(
    rabbit_connection: aio_pika.abc.AbstractRobustConnection,
    bus_prefix: str,
) -> None:
    """Validate that publishing to one event type does not leak into another type's queue."""
    bus = RabbitMQBus(rabbit_connection, key_prefix=bus_prefix)
    try:
        settled_event = make_event(
            EventType.PAYMENT_SETTLED,
            {"account_id": "acc_isolated"},
            "producer",
        )
        await bus.publish(settled_event)

        # Read on payment.failed queue must return empty
        failed_deliveries = await bus.read_batch(
            EventType.PAYMENT_FAILED,
            "failed_workers",
            "consumer",
            count=10,
            block_ms=200,
        )
        assert failed_deliveries == []
    finally:
        await bus.close()
