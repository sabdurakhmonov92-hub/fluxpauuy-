"""Integration tests verifying Redis Streams transport invariants against live Valkey.

Covers publication, consumer groups, non-blocking reads, load balancing,
crash recovery via XAUTOCLAIM, poison entry isolation, approximate trimming,
and per-type stream isolation per Blueprint §6.
"""

import asyncio
from typing import Any, cast

import pytest
import redis.asyncio as redis_async

from fluxpay.shared.events import (
    EventType,
    JsonValue,
    RedisStreamBus,
    make_event,
)

pytestmark = pytest.mark.integration


async def test_event_bus_roundtrip(valkey: redis_async.Redis) -> None:
    """Validate full publication, delivery, payload equality, and ack lifecycle.

    Flow:
    1. ensure_group on stream
    2. publish event
    3. read_batch with block_ms=0 returns exactly 1 Delivery matching original
    4. ack delivery
    5. subsequent read_batch returns empty list
    """
    bus = RedisStreamBus(valkey, key_prefix="flx:test_events")
    event_type = EventType.PAYMENT_SETTLED
    group = "test_settlement_workers"
    consumer = "worker_1"

    await bus.ensure_group(event_type, group)

    payload: dict[str, JsonValue] = {
        "payment_id": "pay_987",
        "agent_id": "ag_123",
        "amount_cents": 2500,
        "success": True,
        "description": "API subscription fee",
    }
    event = make_event(event_type, payload, "payments_service")
    await bus.publish(event)

    deliveries = await bus.read_batch(event_type, group, consumer, count=10, block_ms=0)
    assert len(deliveries) == 1

    delivery = deliveries[0]
    assert delivery.envelope.event_id == event.event_id
    assert delivery.envelope.type == event.type
    assert delivery.envelope.producer == event.producer
    assert delivery.envelope.schema_version == event.schema_version
    assert delivery.envelope.payload == payload
    assert delivery.delivery_count == 1

    # Acknowledge delivery
    await bus.ack(event_type, group, delivery.delivery_id)

    # Read again on the same consumer group — must be empty
    subsequent = await bus.read_batch(event_type, group, consumer, count=10, block_ms=0)
    assert subsequent == []


async def test_non_blocking_empty_read(valkey: redis_async.Redis) -> None:
    """Validate that read_batch with block_ms=0 returns immediately without timing flakiness."""
    bus = RedisStreamBus(valkey, key_prefix="flx:test_events")
    event_type = EventType.PAYMENT_HELD
    group = "empty_test_group"

    await bus.ensure_group(event_type, group)

    deliveries = await bus.read_batch(event_type, group, "consumer_fast", count=10, block_ms=0)
    assert deliveries == []


async def test_consumer_group_load_balance(valkey: redis_async.Redis) -> None:
    """Validate consumer group load balancing and disjoint delivery sets.

    Publishes 10 events. consumerA reads up to 6 events (K in [1..9]);
    consumerB reads the remaining 10 - K events. Asserts delivery ID sets
    are disjoint and sum to 10.
    """
    bus = RedisStreamBus(valkey, key_prefix="flx:test_events")
    event_type = EventType.PAYMENT_SETTLED
    group = "balanced_workers"

    await bus.ensure_group(event_type, group)

    for i in range(10):
        ev = make_event(event_type, {"seq": i, "tag": "bulk"}, "load_producer")
        await bus.publish(ev)

    # consumerA reads up to 6 events (K in [1..9])
    batch_a = await bus.read_batch(event_type, group, "consumerA", count=6, block_ms=0)
    k = len(batch_a)
    assert 1 <= k <= 9

    # consumerB reads remaining events
    batch_b = await bus.read_batch(event_type, group, "consumerB", count=10, block_ms=0)
    assert len(batch_b) == 10 - k

    ids_a = {d.delivery_id for d in batch_a}
    ids_b = {d.delivery_id for d in batch_b}

    # Assert disjoint delivery IDs (no duplicate deliveries across active consumers)
    assert ids_a.isdisjoint(ids_b)
    assert len(ids_a | ids_b) == 10

    # Ack all deliveries
    for d in batch_a:
        await bus.ack(event_type, group, d.delivery_id)
    for d in batch_b:
        await bus.ack(event_type, group, d.delivery_id)


async def test_crash_recovery_stale_claim_and_delivery_count(valkey: redis_async.Redis) -> None:
    """Validate crash recovery via XAUTOCLAIM and delivery_count tracking.

    consumerA reads an event but crashes (never calls ack).
    After the idle window elapses (min_idle_ms=50), consumerB claims the stale entry.
    Asserts delivery_count == 2, indicating at-least-once redelivery.
    Once consumerB acks, pending entries drop to 0.
    """
    bus = RedisStreamBus(valkey, key_prefix="flx:test_events")
    event_type = EventType.PAYMENT_FAILED
    group = "crash_recovery_group"

    await bus.ensure_group(event_type, group)

    event = make_event(event_type, {"error": "timeout", "terminal": True}, "crash_producer")
    await bus.publish(event)

    # consumerA reads the event but DOES NOT ack (simulating worker crash/OOM)
    deliveries = await bus.read_batch(event_type, group, "consumerA", count=10, block_ms=0)
    assert len(deliveries) == 1
    assert deliveries[0].delivery_count == 1

    # Deterministic wait exceeding min_idle_ms=50 to make the entry eligible for claim
    await asyncio.sleep(0.15)

    # consumerB claims the stale entry
    claimed = await bus.claim_stale(
        event_type,
        group,
        "consumerB",
        min_idle_ms=50,
        count=10,
    )
    assert len(claimed) == 1
    recovered = claimed[0]
    assert recovered.envelope.event_id == event.event_id
    # Redelivery count must reflect the second delivery attempt
    assert recovered.delivery_count == 2

    # consumerB successfully acks
    await bus.ack(event_type, group, recovered.delivery_id)

    # Verify pending list is now completely empty
    stream_key = bus._stream_key(event_type)
    pending_summary = await valkey.xpending(stream_key, group)
    pending_count = (
        pending_summary["pending"] if isinstance(pending_summary, dict) else pending_summary[0]
    )
    assert pending_count == 0


async def test_poison_entry_skipped_and_auto_acked(valkey: redis_async.Redis) -> None:
    """Validate that poison/alien stream entries are skipped and auto-acked to prevent wedging.

    DESIGN DECISION:
    Stream entries are immutable; foreign or legacy producers writing undecodable
    fields directly via XADD must never wedge the consumer loop or block valid messages.
    When read_batch encounters a deserialization failure:
    1. It logs a warning with stream key and entry ID (NEVER payload).
    2. It immediately ACKs the poison entry.
    3. It skips the poison entry from the returned deliveries list.

    Test scenario:
    Publish 1 valid event + 1 poison entry directly via XADD.
    read_batch returns only the 1 valid delivery.
    After acking the valid delivery, pending count is 0.
    """
    bus = RedisStreamBus(valkey, key_prefix="flx:test_events")
    event_type = EventType.PAYMENT_SETTLED
    group = "poison_resilience_group"
    stream_key = bus._stream_key(event_type)

    await bus.ensure_group(event_type, group)

    # 1. Publish a valid event
    valid_event = make_event(event_type, {"status": "valid"}, "valid_producer")
    await bus.publish(valid_event)

    # 2. Inject an alien/poison entry directly into the stream
    alien_fields: dict[str, Any] = {
        "corrupted_field": "unparseable_data",
        "missing_required_contract": "true",
    }
    await valkey.xadd(stream_key, cast(dict[Any, Any], alien_fields))

    # 3. Read batch: must return only the valid delivery
    deliveries = await bus.read_batch(event_type, group, "resilient_worker", count=10, block_ms=0)
    assert len(deliveries) == 1
    assert deliveries[0].envelope.event_id == valid_event.event_id

    # 4. Ack the valid delivery
    await bus.ack(event_type, group, deliveries[0].delivery_id)

    # 5. Verify pending entries is 0 (poison entry was auto-acked during read_batch)
    pending_summary = await valkey.xpending(stream_key, group)
    pending_count = (
        pending_summary["pending"] if isinstance(pending_summary, dict) else pending_summary[0]
    )
    assert pending_count == 0


async def test_ensure_group_idempotent(valkey: redis_async.Redis) -> None:
    """Validate that calling ensure_group multiple times is safe and raises no exceptions."""
    bus = RedisStreamBus(valkey, key_prefix="flx:test_events")
    event_type = EventType.PAYMENT_HELD
    group = "idempotent_group"

    # First call creates the group
    await bus.ensure_group(event_type, group)

    # Second call detects BUSYGROUP and silently succeeds
    await bus.ensure_group(event_type, group)


async def test_stream_approximate_trim_bound(valkey: redis_async.Redis) -> None:
    """Validate that XADD approximate trimming bounds stream length to ~ default_maxlen.

    Publishes 12 events to a stream configured with default_maxlen=4.
    Redis approximate trimming (~4) operates at macro-node boundaries, so XLEN
    is bounded by at most 2x the target maxlen (XLEN <= 8).
    """
    bus = RedisStreamBus(valkey, key_prefix="flx:test_events", default_maxlen=4)
    event_type = EventType.PAYMENT_SETTLED
    stream_key = bus._stream_key(event_type)

    for i in range(12):
        ev = make_event(event_type, {"idx": i}, "trim_producer")
        await bus.publish(ev)

    xlen = await valkey.xlen(stream_key)
    # Approximate trim bound: macro-node pruning ensures XLEN is bounded (<= 8 for maxlen=4)
    assert xlen <= 8


async def test_per_type_stream_isolation(valkey: redis_async.Redis) -> None:
    """Validate that publishing to one event type does not leak into another type's stream.

    WHY: Per-type streams guarantee that high-volume or slow-consuming event types
    never cause head-of-line blocking for unrelated event types.
    """
    bus = RedisStreamBus(valkey, key_prefix="flx:test_events")

    # Publish exclusively to payment.settled
    settled_event = make_event(EventType.PAYMENT_SETTLED, {"id": "set_1"}, "producer")
    await bus.publish(settled_event)

    # Read from payment.failed consumer group — must be completely empty
    await bus.ensure_group(EventType.PAYMENT_FAILED, "failed_workers")
    failed_deliveries = await bus.read_batch(
        EventType.PAYMENT_FAILED,
        "failed_workers",
        "consumer_failed",
        count=10,
        block_ms=0,
    )
    assert failed_deliveries == []
