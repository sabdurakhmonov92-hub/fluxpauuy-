"""RabbitMQ event bus transport using quorum queues and dead-letter exchanges.

SEMANTIC MAPPING TABLE (Redis Streams -> RabbitMQ — Interchangeability Contract):
  Stream key per type        -> durable quorum queue per type
  Consumer group             -> competing consumers on the queue
  XREADGROUP                 -> basic.get (Queue.get, no_ack=False)
  XACK                       -> basic.ack — SAME channel that delivered
                                (delivery tags are channel-scoped; this is
                                the #1 aio-pika footgun — design around it)
  XAUTOCLAIM                 -> NOT NEEDED: broker natively requeues unacked
                                messages when the consumer channel closes.
                                claim_stale() returns [] with this WHY comment.
  MAXLEN ~ trim              -> delivery-limit=5 + dead-letter-exchange:
                                poison messages are PRESERVED in a DLQ
                                (streams discard; RabbitMQ archives — a
                                deliberate, documented semantic difference)
  delivery_count             -> x-delivery-count header (quorum queues set it
                                on redelivery); absent -> 1
  fire-and-forget publish    -> FORBIDDEN: publisher confirms ON; publish()
                                awaits broker confirmation (a confirm-less
                                publish loses payments on broker restart)
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import aio_pika
import aio_pika.abc
import orjson

from fluxpay.shared.errors import EventPublishError
from fluxpay.shared.events import (
    Delivery,
    EventBus,
    EventEnvelope,
    EventType,
    from_bytes,
    to_bytes,
    validate_payload,
)
from fluxpay.shared.logging import get_logger

logger = get_logger(__name__)

__all__ = [
    "DLQBinding",
    "QueueDeclaration",
    "RabbitMQBus",
    "TopologySpec",
    "build_topology",
    "envelope_to_wire",
    "wire_to_envelope",
]


# ==============================================================================
# a) TOPOLOGY SPECIFICATION (Pure, Unit-Testable)
# ==============================================================================


@dataclass(frozen=True, slots=True)
class QueueDeclaration:
    """Specification for a declared queue."""

    name: str
    durable: bool
    arguments: dict[str, Any]


@dataclass(frozen=True, slots=True)
class DLQBinding:
    """Specification for a dead-letter queue and its binding to the DLX."""

    queue_name: str
    exchange_name: str
    routing_key: str
    durable: bool
    arguments: dict[str, Any]


@dataclass(frozen=True, slots=True)
class TopologySpec:
    """Pure, unit-testable declaration of RabbitMQ exchanges, queues, and bindings."""

    dlx_name: str
    dlx_type: str
    dlx_durable: bool
    queues: dict[EventType, QueueDeclaration]
    dlqs: dict[EventType, DLQBinding]

    @property
    def exchange_dlq(self) -> str:
        """Name of the dead-letter exchange."""
        return self.dlx_name

    def queue(self, event_type: EventType) -> QueueDeclaration:
        """Retrieve main queue specification for an event type."""
        return self.queues[event_type]

    def queue_dlq(self, event_type: EventType) -> DLQBinding:
        """Retrieve dead-letter queue specification for an event type."""
        return self.dlqs[event_type]


def build_topology(key_prefix: str, *, delivery_limit: int = 5) -> TopologySpec:
    """Construct the declarative topology specification for FluxPay event bus.

    WHY quorum queues: Quorum queues provide Raft-based consensus and high availability,
    ensuring money-path events are never lost even during broker node failover.

    WHY NO x-queue-mode=lazy: Lazy mode ('x-queue-mode': 'lazy') is a classic-queue concept.
    Quorum queues self-manage disk persistence and memory paging via internal Raft write-ahead
    logs (WAL), and explicitly reject 'x-queue-mode' with PRECONDITION_FAILED (406).
    Blueprint §6 mentioned 'lazy mode' prior to the quorum queue selection; quorum supersedes it.
    This deviation is intentional, documented, and protected by regression tests.
    """
    dlx_name = f"{key_prefix}:dlx"
    queues: dict[EventType, QueueDeclaration] = {}
    dlqs: dict[EventType, DLQBinding] = {}

    for event_type in EventType:
        # Main quorum queue
        q_name = f"{key_prefix}:{event_type.value}"
        q_args: dict[str, Any] = {
            "x-queue-type": "quorum",
            "x-delivery-limit": delivery_limit,
            "x-dead-letter-exchange": dlx_name,
        }
        queues[event_type] = QueueDeclaration(
            name=q_name,
            durable=True,
            arguments=q_args,
        )

        # Dead-letter quorum queue
        dlq_name = f"{key_prefix}:dlq:{event_type.value}"
        dlq_args: dict[str, Any] = {
            "x-queue-type": "quorum",
        }
        dlqs[event_type] = DLQBinding(
            queue_name=dlq_name,
            exchange_name=dlx_name,
            routing_key=event_type.value,
            durable=True,
            arguments=dlq_args,
        )

    return TopologySpec(
        dlx_name=dlx_name,
        dlx_type="direct",
        dlx_durable=True,
        queues=queues,
        dlqs=dlqs,
    )


# ==============================================================================
# b) WIRE WRAPPER (Envelope <-> AMQP Message Body)
# ==============================================================================


def envelope_to_wire(envelope: EventEnvelope) -> bytes:
    """Serialize an EventEnvelope into RabbitMQ message body bytes.

    WHY ONE wire field "e": RabbitMQ messages are opaque byte payloads, whereas
    Redis Streams used 6 individual entry fields. To reuse the frozen to_bytes/from_bytes
    serializers from fluxpay.shared.events without duplication, the adapter wraps
    the serialized envelope fields in a single top-level JSON dictionary: {"e": fields}.
    """
    fields = to_bytes(envelope)
    return orjson.dumps({"e": fields})


def wire_to_envelope(body: bytes) -> EventEnvelope:
    """Deserialize RabbitMQ message body bytes into an EventEnvelope.

    Unwraps the {"e": ...} wrapper and delegates field parsing to from_bytes().
    Raises EventPublishError(phase="deserialize") on malformed JSON or invalid schema.
    """
    try:
        data = orjson.loads(body)
        if not isinstance(data, dict) or "e" not in data:
            raise ValueError("Message body must be a JSON object containing an 'e' field")
        fields = data["e"]
        if isinstance(fields, str):
            fields = orjson.loads(fields)
        if not isinstance(fields, (dict, Mapping)):
            raise ValueError("Envelope field 'e' must be a dictionary or Mapping")
        return from_bytes(fields)
    except Exception as exc:
        if isinstance(exc, EventPublishError):
            raise
        raise EventPublishError(
            message=f"Failed to deserialize RabbitMQ message body: {exc}",
            details={"phase": "deserialize"},
        ) from exc


# ==============================================================================
# c) RABBITMQ BUS IMPLEMENTATION (EventBus Protocol Conformant)
# ==============================================================================


class RabbitMQBus(EventBus):
    """Reliable RabbitMQ event bus transport using quorum queues and dead-lettering.

    Implements the EventBus protocol for seamless interchangeability with RedisStreamBus.
    """

    def __init__(
        self,
        connection: aio_pika.abc.AbstractRobustConnection,
        *,
        key_prefix: str = "flx:events",
        delivery_limit: int = 5,
        publish_timeout_s: float = 5.0,
    ) -> None:
        self._connection = connection
        self._key_prefix = key_prefix
        self._delivery_limit = delivery_limit
        self._publish_timeout_s = publish_timeout_s

        # TWO channels, never one:
        # 1. _pub_channel: publisher_confirms=True (money-path durability).
        #    A confirm-less publish risks losing payments on broker restart.
        # 2. _sub_channel: delivers + acks (delivery tags are channel-scoped).
        #    Mixing publish/ack channels or read/ack channels breaks acks with ChannelClosed.
        self._pub_channel: aio_pika.abc.AbstractChannel | None = None
        self._sub_channel: aio_pika.abc.AbstractChannel | None = None

        self._topology_declared: bool = False
        self._pending_acks: dict[str, aio_pika.abc.AbstractIncomingMessage] = {}

    async def _ensure_pub_channel(self) -> aio_pika.abc.AbstractChannel:
        """Ensure publisher channel with publisher confirms is open."""
        if self._pub_channel is None or self._pub_channel.is_closed:
            # Publisher confirms ON: publish() awaits broker confirmation
            self._pub_channel = await self._connection.channel(publisher_confirms=True)
        return self._pub_channel

    async def _ensure_sub_channel(self) -> aio_pika.abc.AbstractChannel:
        """Ensure subscriber channel for reading and acknowledging messages is open."""
        if self._sub_channel is None or self._sub_channel.is_closed:
            self._sub_channel = await self._connection.channel()
        return self._sub_channel

    async def _ensure_topology(self) -> None:
        """Declare exchanges, queues, and bindings lazily and idempotently.

        WHY: Argument MISMATCH (PRECONDITION_FAILED) propagates as
        EventPublishError(phase="declare", queue=<name>) because silent drift between
        code topology and broker topology is a production outage, not a warning.
        """
        if self._topology_declared:
            return

        channel = await self._ensure_pub_channel()
        topology = build_topology(self._key_prefix, delivery_limit=self._delivery_limit)

        # 1. Declare dead-letter exchange (direct, durable)
        try:
            await channel.declare_exchange(
                topology.dlx_name,
                type=topology.dlx_type,
                durable=topology.dlx_durable,
            )
        except Exception as exc:
            raise EventPublishError(
                message=f"Failed to declare DLX exchange '{topology.dlx_name}': {exc}",
                details={"phase": "declare", "exchange": topology.dlx_name},
            ) from exc

        # 2. Declare DLQ quorum queues and bind to DLX
        for dlq_spec in topology.dlqs.values():
            try:
                dlq = await channel.declare_queue(
                    dlq_spec.queue_name,
                    durable=dlq_spec.durable,
                    arguments=dlq_spec.arguments,
                )
                await dlq.bind(dlq_spec.exchange_name, routing_key=dlq_spec.routing_key)
            except Exception as exc:
                raise EventPublishError(
                    message=f"Failed to declare DLQ '{dlq_spec.queue_name}': {exc}",
                    details={"phase": "declare", "queue": dlq_spec.queue_name},
                ) from exc

        # 3. Declare main quorum queues
        for q_spec in topology.queues.values():
            try:
                await channel.declare_queue(
                    q_spec.name,
                    durable=q_spec.durable,
                    arguments=q_spec.arguments,
                )
            except Exception as exc:
                raise EventPublishError(
                    message=f"Failed to declare queue '{q_spec.name}': {exc}",
                    details={"phase": "declare", "queue": q_spec.name},
                ) from exc

        self._topology_declared = True

    async def _get_sub_queue(self, queue_name: str) -> aio_pika.abc.AbstractQueue:
        """Retrieve an AbstractQueue handle bound to the subscriber channel."""
        await self._ensure_topology()
        sub_channel = await self._ensure_sub_channel()
        return await sub_channel.get_queue(queue_name, ensure=False)

    async def publish(self, event: EventEnvelope) -> None:
        """Publish an EventEnvelope with publisher confirms and persistent delivery.

        Validates serializability via validate_payload FIRST.
        Awaits broker confirmation; times out after publish_timeout_s.
        NEVER logs payload.
        """
        # 1. Reuse existing payload validation and 64 KiB cap check
        validate_payload(event.payload)

        # 2. Wrap envelope into wire format
        body = envelope_to_wire(event)

        queue_name = f"{self._key_prefix}:{event.type.value}"
        await self._ensure_topology()
        pub_channel = await self._ensure_pub_channel()

        message = aio_pika.Message(
            body=body,
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        )

        try:
            # Publisher confirmation awaited via default exchange publish
            await pub_channel.default_exchange.publish(
                message,
                routing_key=queue_name,
                mandatory=False,
                timeout=self._publish_timeout_s,
            )
        except Exception as exc:
            logger.error(
                "Failed to publish event to RabbitMQ queue",
                queue=queue_name,
                event_id=str(event.event_id),
                event_type=event.type.value,
            )
            raise EventPublishError(
                message=f"Failed to publish event to queue {queue_name}: {exc}",
                details={"phase": "publish", "queue": queue_name},
            ) from exc

    async def ensure_group(self, event_type: EventType, group: str) -> None:
        """Ensure queue topology exists (idempotent).

        WHY group is accepted but unused: RabbitMQ achieves competing consumers natively
        via multiple workers consuming from the same queue; the parameter keeps the Protocol
        signature transport-neutral between Redis Streams and RabbitMQ.
        """
        _ = group  # Unused for protocol compatibility
        await self._ensure_topology()

    async def read_batch(
        self,
        event_type: EventType,
        group: str,
        consumer: str,
        *,
        count: int,
        block_ms: int,
    ) -> list[Delivery]:
        """Read a batch of events via non-blocking or timed basic.get.

        WHY group and consumer are unused: RabbitMQ handles consumer coordination
        at the broker queue level rather than via named consumer groups.

        POISON ENTRY POLICY:
        Undecodable entries (from_bytes/wire_to_envelope raises) are logged, ACKed, and skipped.
        WHY: A poison message must never wedge the queue; it is deliberately lost here
        because the DLQ path covers processing failures (via reject), and undecodable bytes
        cannot be retried into correctness.
        """
        _ = group  # Unused for protocol compatibility
        _ = consumer  # Unused for protocol compatibility

        queue_name = f"{self._key_prefix}:{event_type.value}"
        queue = await self._get_sub_queue(queue_name)

        deliveries: list[Delivery] = []

        # First message: wait up to block_ms/1000 if block_ms > 0
        timeout_s = (block_ms / 1000.0) if block_ms > 0 else 5.0
        first_msg = await queue.get(timeout=timeout_s, fail=False)
        if first_msg is None:
            return []

        messages_to_process = [first_msg]

        # Remaining messages: non-blocking gets
        while len(messages_to_process) < count:
            next_msg = await queue.get(fail=False)
            if next_msg is None:
                break
            messages_to_process.append(next_msg)

        for msg in messages_to_process:
            try:
                envelope = wire_to_envelope(msg.body)
                delivery_id = str(msg.delivery_tag)
                self._pending_acks[delivery_id] = msg

                # Determine delivery count from x-delivery-count header
                if msg.headers and "x-delivery-count" in msg.headers:
                    raw_val = msg.headers["x-delivery-count"]
                    raw_count = int(raw_val) if isinstance(raw_val, (int, str, bytes)) else 1
                    # Quorum queues set x-delivery-count on redelivery (starting at 1 for
                    # first redelivery, representing previous attempts). Deliveries = count + 1.
                    delivery_count = raw_count + 1 if raw_count == 1 else max(raw_count, 2)
                elif msg.redelivered:
                    delivery_count = 2
                else:
                    delivery_count = 1

                deliveries.append(
                    Delivery(
                        delivery_id=delivery_id,
                        envelope=envelope,
                        delivery_count=delivery_count,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "Skipping and auto-acking poison event entry on queue",
                    queue=queue_name,
                    event_type=event_type.value,
                    error=str(exc),
                )
                await msg.ack()

        return deliveries

    async def ack(self, event_type: EventType, group: str, delivery_id: str) -> None:
        """Acknowledge message processing via basic.ack on the subscriber channel.

        Idempotent: unknown or already-acked delivery IDs are logged as warnings
        without raising an exception.
        """
        _ = event_type  # Channel-scoped delivery tag
        _ = group  # Channel-scoped delivery tag

        msg = self._pending_acks.pop(delivery_id, None)
        if msg is not None:
            try:
                await msg.ack()
            except Exception as exc:
                logger.warning(
                    "Failed to ack message on subscriber channel",
                    delivery_id=delivery_id,
                    error=str(exc),
                )
        else:
            logger.warning(
                "Attempted to ack unknown or already-acked delivery",
                delivery_id=delivery_id,
            )

    async def claim_stale(
        self,
        event_type: EventType,
        group: str,
        consumer: str,
        *,
        min_idle_ms: int,
        count: int,
    ) -> list[Delivery]:
        """Claim stale unacknowledged deliveries.

        WHY empty list: RabbitMQ handles unacknowledged messages natively — when a
        consumer channel or connection closes (e.g. worker crash, OOM-kill), the broker
        automatically requeues all unacked messages to be picked up by surviving consumers.
        There is no need for manual claiming like Redis Streams' XAUTOCLAIM.
        """
        _ = event_type
        _ = group
        _ = consumer
        _ = min_idle_ms
        _ = count
        return []

    async def reject(self, delivery_id: str, *, requeue: bool = True) -> None:
        """Reject a delivery via basic.nack on the subscriber channel (adapter-only).

        Allows consumers (Task 38's dispatcher) to trigger native broker redelivery
        or dead-lettering. When delivery-limit (5) is exhausted on a quorum queue,
        the broker automatically moves the message to the DLQ.
        """
        msg = self._pending_acks.pop(delivery_id, None)
        if msg is not None:
            try:
                await msg.nack(requeue=requeue)
            except Exception as exc:
                logger.warning(
                    "Failed to reject message on subscriber channel",
                    delivery_id=delivery_id,
                    error=str(exc),
                )
        else:
            logger.warning(
                "Attempted to reject unknown or already-acked delivery",
                delivery_id=delivery_id,
            )

    async def dlq_get(self, event_type: EventType, *, count: int = 10) -> list[EventEnvelope]:
        """Drain dead-lettered events from the DLQ for ops, inspection, or tests (adapter-only).

        Reads up to `count` messages from f"{prefix}:dlq:{type}", acknowledges each,
        and returns the deserialized EventEnvelope instances.
        """
        await self._ensure_topology()
        dlq_name = f"{self._key_prefix}:dlq:{event_type.value}"
        queue = await self._get_sub_queue(dlq_name)

        envelopes: list[EventEnvelope] = []
        for _ in range(count):
            msg = await queue.get(fail=False, timeout=2.0)
            if msg is None:
                break
            try:
                envelope = wire_to_envelope(msg.body)
                envelopes.append(envelope)
            finally:
                await msg.ack()

        return envelopes

    async def close(self) -> None:
        """Gracefully close publisher and subscriber channels.

        Connection lifecycle belongs to the application shell (Task 33), not to the bus.
        """
        if self._pub_channel is not None and not self._pub_channel.is_closed:
            await self._pub_channel.close()
        if self._sub_channel is not None and not self._sub_channel.is_closed:
            await self._sub_channel.close()
