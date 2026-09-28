"""Typed event envelope, wire format serialization, and Redis Streams transport.

This module provides the core event bus abstractions for FluxPay.
Event delivery semantics are the foundational design contract:
1. At-least-once delivery: consumers must treat events as potentially redelivered
   (indicated by delivery_count > 1) and deduplicate using event_id or ledger idempotency keys.
2. Isolated per-type streams: prevents slow consumers from causing head-of-line blocking.
3. Crash recovery via stale claiming: prevents stranded payments when workers die
   between read and ack.
4. Poison entry skipping with auto-ACK: prevents malformed messages from wedging the stream.
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Protocol, cast
from uuid import UUID

import orjson
from redis.asyncio import Redis
from redis.exceptions import ResponseError

from fluxpay.shared.errors import EventPublishError
from fluxpay.shared.logging import get_logger

logger = get_logger(__name__)

__all__ = [
    "MAX_PAYLOAD_BYTES",
    "Delivery",
    "EventBus",
    "EventEnvelope",
    "EventType",
    "JsonValue",
    "RedisStreamBus",
    "from_bytes",
    "make_event",
    "to_bytes",
    "validate_payload",
]


# ==============================================================================
# a) EVENT TYPE REGISTRY (Frozen Contract — Additive Only)
# ==============================================================================


class EventType(StrEnum):
    """Immutable registry of public and internal domain event types.

    WHY: These three names are consumed by merchants' webhook endpoints (Blueprint §0) —
    once shipped they are public API, never renamed, never repurposed. New events = new
    members. Old member changes = forbidden.
    """

    PAYMENT_SETTLED = "payment.settled"
    PAYMENT_HELD = "payment.held"
    PAYMENT_FAILED = "payment.failed"


# ==============================================================================
# b) EVENT ENVELOPE (The Inter-Module Contract)
# ==============================================================================

# Flat scalar payloads keep consumers simple, keep Loki/debuggable traces, and prevent
# modules from smuggling nested domain objects across the bus — if a consumer needs
# structure, define it in the payload CONTRACT for that event type, scalars included.
JsonValue = str | int | bool | None

MAX_PAYLOAD_BYTES: Final[int] = 64 * 1024  # 64 KiB cap for predictable latency


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    """Immutable domain event envelope.

    Guarantees structural validity at instantiation time (fail at construction, not at publish):
    - type is a registered EventType member
    - occurred_at is timezone-aware (naive datetime = programming error)
    - schema_version >= 1
    - payload keys are str; values restricted to str | int | bool | None
    """

    event_id: UUID
    type: EventType
    occurred_at: datetime
    producer: str
    schema_version: int
    payload: Mapping[str, JsonValue]

    def __post_init__(self) -> None:
        # Validate event type
        raw_type: Any = self.type
        if isinstance(raw_type, EventType):
            pass
        elif isinstance(raw_type, str):
            try:
                object.__setattr__(self, "type", EventType(raw_type))
            except ValueError as exc:
                raise ValueError(f"Unknown event type: {raw_type}") from exc
        else:
            raise ValueError(f"Event type must be an EventType instance, got {type(raw_type)}")

        # Validate timezone awareness (naive datetime is a programming error)
        tz = self.occurred_at.tzinfo
        if tz is None or tz.utcoffset(self.occurred_at) is None:
            raise ValueError("occurred_at must be timezone-aware (UTC)")

        # Validate schema version
        if self.schema_version < 1:
            raise ValueError(f"schema_version must be >= 1, got {self.schema_version}")

        # Validate payload flat scalar contract
        if not isinstance(self.payload, Mapping):
            raise ValueError(f"payload must be a Mapping, got {type(self.payload)}")

        for k, v in self.payload.items():
            if not isinstance(k, str):
                raise ValueError(f"payload key must be str, got {type(k).__name__}: {k!r}")
            # Note: in Python, bool is a subclass of int (isinstance(True, int) is True).
            # We strictly permit bool, int, str, and None. Floats, lists, dicts, etc. are rejected.
            if isinstance(v, bool):
                continue
            if isinstance(v, (str, int)):
                continue
            if v is None:
                continue
            raise ValueError(
                f"payload value for key {k!r} has invalid type {type(v).__name__}. "
                "Restricted to str | int | bool | None."
            )


def make_event(
    type: EventType,
    payload: Mapping[str, JsonValue],
    producer: str,
    *,
    schema_version: int = 1,
) -> EventEnvelope:
    """Create a new EventEnvelope with a fresh UUIDv4 identity and UTC timestamp."""
    return EventEnvelope(
        event_id=uuid.uuid4(),
        type=type,
        occurred_at=datetime.now(UTC),
        producer=producer,
        schema_version=schema_version,
        payload=payload,
    )


# ==============================================================================
# c) WIRE FORMAT (Documented, Frozen)
# ==============================================================================


def validate_payload(payload: Mapping[str, Any]) -> bytes:
    """Validate payload serializability and enforce the 64 KiB size boundary.

    WHY: 64 KiB keeps Redis latency predictable; big artifacts belong in object storage
    with a reference in payload.
    """
    if not isinstance(payload, Mapping):
        raise EventPublishError(
            message="Payload must be a Mapping",
            details={"phase": "serialize", "reason": "not_a_mapping"},
        )

    for k, v in payload.items():
        if not isinstance(k, str):
            raise EventPublishError(
                message=f"Payload key must be str, got {type(k).__name__}",
                details={"phase": "serialize", "reason": "invalid_key_type"},
            )
        if isinstance(v, bool):
            continue
        if isinstance(v, (str, int)):
            continue
        if v is None:
            continue
        raise EventPublishError(
            message=f"Payload value for key {k!r} has invalid type {type(v).__name__}",
            details={"phase": "serialize", "reason": "invalid_value_type"},
        )

    try:
        encoded = orjson.dumps(payload)
    except Exception as exc:
        raise EventPublishError(
            message="Payload is not orjson-serializable",
            details={"phase": "serialize", "reason": "unserializable"},
        ) from exc

    if len(encoded) > MAX_PAYLOAD_BYTES:
        msg = (
            f"Payload size ({len(encoded)} bytes) exceeds 64 KiB limit ({MAX_PAYLOAD_BYTES} bytes)"
        )
        raise EventPublishError(
            message=msg,
            details={"phase": "serialize", "reason": "payload_too_large"},
        )

    return encoded


def to_bytes(envelope: EventEnvelope) -> dict[str, str]:
    """Serialize an EventEnvelope into Redis Stream entry fields (all str).

    Wire format fields:
      id=<event_id> | type=<"payment.settled"> | ts=<ISO8601 UTC ms>
      | producer=<str> | v=<int> | payload=<orjson compact JSON>

    Timestamp precision:
      Serialized with millisecond precision in UTC (e.g. 2026-09-20T14:23:45.123Z).
      Sub-millisecond (microsecond) components are intentionally truncated per wire format.
    """
    # Enforce UTC and millisecond precision
    ts_ms = envelope.occurred_at.astimezone(UTC).isoformat(timespec="milliseconds")
    ts_str = ts_ms.replace("+00:00", "Z")

    payload_bytes = validate_payload(envelope.payload)

    return {
        "id": str(envelope.event_id),
        "type": str(envelope.type.value),
        "ts": ts_str,
        "producer": envelope.producer,
        "v": str(envelope.schema_version),
        "payload": payload_bytes.decode("utf-8"),
    }


def from_bytes(fields: Mapping[Any, Any]) -> EventEnvelope:
    """Deserialize Redis Stream entry fields into an EventEnvelope.

    Total function: malformed, corrupted, or unknown input raises EventPublishError
    with details={"phase": "deserialize"}. Never crashes a consumer loop with unhandled exceptions.
    """
    try:
        decoded: dict[str, str] = {}
        for k, v in fields.items():
            k_str = k.decode("utf-8") if isinstance(k, bytes) else str(k)
            v_str = v.decode("utf-8") if isinstance(v, bytes) else str(v)
            decoded[k_str] = v_str

        for req in ("id", "type", "ts", "producer", "v", "payload"):
            if req not in decoded:
                raise ValueError(f"Missing required stream field: '{req}'")

        event_id = UUID(decoded["id"])
        event_type = EventType(decoded["type"])

        # Parse timestamp (supporting both Z and +00:00)
        ts_str = decoded["ts"].replace("Z", "+00:00")
        occurred_at = datetime.fromisoformat(ts_str)
        if occurred_at.tzinfo is None:
            raise ValueError("Parsed timestamp lacks timezone information")

        schema_version = int(decoded["v"])
        if schema_version < 1:
            raise ValueError(f"schema_version must be >= 1, got {schema_version}")

        raw_payload = orjson.loads(decoded["payload"])
        if not isinstance(raw_payload, dict):
            raise ValueError(f"payload must be a JSON object, got {type(raw_payload).__name__}")

        # Validate deserialized payload scalar constraints
        for pk, pv in raw_payload.items():
            if not isinstance(pk, str):
                raise ValueError(f"payload key must be str: {pk!r}")
            if isinstance(pv, bool):
                continue
            if isinstance(pv, (str, int)):
                continue
            if pv is None:
                continue
            raise ValueError(
                f"payload value for {pk!r} has invalid scalar type: {type(pv).__name__}"
            )

        return EventEnvelope(
            event_id=event_id,
            type=event_type,
            occurred_at=occurred_at,
            producer=decoded["producer"],
            schema_version=schema_version,
            payload=raw_payload,
        )
    except Exception as exc:
        raise EventPublishError(
            message=f"Failed to deserialize event entry: {exc}",
            details={"phase": "deserialize"},
        ) from exc


# ==============================================================================
# d) TRANSPORT INTERFACE & DELIVERY CONTRACT
# ==============================================================================


@dataclass(frozen=True, slots=True)
class Delivery:
    """Consumer delivery handle wrapping an event envelope.

    delivery_id: Redis entry ID — the ack handle.
    envelope: Deserialized EventEnvelope.
    delivery_count: >= 1; > 1 indicates redelivery after worker crash/timeout.
      Consumers MUST treat processing as at-least-once and deduplicate by event_id
      (the money path deduplicates via ledger idempotency keys — Task 11/16).
    """

    delivery_id: str
    envelope: EventEnvelope
    delivery_count: int


class EventBus(Protocol):
    """Interchangeable transport protocol for event publication and consumption."""

    async def publish(self, event: EventEnvelope) -> None:
        """Publish an event envelope to the transport."""
        ...

    async def ensure_group(self, event_type: EventType, group: str) -> None:
        """Ensure consumer group exists on the event stream (idempotent)."""
        ...

    async def read_batch(
        self,
        event_type: EventType,
        group: str,
        consumer: str,
        *,
        count: int,
        block_ms: int,
    ) -> list[Delivery]:
        """Read a batch of pending/new deliveries for a consumer group."""
        ...

    async def ack(self, event_type: EventType, group: str, delivery_id: str) -> None:
        """Acknowledge successful delivery processing."""
        ...

    async def claim_stale(
        self,
        event_type: EventType,
        group: str,
        consumer: str,
        *,
        min_idle_ms: int,
        count: int,
    ) -> list[Delivery]:
        """Claim unacknowledged stale deliveries from dead consumers."""
        ...


# ==============================================================================
# e) REDIS STREAMS IMPLEMENTATION
# ==============================================================================


class RedisStreamBus(EventBus):
    """High-throughput Redis Streams event bus transport.

    Applies strict Redis Streams best practices:
    - Per-type streams: f"{key_prefix}:{event_type.value}" prevents head-of-line blocking.
    - Approximate trimming: MAXLEN ~ default_maxlen keeps streams bounded with O(1) amortized cost.
    - Idempotent group creation: start id '$' ensures consumer groups only see new events.
    - Poison entry skip-and-ack: malformed entries are logged and auto-ACKed so streams never wedge.
    - Crash recovery: XAUTOCLAIM recovers unacked messages from dead consumers.
    """

    def __init__(
        self,
        redis_client: Redis,
        *,
        key_prefix: str = "flx:events",
        default_maxlen: int = 100_000,
    ) -> None:
        self._redis = redis_client
        self._key_prefix = key_prefix
        self._default_maxlen = default_maxlen

    def _stream_key(self, event_type: EventType) -> str:
        """Derive the stream key for a given event type.

        WHY: Per-type streams → per-type consumer groups → a slow consumer of one
        event type never stalls another type; a single global stream is the classic
        head-of-line blocking mistake.
        """
        return f"{self._key_prefix}:{event_type.value}"

    async def publish(self, event: EventEnvelope) -> None:
        """Publish an EventEnvelope via XADD with approximate trimming.

        WHY approximate trim (MAXLEN ~ default_maxlen): Exact trim adds latency on every
        insert; approximate keeps streams bounded with O(1) amortized cost; memory bound
        is the requirement, exact retention is not.

        Validates serializability and 64 KiB cap FIRST before touching Redis.
        Logs ONLY event_id + type + stream key on failure (NEVER payload).
        """
        stream_key = self._stream_key(event.type)

        # Validate serializability and payload size first
        validate_payload(event.payload)
        fields = to_bytes(event)

        try:
            await self._redis.xadd(
                stream_key,
                cast(dict[Any, Any], fields),
                maxlen=self._default_maxlen,
                approximate=True,
            )
        except Exception as exc:
            logger.error(
                "Failed to publish event to Redis stream",
                stream_key=stream_key,
                event_id=str(event.event_id),
                event_type=event.type.value,
            )
            raise EventPublishError(
                message=f"Failed to publish event to stream {stream_key}: {exc}",
                details={
                    "phase": "publish",
                    "stream_key": stream_key,
                    "event_id": str(event.event_id),
                },
            ) from exc

    async def ensure_group(self, event_type: EventType, group: str) -> None:
        """Ensure consumer group exists on the stream via XGROUP CREATE ... MKSTREAM.

        Tolerates BUSYGROUP (idempotent by design).
        start id: "$" (group sees NEW events only — replay/backfill is explicitly out of scope).
        """
        stream_key = self._stream_key(event_type)
        try:
            await self._redis.xgroup_create(stream_key, group, id="$", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def read_batch(
        self,
        event_type: EventType,
        group: str,
        consumer: str,
        *,
        count: int,
        block_ms: int,
    ) -> list[Delivery]:
        """Read a batch of events via XREADGROUP.

        block_ms=0 → no BLOCK → immediate return.
        WHY: Tests and polling workers need non-blocking reads; daemon loops with block
        are Task 38's concern.

        Poison entry policy:
        read_batch SKIPS undecodable entries but logs; skipped entries are ACKed and
        counted, because a poison entry must never wedge the stream.
        """
        stream_key = self._stream_key(event_type)
        block_arg = block_ms if block_ms > 0 else None

        raw_response = await self._redis.xreadgroup(
            groupname=group,
            consumername=consumer,
            streams={stream_key: ">"},
            count=count,
            block=block_arg,
        )

        if not raw_response:
            return []

        deliveries: list[Delivery] = []
        for _stream, entries in raw_response:
            for entry_id, fields in entries:
                entry_id_str = (
                    entry_id.decode("utf-8") if isinstance(entry_id, bytes) else str(entry_id)
                )
                try:
                    envelope = from_bytes(fields)
                    deliveries.append(
                        Delivery(
                            delivery_id=entry_id_str,
                            envelope=envelope,
                            delivery_count=1,
                        )
                    )
                except EventPublishError:
                    # Poison entry design decision:
                    # Undecodable entries are auto-ACKed and skipped so consumer never wedges.
                    logger.warning(
                        "Skipping and auto-acking poison event entry on stream",
                        stream_key=stream_key,
                        entry_id=entry_id_str,
                        event_type=event_type.value,
                    )
                    await self.ack(event_type, group, entry_id_str)

        return deliveries

    async def ack(self, event_type: EventType, group: str, delivery_id: str) -> None:
        """Acknowledge entry processing via XACK."""
        stream_key = self._stream_key(event_type)
        await self._redis.xack(stream_key, group, delivery_id)

    async def claim_stale(
        self,
        event_type: EventType,
        group: str,
        consumer: str,
        *,
        min_idle_ms: int,
        count: int,
    ) -> list[Delivery]:
        """Claim unacknowledged stale entries via XAUTOCLAIM.

        WHY: Without stale claiming, a worker OOM-kill between read and ack silently
        strands payments — this function is the difference between at-least-once and
        at-most-zero.
        """
        stream_key = self._stream_key(event_type)

        res = await self._redis.xautoclaim(
            stream_key,
            group,
            consumer,
            min_idle_time=min_idle_ms,
            start_id="0-0",
            count=count,
        )

        claimed_entries = res[1] if isinstance(res, (list, tuple)) and len(res) > 1 else []
        if not claimed_entries:
            return []

        # Retrieve times_delivered counts from XPENDING for accurate at-least-once tracking
        delivery_counts: dict[str, int] = {}
        try:
            pending_info = await self._redis.xpending_range(
                stream_key,
                group,
                min="-",
                max="+",
                count=count * 2,
            )
            for p in pending_info:
                mid = p["message_id"]
                mid_str = mid.decode("utf-8") if isinstance(mid, bytes) else str(mid)
                delivery_counts[mid_str] = int(p["times_delivered"])
        except Exception as exc:
            logger.debug("Failed to retrieve pending info for delivery count", exc_info=exc)

        deliveries: list[Delivery] = []
        for item in claimed_entries:
            if item is None or len(item) < 2:
                continue
            entry_id, fields = item[0], item[1]
            if entry_id is None:
                continue
            entry_id_str = (
                entry_id.decode("utf-8") if isinstance(entry_id, bytes) else str(entry_id)
            )

            if len(item) >= 3 and isinstance(item[2], int):
                d_count = item[2]
            else:
                d_count = delivery_counts.get(entry_id_str, 2)

            try:
                envelope = from_bytes(fields)
                deliveries.append(
                    Delivery(
                        delivery_id=entry_id_str,
                        envelope=envelope,
                        delivery_count=d_count,
                    )
                )
            except EventPublishError:
                # Auto-ACK poison entries encountered during recovery as well
                logger.warning(
                    "Skipping and auto-acking poison event entry during stale claim",
                    stream_key=stream_key,
                    entry_id=entry_id_str,
                    event_type=event_type.value,
                )
                await self.ack(event_type, group, entry_id_str)

        return deliveries
