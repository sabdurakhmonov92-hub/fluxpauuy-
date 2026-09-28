"""Unit tests for RabbitMQ event bus topology, wire format wrapper, and protocol conformance.

These tests execute purely in-memory with zero broker dependencies or I/O.
"""

import inspect
from typing import cast

import orjson
import pytest

from fluxpay.shared.errors import EventPublishError
from fluxpay.shared.events import (
    EventBus,
    EventType,
    JsonValue,
    make_event,
)
from fluxpay.shared.rabbitmq_bus import (
    RabbitMQBus,
    build_topology,
    envelope_to_wire,
    wire_to_envelope,
)


@pytest.mark.unit
def test_build_topology_declarations_and_quorum_spec() -> None:
    """Validate declarative topology specification for all three frozen event types.

    Asserts:
    - Dead-letter exchange is direct, durable, named f"{prefix}:dlx".
    - Exactly 3 main queues matching EventType members with x-queue-type=quorum,
      x-delivery-limit=5, and x-dead-letter-exchange pointing to the DLX.
    - Exactly 3 DLQ queues with x-queue-type=quorum and bound to DLX with routing key.
    - Durable flags are True on all exchanges and queues.
    - ABSENCE of 'x-queue-mode' (lazy mode) is asserted across all queues and DLQs
      (the blueprint-deviation guard: quorum queues supersede classic lazy queues
      and reject 'x-queue-mode' with PRECONDITION_FAILED).
    """
    prefix = "flx:events"
    topology = build_topology(prefix, delivery_limit=5)

    # 1. Dead-letter exchange
    assert topology.dlx_name == f"{prefix}:dlx"
    assert topology.dlx_type == "direct"
    assert topology.dlx_durable is True
    assert topology.exchange_dlq == f"{prefix}:dlx"

    # 2. Main queues for all three event types
    assert set(topology.queues.keys()) == set(EventType)
    for event_type in EventType:
        q_spec = topology.queue(event_type)
        expected_name = f"{prefix}:{event_type.value}"
        assert q_spec.name == expected_name
        assert q_spec.durable is True

        args = q_spec.arguments
        assert args["x-queue-type"] == "quorum"
        assert args["x-delivery-limit"] == 5
        assert args["x-dead-letter-exchange"] == f"{prefix}:dlx"

        # REGRESSION GUARD: Assert absence of x-queue-mode=lazy
        assert "x-queue-mode" not in args, (
            f"Queue '{q_spec.name}' must NOT define 'x-queue-mode'; "
            "quorum queues self-manage disk/memory and reject lazy mode."
        )

    # 3. DLQs for all three event types
    assert set(topology.dlqs.keys()) == set(EventType)
    for event_type in EventType:
        dlq_spec = topology.queue_dlq(event_type)
        expected_dlq_name = f"{prefix}:dlq:{event_type.value}"
        assert dlq_spec.queue_name == expected_dlq_name
        assert dlq_spec.exchange_name == f"{prefix}:dlx"
        assert dlq_spec.routing_key == event_type.value
        assert dlq_spec.durable is True

        dlq_args = dlq_spec.arguments
        assert dlq_args["x-queue-type"] == "quorum"

        # REGRESSION GUARD: Assert absence of x-queue-mode=lazy on DLQ
        assert "x-queue-mode" not in dlq_args, (
            f"DLQ '{dlq_spec.queue_name}' must NOT define 'x-queue-mode'; "
            "quorum queues supersede classic lazy queues."
        )


@pytest.mark.unit
def test_wire_wrapper_roundtrip_and_e_envelope() -> None:
    """Validate to_bytes/from_bytes roundtrip through the adapter's {"e": ...} wrapper.

    Verifies:
    - Serialization produces a JSON object containing the single wire field 'e'.
    - Deserialization accurately reconstructs the EventEnvelope, preserving
      identities, types, timestamps (ms precision), producer, and payload.
    - Proves reuse of shared.events serializers (to_bytes/from_bytes) without duplication.
    """
    payload: dict[str, JsonValue] = {
        "payment_id": "pay_xyz",
        "amount_cents": 10000,
        "currency": "USD",
        "livemode": False,
        "memo": None,
    }
    original_envelope = make_event(
        type=EventType.PAYMENT_SETTLED,
        payload=payload,
        producer="billing_service",
        schema_version=1,
    )

    # Serialize through the adapter's wire wrapper
    wire_bytes = envelope_to_wire(original_envelope)
    assert isinstance(wire_bytes, bytes)

    # Inspect the raw JSON structure on the wire
    raw_data = orjson.loads(wire_bytes)
    assert isinstance(raw_data, dict)
    assert set(raw_data.keys()) == {"e"}, "Wire format must wrap envelope in single field 'e'"
    assert raw_data["e"]["id"] == str(original_envelope.event_id)
    assert raw_data["e"]["type"] == "payment.settled"
    assert raw_data["e"]["producer"] == "billing_service"
    assert raw_data["e"]["v"] == "1"

    # Deserialize back into EventEnvelope
    recovered_envelope = wire_to_envelope(wire_bytes)

    assert recovered_envelope.event_id == original_envelope.event_id
    assert recovered_envelope.type == original_envelope.type
    assert recovered_envelope.producer == original_envelope.producer
    assert recovered_envelope.schema_version == original_envelope.schema_version
    assert recovered_envelope.payload == original_envelope.payload

    # Sub-ms timestamp precision preserved
    assert (
        abs((recovered_envelope.occurred_at - original_envelope.occurred_at).total_seconds())
        < 0.001
    )


@pytest.mark.unit
def test_wire_wrapper_robustness_on_malformed_input() -> None:
    """Validate that wire_to_envelope raises EventPublishError(phase='deserialize')
    on invalid input.
    """
    # 1. Non-JSON garbage bytes
    with pytest.raises(EventPublishError) as exc_info:
        wire_to_envelope(b"not-valid-json-bytes")
    assert exc_info.value.details.get("phase") == "deserialize"

    # 2. Valid JSON, but missing "e" wrapper field
    missing_e_bytes = orjson.dumps({"wrong_key": "val"})
    with pytest.raises(EventPublishError) as exc_info:
        wire_to_envelope(missing_e_bytes)
    assert exc_info.value.details.get("phase") == "deserialize"

    # 3. Valid JSON with "e", but "e" is not a dictionary
    invalid_e_type_bytes = orjson.dumps({"e": "not-a-dict"})
    with pytest.raises(EventPublishError) as exc_info:
        wire_to_envelope(invalid_e_type_bytes)
    assert exc_info.value.details.get("phase") == "deserialize"

    # 4. Valid JSON with "e", but inner fields are missing required envelope keys
    incomplete_envelope_bytes = orjson.dumps({"e": {"id": "123"}})
    with pytest.raises(EventPublishError) as exc_info:
        wire_to_envelope(incomplete_envelope_bytes)
    assert exc_info.value.details.get("phase") == "deserialize"


@pytest.mark.unit
def test_protocol_conformance_smoke() -> None:
    """Validate that RabbitMQBus structurally conforms to the EventBus Protocol."""

    # 1. Static typing check (will fail mypy if RabbitMQBus does not satisfy EventBus)
    def _type_check() -> None:
        bus: EventBus = cast(RabbitMQBus, None)
        _ = bus

    # 2. Structural runtime inspection
    required_methods = {
        "publish": ["event"],
        "ensure_group": ["event_type", "group"],
        "read_batch": ["event_type", "group", "consumer", "count", "block_ms"],
        "ack": ["event_type", "group", "delivery_id"],
        "claim_stale": ["event_type", "group", "consumer", "min_idle_ms", "count"],
    }

    for method_name, expected_params in required_methods.items():
        assert hasattr(RabbitMQBus, method_name), (
            f"RabbitMQBus is missing required EventBus method '{method_name}'"
        )
        method = getattr(RabbitMQBus, method_name)
        assert callable(method), f"'{method_name}' must be callable"

        sig = inspect.signature(method)
        param_names = list(sig.parameters.keys())
        # First param is 'self'
        assert param_names[0] == "self"
        for param in expected_params:
            assert param in param_names, (
                f"Method '{method_name}' missing expected parameter '{param}'"
            )
        # All methods must be coroutines
        assert inspect.iscoroutinefunction(method), (
            f"Method '{method_name}' must be an async coroutine function"
        )

    # 3. Adapter-only methods check
    adapter_methods = ["reject", "dlq_get", "close"]
    for method_name in adapter_methods:
        assert hasattr(RabbitMQBus, method_name), (
            f"RabbitMQBus must provide adapter-specific method '{method_name}'"
        )
        assert inspect.iscoroutinefunction(getattr(RabbitMQBus, method_name))
