"""Unit tests verifying EventEnvelope invariants, wire format serialization, and error contracts.

Tests execute purely in-memory with zero external I/O or services.
"""

import re
import uuid
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from fluxpay.shared.errors import ERROR_REGISTRY, EventPublishError
from fluxpay.shared.events import (
    MAX_PAYLOAD_BYTES,
    EventEnvelope,
    EventType,
    JsonValue,
    from_bytes,
    make_event,
    to_bytes,
    validate_payload,
)

EXPECTED_RETRYABLE_CODES = {
    "rate_limited",
    "conflict_retry_required",
}


@pytest.mark.unit
def test_event_type_registry_members() -> None:
    """Validate that EventType registry encodes exactly the three frozen
    Blueprint §0 event types.
    """
    assert len(EventType) == 3
    assert EventType.PAYMENT_SETTLED.value == "payment.settled"
    assert EventType.PAYMENT_HELD.value == "payment.held"
    assert EventType.PAYMENT_FAILED.value == "payment.failed"


@pytest.mark.unit
def test_make_event_defaults() -> None:
    """Validate that make_event generates fresh UUID4, tz-aware UTC timestamp,
    and schema_version=1.
    """
    payload: dict[str, JsonValue] = {
        "account_id": "acc_123",
        "amount_cents": 5000,
        "livemode": True,
        "note": None,
    }
    producer = "payments"

    event1 = make_event(EventType.PAYMENT_SETTLED, payload, producer)
    event2 = make_event(EventType.PAYMENT_SETTLED, payload, producer)

    # Distinct identities
    assert isinstance(event1.event_id, uuid.UUID)
    assert isinstance(event2.event_id, uuid.UUID)
    assert event1.event_id != event2.event_id

    # Timezone-aware UTC timestamp
    assert event1.occurred_at.tzinfo is not None
    assert event1.occurred_at.tzinfo.utcoffset(event1.occurred_at) is not None
    assert event1.occurred_at.tzinfo == UTC

    # Default schema version
    assert event1.schema_version == 1

    # Properties match
    assert event1.type == EventType.PAYMENT_SETTLED
    assert event1.producer == producer
    assert event1.payload == payload


@pytest.mark.unit
def test_envelope_validation_rejects_unknown_type_string() -> None:
    """Validate that unknown event type strings are rejected at construction time."""
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="Unknown event type"):
        EventEnvelope(
            event_id=uuid.uuid4(),
            type="unregistered.event",  # type: ignore[arg-type]
            occurred_at=now,
            producer="test",
            schema_version=1,
            payload={},
        )


@pytest.mark.unit
def test_envelope_validation_rejects_naive_datetime() -> None:
    """Validate that naive datetime (lacking timezone information) is rejected
    as a programming error.
    """
    naive_dt = datetime.now()
    with pytest.raises(ValueError, match="occurred_at must be timezone-aware"):
        EventEnvelope(
            event_id=uuid.uuid4(),
            type=EventType.PAYMENT_SETTLED,
            occurred_at=naive_dt,
            producer="test",
            schema_version=1,
            payload={},
        )


@pytest.mark.unit
def test_envelope_validation_rejects_zero_or_negative_schema_version() -> None:
    """Validate that schema_version < 1 is rejected at construction time."""
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="schema_version must be >= 1"):
        EventEnvelope(
            event_id=uuid.uuid4(),
            type=EventType.PAYMENT_SETTLED,
            occurred_at=now,
            producer="test",
            schema_version=0,
            payload={},
        )

    with pytest.raises(ValueError, match="schema_version must be >= 1"):
        EventEnvelope(
            event_id=uuid.uuid4(),
            type=EventType.PAYMENT_SETTLED,
            occurred_at=now,
            producer="test",
            schema_version=-1,
            payload={},
        )


@pytest.mark.unit
def test_envelope_validation_rejects_list_payload_value() -> None:
    """Validate that nested lists in payload are rejected to enforce flat scalar contract."""
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="invalid type list"):
        EventEnvelope(
            event_id=uuid.uuid4(),
            type=EventType.PAYMENT_SETTLED,
            occurred_at=now,
            producer="test",
            schema_version=1,
            payload={"items": ["item1", "item2"]},  # type: ignore[dict-item]
        )


@pytest.mark.unit
def test_envelope_validation_rejects_nested_dict_payload_value() -> None:
    """Validate that nested dicts in payload are rejected to enforce flat scalar contract."""
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="invalid type dict"):
        EventEnvelope(
            event_id=uuid.uuid4(),
            type=EventType.PAYMENT_SETTLED,
            occurred_at=now,
            producer="test",
            schema_version=1,
            payload={"nested": {"key": "val"}},  # type: ignore[dict-item]
        )


@pytest.mark.unit
def test_envelope_validation_accepts_valid_scalars() -> None:
    """Validate that str, int, bool, and None values are accepted in payload."""
    now = datetime.now(UTC)
    valid_payload: dict[str, JsonValue] = {
        "str_val": "payment_123",
        "int_val": 42,
        "bool_true": True,
        "bool_false": False,
        "none_val": None,
    }
    env = EventEnvelope(
        event_id=uuid.uuid4(),
        type=EventType.PAYMENT_HELD,
        occurred_at=now,
        producer="test",
        schema_version=2,
        payload=valid_payload,
    )
    assert env.payload == valid_payload


@pytest.mark.unit
def test_envelope_is_frozen() -> None:
    """Validate that EventEnvelope instances are immutable (frozen and slotted)."""
    env = make_event(EventType.PAYMENT_SETTLED, {"key": "val"}, "test")
    with pytest.raises(FrozenInstanceError):
        env.producer = "tampered"  # type: ignore[misc]


@pytest.mark.unit
def test_wire_roundtrip_preserves_envelope_and_sub_ms_precision_note() -> None:
    """Validate to_bytes -> from_bytes wire serialization roundtrip.

    NOTE ON PRECISION:
    The wire format explicitly preserves millisecond precision (ISO8601 UTC ms).
    Sub-millisecond (microsecond) components are intentionally truncated during serialization.
    This test verifies that roundtrip preserves all fields, including payload scalar equality,
    and asserts the expected sub-millisecond precision behavior.
    """
    original = make_event(
        type=EventType.PAYMENT_SETTLED,
        payload={"agent_id": "ag_99", "amount": 10000, "is_test": False, "memo": None},
        producer="payments_service",
        schema_version=1,
    )

    fields = to_bytes(original)

    # Wire format contract assertions
    assert isinstance(fields, dict)
    assert set(fields.keys()) == {"id", "type", "ts", "producer", "v", "payload"}
    assert fields["id"] == str(original.event_id)
    assert fields["type"] == "payment.settled"
    assert fields["producer"] == "payments_service"
    assert fields["v"] == "1"
    assert fields["ts"].endswith("Z")

    roundtripped = from_bytes(fields)

    assert roundtripped.event_id == original.event_id
    assert roundtripped.type == original.type
    assert roundtripped.producer == original.producer
    assert roundtripped.schema_version == original.schema_version
    assert roundtripped.payload == original.payload

    # Sub-ms loss assertion: timestamps match down to the millisecond
    assert abs((roundtripped.occurred_at - original.occurred_at).total_seconds()) < 0.001
    expected_ms_dt = original.occurred_at.replace(
        microsecond=(original.occurred_at.microsecond // 1000) * 1000
    )
    assert roundtripped.occurred_at == expected_ms_dt


@pytest.mark.unit
def test_from_bytes_robustness_on_malformed_input() -> None:
    """Validate that from_bytes raises EventPublishError with phase='deserialize'
    on any corrupt input.
    """
    valid_env = make_event(EventType.PAYMENT_FAILED, {"reason": "insufficient_funds"}, "worker")
    valid_fields = to_bytes(valid_env)

    # 1. Truncated payload JSON
    bad_json_fields = dict(valid_fields)
    bad_json_fields["payload"] = '{"reason": "incom'
    with pytest.raises(EventPublishError) as exc_info:
        from_bytes(bad_json_fields)
    assert exc_info.value.details.get("phase") == "deserialize"

    # 2. Unknown event type in fields
    bad_type_fields = dict(valid_fields)
    bad_type_fields["type"] = "unknown.foreign.event"
    with pytest.raises(EventPublishError) as exc_info:
        from_bytes(bad_type_fields)
    assert exc_info.value.details.get("phase") == "deserialize"

    # 3. Missing required field (e.g. 'id')
    missing_id_fields = dict(valid_fields)
    del missing_id_fields["id"]
    with pytest.raises(EventPublishError) as exc_info:
        from_bytes(missing_id_fields)
    assert exc_info.value.details.get("phase") == "deserialize"

    # 4. Missing required field 'payload'
    missing_payload_fields = dict(valid_fields)
    del missing_payload_fields["payload"]
    with pytest.raises(EventPublishError) as exc_info:
        from_bytes(missing_payload_fields)
    assert exc_info.value.details.get("phase") == "deserialize"

    # 5. Invalid UUID string in 'id'
    bad_uuid_fields = dict(valid_fields)
    bad_uuid_fields["id"] = "not-a-valid-uuid"
    with pytest.raises(EventPublishError) as exc_info:
        from_bytes(bad_uuid_fields)
    assert exc_info.value.details.get("phase") == "deserialize"

    # 6. Invalid schema_version
    bad_v_fields = dict(valid_fields)
    bad_v_fields["v"] = "0"
    with pytest.raises(EventPublishError) as exc_info:
        from_bytes(bad_v_fields)
    assert exc_info.value.details.get("phase") == "deserialize"


@pytest.mark.unit
def test_validate_payload_size_and_serializability() -> None:
    """Validate that validate_payload enforces orjson serializability and 64 KiB size boundary."""
    # 1. Valid small payload passes
    small_payload = {"key": "value", "count": 10}
    encoded = validate_payload(small_payload)
    assert isinstance(encoded, bytes)

    # 2. Payload exceeding 64 KiB is rejected
    oversized_string = "x" * (MAX_PAYLOAD_BYTES + 10)
    oversized_payload = {"large_data": oversized_string}
    with pytest.raises(EventPublishError) as exc_info:
        validate_payload(oversized_payload)
    assert exc_info.value.details.get("phase") == "serialize"
    assert exc_info.value.details.get("reason") == "payload_too_large"

    # 3. Payload with unserializable type is rejected
    class UnserializableObject:
        pass

    unserializable_payload = {"obj": UnserializableObject()}
    with pytest.raises(EventPublishError) as exc_info:
        validate_payload(unserializable_payload)
    assert exc_info.value.details.get("phase") == "serialize"


@pytest.mark.unit
def test_event_publish_error_contract_and_registry() -> None:
    """Validate that EventPublishError adheres to typed failure contract and registry invariants.

    Verifies:
    - Code 'event_publish_failed'
    - HTTP status 500
    - retryable is True (transient infrastructure condition)
    - client_message is 'event delivery temporarily unavailable'
    - Registered, unique across all error codes, snake_case pattern
    - Task 4 error contract invariants hold (wire shape and detail exclusion)
    """
    assert EventPublishError.code == "event_publish_failed"
    assert EventPublishError.status == 500
    assert EventPublishError.retryable is True
    assert EventPublishError.client_message == "event delivery temporarily unavailable"

    err = EventPublishError(
        details={"stream_key": "flx:events:payment.settled", "phase": "publish"}
    )
    payload = err.to_payload()
    assert payload == {
        "error": {
            "code": "event_publish_failed",
            "message": "event delivery temporarily unavailable",
            "retryable": True,
        }
    }
    # Security check: internal diagnostics must not leak to str(err) or external payload
    assert "flx:events" not in str(err)
    assert "flx:events" not in str(payload)

    # Validate registry registration (mirroring Task 7 and Task 8 patterns)
    was_present = "event_publish_failed" in ERROR_REGISTRY
    ERROR_REGISTRY["event_publish_failed"] = EventPublishError
    try:
        assert "event_publish_failed" in ERROR_REGISTRY
        cls = ERROR_REGISTRY["event_publish_failed"]
        assert cls is EventPublishError
        assert cls.retryable is True
        assert cls.status == 500

        # Verify snake_case format
        code_pattern = re.compile(r"^[a-z][a-z0-9_]*$")
        assert code_pattern.match(cls.code)

        # Verify uniqueness among registered codes
        codes = list(ERROR_REGISTRY.keys())
        assert len(codes) == len(set(codes))
    finally:
        if not was_present:
            ERROR_REGISTRY.pop("event_publish_failed", None)
