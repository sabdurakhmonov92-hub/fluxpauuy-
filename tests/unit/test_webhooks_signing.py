"""Unit tests for webhook signing, verification, and schema contract payload building."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import jsonschema  # type: ignore[import-untyped]
import pytest

from fluxpay.notifications.webhooks import (
    HEADER_EVENT_ID,
    HEADER_SIGNATURE,
    WEBHOOK_SECRET_CONTEXT_PREFIX,
    build_payload,
    sign_webhook,
    verify_webhook,
    webhook_secret_context,
)
from fluxpay.shared.errors import EventPublishError
from fluxpay.shared.events import EventEnvelope, EventType, make_event

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "contracts" / "webhook.schema.json"


@pytest.fixture(scope="session")
def webhook_schema() -> dict[str, Any]:
    """Load the frozen Task 24 merchant webhook JSON schema contract."""
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        schema: dict[str, Any] = json.load(f)
        return schema


# ==============================================================================
# 1. HMAC-SHA256 SIGNING & VERIFICATION (PURE KAT & ROUNDTRIP)
# ==============================================================================


def test_sign_webhook_known_answer_test() -> None:
    """Validate sign_webhook against a deterministic known-answer test vector (KAT)."""
    secret = b"fixed_secret_for_webhook_signing"
    body = b"hello_fluxpay"
    # Pre-computed KAT vector:
    expected_hmac = "0ff7403e140f2c18c96ca02b2cbc0326c5861839f2c48bd6cc93f9d2dd2e2191"

    signature = sign_webhook(secret, body)
    assert signature == expected_hmac
    assert len(signature) == 64
    assert signature.islower()


def test_verify_webhook_roundtrip() -> None:
    """Validate timing-safe verification for authentic and tampered payloads."""
    secret = b"merchant_endpoint_secret_key_9999"
    body = b'{"event":"payment.settled","amount":5000}'
    signature = sign_webhook(secret, body)

    # 1. Authentic signature passes
    assert verify_webhook(secret, body, signature) is True
    # Uppercase hex also matches (case-insensitive verify)
    assert verify_webhook(secret, body, signature.upper()) is True

    # 2. Tampered body fails
    tampered_body = b'{"event":"payment.settled","amount":9999}'
    assert verify_webhook(secret, tampered_body, signature) is False

    # 3. Wrong secret fails
    wrong_secret = b"wrong_secret_key_00000000000000"
    assert verify_webhook(wrong_secret, body, signature) is False

    # 4. Truncated or invalid signature strings fail safely
    assert verify_webhook(secret, body, signature[:-1]) is False
    assert verify_webhook(secret, body, "invalid-hex-string") is False
    assert verify_webhook(secret, body, "") is False


def test_sign_webhook_type_errors() -> None:
    """Ensure sign_webhook rejects non-bytes inputs with clear TypeErrors."""
    with pytest.raises(TypeError, match="secret must be bytes or bytearray"):
        sign_webhook("str_secret", b"body")  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="body must be bytes or bytearray"):
        sign_webhook(b"secret", "str_body")  # type: ignore[arg-type]


def test_webhook_secret_context() -> None:
    """Ensure endpoint context adheres to the Task 7/23 AAD context convention."""
    endpoint_id = uuid4()
    ctx = webhook_secret_context(endpoint_id)
    assert ctx == f"{WEBHOOK_SECRET_CONTEXT_PREFIX}{endpoint_id}"
    assert ctx == f"webhook_secret:{endpoint_id}"


def test_header_constants() -> None:
    """Ensure header constants adhere to the frozen specification."""
    assert HEADER_SIGNATURE == "X-FLX-Signature"
    assert HEADER_EVENT_ID == "X-FLX-Event-Id"


# ==============================================================================
# 2. PAYLOAD BUILDER & JSONSCHEMA CONTRACT VALIDATION
# ==============================================================================


def test_build_payload_settled_schema_valid(webhook_schema: dict[str, Any]) -> None:
    """Validate that payment.settled EventEnvelope transforms into schema-valid webhook JSON."""
    tx_id = uuid4()
    agent_id = uuid4()
    occurred_at = datetime(2026, 9, 26, 12, 0, 0, 123456, tzinfo=UTC)

    envelope = EventEnvelope(
        event_id=uuid4(),
        type=EventType.PAYMENT_SETTLED,
        occurred_at=occurred_at,
        producer="fluxpay.payments",
        schema_version=1,
        payload={
            "tx_id": str(tx_id),
            "payment_id": str(tx_id),
            "agent_id": str(agent_id),
            "merchant": "mch_acme_corp",
            "amount": 25000,
            "fee": 250,
            "total": 25250,
            "currency": "USDC",
        },
    )

    payload = build_payload(envelope)

    # 1. Structural assertions
    assert payload["event"] == "payment.settled"
    assert payload["event_id"] == str(envelope.event_id)
    assert payload["created_at"] == "2026-09-26T12:00:00.123456Z"
    assert payload["data"] == {
        "tx_id": str(tx_id),
        "amount": 25000,
        "currency": "USDC",
    }

    # 2. Strict validation against Task 24 contracts/webhook.schema.json
    jsonschema.validate(instance=payload, schema=webhook_schema)


def test_build_payload_held_and_failed_schema_valid(webhook_schema: dict[str, Any]) -> None:
    """Validate payment.held and payment.failed payloads against the JSON schema."""
    for event_type in (EventType.PAYMENT_HELD, EventType.PAYMENT_FAILED):
        tx_id = uuid4()
        envelope = make_event(
            type=event_type,
            payload={
                "tx_id": str(tx_id),
                "merchant": "mch_test",
                "amount": 1000,
                "currency": "EUR",
                "reason": "velocity_limit_exceeded",
            },
            producer="fluxpay.payments",
        )
        payload = build_payload(envelope)
        assert payload["event"] == event_type.value
        assert payload["data"]["tx_id"] == str(tx_id)
        assert payload["data"]["amount"] == 1000
        assert payload["data"]["currency"] == "EUR"

        # Validate against schema
        jsonschema.validate(instance=payload, schema=webhook_schema)


def test_build_payload_rejects_unsupported_event_type() -> None:
    """Ensure domain events not intended for merchant webhooks are rejected loudly."""
    # Construct an envelope with an unregistered or unexpected event type string
    envelope = EventEnvelope(
        event_id=uuid4(),
        type=EventType.PAYMENT_SETTLED,  # will manually mutate in test or use custom
        occurred_at=datetime.now(UTC),
        producer="test",
        schema_version=1,
        payload={"tx_id": str(uuid4()), "amount": 100, "currency": "USD"},
    )
    # Re-wrap with mock or unsupported type
    object.__setattr__(envelope, "type", "ledger.account_created")

    with pytest.raises(EventPublishError) as exc_info:
        build_payload(envelope)

    assert exc_info.value.details.get("phase") == "payload"
    assert exc_info.value.details.get("reason") == "unsupported_event_type"


def test_build_payload_missing_or_invalid_fields() -> None:
    """Ensure missing tx_id, amount, or currency raises EventPublishError."""
    # 1. Missing tx_id
    env1 = make_event(
        type=EventType.PAYMENT_SETTLED,
        payload={"amount": 1000, "currency": "USD"},
        producer="test",
    )
    with pytest.raises(EventPublishError) as exc1:
        build_payload(env1)
    assert exc1.value.details.get("reason") == "missing_tx_id"

    # 2. Invalid tx_id format (not a UUID)
    env2 = make_event(
        type=EventType.PAYMENT_SETTLED,
        payload={"tx_id": "not-a-valid-uuid", "amount": 1000, "currency": "USD"},
        producer="test",
    )
    with pytest.raises(EventPublishError) as exc2:
        build_payload(env2)
    assert exc2.value.details.get("reason") == "invalid_tx_id"

    # 3. Invalid amount (negative or zero)
    env3 = make_event(
        type=EventType.PAYMENT_SETTLED,
        payload={"tx_id": str(uuid4()), "amount": 0, "currency": "USD"},
        producer="test",
    )
    with pytest.raises(EventPublishError) as exc3:
        build_payload(env3)
    assert exc3.value.details.get("reason") == "amount_below_minimum"

    # 4. Invalid currency format
    env4 = make_event(
        type=EventType.PAYMENT_SETTLED,
        payload={"tx_id": str(uuid4()), "amount": 1000, "currency": "u"},
        producer="test",
    )
    with pytest.raises(EventPublishError) as exc4:
        build_payload(env4)
    assert exc4.value.details.get("reason") == "invalid_currency"
