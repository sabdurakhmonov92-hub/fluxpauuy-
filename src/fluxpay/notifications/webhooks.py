"""Webhook payload building, canonical HMAC-SHA256 signing, and verification.

==============================================================================
WEBHOOK SIGNING VS. REQUEST AUTHENTICATION ASYMMETRY (WHY RAW BODY ONLY)
==============================================================================
In Task 21 (API gateway request authentication), clients invoke arbitrary endpoints
with diverse HTTP verbs, query parameters, path variables, and custom headers.
There, strict canonicalization (normalizing method, path, query, sorted headers,
and timestamp expiration window) is mandatory to prevent parameter injection,
URI path confusion, and replay attacks on the edge ingress.

Outgoing webhooks present a fundamentally different threat model:
1. One-Way Notification: FluxPay is the authoritative dispatcher, not an untrusted
   client. FluxPay strictly fixes the HTTP method (always POST), content type
   (application/json), and header contract.
2. Merchant-Side Simplicity & Portability: Merchants integrate webhooks in Python,
   Node.js, Go, PHP, Java, Ruby, and bash. Complex canonicalization algorithms
   (normalizing header casing, whitespace stripping, URI-encoding quirks) cause
   frequent merchant integration failures and support tickets.
3. Immutability & Replay Defense:
   - Authenticity & Integrity: Computed via HMAC-SHA256 directly over the exact raw body bytes.
     Merchant verification is a single line:
       `hmac.compare_digest(hmac.new(secret, request.body, hashlib.sha256).hexdigest(), signature)`
   - Replay Protection: Anchored in `event_id` carried in the `X-FLX-Event-Id` header and inside
     the signed JSON body. Per Task 9 law, consumers deduplicate by `event_id`.
   - Event Timestamp: Carried in signed JSON payload (`created_at` in ISO-8601 UTC),
     eliminating the risk of timestamp header drift or clock skew rejections.
Simpler is not only easier for merchants; it is strictly more correct and robust on the wire.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from typing import Any, Final
from uuid import UUID

from fluxpay.ledger.hashchain import format_timestamp
from fluxpay.shared.errors import EventPublishError
from fluxpay.shared.events import EventEnvelope, EventType

__all__ = [
    "CURRENCY_REGEX",
    "HEADER_EVENT_ID",
    "HEADER_SIGNATURE",
    "SUPPORTED_WEBHOOK_EVENTS",
    "WEBHOOK_SECRET_CONTEXT_PREFIX",
    "build_payload",
    "sign_webhook",
    "verify_webhook",
    "webhook_secret_context",
]

HEADER_SIGNATURE: Final[str] = "X-FLX-Signature"
HEADER_EVENT_ID: Final[str] = "X-FLX-Event-Id"

WEBHOOK_SECRET_CONTEXT_PREFIX: Final[str] = "webhook_secret:"  # noqa: S105

CURRENCY_REGEX: Final[re.Pattern[str]] = re.compile(r"^[A-Z0-9]{2,10}$")

SUPPORTED_WEBHOOK_EVENTS: Final[frozenset[str]] = frozenset(
    {
        EventType.PAYMENT_SETTLED.value,
        EventType.PAYMENT_HELD.value,
        EventType.PAYMENT_FAILED.value,
    }
)


def webhook_secret_context(endpoint_id: UUID | str) -> str:
    """Compose the byte-exact AAD context string bound during vault encryption (Task 7/23).

    Mirroring the agent secret pattern, binding the endpoint_id into the AAD guarantees
    that an encrypted secret ciphertext cannot be transplanted from one endpoint row to another.
    """
    return f"{WEBHOOK_SECRET_CONTEXT_PREFIX}{endpoint_id}"


def sign_webhook(secret: bytes, body: bytes) -> str:
    """Compute HMAC-SHA256 lowercase hex digest over raw body bytes.

    Args:
        secret: Plaintext shared secret key bytes for the merchant endpoint.
        body: Exact raw JSON bytes to be transmitted on the HTTP wire.

    Returns:
        64-character lowercase hex string representation of the HMAC-SHA256 signature.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError(f"secret must be bytes or bytearray, got {type(secret).__name__}")
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError(f"body must be bytes or bytearray, got {type(body).__name__}")

    return hmac.new(bytes(secret), bytes(body), hashlib.sha256).hexdigest()


def verify_webhook(secret: bytes, body: bytes, signature: str) -> bool:
    """Verify an incoming webhook signature using constant-time comparison.

    Provides the canonical merchant verification reference implementation.

    Args:
        secret: Shared secret key bytes for the endpoint.
        body: Exact raw request body bytes received on the wire.
        signature: Hex signature received in the X-FLX-Signature header.

    Returns:
        True if the signature is valid and authentic, False otherwise.
    """
    expected = sign_webhook(secret, body)
    return hmac.compare_digest(expected.lower(), signature.strip().lower())


def build_payload(event: EventEnvelope) -> dict[str, Any]:
    """Transform an internal EventEnvelope into the frozen merchant webhook JSON contract.

    Enforces the Task 24 contract (contracts/webhook.schema.json).
    Rejects malformed envelopes or unknown event types with EventPublishError(phase="payload").

    Args:
        event: Domain EventEnvelope emitted onto the bus (Task 9).

    Returns:
        Dictionary conforming strictly to https://fluxpay.io/schemas/webhook-v1.json.

    Raises:
        EventPublishError: If the event type is unsupported or required scalars are invalid.
    """
    if not isinstance(event, EventEnvelope):
        raise EventPublishError(
            message=f"Expected EventEnvelope instance, got {type(event).__name__}",
            details={"phase": "payload", "reason": "invalid_envelope_instance"},
        )

    # 1. Validate event type against the frozen merchant contract
    raw_type = event.type.value if hasattr(event.type, "value") else str(event.type)
    if raw_type not in SUPPORTED_WEBHOOK_EVENTS:
        raise EventPublishError(
            message=f"Unsupported event type for merchant webhook delivery: '{raw_type}'",
            details={"phase": "payload", "reason": "unsupported_event_type", "type": raw_type},
        )

    payload_dict: Mapping[str, Any] = event.payload if isinstance(event.payload, Mapping) else {}

    # 2. Extract and validate tx_id
    raw_tx_id = payload_dict.get("tx_id")
    if not raw_tx_id:
        raise EventPublishError(
            message="Webhook event payload missing required 'tx_id'",
            details={"phase": "payload", "reason": "missing_tx_id"},
        )
    try:
        tx_uuid = UUID(str(raw_tx_id))
    except (ValueError, TypeError) as exc:
        raise EventPublishError(
            message=f"Webhook event payload 'tx_id' must be a valid UUID, got {raw_tx_id!r}",
            details={"phase": "payload", "reason": "invalid_tx_id"},
        ) from exc

    # 3. Extract and validate amount
    raw_amount = payload_dict.get("amount")
    if raw_amount is None or isinstance(raw_amount, bool) or not isinstance(raw_amount, int):
        err_msg = (
            f"Webhook event payload 'amount' must be an integer, got {type(raw_amount).__name__}"
        )
        raise EventPublishError(
            message=err_msg,
            details={"phase": "payload", "reason": "invalid_amount_type"},
        )
    if raw_amount < 1:
        raise EventPublishError(
            message=f"Webhook event payload 'amount' must be >= 1 minor unit, got {raw_amount}",
            details={"phase": "payload", "reason": "amount_below_minimum"},
        )

    # 4. Extract and validate currency
    raw_currency = payload_dict.get("currency")
    if not isinstance(raw_currency, str) or not CURRENCY_REGEX.match(raw_currency):
        err_curr = (
            f"Webhook event payload 'currency' must match ^[A-Z0-9]{{2,10}}$, got {raw_currency!r}"
        )
        raise EventPublishError(
            message=err_curr,
            details={"phase": "payload", "reason": "invalid_currency"},
        )

    # 5. Format canonical UTC ISO-8601 timestamp
    created_at_str = format_timestamp(event.occurred_at)

    return {
        "event": raw_type,
        "event_id": str(event.event_id),
        "created_at": created_at_str,
        "data": {
            "tx_id": str(tx_uuid),
            "amount": raw_amount,
            "currency": raw_currency,
        },
    }
