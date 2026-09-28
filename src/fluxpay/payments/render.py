"""Payment wire serialization and canonical rendering.

Boundary Contract:
This module is the single-source-of-truth wire renderer for payment responses and error
envelopes. Both internal payment orchestrators (Task 31) and external HTTP route handlers
(Task 33) consume this module.

Strict Isolation:
This module imports ONLY from:
- fluxpay.contracts (frozen wire schemas)
- fluxpay.shared.errors (domain error taxonomy)
- orjson (deterministic fast binary serialization)
Zero imports from fluxpay.ledger, fluxpay.payments.service, or web frameworks (FastAPI/Starlette).
"""

from __future__ import annotations

import json
from typing import Any, Literal, Protocol
from uuid import UUID

import orjson

from fluxpay.contracts.schemas import ErrorEnvelope, PaymentResponse
from fluxpay.shared.errors import FluxPayError

__all__ = [
    "PayOutcomeProtocol",
    "render_error",
    "render_payment",
]


class PayOutcomeProtocol(Protocol):
    """Protocol matching domain PayOutcome without importing service internals.

    Preserves strict boundary isolation: render.py depends only on contracts,
    errors, and serialization primitives.
    """

    status: Literal["settled", "held"]
    tx_id: UUID


def render_payment(
    outcome: PayOutcomeProtocol | PaymentResponse | Any = None,
    *,
    tx_id: UUID | None = None,
    id: UUID | None = None,
    status: Literal["settled", "held"] | None = None,
) -> bytes:
    """Render payment outcome to canonical wire bytes with internal self-checking validation.

    WHY self-checking renderer:
    A malformed outcome (e.g. invalid status, missing ID, schema corruption) must FAIL HERE
    at the renderer boundary inside our service domain, NEVER downstream at the external client
    agent. The internal model_validate roundtrip guarantees that any bytes emitted over the wire
    strictly conform to the Task 24 frozen schema.

    WHY canonical compactness freeze:
    Pydantic v2 model_dump_json() emits compact JSON without whitespace (e.g.
    b'"status":"settled"'). Task 22's fast-path and Task 11's database cache store and replay
    these exact bytes. Any whitespace drift would break byte-exact reproducibility across cache.
    """
    target_id: UUID | None = None
    target_status: Literal["settled", "held"] | None = None

    if outcome is not None:
        target_id = getattr(outcome, "tx_id", None) or getattr(outcome, "id", None)
        target_status = getattr(outcome, "status", None)

    if target_id is None:
        target_id = tx_id or id

    if target_status is None:
        target_status = status

    if target_id is None or target_status is None:
        raise ValueError(
            f"Cannot render payment: target_id ({target_id}) and target_status ({target_status}) "
            "must both be provided."
        )

    # 1. Construct frozen Task 24 wire model (validates UUID and Literal status)
    resp = PaymentResponse(id=target_id, status=target_status)

    # 2. Compact canonical serialization
    wire_bytes = resp.model_dump_json().encode("utf-8")

    # 3. Self-checking validation roundtrip inside:
    # A malformed outcome fails HERE, at render, never at the client.
    roundtrip = PaymentResponse.model_validate(json.loads(wire_bytes))
    if roundtrip.id != target_id or roundtrip.status != target_status:
        raise ValueError(
            f"Render validation roundtrip failed: expected ({target_id}, {target_status}), "
            f"got ({roundtrip.id}, {roundtrip.status})"
        )

    return wire_bytes


def render_error(exc: FluxPayError) -> bytes:
    """Render FluxPayError to canonical wire bytes with ErrorEnvelope roundtrip validation.

    WHY consistency:
    Produces orjson.dumps(to_payload(exc)) matching Task 4's wire format and validates that
    the byte-shape satisfies the Task 24 ErrorEnvelope contract.
    """
    payload = exc.to_payload()
    wire_bytes = orjson.dumps(payload)

    # Self-checking roundtrip: validate byte-shape against Task 24 ErrorEnvelope
    ErrorEnvelope.model_validate(orjson.loads(wire_bytes))

    return wire_bytes
