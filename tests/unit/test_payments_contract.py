"""Payment wire contract test suite: the wire dialect proof (Task 32).

Verifies the frozen wire contract for payment outcomes, error envelopes, and fee math:
1. Canonical compactness freeze: PaymentResponse bytes are strictly compact (no whitespace drift).
2. Self-checking renderer: render_payment verifies roundtrip internally so malformed outcomes
   fail at render, never at the external client.
3. Internal isolation: replayed and response_status flags are excluded from the public wire bytes.
4. Error dialect matrix: exact code, status, and locked retryable table for payments errors.
5. Fee <-> schema <-> service triangle: documented openapi.yaml examples are arithmetically true.
6. Deterministic tx_id KAT: namespace and derivation formula freeze.
7. Status evolution guard: status is strictly frozen to Literal["settled", "held"].
8. Meta-test: render.py imports ONLY contracts, errors, orjson (zero ledger/service imports).
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import orjson
import pytest
from pydantic import ValidationError

from fluxpay.contracts.schemas import ErrorEnvelope, PaymentRequest, PaymentResponse
from fluxpay.payments.fees import FeeQuote, quote
from fluxpay.payments.render import render_error, render_payment
from fluxpay.payments.service import (
    FLXPAY_TX_NAMESPACE,
    PayOutcome,
    deterministic_tx_id,
)
from fluxpay.shared.errors import (
    GateUnavailable,
    IdempotencyConflict,
    InsufficientFunds,
    OCCConflict,
    PaymentPolicyError,
)
from fluxpay.shared.errors import (
    ValidationError as FluxPayValidationError,
)

pytestmark = pytest.mark.unit

REPO_ROOT: Path = Path(__file__).resolve().parents[2]

# Deterministic KAT constants (KAT-frozen anchor)
KAT_AGENT_ID = UUID("00000000-0000-0000-0000-000000000001")
KAT_IDEM_KEY = "idem-test-key-12345678"
KAT_EXPECTED_TX_ID = UUID("1253d480-fffa-5933-a2d8-656f3be2cb7d")

# Locked retryable table for payments route-mappable taxonomy
LOCKED_PAYMENT_RETRYABLE_TABLE: dict[str, bool] = {
    "rate_limited": True,
    "conflict_retry_required": True,
    "gate_unavailable": True,
    "validation_failed": False,
    "payment_policy_rejected": False,
    "insufficient_funds": False,
    "idempotency_conflict": False,
}


# ==============================================================================
# 1. SETTLED BYTES: CANONICAL COMPACTNESS & ROUNDTRIP
# ==============================================================================


def test_settled_bytes_canonical_compactness_and_roundtrip() -> None:
    """SETTLED bytes: render PayOutcome('settled') -> PaymentResponse.model_validate.

    WHY canonical-compactness freeze:
    Pydantic v2 `model_dump_json()` emits compact JSON without whitespace (e.g.
    b'"status":"settled"'). Task 22's fast-path and Task 11's database cache store and replay
    these exact bytes. Any whitespace drift (e.g., adding spaces after colons) would break
    byte-exact replay across cache tiers. This test pins the exact byte representation.
    """
    tx_id = UUID("11111111-2222-3333-4444-555555555555")
    outcome = PayOutcome(
        status="settled",
        tx_id=tx_id,
        response_status=201,
        wire_body=b"",
        replayed=False,
    )

    wire_bytes = render_payment(outcome)

    # 1. Byte-compactness freeze: literal compact substring assertion
    assert b'"status":"settled"' in wire_bytes, (
        f'Expected compact JSON substring b\'"status":"settled"\', got: {wire_bytes!r}'
    )
    assert b'"id":"11111111-2222-3333-4444-555555555555"' in wire_bytes
    # No whitespace around delimiters in canonical compact encoding
    assert b": " not in wire_bytes, "Canonical wire JSON must not contain space after colon"
    assert b", " not in wire_bytes, "Canonical wire JSON must not contain space after comma"

    # 2. Roundtrip through Task 24 frozen schema
    parsed = PaymentResponse.model_validate(json.loads(wire_bytes))
    assert parsed.id == tx_id
    assert str(parsed.id) == "11111111-2222-3333-4444-555555555555"
    assert parsed.status == "settled"


# ==============================================================================
# 2. HELD BYTES: CANONICAL COMPACTNESS & ROUNDTRIP
# ==============================================================================


def test_held_bytes_canonical_compactness_and_roundtrip() -> None:
    """HELD bytes: render PayOutcome('held') -> PaymentResponse.model_validate.

    Asserts that quarantined/held payments produce byte-compact wire payloads with
    status="held" that validate strictly against Task 24's PaymentResponse model.
    """
    tx_id = UUID("22222222-3333-4444-5555-666666666666")
    outcome = PayOutcome(
        status="held",
        tx_id=tx_id,
        response_status=201,
        wire_body=b"",
        replayed=False,
    )

    wire_bytes = render_payment(outcome)

    # 1. Byte-compactness freeze
    assert b'"status":"held"' in wire_bytes, (
        f'Expected compact JSON substring b\'"status":"held"\', got: {wire_bytes!r}'
    )
    assert b'"id":"22222222-3333-4444-5555-666666666666"' in wire_bytes
    assert b": " not in wire_bytes
    assert b", " not in wire_bytes

    # 2. Roundtrip validation
    parsed = PaymentResponse.model_validate(json.loads(wire_bytes))
    assert parsed.id == tx_id
    assert parsed.status == "held"


# ==============================================================================
# 3. REPLAYED FLAG: NEVER LEAKS ONTO WIRE
# ==============================================================================


def test_replayed_flag_never_leaks_onto_wire() -> None:
    """Verify internal orchestration flags (replayed, response_status) never leak onto the wire.

    WHY replayed-not-on-wire:
    Internal orchestration metadata (such as `replayed=True` indicating a cache hit, or
    `response_status=201`) is private service state machine data. The external wire contract
    (Task 24) is strictly frozen with `extra="forbid"`. Leaking internal metadata onto the
    wire would violate the schema and cause contract validation errors in autonomous client agents.
    """
    tx_id = UUID("33333333-4444-5555-6666-777777777777")

    # Test both replayed=False and replayed=True
    for replayed in (False, True):
        outcome = PayOutcome(
            status="settled",
            tx_id=tx_id,
            response_status=201,
            wire_body=b"",
            replayed=replayed,
        )
        wire_bytes = render_payment(outcome)

        assert b"replayed" not in wire_bytes, "Internal 'replayed' flag leaked into wire bytes!"
        assert b"response_status" not in wire_bytes, "Internal 'response_status' leaked into wire!"
        assert b"wire_body" not in wire_bytes, "Internal 'wire_body' leaked into wire!"


# ==============================================================================
# 4. ERROR DIALECT MATRIX & LOCKED RETRYABLE TABLE
# ==============================================================================


def test_error_dialect_matrix_and_locked_retryable_table() -> None:
    """ERROR matrix: verify exact code, HTTP status, and retryable flag per error class.

    For each route-mappable payment error:
    - ValidationError -> 422, validation_failed, retryable=False
    - PaymentPolicyError -> 422, payment_policy_rejected, retryable=False
    - InsufficientFunds -> 400, insufficient_funds, retryable=False
    - IdempotencyConflict -> 409, idempotency_conflict, retryable=False
    - GateUnavailable -> 503, gate_unavailable, retryable=True
    - OCCConflict -> 503, conflict_retry_required, retryable=True

    Proves roundtrip through `render_error` -> `ErrorEnvelope.model_validate` and locks
    the retryable taxonomy for payment errors.
    """
    test_cases = [
        (
            FluxPayValidationError(message="Invalid payment request payload."),
            "validation_failed",
            422,
            False,
        ),
        (
            PaymentPolicyError(message="Payment velocity ceiling exceeded."),
            "payment_policy_rejected",
            422,
            False,
        ),
        (
            InsufficientFunds(message="Payer account has insufficient available balance."),
            "insufficient_funds",
            400,
            False,
        ),
        (
            IdempotencyConflict(message="Idempotency key reused with mismatched body."),
            "idempotency_conflict",
            409,
            False,
        ),
        (
            GateUnavailable(message="Ingress gate cluster unreachable."),
            "gate_unavailable",
            503,
            True,
        ),
        (
            OCCConflict(message="Ledger optimistic concurrency conflict."),
            "conflict_retry_required",
            503,
            True,
        ),
    ]

    for err_instance, expected_code, expected_status, expected_retryable in test_cases:
        # 1. Assert class-level contract matches expected taxonomy
        assert err_instance.code == expected_code
        assert err_instance.status == expected_status
        assert err_instance.retryable is expected_retryable

        # 2. Lock against the payment retryable taxonomy table
        assert LOCKED_PAYMENT_RETRYABLE_TABLE[expected_code] is expected_retryable, (
            f"Retryable flag drift detected for code '{expected_code}'!"
        )

        # 3. Render error through the single renderer
        wire_bytes = render_error(err_instance)

        # 4. Assert byte-compact JSON and ErrorEnvelope validation
        parsed_json = orjson.loads(wire_bytes)
        envelope = ErrorEnvelope.model_validate(parsed_json)

        assert envelope.error.code == expected_code
        assert envelope.error.message == err_instance.message
        assert envelope.error.retryable is expected_retryable


# ==============================================================================
# 5. CROSS-CHECK: FEE <-> SCHEMA <-> SERVICE TRIANGLE (EXAMPLE-TRUTH TEST)
# ==============================================================================


def test_fee_schema_service_triangle_truth() -> None:
    """Cross-check: fee <-> schema <-> service triangle must be closed.

    WHY example-truth test:
    The documented example in openapi.yaml and Task 24 schemas (`PaymentRequest` example
    amount 1050) must produce mathematically and arithmetically TRUE quotes when passed
    to the fee calculation engine: `quote(1050) == (1050, 10, 1060)`.
    Documented examples that lie (or violate bounds) are classic onboarding killers for developer
    agents and lead to spurious validation failures in automated agents.
    """
    # 1. Standard benchmark quote: 10,000 minor units ($0.01) -> 1% fee = 100, total = 10,100
    q_10k = quote(10_000, "USDC")
    assert q_10k == FeeQuote(
        amount_minor=10_000,
        fee_minor=100,
        total_minor=10_100,
        currency="USDC",
    )

    # 2. Extract documented example from Task 24 frozen schema
    schema_extra = PaymentRequest.model_config.get("json_schema_extra")
    assert isinstance(schema_extra, dict), "PaymentRequest is missing json_schema_extra metadata"
    example_payload = schema_extra.get("example")
    assert isinstance(example_payload, dict), "PaymentRequest schema is missing example payload"

    example_amount = example_payload["amount"]
    example_currency = example_payload["currency"]
    assert isinstance(example_amount, int), f"Expected int amount, got {example_amount!r}"
    assert isinstance(example_currency, str), f"Expected str currency, got {example_currency!r}"
    assert example_amount == 1050
    assert example_currency == "USDC"

    # 3. Verify that documented example is arithmetically TRUE in the fee engine
    q_example = quote(example_amount, example_currency)
    assert q_example.amount_minor == 1050
    assert q_example.fee_minor == 10  # (1050 * 100) // 10000 = 10
    assert q_example.total_minor == 1060  # 1050 + 10 = 1060
    assert q_example == FeeQuote(1050, 10, 1060, "USDC")


# ==============================================================================
# 6. DETERMINISTIC TX_ID: KNOWN-ANSWER TEST (KAT) FREEZE
# ==============================================================================


def test_deterministic_tx_id_kat_and_namespace_freeze() -> None:
    """Freeze deterministic_tx_id against hardcoded KAT anchor and namespace constant.

    Guarantees that the uuid5 namespace and hashing algorithm remain immutable.
    Regeneration or namespace mutation is a breaking change alarm.
    """
    assert FLXPAY_TX_NAMESPACE == UUID("9c4b7264-77a8-4448-9366-eb15c6d04212")

    actual = deterministic_tx_id(KAT_AGENT_ID, KAT_IDEM_KEY)
    assert actual == KAT_EXPECTED_TX_ID
    assert str(actual) == "1253d480-fffa-5933-a2d8-656f3be2cb7d"
    assert actual.version == 5


# ==============================================================================
# 7. STATUS EVOLUTION GUARD: REJECTS "PENDING"
# ==============================================================================


def test_status_evolution_guard_rejects_pending() -> None:
    """Verify PaymentResponse strictly rejects 'pending' and non-terminal statuses.

    'pending' is reserved for future Phase 2 asynchronous settlement rails.
    Today's synchronous wire dialect strictly limits status to Literal['settled', 'held'].
    """
    tx_id = UUID("44444444-5555-6666-7777-888888888888")

    # 'pending' is rejected TODAY
    with pytest.raises(ValidationError, match="Input should be 'settled' or 'held'"):
        PaymentResponse.model_validate({"id": str(tx_id), "status": "pending"})

    # 'failed' is rejected TODAY (failures are HTTP error envelopes)
    with pytest.raises(ValidationError, match="Input should be 'settled' or 'held'"):
        PaymentResponse.model_validate({"id": str(tx_id), "status": "failed"})


# ==============================================================================
# 8. SELF-CHECKING RENDERER: DEFENSIVE FAIL-FAST
# ==============================================================================


def test_self_checking_renderer_catches_malformed_outcomes() -> None:
    """Self-checking renderer: a malformed outcome fails at render, never at the client.

    WHY self-checking renderer:
    If an internal component passes an invalid status, an invalid UUID, or corrupted fields
    to `render_payment`, the renderer fails immediately during internal roundtrip validation
    rather than emitting malformed JSON over the wire to external AI agents.
    """

    # 1. Invalid status on duck-typed outcome
    @dataclass
    class BadStatusOutcome:
        tx_id: UUID
        status: str

    bad_status = BadStatusOutcome(
        tx_id=UUID("55555555-6666-7777-8888-999999999999"),
        status="pending",  # Invalid in Phase 1
    )
    with pytest.raises(ValidationError, match="Input should be 'settled' or 'held'"):
        render_payment(bad_status)

    # 2. Missing fields raises ValueError
    with pytest.raises(ValueError, match="Cannot render payment"):
        render_payment(None)


# ==============================================================================
# 9. META-TEST: RENDER.PY ISOLATION (ZERO LEDGER/SERVICE IMPORTS)
# ==============================================================================


def test_render_leaf_isolation_no_forbidden_imports() -> None:
    """Meta-test: render.py MUST NOT import from fluxpay.ledger or fluxpay.payments.service.

    The renderer boundary IS the contract boundary. To prevent architectural cycle leaks,
    render.py must strictly depend only on contracts, errors, orjson, and Python stdlib.
    """
    render_path = REPO_ROOT / "src" / "fluxpay" / "payments" / "render.py"
    assert render_path.is_file(), f"Missing render.py at {render_path}"

    with render_path.open("r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=str(render_path))

    forbidden_patterns = {
        "fluxpay.ledger",
        "fluxpay.payments.service",
        "fastapi",
        "starlette",
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for forbidden in forbidden_patterns:
                    assert not alias.name.startswith(forbidden), (
                        f"Forbidden import in render.py: '{alias.name}'"
                    )
        elif isinstance(node, ast.ImportFrom) and node.module:
            for forbidden in forbidden_patterns:
                assert not node.module.startswith(forbidden), (
                    f"Forbidden import from in render.py: '{node.module}'"
                )
