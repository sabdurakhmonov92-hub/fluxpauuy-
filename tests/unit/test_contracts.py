"""Contract-lock test suite for API wire schemas and webhook JSON schema.

Enforces zero-drift invariants between:
1. Public event types (Task 9 EventType) and external merchant webhook schema.
2. Server domain error registry (Task 4 ERROR_REGISTRY) and wire ErrorEnvelope.
3. Financial constraints: StrictInt monetary validation, forbid extra fields, frozen immutability.
4. Schema isolation: leaf module import law (no fluxpay, fastapi, or starlette imports).
"""

import ast
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import jsonschema  # type: ignore[import-untyped]
import pytest
from jsonschema.validators import validator_for  # type: ignore[import-untyped]
from pydantic import ValidationError

from fluxpay.contracts.schemas import (
    CURRENCY_PATTERN,
    IDEMPOTENCY_KEY_PATTERN,
    MERCHANT_ID_PATTERN,
    BalanceResponse,
    ErrorBody,
    ErrorEnvelope,
    PaymentDetail,
    PaymentRequest,
    PaymentResponse,
)
from fluxpay.shared.errors import ERROR_REGISTRY
from fluxpay.shared.events import EventType

pytestmark = pytest.mark.unit

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
WEBHOOK_SCHEMA_PATH: Path = REPO_ROOT / "contracts" / "webhook.schema.json"


@pytest.fixture(scope="session")
def webhook_schema() -> dict[str, Any]:
    """Load and parse the frozen merchant-facing webhook JSON Schema artifact."""
    assert WEBHOOK_SCHEMA_PATH.is_file(), (
        f"Missing webhook schema artifact at {WEBHOOK_SCHEMA_PATH}"
    )
    with WEBHOOK_SCHEMA_PATH.open("r", encoding="utf-8") as f:
        schema: dict[str, Any] = json.load(f)
    return schema


# ==============================================================================
# Cross-Check 1: EventType Registry Mirror (Task 9 Inversion)
# ==============================================================================


def test_cross_check_event_type_mirrors_webhook_schema(
    webhook_schema: dict[str, Any],
) -> None:
    """Cross-check 1: Webhook schema enum MUST identically mirror EventType members.

    WHY:
    Event bus events (Task 9) and merchant webhooks (Task 24) must NEVER drift silently.
    If an engineer registers a new event type in Task 9 without declaring it in the
    external merchant webhook schema, this test will fail CI immediately.
    """
    event_prop = webhook_schema["properties"]["event"]
    declared_enum: list[str] = event_prop["enum"]

    bus_event_values = {e.value for e in EventType}
    schema_enum_values = set(declared_enum)

    assert bus_event_values == schema_enum_values, (
        f"Event drift detected! Task 9 EventType {bus_event_values} != "
        f"webhook.schema.json enum {schema_enum_values}"
    )
    assert len(declared_enum) == len(schema_enum_values), "Duplicate entries found in webhook enum"
    assert declared_enum == ["payment.settled", "payment.held", "payment.failed"]


# ==============================================================================
# Cross-Check 2: Error Registry Envelope Mirror (Task 4 Roundtrip)
# ==============================================================================


def test_cross_check_error_envelope_roundtrips_every_registry_error() -> None:
    """Cross-check 2: ErrorEnvelope MUST roundtrip EVERY class in ERROR_REGISTRY.

    WHY:
    The test dynamically iterates over all registered error types in Task 4.
    As new error classes are added to ERROR_REGISTRY, this test automatically exercises
    them without manual test updates — providing zero-maintenance drift defense.
    """
    assert len(ERROR_REGISTRY) >= 12, "ERROR_REGISTRY appears unexpectedly depleted"

    for code, err_cls in ERROR_REGISTRY.items():
        err_instance = err_cls()
        payload = err_instance.to_payload()

        # 1. Structural wire validation
        envelope = ErrorEnvelope.model_validate(payload)

        # 2. Field-level equivalence
        assert envelope.error.code == err_instance.code == code
        assert envelope.error.message == err_instance.message
        assert envelope.error.retryable == err_instance.retryable

        # 3. Byte-level serialization equivalence
        assert envelope.model_dump() == payload


# ==============================================================================
# StrictInt Monetary Discipline Guards
# ==============================================================================


def test_strict_int_amount_guards() -> None:
    """Verify StrictInt enforces money discipline (no bools, no strings, positive)."""
    # 1. Booleans are rejected (True is NOT 1, False is NOT 0 in financial contracts)
    with pytest.raises(ValidationError, match="Input should be a valid integer"):
        PaymentRequest(to="merchant_demo", amount=True, currency="USDC")

    with pytest.raises(ValidationError, match="Input should be a valid integer"):
        PaymentRequest(to="merchant_demo", amount=False, currency="USDC")

    # 2. String numeric values are rejected (no silent coercion)
    with pytest.raises(ValidationError, match="Input should be a valid integer"):
        PaymentRequest(to="merchant_demo", amount="100", currency="USDC")

    # 3. Non-positive amounts are rejected (gt=0)
    with pytest.raises(ValidationError, match="Input should be greater than 0"):
        PaymentRequest(to="merchant_demo", amount=0, currency="USDC")

    with pytest.raises(ValidationError, match="Input should be greater than 0"):
        PaymentRequest(to="merchant_demo", amount=-5, currency="USDC")

    # 4. Valid positive integer passes
    req = PaymentRequest(to="merchant_demo", amount=1050, currency="USDC")
    assert req.amount == 1050


def test_strict_int_balance_guards() -> None:
    """Verify BalanceResponse enforces non-negative StrictInt."""
    with pytest.raises(ValidationError):
        BalanceResponse(balance=True, currency="USDC")

    with pytest.raises(ValidationError):
        BalanceResponse(balance="100", currency="USDC")

    with pytest.raises(ValidationError, match="greater than or equal to 0"):
        BalanceResponse(balance=-1, currency="USDC")

    # Zero is allowed for balance
    bal_zero = BalanceResponse(balance=0, currency="USDC")
    assert bal_zero.balance == 0

    bal_pos = BalanceResponse(balance=1050, currency="USDC")
    assert bal_pos.balance == 1050


# ==============================================================================
# Extra Fields Forbid (extra="forbid")
# ==============================================================================


def test_extra_fields_forbidden_on_all_models() -> None:
    """Verify extra='forbid' rejects misspelled or unexpected fields with 422 ValidationError."""
    # Misspelled 'ammount' must 422, not vanish silently into extra fields
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        PaymentRequest.model_validate(
            {"to": "merchant_demo", "amount": 1050, "currency": "USDC", "ammount": 1}
        )

    # Unknown field on PaymentResponse
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        PaymentResponse.model_validate(
            {"id": str(uuid4()), "status": "settled", "unexpected_field": True}
        )

    # Unknown field on BalanceResponse
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        BalanceResponse.model_validate({"balance": 100, "currency": "USDC", "extra": "forbidden"})

    # Unknown field on PaymentDetail
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        PaymentDetail.model_validate(
            {
                "id": str(uuid4()),
                "status": "settled",
                "amount": 100,
                "currency": "USDC",
                "created_at": "2026-09-25T12:00:00+00:00",
                "extra": "bad",
            }
        )

    # Unknown field on ErrorEnvelope and ErrorBody
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ErrorEnvelope.model_validate(
            {
                "error": {
                    "code": "test",
                    "message": "msg",
                    "retryable": False,
                    "extra_inner": 123,
                }
            }
        )

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ErrorEnvelope.model_validate(
            {
                "error": {"code": "test", "message": "msg", "retryable": False},
                "extra_outer": 123,
            }
        )


# ==============================================================================
# Model Immutability (frozen=True)
# ==============================================================================


def test_models_are_frozen() -> None:
    """Verify that mutating validated contract instances raises a ValidationError."""
    req = PaymentRequest(to="merchant_demo", amount=1050, currency="USDC")
    with pytest.raises(ValidationError, match="Instance is frozen"):
        req.amount = 2000  # type: ignore[misc]

    resp = PaymentResponse(id=uuid4(), status="settled")
    with pytest.raises(ValidationError, match="Instance is frozen"):
        resp.status = "held"  # type: ignore[misc]

    bal = BalanceResponse(balance=1000, currency="USDC")
    with pytest.raises(ValidationError, match="Instance is frozen"):
        bal.balance = 500  # type: ignore[misc]

    err = ErrorBody(code="bad", message="bad", retryable=False)
    with pytest.raises(ValidationError, match="Instance is frozen"):
        err.retryable = True  # type: ignore[misc]


# ==============================================================================
# Grammar & Pattern Constraints
# ==============================================================================


def test_currency_pattern_validation() -> None:
    """Verify CURRENCY_PATTERN mirrors Task 12 law L1 (2-10 uppercase alphanumeric)."""
    assert CURRENCY_PATTERN == r"^[A-Z0-9]{2,10}$"

    # Valid currencies
    for valid_curr in ("US", "USD", "USDC", "USDT10", "A" * 10):
        req = PaymentRequest(to="merchant_demo", amount=100, currency=valid_curr)
        assert req.currency == valid_curr

    # Lowercase rejected
    with pytest.raises(ValidationError, match="String should match pattern"):
        PaymentRequest(to="merchant_demo", amount=100, currency="usdc")

    # Too short (<2 chars)
    with pytest.raises(ValidationError, match="String should match pattern"):
        PaymentRequest(to="merchant_demo", amount=100, currency="U")

    # Too long (>10 chars)
    with pytest.raises(ValidationError, match="String should match pattern"):
        PaymentRequest(to="merchant_demo", amount=100, currency="A" * 11)

    # Disallowed characters rejected
    with pytest.raises(ValidationError, match="String should match pattern"):
        PaymentRequest(to="merchant_demo", amount=100, currency="USD$")


def test_merchant_id_pattern_validation() -> None:
    """Verify MERCHANT_ID_PATTERN enforces canonical lowercase handles (3-64 chars)."""
    assert MERCHANT_ID_PATTERN == r"^[a-z0-9_.-]{3,64}$"

    # Valid merchant IDs
    for valid_handle in ("abc", "merchant_demo", "a.b-c_d", "123", "a" * 64):
        req = PaymentRequest(to=valid_handle, amount=100, currency="USDC")
        assert req.to == valid_handle

    # Uppercase rejected (zero normalization ambiguity for machine agents)
    with pytest.raises(ValidationError, match="String should match pattern"):
        PaymentRequest(to="ABc", amount=100, currency="USDC")

    with pytest.raises(ValidationError, match="String should match pattern"):
        PaymentRequest(to="AB", amount=100, currency="USDC")

    # Too short (<3 chars)
    with pytest.raises(ValidationError, match="String should match pattern"):
        PaymentRequest(to="ab", amount=100, currency="USDC")

    # Too long (>64 chars)
    with pytest.raises(ValidationError, match="String should match pattern"):
        PaymentRequest(to="a" * 65, amount=100, currency="USDC")

    # Disallowed symbols rejected
    with pytest.raises(ValidationError, match="String should match pattern"):
        PaymentRequest(to="merchant@demo", amount=100, currency="USDC")


def test_idempotency_key_pattern_mirror() -> None:
    """Verify IDEMPOTENCY_KEY_PATTERN mirrors Task 19 charset."""
    assert IDEMPOTENCY_KEY_PATTERN == r"^[A-Za-z0-9-]{16,128}$"


# ==============================================================================
# Status Literal Freeze & Evolution Rule
# ==============================================================================


def test_status_literal_freeze() -> None:
    """Verify status Literal is strictly frozen to 'settled' | 'held' today.

    'pending' is reserved for Phase 2 async rails and must be rejected today.
    'failed' is rejected because failures are mapped to HTTP error envelopes.
    """
    tx_id = uuid4()

    # Valid statuses
    s1 = PaymentResponse(id=tx_id, status="settled")
    assert s1.status == "settled"

    s2 = PaymentResponse(id=tx_id, status="held")
    assert s2.status == "held"

    # 'pending' rejected TODAY
    with pytest.raises(ValidationError, match="Input should be 'settled' or 'held'"):
        PaymentResponse(id=tx_id, status="pending")

    # 'failed' rejected
    with pytest.raises(ValidationError, match="Input should be 'settled' or 'held'"):
        PaymentResponse(id=tx_id, status="failed")


# ==============================================================================
# UUID Validation
# ==============================================================================


def test_payment_response_id_uuid_validation() -> None:
    """Verify id must be a valid UUID in PaymentResponse and PaymentDetail."""
    tx_id = uuid4()
    resp = PaymentResponse(id=tx_id, status="settled")
    assert resp.id == tx_id

    # String UUID parses into UUID object
    resp2 = PaymentResponse.model_validate({"id": str(tx_id), "status": "settled"})
    assert isinstance(resp2.id, UUID)
    assert resp2.id == tx_id

    # Non-UUID string rejected
    with pytest.raises(ValidationError, match="Input should be a valid UUID"):
        PaymentResponse(id="not-a-uuid", status="settled")


# ==============================================================================
# Datetime UTC Serialization and Timezone Discipline
# ==============================================================================


def test_created_at_wire_format_and_tz_awareness() -> None:
    """Verify created_at is strictly timezone-aware and serialized with '+00:00'."""
    tx_id = uuid4()

    # 1. Naive datetime REJECTED (ledger discipline mirrors Task 12)
    naive_dt = datetime(2026, 9, 25, 12, 0, 0)
    with pytest.raises(ValidationError, match="Input should have timezone info"):
        PaymentDetail(
            id=tx_id,
            status="settled",
            amount=1050,
            currency="USDC",
            created_at=naive_dt,
        )

    # 2. Naive string representation REJECTED
    with pytest.raises(ValidationError, match="Input should have timezone info"):
        PaymentDetail.model_validate(
            {
                "id": str(tx_id),
                "status": "settled",
                "amount": 1050,
                "currency": "USDC",
                "created_at": "2026-09-25T12:00:00",
            }
        )

    # 3. Aware UTC datetime serializes to ISO-8601 with '+00:00'
    utc_dt = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
    detail = PaymentDetail(
        id=tx_id,
        status="settled",
        amount=1050,
        currency="USDC",
        created_at=utc_dt,
    )

    json_wire = detail.model_dump_json()
    assert "+00:00" in json_wire, f"Expected '+00:00' in wire JSON, got: {json_wire}"
    assert '"created_at":"2026-09-25T12:00:00+00:00"' in json_wire

    # 4. Roundtrip parse restores identical instant
    roundtripped = PaymentDetail.model_validate_json(json_wire)
    assert roundtripped.created_at == utc_dt
    assert roundtripped.id == tx_id
    assert roundtripped.amount == 1050


# ==============================================================================
# Meta-Test: Schemas Leaf Isolation (Import Blacklist)
# ==============================================================================


def test_schemas_leaf_isolation_no_forbidden_imports() -> None:
    """Meta-test: schemas.py MUST NOT import fastapi, starlette, or fluxpay.

    Enforces that contracts remain a pure leaf module cleanly reusable by SDKs
    and lightweight workers without pulling the web framework or database stack.
    """
    schemas_path = REPO_ROOT / "src" / "fluxpay" / "contracts" / "schemas.py"
    assert schemas_path.is_file(), f"Missing schemas.py at {schemas_path}"

    with schemas_path.open("r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=str(schemas_path))

    forbidden_roots = {"fastapi", "starlette", "fluxpay"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_module = alias.name.split(".")[0]
                assert root_module not in forbidden_roots, (
                    f"Forbidden import in schemas.py: '{alias.name}'"
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            root_module = node.module.split(".")[0]
            assert root_module not in forbidden_roots, (
                f"Forbidden import from in schemas.py: '{node.module}'"
            )


# ==============================================================================
# Webhook JSON Schema Artifact Verification
# ==============================================================================


def test_webhook_schema_draft_2020_12_and_forbidden_additional_properties(
    webhook_schema: dict[str, Any],
) -> None:
    """Verify webhook JSON Schema satisfies draft 2020-12 and forbids additionalProperties."""
    assert webhook_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert webhook_schema["$id"] == "https://fluxpay.io/schemas/webhook-v1.json"
    expected_comment = (
        "frozen merchant contract — additive only; "
        "new fields optional with defaults; breaking = new $id"
    )
    assert webhook_schema["$comment"] == expected_comment

    # Recursive check: every object-level schema must have additionalProperties: false
    def _assert_no_additional_props(node: Any, path: str = "root") -> None:
        if isinstance(node, dict):
            if node.get("type") == "object" or "properties" in node:
                assert node.get("additionalProperties") is False, (
                    f"Object schema at '{path}' is missing 'additionalProperties: false'"
                )
            for k, v in node.items():
                _assert_no_additional_props(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, item in enumerate(node):
                _assert_no_additional_props(item, f"{path}[{i}]")

    _assert_no_additional_props(webhook_schema)


def test_webhook_payloads_validate_against_schema(webhook_schema: dict[str, Any]) -> None:
    """Validate example payloads using jsonschema Draft 2020-12 validator."""
    validator_cls = validator_for(webhook_schema)
    validator_cls.check_schema(webhook_schema)
    validator = validator_cls(webhook_schema)

    # 1. Valid payment.settled payload
    settled_event = {
        "event": "payment.settled",
        "event_id": str(uuid4()),
        "created_at": "2026-09-25T12:00:00Z",
        "data": {
            "tx_id": str(uuid4()),
            "amount": 1050,
            "currency": "USDC",
        },
    }
    validator.validate(settled_event)

    # 2. Valid payment.failed payload
    failed_event = {
        "event": "payment.failed",
        "event_id": str(uuid4()),
        "created_at": "2026-09-25T12:00:00+00:00",
        "data": {
            "tx_id": str(uuid4()),
            "amount": 5000,
            "currency": "USD",
        },
    }
    validator.validate(failed_event)

    # 3. Invalid payload: unknown property at root
    with pytest.raises(jsonschema.ValidationError):
        bad_extra_root = dict(settled_event, extra_field="forbidden")
        validator.validate(bad_extra_root)

    # 4. Invalid payload: unknown property inside data
    with pytest.raises(jsonschema.ValidationError):
        bad_extra_data = {
            "event": "payment.settled",
            "event_id": str(uuid4()),
            "created_at": "2026-09-25T12:00:00Z",
            "data": {
                "tx_id": str(uuid4()),
                "amount": 1050,
                "currency": "USDC",
                "tampered_data": True,
            },
        }
        validator.validate(bad_extra_data)

    # 5. Invalid payload: unknown event type
    with pytest.raises(jsonschema.ValidationError):
        bad_event = dict(settled_event, event="payment.cancelled")
        validator.validate(bad_event)

    # 6. Invalid payload: amount < 1
    with pytest.raises(jsonschema.ValidationError):
        bad_amount = {
            "event": "payment.settled",
            "event_id": str(uuid4()),
            "created_at": "2026-09-25T12:00:00Z",
            "data": {
                "tx_id": str(uuid4()),
                "amount": 0,
                "currency": "USDC",
            },
        }
        validator.validate(bad_amount)

    # 7. Invalid payload: lowercase currency
    with pytest.raises(jsonschema.ValidationError):
        bad_curr = {
            "event": "payment.settled",
            "event_id": str(uuid4()),
            "created_at": "2026-09-25T12:00:00Z",
            "data": {
                "tx_id": str(uuid4()),
                "amount": 1050,
                "currency": "usdc",
            },
        }
        validator.validate(bad_curr)
