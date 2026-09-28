"""Unit tests verifying the typed failure contract and error hierarchy.

Validates that error codes, HTTP statuses, and retryable semantics conform to the frozen
contract, and proves that internal diagnostic details never leak to external payloads.
"""

import re

import pytest

from fluxpay.shared.errors import (
    ERROR_REGISTRY,
    AuthenticationError,
    FluxPayError,
    IdempotencyConflict,
    InsufficientFunds,
    InternalError,
    LedgerNotFoundError,
    NotFoundError,
    OCCConflict,
    RateLimitError,
    ReplayError,
    UnbalancedTransaction,
    ValidationError,
    as_fluxpay_error,
)

EXPECTED_ERROR_CLASSES = (
    FluxPayError,
    AuthenticationError,
    ReplayError,
    RateLimitError,
    IdempotencyConflict,
    InsufficientFunds,
    UnbalancedTransaction,
    LedgerNotFoundError,
    OCCConflict,
    ValidationError,
    NotFoundError,
    InternalError,
)

EXPECTED_RETRYABLE_CODES = {
    "rate_limited",
    "conflict_retry_required",
}


@pytest.mark.unit
def test_all_twelve_error_classes_registered() -> None:
    """Validate that all 12 error classes are present in the auto-derived registry."""
    assert len(EXPECTED_ERROR_CLASSES) == 12
    assert len(ERROR_REGISTRY) == 12
    for cls in EXPECTED_ERROR_CLASSES:
        assert cls.code in ERROR_REGISTRY
        assert ERROR_REGISTRY[cls.code] is cls


@pytest.mark.unit
def test_error_registry_codes_are_unique_and_valid_format() -> None:
    """Validate that every registered error code is unique and matches snake_case regex."""
    code_pattern = re.compile(r"^[a-z][a-z0-9_]*$")
    seen_codes: set[str] = set()

    for code, cls in ERROR_REGISTRY.items():
        assert code not in seen_codes, f"Duplicate error code detected: '{code}'"
        seen_codes.add(code)
        assert code_pattern.match(code), (
            f"Error code '{code}' in class '{cls.__name__}' does not match snake_case pattern."
        )


@pytest.mark.unit
def test_all_registered_errors_have_valid_http_statuses() -> None:
    """Validate that all error classes define HTTP statuses in the 400-599 range."""
    for code, cls in ERROR_REGISTRY.items():
        assert 400 <= cls.status <= 599, (
            f"Class '{cls.__name__}' with code '{code}' has invalid HTTP status {cls.status}. "
            f"Must be between 400 and 599."
        )


@pytest.mark.unit
def test_retryable_semantics_contract() -> None:
    """Contract-lock test: exactly and only designated transient errors are retryable.

    Adding or removing a retryable error alters AI agent retry loops and requires an
    explicit engineering decision and test update.
    """
    actual_retryable_codes = {code for code, cls in ERROR_REGISTRY.items() if cls.retryable}
    assert actual_retryable_codes == EXPECTED_RETRYABLE_CODES, (
        f"Retryable error codes mismatch! Expected {EXPECTED_RETRYABLE_CODES}, "
        f"got {actual_retryable_codes}."
    )


@pytest.mark.unit
@pytest.mark.parametrize("error_cls", EXPECTED_ERROR_CLASSES)
def test_to_payload_frozen_wire_shape(error_cls: type[FluxPayError]) -> None:
    """Validate that to_payload produces the exact frozen wire format for every error."""
    err = error_cls()
    payload = err.to_payload()

    assert set(payload.keys()) == {"error"}
    error_obj = payload["error"]
    assert set(error_obj.keys()) == {"code", "message", "retryable"}
    assert error_obj["code"] == error_cls.code
    assert error_obj["message"] == error_cls.client_message
    assert error_obj["retryable"] == error_cls.retryable


@pytest.mark.unit
def test_details_never_appear_in_to_payload() -> None:
    """Validate that internal details passed to error instances are excluded from to_payload."""
    dangerous_details = {
        "internal_account_id": "acc_secret_998877",
        "raw_sql_query": "SELECT * FROM accounts WHERE key = 'secret_pass'",
        "unmasked_balance_cents": "100500",
    }
    err = InsufficientFunds(details=dangerous_details)
    payload = err.to_payload()

    assert "details" not in payload["error"]
    for key, value in dangerous_details.items():
        assert key not in str(payload)
        assert value not in str(payload)


@pytest.mark.unit
def test_str_representation_is_client_safe() -> None:
    """Validate that str(err) returns only the safe message and never internal details."""
    dangerous_details = {
        "sql": "SELECT * FROM agents WHERE secret='super_secret_token'",
        "path": "/etc/shadow",
    }
    err = ValidationError(details=dangerous_details)

    assert str(err) == err.client_message
    assert "secret" not in str(err)
    assert "/etc/shadow" not in str(err)


@pytest.mark.unit
def test_as_fluxpay_error_passthrough() -> None:
    """Validate that existing FluxPayError instances pass through as_fluxpay_error untouched."""
    original = RateLimitError(details={"retry_after_ms": "500"})
    converted = as_fluxpay_error(original)
    assert converted is original


@pytest.mark.unit
def test_as_fluxpay_error_wraps_arbitrary_exceptions_safely() -> None:
    """Validate that arbitrary exceptions are safely wrapped into InternalError."""
    sensitive_msg = "psycopg2.OperationalError: connection to server at '10.0.0.5' failed: password"
    raw_exc = ValueError(sensitive_msg)

    converted = as_fluxpay_error(raw_exc)
    assert isinstance(converted, InternalError)
    assert converted.status == 500
    assert converted.code == "internal_error"
    assert converted.retryable is False
    assert converted.details == {"type": "ValueError"}

    # Security check: the sensitive message from raw_exc must NOT appear in message or payload
    assert sensitive_msg not in converted.message
    assert sensitive_msg not in str(converted)
    assert sensitive_msg not in str(converted.to_payload())


@pytest.mark.unit
def test_unbalanced_transaction_invariants() -> None:
    """Validate UnbalancedTransaction alarm error invariants."""
    err = UnbalancedTransaction(details={"discrepancy_cents": "100"})
    assert err.code == "internal_ledger_error"
    assert err.status == 500
    assert err.retryable is False
    assert err.client_message == "An internal ledger error occurred."
    assert "100" not in str(err)
    assert "100" not in str(err.to_payload())
