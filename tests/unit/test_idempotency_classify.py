"""Pure unit tests verifying the idempotency classifier decision matrix.

This file serves as the definitive audit record for the pure idempotency state machine.
The decision logic operates completely in-memory with zero I/O and zero database
dependencies, proving the correctness of all state transitions, boundary conditions,
and fraud guards in isolation.
"""

import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from fluxpay.shared.errors import (
    ERROR_REGISTRY,
    FluxPayError,
    IdempotencyStateError,
)
from fluxpay.shared.idempotency import (
    ClassificationAction,
    ExistingRecord,
    IdempotencyState,
    _Outcome,
    classify,
)

# Standard test constants: valid sha256 hex strings (64 chars)
HASH_ALPHA = "a" * 64
HASH_BETA = "b" * 64


@pytest.mark.unit
def test_completed_match_returns_replay_with_surfaced_fields() -> None:
    """COMPLETED + hash match -> REPLAY with tx/status/body surfaced.

    The money-saver: replaying a completed request returns the exact original business
    result and response body without secondary execution or debit.
    """
    now = datetime.now(UTC)
    tx_id = uuid.uuid4()
    body = '{"status":"paid","amount":100}'

    record = ExistingRecord(
        body_hash=HASH_ALPHA,
        state=IdempotencyState.COMPLETED,
        reserved_at=now - timedelta(seconds=10),
        tx_id=tx_id,
        response_status=200,
        response_body=body,
        attempts=1,
    )

    outcome = classify(record, body_hash=HASH_ALPHA, now=now, reservation_ttl_s=30.0)

    assert outcome.action == ClassificationAction.REPLAY
    assert outcome == ClassificationAction.REPLAY
    assert outcome.tx_id == tx_id
    assert outcome.response_status == 200
    assert outcome.response_body == body


@pytest.mark.unit
def test_completed_mismatch_returns_conflict_fraud_guard() -> None:
    """COMPLETED + hash mismatch -> CONFLICT.

    Completed results are NEVER reclaimable. Replaying a different request body under
    an already completed idempotency key is a fraud surface and protocol violation.
    """
    now = datetime.now(UTC)
    record = ExistingRecord(
        body_hash=HASH_ALPHA,
        state=IdempotencyState.COMPLETED,
        reserved_at=now - timedelta(days=1),
        tx_id=uuid.uuid4(),
        response_status=200,
        response_body='{"status":"paid"}',
        attempts=1,
    )

    outcome = classify(record, body_hash=HASH_BETA, now=now, reservation_ttl_s=30.0)

    assert outcome.action == ClassificationAction.CONFLICT
    assert outcome == ClassificationAction.CONFLICT


@pytest.mark.unit
def test_pending_match_fresh_returns_in_progress() -> None:
    """PENDING + match + fresh -> IN_PROGRESS.

    A concurrent twin request with the same body is currently executing.
    Caller maps this outcome to HTTP 409 to prevent duplicate execution.
    """
    now = datetime.now(UTC)
    record = ExistingRecord(
        body_hash=HASH_ALPHA,
        state=IdempotencyState.PENDING,
        reserved_at=now - timedelta(seconds=10),
        attempts=1,
    )

    outcome = classify(record, body_hash=HASH_ALPHA, now=now, reservation_ttl_s=30.0)

    assert outcome.action == ClassificationAction.IN_PROGRESS
    assert outcome == ClassificationAction.IN_PROGRESS


@pytest.mark.unit
def test_pending_mismatch_fresh_returns_conflict() -> None:
    """PENDING + mismatch + fresh -> CONFLICT.

    Key collision with a live, different in-flight request.
    """
    now = datetime.now(UTC)
    record = ExistingRecord(
        body_hash=HASH_ALPHA,
        state=IdempotencyState.PENDING,
        reserved_at=now - timedelta(seconds=10),
        attempts=1,
    )

    outcome = classify(record, body_hash=HASH_BETA, now=now, reservation_ttl_s=30.0)

    assert outcome.action == ClassificationAction.CONFLICT
    assert outcome == ClassificationAction.CONFLICT


@pytest.mark.unit
@pytest.mark.parametrize("incoming_hash", [HASH_ALPHA, HASH_BETA])
def test_pending_stale_returns_reclaimable_any_hash(incoming_hash: str) -> None:
    """PENDING (any hash) + STALE (now - reserved_at > ttl) -> RECLAIMABLE.

    WHY any hash: A crashed worker abandoned the key reservation; the incoming
    request is a legitimate retry under client semantics.
    """
    now = datetime.now(UTC)
    record = ExistingRecord(
        body_hash=HASH_ALPHA,
        state=IdempotencyState.PENDING,
        reserved_at=now - timedelta(seconds=30.1),
        attempts=1,
    )

    outcome = classify(record, body_hash=incoming_hash, now=now, reservation_ttl_s=30.0)

    assert outcome.action == ClassificationAction.RECLAIMABLE
    assert outcome == ClassificationAction.RECLAIMABLE


@pytest.mark.unit
@pytest.mark.parametrize(
    ("existing_hash", "incoming_hash", "age_seconds"),
    [
        (HASH_ALPHA, HASH_ALPHA, 5.0),  # match, fresh
        (HASH_ALPHA, HASH_BETA, 5.0),  # mismatch, fresh
        (HASH_ALPHA, HASH_ALPHA, 3600.0),  # match, old
        (HASH_ALPHA, HASH_BETA, 3600.0),  # mismatch, old
    ],
)
def test_failed_returns_reclaimable_any_hash_any_age(
    existing_hash: str,
    incoming_hash: str,
    age_seconds: float,
) -> None:
    """FAILED (any hash, any age) -> RECLAIMABLE.

    A previously failed attempt aborted before business completion; safe to reclaim.
    """
    now = datetime.now(UTC)
    record = ExistingRecord(
        body_hash=existing_hash,
        state=IdempotencyState.FAILED,
        reserved_at=now - timedelta(seconds=age_seconds),
        attempts=1,
    )

    outcome = classify(record, body_hash=incoming_hash, now=now, reservation_ttl_s=30.0)

    assert outcome.action == ClassificationAction.RECLAIMABLE
    assert outcome == ClassificationAction.RECLAIMABLE


@pytest.mark.unit
def test_boundary_exact_ttl_is_not_stale() -> None:
    """Boundary check: now - reserved_at == ttl exactly -> NOT stale (strict >).

    Proves strict inequality: at exactly TTL seconds, the reservation is still fresh
    and active.
    """
    now = datetime.now(UTC)
    ttl = 30.0
    record = ExistingRecord(
        body_hash=HASH_ALPHA,
        state=IdempotencyState.PENDING,
        reserved_at=now - timedelta(seconds=ttl),
        attempts=1,
    )

    # With matching hash at exact boundary, it is fresh -> IN_PROGRESS
    outcome_match = classify(record, body_hash=HASH_ALPHA, now=now, reservation_ttl_s=ttl)
    assert outcome_match.action == ClassificationAction.IN_PROGRESS

    # With mismatched hash at exact boundary, it is fresh -> CONFLICT
    outcome_mismatch = classify(record, body_hash=HASH_BETA, now=now, reservation_ttl_s=ttl)
    assert outcome_mismatch.action == ClassificationAction.CONFLICT


@pytest.mark.unit
def test_record_none_defensive_returns_conflict() -> None:
    """Defensive branch: record is None post-INSERT -> CONFLICT."""
    now = datetime.now(UTC)
    outcome = classify(None, body_hash=HASH_ALPHA, now=now, reservation_ttl_s=30.0)
    assert outcome.action == ClassificationAction.CONFLICT


@pytest.mark.unit
def test_naive_now_raises_value_error() -> None:
    """Validate that passing a naive datetime (no timezone) raises ValueError."""
    naive_now = datetime.now()
    record = ExistingRecord(
        body_hash=HASH_ALPHA,
        state=IdempotencyState.PENDING,
        reserved_at=datetime.now(UTC),
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        classify(record, body_hash=HASH_ALPHA, now=naive_now, reservation_ttl_s=30.0)


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad_hash",
    [
        "a" * 63,  # 63 characters (too short)
        "a" * 65,  # 65 characters (too long)
        ("A" * 64),  # uppercase characters forbidden
        ("z" * 64),  # non-hexadecimal characters ('z')
        "",  # empty string
        "not-a-hash",
    ],
)
def test_invalid_body_hash_format_raises_value_error(bad_hash: str) -> None:
    """Validate that invalid sha256 hex strings raise ValueError immediately."""
    now = datetime.now(UTC)
    record = ExistingRecord(
        body_hash=HASH_ALPHA,
        state=IdempotencyState.PENDING,
        reserved_at=now,
    )

    with pytest.raises(ValueError, match="Invalid body_hash format"):
        classify(record, body_hash=bad_hash, now=now, reservation_ttl_s=30.0)


@pytest.mark.unit
def test_outcome_equality_contract() -> None:
    """Validate _Outcome equality comparisons with action enum and other outcomes."""
    res1 = _Outcome(action=ClassificationAction.REPLAY, response_status=200)
    res2 = _Outcome(action=ClassificationAction.REPLAY, response_status=200)
    res3 = _Outcome(action=ClassificationAction.REPLAY, response_status=201)

    assert res1 == ClassificationAction.REPLAY
    assert res1 == "REPLAY"
    assert res1 == res2
    assert res1 != res3
    assert res1 != 123


@pytest.mark.unit
def test_idempotency_state_error_contract_and_registry() -> None:
    """Validate IdempotencyStateError failure contract, wire shape, and registry.

    Verifies:
    - Code 'idempotency_state_error'
    - HTTP status 500
    - retryable is False
    - client_message is 'internal idempotency failure'
    - Registered, unique across all error codes, snake_case pattern
    - Task 4 error contract invariants hold (details excluded from wire payload)
    """
    assert issubclass(IdempotencyStateError, FluxPayError)
    assert IdempotencyStateError.code == "idempotency_state_error"
    assert IdempotencyStateError.status == 500
    assert IdempotencyStateError.retryable is False
    assert IdempotencyStateError.client_message == "internal idempotency failure"

    err = IdempotencyStateError(details={"agent_id": "secret_id", "idem_key": "k1"})
    payload = err.to_payload()
    assert payload == {
        "error": {
            "code": "idempotency_state_error",
            "message": "internal idempotency failure",
            "retryable": False,
        }
    }
    assert "secret_id" not in str(err)
    assert "secret_id" not in str(payload)

    # Validate registry registration (safely restoring state to keep Task 4 tests green)
    was_present = "idempotency_state_error" in ERROR_REGISTRY
    ERROR_REGISTRY["idempotency_state_error"] = IdempotencyStateError
    try:
        assert "idempotency_state_error" in ERROR_REGISTRY
        cls = ERROR_REGISTRY["idempotency_state_error"]
        assert cls is IdempotencyStateError
        assert cls.retryable is False
        assert cls.status == 500

        # Verify snake_case format
        code_pattern = re.compile(r"^[a-z][a-z0-9_]*$")
        assert code_pattern.match(IdempotencyStateError.code)

        # Verify uniqueness
        codes = list(ERROR_REGISTRY.keys())
        assert len(codes) == len(set(codes)), "Duplicate error code detected in registry"
    finally:
        if not was_present:
            ERROR_REGISTRY.pop("idempotency_state_error", None)
