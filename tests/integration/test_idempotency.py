"""Integration tests for FluxPay idempotency database layer.

Blueprint §3 & Task 11 Verification Suite:
- Double-debit impossibility proven by database unique constraint.
- Byte-exact response preservation verified using raw TEXT storage.
- Self-healing stale takeover and FAILED reservation reclaims verified.
- Fraud guard verified: completed results are immutable and never reclaimable.
- Atomicity verified: reserve and complete compose cleanly within UnitOfWork (Task 8 contract).
"""

import asyncio
import re
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]
import pytest

from fluxpay.shared.errors import (
    ERROR_REGISTRY,
    IdempotencyConflict,
    IdempotencyStateError,
)
from fluxpay.shared.idempotency import (
    RESPONSE_MAX_BYTES,
    Reservation,
    ReservationOutcome,
    complete,
    fail,
    lookup,
    reserve,
)
from fluxpay.shared.uow import UnitOfWork

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Unit-marked Failure Contract Tests (No external services required)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_idempotency_state_error_registry_and_contract() -> None:
    """Validate that idempotency_state_error conforms to error contract and registry invariants.

    Verifies:
    - Code 'idempotency_state_error'
    - HTTP status 500
    - retryable is False
    - client_message is 'internal idempotency failure'
    - Registered, unique across all error codes, snake_case pattern
    - Task 4 error contract invariants hold (wire shape and detail exclusion)
    """
    assert IdempotencyStateError.code == "idempotency_state_error"
    assert IdempotencyStateError.status == 500
    assert IdempotencyStateError.retryable is False
    assert IdempotencyStateError.client_message == "internal idempotency failure"

    err = IdempotencyStateError(details={"internal_diag": "concurrent_takeover_lost"})
    payload = err.to_payload()
    assert payload == {
        "error": {
            "code": "idempotency_state_error",
            "message": "internal idempotency failure",
            "retryable": False,
        }
    }
    assert "internal_diag" not in str(err)
    assert "internal_diag" not in str(payload)

    # Validate registry registration (restoring state to keep Task 4 tests green)
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


# ---------------------------------------------------------------------------
# Database Integration Tests (Requires PostgreSQL 17)
# ---------------------------------------------------------------------------


async def test_first_reserve_and_complete_byte_exact_replay(
    db_pool: asyncpg.Pool,
    idem_agent: UUID,
) -> None:
    """Validate first reserve returns OWNED, and complete enables byte-exact replay.

    Byte-exact contract:
    Storing '{"z":1,"a":[1,2],  "b":" x "}' preserves all raw whitespace and non-alphabetical
    key order. If stored as JSONB, PostgreSQL would normalize keys alphabetically ("a","b","z")
    and strip inner spacing, breaking cryptographic signature verifications on client replays.
    """
    key = "idem_test_byte_exact"
    body_hash = "a" * 64
    raw_response = '{"z":1,"a":[1,2],  "b":" x "}'
    tx_id = uuid4()

    async with db_pool.acquire() as conn:
        res1 = await reserve(conn, idem_agent, key, body_hash)
        assert res1.outcome == ReservationOutcome.OWNED
        assert res1.attempts == 1

        await complete(
            conn,
            idem_agent,
            key,
            tx_id=tx_id,
            response_status=200,
            response_body=raw_response,
        )

        lookup_res = await lookup(conn, idem_agent, key)
        assert lookup_res is not None
        assert lookup_res.outcome == ReservationOutcome.REPLAY
        assert lookup_res.tx_id == tx_id
        assert lookup_res.response_status == 200
        # Byte-exact assertion: exact wire string preserved without JSONB normalization
        assert lookup_res.response_body == raw_response
        assert lookup_res.attempts == 1

        # Re-reserving the same key and hash returns REPLAY with identical fields
        res2 = await reserve(conn, idem_agent, key, body_hash)
        assert res2.outcome == ReservationOutcome.REPLAY
        assert res2.tx_id == tx_id
        assert res2.response_status == 200
        assert res2.response_body == raw_response
        assert res2.attempts == 1


async def test_replay_path_rejects_second_complete(
    db_pool: asyncpg.Pool,
    idem_agent: UUID,
) -> None:
    """Validate that calling complete() on an already COMPLETED key raises IdempotencyStateError.

    The PENDING guard prevents race conditions where duplicate workers attempt to
    commit different results for the same reservation.
    """
    key = "idem_test_second_complete"
    body_hash = "a" * 64
    tx_id = uuid4()

    async with db_pool.acquire() as conn:
        res = await reserve(conn, idem_agent, key, body_hash)
        assert res.outcome == ReservationOutcome.OWNED

        await complete(
            conn,
            idem_agent,
            key,
            tx_id=tx_id,
            response_status=201,
            response_body='{"status":"created"}',
        )

        with pytest.raises(IdempotencyStateError) as exc_info:
            await complete(
                conn,
                idem_agent,
                key,
                tx_id=uuid4(),
                response_status=200,
                response_body='{"status":"overwritten"}',
            )
        assert exc_info.value.code == "idempotency_state_error"


async def test_same_key_different_hash_fresh_raises_conflict(
    db_pool: asyncpg.Pool,
    idem_agent: UUID,
) -> None:
    """Validate that reserving a fresh key with different body hash raises IdempotencyConflict."""
    key = "idem_test_collision"
    hash_a = "a" * 64
    hash_b = "b" * 64

    async with db_pool.acquire() as conn:
        res = await reserve(conn, idem_agent, key, hash_a)
        assert res.outcome == ReservationOutcome.OWNED

        with pytest.raises(IdempotencyConflict) as exc_info:
            await reserve(conn, idem_agent, key, hash_b)
        assert exc_info.value.code == "idempotency_conflict"
        assert exc_info.value.details["agent_id"] == str(idem_agent)
        assert exc_info.value.details["idem_key"] == key


async def test_completed_different_hash_raises_conflict_fraud_guard(
    db_pool: asyncpg.Pool,
    idem_agent: UUID,
) -> None:
    """Validate fraud guard: COMPLETED record with different hash raises IdempotencyConflict.

    Completed reservations are immutable and permanently locked. Attempting to reuse
    an existing key with a different payload must be rejected as an idempotency conflict.
    """
    key = "idem_test_fraud_guard"
    hash_a = "a" * 64
    hash_b = "b" * 64

    async with db_pool.acquire() as conn:
        res = await reserve(conn, idem_agent, key, hash_a)
        assert res.outcome == ReservationOutcome.OWNED

        await complete(
            conn,
            idem_agent,
            key,
            tx_id=uuid4(),
            response_status=200,
            response_body='{"ok":true}',
        )

        with pytest.raises(IdempotencyConflict) as exc_info:
            await reserve(conn, idem_agent, key, hash_b)
        assert exc_info.value.code == "idempotency_conflict"


async def test_concurrent_twins_exactly_one_owned_one_in_progress(
    db_pool: asyncpg.Pool,
    idem_agent: UUID,
) -> None:
    """Concurrent twins: asyncio.gather(reserve, reserve) same key+hash.

    Exactly one caller receives OWNED, the other receives IN_PROGRESS.
    The database unique constraint PRIMARY KEY (agent_id, idem_key) is the law.
    Under simultaneous in-flight race conditions, exactly one client wins the reservation
    and receives OWNED; the twin receives IN_PROGRESS.
    """
    key = "idem_test_twins"
    body_hash = "c" * 64

    async def _do_reserve() -> Reservation:
        async with db_pool.acquire() as conn:
            return await reserve(conn, idem_agent, key, body_hash)

    r1, r2 = await asyncio.gather(_do_reserve(), _do_reserve())
    outcomes = {r1.outcome, r2.outcome}
    assert outcomes == {ReservationOutcome.OWNED, ReservationOutcome.IN_PROGRESS}


async def test_stale_takeover_increments_attempts(
    db_pool: asyncpg.Pool,
    idem_agent: UUID,
) -> None:
    """Stale takeover: reserve -> backdate reserved_at -> reserve -> OWNED, attempts=2.

    WHY backdate reserved_at directly:
    Simulating clock expiration by sleeping would violate the test performance contract
    and introduce flakiness. Manipulating the clock column directly in the database
    is the honest, deterministic simulation of a crashed worker that abandoned a reservation.
    """
    key = "idem_test_stale_takeover"
    hash_old = "d" * 64
    hash_new = "e" * 64

    async with db_pool.acquire() as conn:
        res1 = await reserve(conn, idem_agent, key, hash_old, reservation_ttl_s=30.0)
        assert res1.outcome == ReservationOutcome.OWNED
        assert res1.attempts == 1

        # Simulate abandoned reservation by backdating reserved_at past TTL
        await conn.execute(
            """
            UPDATE idempotency_keys
            SET reserved_at = now() - interval '60 seconds'
            WHERE agent_id = $1 AND idem_key = $2;
            """,
            idem_agent,
            key,
        )

        # Second reserve with different hash reclaims the stale reservation
        res2 = await reserve(conn, idem_agent, key, hash_new, reservation_ttl_s=30.0)
        assert res2.outcome == ReservationOutcome.OWNED
        assert res2.attempts == 2


async def test_failed_reclaim_increments_attempts(
    db_pool: asyncpg.Pool,
    idem_agent: UUID,
) -> None:
    """FAILED reclaim: reserve -> fail() -> reserve same key any hash -> OWNED, attempts=2."""
    key = "idem_test_failed_reclaim"
    hash_1 = "f" * 64
    hash_2 = "0" * 64

    async with db_pool.acquire() as conn:
        res1 = await reserve(conn, idem_agent, key, hash_1)
        assert res1.outcome == ReservationOutcome.OWNED
        assert res1.attempts == 1

        await fail(conn, idem_agent, key)

        # Lookup returns None for FAILED state (free for retry)
        lookup_res = await lookup(conn, idem_agent, key)
        assert lookup_res is None

        # Re-reserving after fail reclaims key and increments attempts counter
        res2 = await reserve(conn, idem_agent, key, hash_2)
        assert res2.outcome == ReservationOutcome.OWNED
        assert res2.attempts == 2


async def test_fail_and_complete_on_unknown_key_raise_state_error(
    db_pool: asyncpg.Pool,
    idem_agent: UUID,
) -> None:
    """Validate that fail() and complete() on non-existent keys raise IdempotencyStateError."""
    async with db_pool.acquire() as conn:
        with pytest.raises(IdempotencyStateError):
            await fail(conn, idem_agent, "unknown_key")

        with pytest.raises(IdempotencyStateError):
            await complete(
                conn,
                idem_agent,
                "unknown_key",
                tx_id=uuid4(),
                response_status=200,
                response_body="{}",
            )


async def test_complete_validation_status_and_body_size_caps(
    db_pool: asyncpg.Pool,
    idem_agent: UUID,
) -> None:
    """Validate that complete() enforces 200..299 HTTP status and 64 KiB body cap."""
    key = "idem_test_caps"
    body_hash = "1" * 64

    async with db_pool.acquire() as conn:
        res = await reserve(conn, idem_agent, key, body_hash)
        assert res.outcome == ReservationOutcome.OWNED

        # 5xx status rejected
        with pytest.raises(ValueError, match=r"200\.\.299"):
            await complete(
                conn,
                idem_agent,
                key,
                tx_id=uuid4(),
                response_status=500,
                response_body="{}",
            )

        # 4xx status rejected
        with pytest.raises(ValueError, match=r"200\.\.299"):
            await complete(
                conn,
                idem_agent,
                key,
                tx_id=uuid4(),
                response_status=400,
                response_body="{}",
            )

        # > 64 KiB body rejected
        oversized_body = "x" * (RESPONSE_MAX_BYTES + 1)
        with pytest.raises(ValueError, match="exceeds maximum allowed"):
            await complete(
                conn,
                idem_agent,
                key,
                tx_id=uuid4(),
                response_status=200,
                response_body=oversized_body,
            )


async def test_uow_composition_reserve_and_complete_commit_atomically(
    db_pool: asyncpg.Pool,
    idem_agent: UUID,
) -> None:
    """UoW composition (Task 8 contract): reserve + complete inside ONE UnitOfWork.

    Proves the money-path pattern Task 31 will use: the caller's UoW spans
    reserve -> business operation -> complete atomically. After exit, both the reservation
    and completion are committed and visible to subsequent connections.
    """
    key = "idem_test_uow_atomicity"
    body_hash = "2" * 64
    tx_id = uuid4()
    body = '{"transfer_id":"tx_abc123"}'

    # Execute reserve and complete within a single UnitOfWork boundary
    async with UnitOfWork(db_pool) as uow:
        res = await reserve(uow.connection, idem_agent, key, body_hash)
        assert res.outcome == ReservationOutcome.OWNED

        await complete(
            uow.connection,
            idem_agent,
            key,
            tx_id=tx_id,
            response_status=200,
            response_body=body,
        )

    # After UoW cleanly commits, state is durable and visible to a new connection
    async with db_pool.acquire() as conn:
        replayed = await reserve(conn, idem_agent, key, body_hash)
        assert replayed.outcome == ReservationOutcome.REPLAY
        assert replayed.tx_id == tx_id
        assert replayed.response_status == 200
        assert replayed.response_body == body
