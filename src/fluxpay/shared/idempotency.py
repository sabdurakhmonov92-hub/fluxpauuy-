"""Distributed idempotency state machine and database layer for FluxPay.

Blueprint §3 & Task 11 Design Invariants:
1. Two-Tier Idempotency Model:
   Redis fast-path (Task 22) caches hot keys; PostgreSQL (this module) is the sole
   authoritative source of truth. Redis may evict or failover; PostgreSQL enforces
   unique constraints at the engine level to make double-debit impossible.
2. Caller-Owned Transaction Boundary:
   Database functions take an active asyncpg.Connection provided by the caller's UnitOfWork
   (Task 8). The idempotency reservation and business result commit together atomically.
3. Byte-Exact Wire Replay:
   response_body is stored as raw TEXT, not JSONB. Autonomous AI agents verify cryptographic
   signatures over byte-exact wire responses; JSONB normalization would alter key order
   or whitespace, invalidating client signatures on replay.
4. Self-Healing Stale Takeover:
   Crashed workers abandoning PENDING reservations are safely reclaimed via atomic conditional
   UPDATE governed by the database clock.
5. Pure Decision Classifier:
   State machine classification logic has zero I/O and zero asyncpg dependencies, enabling
   exhaustive in-memory unit testing of the complete decision matrix.
"""

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]

from fluxpay.shared.errors import IdempotencyConflict, IdempotencyStateError
from fluxpay.shared.logging import get_logger

__all__ = [
    "RESPONSE_MAX_BYTES",
    "ClassificationAction",
    "ExistingRecord",
    "IdempotencyState",
    "Reservation",
    "ReservationOutcome",
    "_Outcome",
    "claim_tx",  # --- Task 31 append
    "classify",
    "complete",
    "fail",
    "lookup",
    "reserve",
]

logger = get_logger(__name__)

# 64 KiB cap philosophy (mirrors Task 9 validate_payload invariant).
# WHY: Prevents runaway payload bloat in database row storage while comfortably
# fitting standard JSON payment API responses and metadata envelopes.
RESPONSE_MAX_BYTES: Final[int] = 65_536

# SHA-256 hex digest validator: exactly 64 lowercase hexadecimal characters.
_HASH_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")


class IdempotencyState(StrEnum):
    """Lifecycle state of an idempotency reservation in PostgreSQL."""

    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ReservationOutcome(StrEnum):
    """Outcome returned to caller after attempting to reserve or lookup a key."""

    OWNED = "OWNED"  # Caller owns reservation — proceed with business logic
    IN_PROGRESS = "IN_PROGRESS"  # Same key+hash in flight — caller maps to HTTP 409
    REPLAY = "REPLAY"  # COMPLETED with same hash — return cached wire response


class ClassificationAction(StrEnum):
    """Internal decision states emitted by the pure classifier."""

    REPLAY = "REPLAY"
    IN_PROGRESS = "IN_PROGRESS"
    CONFLICT = "CONFLICT"
    RECLAIMABLE = "RECLAIMABLE"


@dataclass(frozen=True, slots=True)
class Reservation:
    """Caller-facing reservation result holding execution permissions and cached responses."""

    outcome: ReservationOutcome
    tx_id: UUID | None
    response_status: int | None
    response_body: str | None
    attempts: int


@dataclass(frozen=True, slots=True)
class ExistingRecord:
    """Input representation of an existing database row passed to the pure classifier."""

    body_hash: str
    state: IdempotencyState
    reserved_at: datetime
    tx_id: UUID | None = None
    response_status: int | None = None
    response_body: str | None = None
    attempts: int = 1


@dataclass(frozen=True, slots=True)
class _Outcome:
    """Pure classifier output holding decision action and surfaced replay fields."""

    action: ClassificationAction
    tx_id: UUID | None = None
    response_status: int | None = None
    response_body: str | None = None

    def __eq__(self, other: object) -> bool:
        """Allow direct equality comparison with ClassificationAction or _Outcome."""
        if isinstance(other, (ClassificationAction, str)):
            return self.action == other
        if isinstance(other, _Outcome):
            return (
                self.action == other.action
                and self.tx_id == other.tx_id
                and self.response_status == other.response_status
                and self.response_body == other.response_body
            )
        return False


def _validate_body_hash(body_hash: str) -> None:
    """Validate sha256 hex format at boundary; fail loud on programming errors."""
    if not _HASH_PATTERN.match(body_hash):
        raise ValueError(
            f"Invalid body_hash format: expected 64 lowercase hex characters, got {body_hash!r}"
        )


def classify(
    record: ExistingRecord | None,
    *,
    body_hash: str,
    now: datetime,
    reservation_ttl_s: float,
) -> _Outcome:
    """Classify reservation state against incoming request parameters without I/O.

    Zero I/O, zero asyncpg imports: pure domain decision matrix.

    Decision Matrix Invariants:
    - record is None: Cannot happen post-INSERT in normal operation; defensive branch
      treats as CONFLICT to prevent duplicate debit.
    - COMPLETED + hash match -> REPLAY: Returns cached wire response; prevents second debit.
    - COMPLETED + hash mismatch -> CONFLICT: Completed results are NEVER reclaimable.
      Replaying a different request body under an already-used key is a fraud attack surface.
    - PENDING + hash mismatch + fresh -> CONFLICT: Key collision with concurrent live request.
    - PENDING + hash match + fresh -> IN_PROGRESS: Concurrent twin request in flight.
    - PENDING (any hash) + STALE (now - reserved_at > ttl) -> RECLAIMABLE:
      WHY any hash: Crashed worker abandoned key; new request is legitimate retry.
    - FAILED (any hash, any age) -> RECLAIMABLE: Aborted before business completion; safe to retry.
    """
    _validate_body_hash(body_hash)
    if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
        raise ValueError("now must be timezone-aware (tz-aware)")

    # Defensive guard: non-existent record post-INSERT treated as conflict
    if record is None:
        return _Outcome(action=ClassificationAction.CONFLICT)

    # COMPLETED state: completed results are immutable and permanent
    if record.state == IdempotencyState.COMPLETED:
        if record.body_hash == body_hash:
            # COMPLETED + hash match -> REPLAY (the money-saver: no second debit, ever)
            return _Outcome(
                action=ClassificationAction.REPLAY,
                tx_id=record.tx_id,
                response_status=record.response_status,
                response_body=record.response_body,
            )
        # COMPLETED + hash mismatch -> CONFLICT (completed results are NEVER reclaimable)
        return _Outcome(action=ClassificationAction.CONFLICT)

    # FAILED state: previous attempt crashed or explicitly failed before business completion
    if record.state == IdempotencyState.FAILED:
        # FAILED (any hash, any age) -> RECLAIMABLE
        return _Outcome(action=ClassificationAction.RECLAIMABLE)

    # PENDING state: evaluate staleness against reservation TTL
    if record.state == IdempotencyState.PENDING:
        age_seconds = (now - record.reserved_at).total_seconds()
        # Strict > boundary: age == ttl exactly is NOT stale
        if age_seconds > reservation_ttl_s:
            # PENDING (any hash) + STALE -> RECLAIMABLE
            return _Outcome(action=ClassificationAction.RECLAIMABLE)

        # Fresh PENDING reservation
        if record.body_hash == body_hash:
            # PENDING + hash match + fresh -> IN_PROGRESS
            return _Outcome(action=ClassificationAction.IN_PROGRESS)

        # PENDING + hash mismatch + fresh -> CONFLICT (live collision)
        return _Outcome(action=ClassificationAction.CONFLICT)


async def reserve(
    conn: asyncpg.Connection,
    agent_id: UUID,
    idem_key: str,
    body_hash: str,
    *,
    reservation_ttl_s: float = 30.0,
) -> Reservation:
    """Reserve an idempotency key atomically or take over a stale reservation.

    Step 1: Attempt initial INSERT with ON CONFLICT DO NOTHING. If inserted, caller
            owns the reservation (attempts=1).
    Step 2: On conflict, attempt atomic conditional UPDATE to reclaim if state is FAILED
            or PENDING older than reservation_ttl_s.
            WHY conditional UPDATE: In a race between concurrent reclaimers, exactly one
            UPDATE matches. The DB clock owns staleness (single authority).
    Step 3: If conditional UPDATE missed, query current row and classify. REPLAY/IN_PROGRESS
            return mapped Reservation; CONFLICT raises IdempotencyConflict. If RECLAIMABLE,
            loops step 2 (max 2 iterations) to resolve transient clock skew before raising
            IdempotencyStateError.
    """
    _validate_body_hash(body_hash)

    # Step 1: Initial atomic reservation attempt
    insert_row = await conn.fetchrow(
        """
        INSERT INTO idempotency_keys (
            agent_id, idem_key, body_hash, state, attempts, reserved_at, created_at
        )
        VALUES ($1, $2, $3, 'PENDING', 1, now(), now())
        ON CONFLICT (agent_id, idem_key) DO NOTHING
        RETURNING attempts;
        """,
        agent_id,
        idem_key,
        body_hash,
    )
    if insert_row is not None:
        return Reservation(
            outcome=ReservationOutcome.OWNED,
            tx_id=None,
            response_status=None,
            response_body=None,
            attempts=int(insert_row["attempts"]),
        )

    # Step 2: Atomic takeover attempt on existing FAILED or stale PENDING record
    takeover_row = await conn.fetchrow(
        """
        UPDATE idempotency_keys
        SET state = 'PENDING',
            body_hash = $3,
            reserved_at = now(),
            attempts = attempts + 1
        WHERE agent_id = $1
          AND idem_key = $2
          AND state IN ('PENDING', 'FAILED')
          AND (
              state = 'FAILED'
              OR reserved_at < now() - make_interval(secs => $4)
          )
        RETURNING attempts;
        """,
        agent_id,
        idem_key,
        body_hash,
        reservation_ttl_s,
    )
    if takeover_row is not None:
        attempts = int(takeover_row["attempts"])
        logger.warning(
            "idempotency_reservation_reclaimed",
            agent_id=str(agent_id),
            idem_key=idem_key,
            outcome="OWNED",
            attempts=attempts,
        )
        return Reservation(
            outcome=ReservationOutcome.OWNED,
            tx_id=None,
            response_status=None,
            response_body=None,
            attempts=attempts,
        )

    # Step 3: Classify current record and converge bounded loop
    for _ in range(2):
        row = await conn.fetchrow(
            """
            SELECT body_hash, state, reserved_at, tx_id, response_status, response_body,
                   attempts, now() AS db_now
            FROM idempotency_keys
            WHERE agent_id = $1 AND idem_key = $2;
            """,
            agent_id,
            idem_key,
        )
        if row is None:
            record: ExistingRecord | None = None
            db_now = datetime.now(UTC)
            current_attempts = 1
        else:
            record = ExistingRecord(
                body_hash=str(row["body_hash"]),
                state=IdempotencyState(row["state"]),
                reserved_at=row["reserved_at"],
                tx_id=row["tx_id"],
                response_status=row["response_status"],
                response_body=row["response_body"],
                attempts=int(row["attempts"]),
            )
            db_now = row["db_now"]
            current_attempts = int(row["attempts"])

        outcome = classify(
            record,
            body_hash=body_hash,
            now=db_now,
            reservation_ttl_s=reservation_ttl_s,
        )

        if outcome.action == ClassificationAction.REPLAY:
            return Reservation(
                outcome=ReservationOutcome.REPLAY,
                tx_id=outcome.tx_id,
                response_status=outcome.response_status,
                response_body=outcome.response_body,
                attempts=current_attempts,
            )
        if outcome.action == ClassificationAction.IN_PROGRESS:
            return Reservation(
                outcome=ReservationOutcome.IN_PROGRESS,
                tx_id=None,
                response_status=None,
                response_body=None,
                attempts=current_attempts,
            )
        if outcome.action == ClassificationAction.CONFLICT:
            logger.warning(
                "idempotency_conflict_detected",
                agent_id=str(agent_id),
                idem_key=idem_key,
                outcome="CONFLICT",
            )
            raise IdempotencyConflict(details={"agent_id": str(agent_id), "idem_key": idem_key})
        if outcome.action == ClassificationAction.RECLAIMABLE:
            retry_takeover = await conn.fetchrow(
                """
                UPDATE idempotency_keys
                SET state = 'PENDING',
                    body_hash = $3,
                    reserved_at = now(),
                    attempts = attempts + 1
                WHERE agent_id = $1
                  AND idem_key = $2
                  AND state IN ('PENDING', 'FAILED')
                  AND (
                      state = 'FAILED'
                      OR reserved_at < now() - make_interval(secs => $4)
                  )
                RETURNING attempts;
                """,
                agent_id,
                idem_key,
                body_hash,
                reservation_ttl_s,
            )
            if retry_takeover is not None:
                attempts = int(retry_takeover["attempts"])
                logger.warning(
                    "idempotency_reservation_reclaimed",
                    agent_id=str(agent_id),
                    idem_key=idem_key,
                    outcome="OWNED",
                    attempts=attempts,
                )
                return Reservation(
                    outcome=ReservationOutcome.OWNED,
                    tx_id=None,
                    response_status=None,
                    response_body=None,
                    attempts=attempts,
                )

    # Bounded iterations exhausted without convergence: trigger operational alarm
    logger.error(
        "idempotency_unsettled_state_alarm",
        agent_id=str(agent_id),
        idem_key=idem_key,
        outcome="UNSETTLED",
    )
    raise IdempotencyStateError(
        details={
            "agent_id": str(agent_id),
            "idem_key": idem_key,
            "reason": "unsettled reservation state after bounded takeover retries",
        }
    )


async def complete(
    conn: asyncpg.Connection,
    agent_id: UUID,
    idem_key: str,
    *,
    tx_id: UUID,
    response_status: int,
    response_body: str,
) -> None:
    """Complete a PENDING idempotency reservation with business result and response wire bytes.

    Invariants:
    - response_status must be in 200..299 range (only successes are replayable;
      failures retry under client semantics).
    - response_body byte size must not exceed RESPONSE_MAX_BYTES (64 KiB cap philosophy).
    - PENDING guard: UPDATE strictly filters on state = 'PENDING'. If 0 rows are returned,
      the reservation was either missing or hijacked by a concurrent reclaim takeover.
      Caching must abort immediately by raising IdempotencyStateError.
    """
    if not (200 <= response_status <= 299):
        raise ValueError(f"response_status must be in 200..299 range, got {response_status}")

    body_bytes = response_body.encode("utf-8")
    if len(body_bytes) > RESPONSE_MAX_BYTES:
        raise ValueError(
            f"response_body size ({len(body_bytes)} bytes) exceeds maximum "
            f"allowed {RESPONSE_MAX_BYTES} bytes"
        )

    result = await conn.execute(
        """
        UPDATE idempotency_keys
        SET state = 'COMPLETED',
            tx_id = $3,
            response_status = $4,
            response_body = $5,
            completed_at = now()
        WHERE agent_id = $1
          AND idem_key = $2
          AND state = 'PENDING';
        """,
        agent_id,
        idem_key,
        tx_id,
        response_status,
        response_body,
    )
    if result == "UPDATE 0":
        logger.error(
            "idempotency_complete_state_guard_failed",
            agent_id=str(agent_id),
            idem_key=idem_key,
            outcome="STATE_ERROR",
        )
        raise IdempotencyStateError(
            details={
                "agent_id": str(agent_id),
                "idem_key": idem_key,
                "reason": "reservation moved or not in PENDING state during completion",
            }
        )


async def fail(
    conn: asyncpg.Connection,
    agent_id: UUID,
    idem_key: str,
) -> None:
    """Transition reservation from PENDING to FAILED.

    WHY FAILED not DELETE:
    Preserves forensic audit trail and attempt counts for reconciliation anomaly
    detection (Task 41). Deleting rows destroys evidence of crashes and network
    partition retries. Pruning and table cleanup are deferred to a background
    worker in Phase 2.

    PENDING guard:
    Ensures that only PENDING reservations can transition to FAILED. If 0 rows match,
    the reservation was already moved or hijacked.
    """
    result = await conn.execute(
        """
        UPDATE idempotency_keys
        SET state = 'FAILED'
        WHERE agent_id = $1
          AND idem_key = $2
          AND state = 'PENDING';
        """,
        agent_id,
        idem_key,
    )
    if result == "UPDATE 0":
        logger.error(
            "idempotency_fail_state_guard_failed",
            agent_id=str(agent_id),
            idem_key=idem_key,
            outcome="STATE_ERROR",
        )
        raise IdempotencyStateError(
            details={
                "agent_id": str(agent_id),
                "idem_key": idem_key,
                "reason": "reservation moved or not in PENDING state during failure marking",
            }
        )


async def lookup(
    conn: asyncpg.Connection,
    agent_id: UUID,
    idem_key: str,
) -> Reservation | None:
    """Read-only idempotency key lookup for Task 22 GET-path checks.

    Mapping:
    - COMPLETED -> REPLAY-shaped Reservation with cached tx_id, status, and wire body
    - PENDING -> IN_PROGRESS-shaped Reservation
    - FAILED / not found -> None (key is free for reservation)
    """
    row = await conn.fetchrow(
        """
        SELECT state, tx_id, response_status, response_body, attempts
        FROM idempotency_keys
        WHERE agent_id = $1 AND idem_key = $2;
        """,
        agent_id,
        idem_key,
    )
    if row is None:
        return None

    state = str(row["state"])
    if state == IdempotencyState.COMPLETED.value:
        return Reservation(
            outcome=ReservationOutcome.REPLAY,
            tx_id=row["tx_id"],
            response_status=row["response_status"],
            response_body=row["response_body"],
            attempts=int(row["attempts"]),
        )
    if state == IdempotencyState.PENDING.value:
        return Reservation(
            outcome=ReservationOutcome.IN_PROGRESS,
            tx_id=None,
            response_status=None,
            response_body=None,
            attempts=int(row["attempts"]),
        )
    # FAILED state is treated as None (free to reserve)
    return None


# --- Task 31 append
async def claim_tx(
    conn: asyncpg.Connection,
    agent_id: UUID,
    idem_key: str,
    tx_id: UUID,
) -> bool:
    """Associate a deterministic tx_id with a PENDING reservation before ledger post.

    Returns True if claimed (or already claimed with the same tx_id), False otherwise.
    """
    row = await conn.fetchrow(
        """
        UPDATE idempotency_keys
        SET tx_id = $3
        WHERE agent_id = $1
          AND idem_key = $2
          AND state = 'PENDING'
          AND (tx_id IS NULL OR tx_id = $3)
        RETURNING tx_id;
        """,
        agent_id,
        idem_key,
        tx_id,
    )
    return row is not None
