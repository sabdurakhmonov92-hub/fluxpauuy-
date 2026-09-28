"""Idempotency fast-path: Redis tier over the database state machine.

Blueprint §3 & Task 22 Design Invariants:
1. Two-Tier Idempotency Model (The Hierarchy):
   Redis fast-path (this module) accelerates hot keys (0.3ms blueprint promise);
   PostgreSQL (Task 11) is the sole authoritative source of truth. Redis may miss,
   evict, failover, or experience network partitions; PostgreSQL enforces unique
   constraints at the engine level to make double-debit mathematically impossible.
   This layer NEVER decides money; it accelerates decisions the DB tier guarantees.
2. Byte-Exact Wire Replay:
   Cached responses are stored as raw bytes: `b"<3-digit-ASCII-status>|" + raw_body_bytes`
   (e.g. `b"201|{\"status\":\"paid\"}"`). Zero encode/decode overhead, body bytes
   roundtrip EXACTLY to preserve cryptographic client signatures (Task 11 & 19 law).
   Content-type is assumed application/json per Task 24 contract.
3. 64 KiB Cap Philosophy:
   max_cache_bytes defaults to 65_536 (64 KiB), mirroring the unified platform cap
   philosophy across Task 9 (validate_payload), Task 11 (RESPONSE_MAX_BYTES), and
   Task 21 (MAX_BODY_BYTES). Payloads exceeding 64 KiB bypass fast-path caching and
   release the lock, allowing cold DB tier processing.
4. Single-RTT Pipeline:
   begin() batches SET lock NX EX ttl, GET lock, and GET resp into a single Redis
   pipeline roundtrip. The 0.3ms blueprint guarantee demands exactly one network flight.
5. Evicted-Lock Self-Repair:
   The distributed lock can expire or be evicted under memory pressure while the
   cached response outlives it. If SETNX succeeds but GET resp finds a cached response,
   the classifier self-repairs by emitting REPLAY_CACHED immediately without handler
   re-execution.
6. Stranded-Lock Elimination:
   Lock STAYS on success (as the tombstone routing duplicates to replay). Lock is
   DELETED on non-2xx failures, exceptions, or oversized payloads so legitimate client
   retries are never blocked.
7. UTC-Free Design:
   Idempotency keys are TTL-bound in Redis (24h default); no calendar-day keys are used.
8. Logging Hygiene:
   Absence beats redaction (Task 5 law). Log events record outcome, agent_id, and
   idem_key only; NEVER response bodies or request payloads.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Final

import redis.asyncio as redis_async

from fluxpay.gateway.canonical import validate_idempotency_key
from fluxpay.shared.logging import get_logger

__all__ = [
    "FastPathOutcome",
    "IdempotencyFastPath",
    "classify_fastpath",
    "fastpath_keys",
    "pack_response",
    "parse_response",
]

logger = get_logger("fluxpay.gateway.idempotency")

# SHA-256 hex digest validator: exactly 64 lowercase hexadecimal characters.
_HASH_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")


class FastPathOutcome(StrEnum):
    """Fast-path classification outcomes."""

    PROCEED = "PROCEED"  # lock acquired + no cached response → execute
    REPLAY_CACHED = "REPLAY_CACHED"  # return cached response, handler NEVER runs
    IN_PROGRESS = "IN_PROGRESS"  # same key+hash, twin in flight → 409
    CONFLICT = "CONFLICT"  # same key, DIFFERENT body → 409 (fraud guard)


def _validate_body_hash(body_hash: str) -> None:
    """Validate sha256 hex format at boundary; fail loud on programming errors."""
    if not isinstance(body_hash, str) or not _HASH_PATTERN.match(body_hash):
        raise ValueError(
            f"Invalid body_hash format: expected 64 lowercase hex characters, got {body_hash!r}"
        )


def classify_fastpath(
    *,
    acquired: bool,
    stored_hash: str | None,
    cached: bytes | None,
    body_hash: str,
) -> FastPathOutcome:
    """Classify incoming request idempotency state without I/O.

    Matrix:
    - acquired + cached is None → PROCEED (fresh execution)
    - acquired + cached present → REPLAY_CACHED (evicted-lock self-repair)
      WHY this row exists: The lock can expire or be evicted under Redis memory pressure
      while the cached response outlives it (independent TTLs / eviction). Without this
      row, an evicted lock causes cold re-execution. With it, the hot path self-repairs:
      one extra GET in the pipeline recovers the cached response with zero extra RTT.
    - not acquired + stored_hash != body_hash → CONFLICT
      (matches Task 11 DB fraud guard: key reused with different request payload)
    - not acquired + stored_hash == body_hash + cached present → REPLAY_CACHED
      (duplicate request after successful execution; immediate replay)
    - not acquired + stored_hash == body_hash + cached is None → IN_PROGRESS
      (twin concurrent request in flight; mapped to 409 per Task 11 taxonomy)
    """
    _validate_body_hash(body_hash)

    if acquired:
        # Acquired lock: fresh request or evicted-lock self-repair
        if cached is None:
            return FastPathOutcome.PROCEED
        return FastPathOutcome.REPLAY_CACHED

    # Lock not acquired (held by concurrent twin or already finished request)
    if stored_hash != body_hash:
        return FastPathOutcome.CONFLICT
    if cached is not None:
        return FastPathOutcome.REPLAY_CACHED
    return FastPathOutcome.IN_PROGRESS


def fastpath_keys(agent_id: str, idem_key: str) -> tuple[str, str]:
    """Generate Redis cluster co-located keys for idempotency lock and response cache.

    WHY hash-tag {agent_id}:
    In Redis Cluster, slot hashing uses the substring within braces '{...}'. Hash-tagging
    guarantees that lock_key and resp_key always hash to the exact same cluster node and
    slot, enabling atomic pipeline and multi-key evaluation without CROSSSLOT errors.
    """
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError("agent_id must be a non-empty string")
    validate_idempotency_key(idem_key)
    lock_key = f"flx:idem:{{{agent_id}}}:{idem_key}"
    resp_key = f"flx:idem:{{{agent_id}}}:{idem_key}:resp"
    return lock_key, resp_key


def pack_response(status: int, body: bytes) -> bytes:
    """Pack HTTP status code and raw response body bytes into cache format.

    Format: b"<3-digit-status>|" + body
    Byte-exact contract: Body bytes are stored without re-encoding or JSON transformation.
    """
    if not (200 <= status <= 299):
        raise ValueError(f"status must be in 200..299 range, got {status}")
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError("body must be bytes-like")
    return f"{status:03d}".encode("ascii") + b"|" + bytes(body)


def parse_response(cached: bytes) -> tuple[int, bytes]:
    """Parse cached wire format into HTTP status code and raw body bytes.

    Format: b"<3-digit-status>|" + body
    """
    if not isinstance(cached, (bytes, bytearray)):
        raise TypeError("cached must be bytes-like")
    if len(cached) < 4 or cached[3:4] != b"|":
        raise ValueError("malformed cached response: missing 3-digit status and pipe separator")

    status_str = cached[:3].decode("ascii", errors="replace")
    if not status_str.isdigit():
        raise ValueError(f"malformed status code prefix: {status_str!r}")

    status = int(status_str)
    if not (200 <= status <= 299):
        raise ValueError(f"cached status code must be in 200..299 range, got {status}")

    return status, bytes(cached[4:])


class IdempotencyFastPath:
    """Redis fast-path tier accelerating idempotency checks over the PostgreSQL state machine.

    Architecture Invariants:
    1. Layering: Redis tier provides hot-path acceleration (0.3ms blueprint promise);
       PostgreSQL (Task 11) is the authoritative source of truth. Redis may evict or
       drop keys; database unique constraints guarantee money safety.
    2. Single Roundtrip Pipeline: begin() executes SET NX + GET lock + GET resp in ONE
       pipeline roundtrip.
    3. Self-Healing Eviction: Evicted locks with surviving response keys self-repair
       and replay immediately without hitting the database.
    4. Stranded-Lock Prevention: Failed or aborted executions release the lock so clients
       can retry safely.
    5. 64 KiB Cap Philosophy: Mirrors Task 9/11 cap philosophy. Payloads exceeding
       max_cache_bytes (64 KiB) release lock and bypass caching.
    """

    def __init__(
        self,
        valkey: redis_async.Redis,
        *,
        ttl_s: int,
        max_cache_bytes: int = 65_536,
    ) -> None:
        if ttl_s <= 0:
            raise ValueError(f"ttl_s must be positive, got {ttl_s}")
        if max_cache_bytes <= 0:
            raise ValueError(f"max_cache_bytes must be positive, got {max_cache_bytes}")
        self._valkey: redis_async.Redis = valkey
        self._ttl_s: int = ttl_s
        self._max_cache_bytes: int = max_cache_bytes

    @property
    def ttl_s(self) -> int:
        return self._ttl_s

    @property
    def max_cache_bytes(self) -> int:
        return self._max_cache_bytes

    async def begin(
        self,
        agent_id: str,
        idem_key: str,
        body_hash: str,
    ) -> tuple[FastPathOutcome, bytes | None]:
        """Attempt to acquire lock and evaluate idempotency fast-path in one pipeline roundtrip.

        Returns (outcome, cached_bytes | None). When outcome is REPLAY_CACHED, cached_bytes
        contains the raw wire payload b"###|" + body_bytes.
        """
        _validate_body_hash(body_hash)
        lock_key, resp_key = fastpath_keys(agent_id, idem_key)

        # ONE pipeline roundtrip: SET lock NX EX ttl + GET lock + GET resp
        # WHY pipeline not two awaits: the 0.3ms blueprint number is ONE roundtrip;
        # two awaits = two roundtrips.
        pipe = self._valkey.pipeline(transaction=False)
        pipe.set(lock_key, body_hash, nx=True, ex=self._ttl_s)
        pipe.get(lock_key)
        pipe.get(resp_key)
        set_res, stored_raw, cached_raw = await pipe.execute()

        acquired = bool(set_res)
        stored_hash: str | None = None
        if isinstance(stored_raw, (bytes, bytearray)):
            stored_hash = stored_raw.decode("ascii", errors="replace")
        elif isinstance(stored_raw, str):
            stored_hash = stored_raw

        cached: bytes | None = None
        if isinstance(cached_raw, (bytes, bytearray)):
            cached = bytes(cached_raw)
        elif isinstance(cached_raw, str):
            cached = cached_raw.encode("utf-8")

        outcome = classify_fastpath(
            acquired=acquired,
            stored_hash=stored_hash,
            cached=cached,
            body_hash=body_hash,
        )

        logger.info(
            "fastpath_begin",
            outcome=outcome.value,
            agent_id=agent_id,
            idem_key=idem_key,
        )

        if outcome == FastPathOutcome.REPLAY_CACHED:
            return outcome, cached
        return outcome, None

    async def finish(
        self,
        agent_id: str,
        idem_key: str,
        *,
        status: int,
        body: bytes,
    ) -> None:
        """Store completed 2xx response in Redis cache; delete lock on failure or oversize.

        - 2xx and len(body) <= max_cache_bytes → SET resp EX ttl (lock STAYS — the tombstone
          that routes duplicates to replay).
        - non-2xx OR too-big → DELETE lock. WHY: A failed execution must not lock the key
          (client retry is legitimate — Task 11 FAILED state mirrors this); a >64 KiB response
          bypasses the fast path entirely and releases (DB tier would reject it too —
          consistent caps; duplicates re-execute, money still safe).
        - status outside 200-299 passed here = middleware bug → ValueError (fail loud;
          finish only sees completed responses).
        """
        if not (200 <= status <= 299):
            await self.release(agent_id, idem_key)
            raise ValueError(
                f"status outside 200..299 ({status}) passed to finish; "
                "completed responses must be 2xx"
            )

        _lock_key, resp_key = fastpath_keys(agent_id, idem_key)

        if len(body) > self._max_cache_bytes:
            # Over 64 KiB response: delete lock and bypass caching
            await self.release(agent_id, idem_key)
            logger.info(
                "fastpath_oversized_bypassed",
                agent_id=agent_id,
                idem_key=idem_key,
                size_bytes=len(body),
            )
            return

        packed = pack_response(status, body)
        await self._valkey.set(resp_key, packed, ex=self._ttl_s)
        logger.info(
            "fastpath_finished",
            outcome="CACHED",
            agent_id=agent_id,
            idem_key=idem_key,
        )

    async def release(self, agent_id: str, idem_key: str) -> None:
        """Delete lock key to allow safe retry on failure or exception (idempotent)."""
        lock_key, _ = fastpath_keys(agent_id, idem_key)
        await self._valkey.delete(lock_key)
        logger.info(
            "fastpath_released",
            outcome="RELEASED",
            agent_id=agent_id,
            idem_key=idem_key,
        )
