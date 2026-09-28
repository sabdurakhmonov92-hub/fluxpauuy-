"""Merchant repository and settlement-path read-through cache for FluxPay.

Blueprint §1 Third-Party Merchants + §5 Account Topology + §7 Registry Lifecycle.

=============================================================================
CACHE VALUE & REGISTRY DESIGN DECISIONS (WHY THE SYSTEM IS BUILT THIS WAY)
=============================================================================

1. WHY CACHE UNDER EXTERNAL_ID KEY (The Single-Key Decision):
-------------------------------------------------------------
The payment processing path (Task 31) resolves incoming API requests by `external_id`
(the canonical business handle provided in payment payloads).
If we cached by `id` (UUID), the resolution path would require a database query to map
`external_id` -> `id` before checking Redis, which would double the cache-miss penalty
and destroy the read-through performance benefit on the hot path.
Resolution:
Redis caches the merchant record under key `flx:merchant:ext:{<external_id>}` (hash-tag law),
where the value carries the merchant UUID and all identity attributes.
Admin mutations (Task 27 provisioning, Task 29 admin updates) already operate on the
`external_id` handle and execute `invalidate(external_id)` directly.
Having ONE key provides ONE clear invalidation story. A secondary UUID-keyed cache is a
Phase 2 optimization only if profiling demonstrates high-volume internal lookups by UUID.

2. WHY IDENTITY IS SEPARATED FROM MONEY (No Balance Fields):
------------------------------------------------------------
`MerchantRecord` holds identity and lifecycle metadata ONLY:
    `id`, `external_id`, `name`, `active`, `version`, `created_at`, `updated_at`.
Under NO circumstances does `MerchantRecord` contain balance, ledger account ID, or currency limits.
Per Task 16's double-entry ledger architecture, `ledger_accounts` is the sole authoritative
source of financial truth. Caching balances in the registry would violate Task 16's
zero-balance-cache doctrine, introducing devastating race conditions, double-spend
vulnerabilities, or stale ledger state.
Identity and money remain strictly separated.

3. WHY ACTIVE=FALSE IS RETURNED, NOT FILTERED (Layering Discipline):
-------------------------------------------------------------------
Unlike `AgentRepo` (Task 23), which filters out inactive agents because it serves the gateway
authentication gate (where an inactive agent must be rejected as unauthenticated), `MerchantRepo`
serves the business payment path (Task 31).
Lookup and policy are separate concerns:
`MerchantRepo.resolve()` reports the objective identity truth: the merchant exists, and their
current state is `active=False`.
The payment orchestrator (Task 31) evaluates this truth and raises a domain-specific
`ValidationError("Merchant is inactive")` with appropriate HTTP 422 status and error code.
Filtering inactive merchants at the repository layer would conflate "merchant does not exist"
(HTTP 404 / unknown merchant) with "merchant is suspended" (HTTP 422 / forbidden action).

4. WHY MERCHANT_CACHE_TTL_S = 300s (The 5-Minute Bound):
---------------------------------------------------------
Merchants are legal business entities whose status and operational profile change far less
frequently than agents. A 300-second (5-minute) TTL is an honest balance between low database
read pressure and eventual consistency. Active invalidation on mutation via `invalidate()`
guarantees immediate freshness in Task 27/29; the 300s TTL serves as the safety net for
multi-instance deployments prior to distributed invalidation pub/sub.

5. WHY NO NEGATIVE CACHING:
---------------------------
When an `external_id` is absent from PostgreSQL, `resolve()` returns `None` WITHOUT writing
anything to Redis.
PostgreSQL lookups on `external_id` are backed by a UNIQUE B-tree index and execute in
sub-millisecond time. Negative caching would turn "merchant not yet provisioned" into an
unusable state for up to 300 seconds immediately after administrative creation (Task 27).
Correctness and immediate usability post-provisioning beat premature micro-optimization.

6. WHY FAIL-CLOSED ON CORRUPTED CACHE:
--------------------------------------
If Redis returns malformed JSON, schema violations, or unexpected keys, `resolve()`:
1. Emits a structured security alarm (`merchant_cache_corrupt`).
2. Actively deletes the corrupted key from Redis (self-healing).
3. Fails closed by returning `None`.
A corrupted cache record must never route money to an unintended entity.

7. PROTOCOL SEAM OMISSION:
--------------------------
An abstract Protocol (like `AgentResolver`) is deliberately omitted here. Agent resolution
crosses the gateway middleware boundary where dependency inversion decouples the HTTP pipeline.
Merchant resolution is a concrete business-layer dependency of Task 31's payment engine.
Direct dependency keeps the code boring, readable, and free of speculative abstractions.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import orjson
import redis.asyncio as redis_async

from fluxpay.contracts.schemas import MERCHANT_ID_PATTERN
from fluxpay.shared.logging import get_logger

__all__ = [
    "MERCHANT_CACHE_TTL_S",
    "MERCHANT_KEY_PREFIX",
    "MerchantRecord",
    "MerchantRepo",
    "compose_merchant_cache_key",
]

logger = get_logger(__name__)

# Frozen cache TTL: 5 minutes (300 seconds)
MERCHANT_CACHE_TTL_S: Final[int] = 300

# Redis key prefix for external_id lookups
MERCHANT_KEY_PREFIX: Final[str] = "flx:merchant:ext:"

# Compiled regex mirroring Task 24's frozen external_id grammar
MERCHANT_ID_RE: Final[re.Pattern[str]] = re.compile(MERCHANT_ID_PATTERN)

# Exact required envelope keys stored in Redis cache. Extra or missing keys trigger ValueError.
REQUIRED_MERCHANT_ENVELOPE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "id",
        "external_id",
        "name",
        "active",
        "version",
        "created_at",
        "updated_at",
    }
)


def compose_merchant_cache_key(external_id: str) -> str:
    """Compose Redis read-through cache key with hash tag for cluster co-location.

    Task 20 / Task 23 law: `{external_id}` hash tag guarantees all keys belonging
    to this merchant map to the identical Redis cluster hash slot.
    Key format: flx:merchant:ext:{<external_id>}
    """
    return f"{MERCHANT_KEY_PREFIX}{{{external_id}}}"


@dataclass(frozen=True, slots=True)
class MerchantRecord:
    """Read-only view of merchant registry record for settlement lookup and admin reads.

    NO account or balance fields exist here:
    - The financial ledger (ledger_accounts) is the sole source of truth for balances (Task 16).
    - Separation of concerns: identity and money must NEVER be coupled in cache memory.
    - Caching balance in the merchant record would violate Task 16's cache philosophy
      and introduce catastrophic double-spend or stale balance risk.
    """

    id: UUID
    external_id: str
    name: str
    active: bool
    version: int
    created_at: datetime
    updated_at: datetime


def _pack_merchant(record: MerchantRecord) -> bytes:
    """Serialize merchant record to compact binary JSON via orjson.

    Pure function exposed for testability.
    """
    data = {
        "id": str(record.id),
        "external_id": record.external_id,
        "name": record.name,
        "active": record.active,
        "version": record.version,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
    }
    return orjson.dumps(data)


def _parse_merchant(payload: bytes | str) -> MerchantRecord:
    """Deserialize and strictly validate a cached merchant envelope.

    Protocol drift guard: rejects unknown extra keys, missing keys, or invalid types
    with ValueError, mirroring Task 23 fail-closed philosophy.
    """
    try:
        data: Any = orjson.loads(payload)
    except Exception as exc:
        raise ValueError(f"Invalid JSON in merchant cache envelope: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Merchant cache envelope payload must be a JSON object")

    keys = set(data.keys())
    if keys != REQUIRED_MERCHANT_ENVELOPE_KEYS:
        missing = REQUIRED_MERCHANT_ENVELOPE_KEYS - keys
        extra = keys - REQUIRED_MERCHANT_ENVELOPE_KEYS
        raise ValueError(
            f"Merchant cache envelope schema violation (missing: {missing}, extra: {extra})"
        )

    try:
        merchant_id = UUID(data["id"])
    except (ValueError, TypeError) as exc:
        raise ValueError("id must be a valid UUID string") from exc

    external_id = data["external_id"]
    if not isinstance(external_id, str) or not MERCHANT_ID_RE.fullmatch(external_id):
        raise ValueError("external_id must match MERCHANT_ID_PATTERN")

    name = data["name"]
    if not isinstance(name, str):
        raise ValueError("name must be a string")

    active = data["active"]
    if not isinstance(active, bool):
        raise ValueError("active must be a boolean")

    version = data["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("version must be an integer >= 1")

    try:
        created_at = datetime.fromisoformat(data["created_at"])
    except (ValueError, TypeError) as exc:
        raise ValueError("created_at must be an ISO-8601 timestamp string") from exc

    try:
        updated_at = datetime.fromisoformat(data["updated_at"])
    except (ValueError, TypeError) as exc:
        raise ValueError("updated_at must be an ISO-8601 timestamp string") from exc

    return MerchantRecord(
        id=merchant_id,
        external_id=external_id,
        name=name,
        active=active,
        version=version,
        created_at=created_at,
        updated_at=updated_at,
    )


class MerchantRepo:
    """PostgreSQL repository with Redis read-through cache for merchant settlement lookup.

    Provides sub-millisecond settlement resolution, fail-closed tamper resilience,
    and active cache invalidation.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        valkey: redis_async.Redis,
        *,
        cache_ttl_s: int = MERCHANT_CACHE_TTL_S,
    ) -> None:
        self._pool = pool
        self._valkey = valkey
        self._cache_ttl_s = cache_ttl_s

    async def resolve(self, external_id: str) -> MerchantRecord | None:
        """Resolve a merchant by external_id, returning MerchantRecord or None.

        Settlement-path resolution algorithm:
        1. Validate Grammar FIRST:
           - Matches Task 24 grammar `^[a-z0-9_.-]{3,64}$`.
           - If invalid: return None immediately BEFORE any Redis or database call.
           - Layering decision: Invalid grammar indicates client error; None is sufficient
             at the repo layer. Task 31 maps invalid/unknown to ValidationError.
        2. Cache Check: GET flx:merchant:ext:{<external_id>}
           - Hit: strictly parse envelope via _parse_merchant.
           - On tamper or corrupted payload: DELETE key, log alarm, return None (fail closed).
           - Active vs Inactive: return the MerchantRecord truthfully (including active=False).
             The caller (Task 31) evaluates active state and decides business policy.
        3. Cache Miss: Query PostgreSQL by external_id.
           - Absent: return None (NO negative caching).
           - Present: write record envelope to Redis (EX 300s) and return MerchantRecord.
        """
        # -------------------------------------------------------------------------
        # 1. GRAMMAR VALIDATION FIRST (Task 24 Pattern)
        # -------------------------------------------------------------------------
        if not isinstance(external_id, str) or not MERCHANT_ID_RE.fullmatch(external_id):
            return None

        key = compose_merchant_cache_key(external_id)

        # -------------------------------------------------------------------------
        # 2. READ-THROUGH CACHE HIT PATH
        # -------------------------------------------------------------------------
        try:
            cached = await self._valkey.get(key)
        except Exception:
            # Redis unavailable: fall back directly to authoritative DB path
            cached = None

        if cached is not None:
            try:
                record = _parse_merchant(cached)
            except Exception:
                # Tampered or corrupted cache payload: fail closed and self-heal
                logger.error(
                    "merchant_cache_corrupt",
                    external_id=external_id,
                    outcome="tamper_detected",
                )
                with contextlib.suppress(Exception):
                    await self._valkey.delete(key)
                return None

            # Truthful reporting: return record even if active=False (Task 31 decides policy)
            return record

        # -------------------------------------------------------------------------
        # 3. AUTHORITATIVE POSTGRESQL MISS PATH
        # -------------------------------------------------------------------------
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, external_id, name, active, version, created_at, updated_at
                FROM merchants
                WHERE external_id = $1;
                """,
                external_id,
            )

        if row is None:
            # NO negative caching — UNIQUE B-tree lookups are cheap; negative caching
            # would turn newly provisioned merchants into a 300s unusable state.
            return None

        record = MerchantRecord(
            id=row["id"],
            external_id=row["external_id"],
            name=row["name"],
            active=row["active"],
            version=row["version"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

        # -------------------------------------------------------------------------
        # 4. CACHE POPULATION
        # -------------------------------------------------------------------------
        packed = _pack_merchant(record)
        with contextlib.suppress(Exception):
            await self._valkey.set(key, packed, ex=self._cache_ttl_s)

        return record

    async def invalidate(self, external_id: str) -> None:
        """Invalidate the merchant cache entry by external_id (idempotent).

        Called by Task 27 (lifecycle provisioning) and Task 29 (admin updates)
        immediately following database mutations.
        """
        key = compose_merchant_cache_key(external_id)
        with contextlib.suppress(Exception):
            await self._valkey.delete(key)
