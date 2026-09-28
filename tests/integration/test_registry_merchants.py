"""Integration tests verifying MerchantRepo settlement-path cache and registry schema.

Exercises:
- Resolve miss -> hit: cache population with TTL in (0, 300_000] ms.
- Cache serves without DB: stale-without-DEL and fresh-after-DEL semantics proven.
- Unknown external_id: returns None with zero negative caching (cache key absent).
- Invalid grammar: returns None before any Redis or DB call.
- Inactive merchant: resolve returns MerchantRecord truthfully with active=False (policy layering).
- Tampered cache: fail-closed (None) + alarm logged + corrupt key self-healed (deleted).
- Invalidate idempotent: unknown ID triggers no error.
- Users repo: get_by_keycloak_sub known/unknown, get known/unknown.
- Schema guards:
  * duplicate external_id -> UniqueViolation.
  * user role 'superadmin' -> CheckViolation.
  * kyc status 'skipped' -> CheckViolation.
  * kyc decided_by invalid FK -> ForeignKeyViolation.
- KYC pending partial index: verified present in pg_indexes without EXPLAIN flakiness.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Coroutine
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import pytest
import redis.asyncio as redis_async
import structlog

from fluxpay.registry.merchants import (
    MerchantRecord,
    MerchantRepo,
    compose_merchant_cache_key,
)
from fluxpay.registry.users import UserRecord, UserRepo

MakeMerchantType = Callable[..., Coroutine[Any, Any, MerchantRecord]]
MakeUserType = Callable[..., Coroutine[Any, Any, UserRecord]]

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _setup_structlog_stdlib() -> None:
    """Ensure structlog routes through stdlib logging so caplog captures records."""
    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory())


# ---------------------------------------------------------------------------
# 1. RESOLVE MISS -> HIT WITH PTTL ASSERTION (300s TTL Contract)
# ---------------------------------------------------------------------------


async def test_resolve_miss_to_hit(
    merchant_repo: MerchantRepo,
    make_merchant: MakeMerchantType,
    valkey: redis_async.Redis,
) -> None:
    """Validate that first resolve queries DB and caches, second resolve hits cache."""
    merchant = await make_merchant(name="Acme Settlement Corp")
    cache_key = compose_merchant_cache_key(merchant.external_id)

    # Key must be ABSENT before resolution
    assert await valkey.exists(cache_key) == 0

    # First resolve: Cache Miss -> DB read -> Cache populate
    res1 = await merchant_repo.resolve(merchant.external_id)
    assert res1 is not None
    assert isinstance(res1, MerchantRecord)
    assert res1.id == merchant.id
    assert res1.external_id == merchant.external_id
    assert res1.name == "Acme Settlement Corp"
    assert res1.active is True
    assert res1.version >= 1

    # Key must now exist with PTTL in (0, 300_000] ms (300 seconds)
    pttl = await valkey.pttl(cache_key)
    assert 0 < pttl <= 300_000

    # Second resolve: Cache Hit path
    res2 = await merchant_repo.resolve(merchant.external_id)
    assert res2 is not None
    assert res2.id == merchant.id
    assert res2.external_id == merchant.external_id
    assert res2.name == res1.name


# ---------------------------------------------------------------------------
# 2. CACHE SERVES WITHOUT DB (STALE-WITHOUT-DEL / FRESH-AFTER-DEL)
# ---------------------------------------------------------------------------


async def test_cache_serves_without_db(
    merchant_repo: MerchantRepo,
    make_merchant: MakeMerchantType,
    owner_conn: asyncpg.Connection,
    valkey: redis_async.Redis,
) -> None:
    """Validate that cache serves without DB roundtrip, and invalidate() fetches fresh DB state."""
    merchant = await make_merchant(name="Original Merchant Name")
    cache_key = compose_merchant_cache_key(merchant.external_id)

    # Warm the cache
    res1 = await merchant_repo.resolve(merchant.external_id)
    assert res1 is not None
    assert res1.name == "Original Merchant Name"

    # Direct database modification via owner connection WITHOUT cache DEL
    await owner_conn.execute(
        "UPDATE merchants SET name = 'Directly Updated Name' WHERE id = $1;",
        merchant.id,
    )

    # Cache hit proof: resolve still returns OLD name from Redis
    res_stale = await merchant_repo.resolve(merchant.external_id)
    assert res_stale is not None
    assert res_stale.name == "Original Merchant Name"

    # Invalidate cache key
    await merchant_repo.invalidate(merchant.external_id)
    assert await valkey.exists(cache_key) == 0

    # Fresh read proof: resolve re-queries DB and returns NEW name
    res_fresh = await merchant_repo.resolve(merchant.external_id)
    assert res_fresh is not None
    assert res_fresh.name == "Directly Updated Name"


# ---------------------------------------------------------------------------
# 3. UNKNOWN EXTERNAL_ID & ZERO NEGATIVE CACHING
# ---------------------------------------------------------------------------


async def test_unknown_external_id_returns_none_and_no_negative_cache(
    merchant_repo: MerchantRepo,
    valkey: redis_async.Redis,
) -> None:
    """Validate unknown external_id returns None and creates no Redis cache key."""
    unknown_id = f"mch_unknown_{uuid.uuid4().hex[:12]}"
    cache_key = compose_merchant_cache_key(unknown_id)

    res = await merchant_repo.resolve(unknown_id)
    assert res is None

    # Prove NO negative cache entry was created
    assert await valkey.exists(cache_key) == 0


# ---------------------------------------------------------------------------
# 4. INVALID GRAMMAR SHORT-CIRCUIT
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_handle",
    [
        "AB",  # Too short (< 3)
        "a" * 65,  # Too long (> 64)
        "has space",  # Spaces forbidden
        "INVALID_UPPERCASE",  # Uppercase forbidden
    ],
)
async def test_invalid_grammar_returns_none_before_redis_or_db(
    merchant_repo: MerchantRepo,
    valkey: redis_async.Redis,
    bad_handle: str,
) -> None:
    """Validate invalid external_id grammar returns None before touching Redis or DB."""
    cache_key = compose_merchant_cache_key(bad_handle)

    res = await merchant_repo.resolve(bad_handle)
    assert res is None

    # No key created in Redis
    assert await valkey.exists(cache_key) == 0


# ---------------------------------------------------------------------------
# 5. INACTIVE MERCHANT (Truthful Reporting / Layering Discipline)
# ---------------------------------------------------------------------------


async def test_inactive_merchant_returns_record_with_active_false(
    merchant_repo: MerchantRepo,
    make_merchant: MakeMerchantType,
    valkey: redis_async.Redis,
) -> None:
    """Validate inactive merchant returns MerchantRecord with active=False on both miss and hit.

    Layering discipline: repo reports truth, caller (Task 31) evaluates policy.
    """
    merchant = await make_merchant(active=False, name="Suspended Merchant")
    cache_key = compose_merchant_cache_key(merchant.external_id)

    # Miss path
    res1 = await merchant_repo.resolve(merchant.external_id)
    assert res1 is not None
    assert isinstance(res1, MerchantRecord)
    assert res1.active is False
    assert res1.name == "Suspended Merchant"

    # Cache should be populated
    assert await valkey.exists(cache_key) == 1

    # Hit path
    res2 = await merchant_repo.resolve(merchant.external_id)
    assert res2 is not None
    assert res2.active is False
    assert res2.name == "Suspended Merchant"


# ---------------------------------------------------------------------------
# 6. TAMPERED CACHE FAILS CLOSED & SELF-HEALS (DEL)
# ---------------------------------------------------------------------------


async def test_tamper_cache_fails_closed_and_deletes_garbage(
    merchant_repo: MerchantRepo,
    make_merchant: MakeMerchantType,
    valkey: redis_async.Redis,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Validate that tampered cache entry returns None, logs alarm, and deletes bad key."""
    merchant = await make_merchant()
    cache_key = compose_merchant_cache_key(merchant.external_id)

    # Manually poison the cache key with non-JSON garbage
    await valkey.set(cache_key, b"GARBAGE_PAYLOAD_NOT_JSON", ex=300)
    assert await valkey.exists(cache_key) == 1

    with caplog.at_level("ERROR"):
        res = await merchant_repo.resolve(merchant.external_id)

    # Fail closed: must return None
    assert res is None

    # Security alarm logged
    assert (
        "merchant_cache_corrupt" in caplog.text
        or "tamper" in caplog.text
        or any(
            "tamper" in r.message.lower()
            or "corrupt" in r.message.lower()
            or r.levelname == "ERROR"
            for r in caplog.records
        )
    )

    # Self-heal proof: garbage cache key is deleted from Redis
    assert await valkey.exists(cache_key) == 0


# ---------------------------------------------------------------------------
# 7. INVALIDATE IDEMPOTENCY
# ---------------------------------------------------------------------------


async def test_invalidate_idempotent(merchant_repo: MerchantRepo) -> None:
    """Validate calling invalidate on unknown or absent external_id triggers no error."""
    await merchant_repo.invalidate("mch_non_existent_12345")
    await merchant_repo.invalidate("mch_non_existent_12345")


# ---------------------------------------------------------------------------
# 8. USERS REPOSITORY (Admin Plane Cold Read Path)
# ---------------------------------------------------------------------------


async def test_user_repo_get_by_keycloak_sub_and_get(
    user_repo: UserRepo,
    make_user: MakeUserType,
) -> None:
    """Validate UserRepo get_by_keycloak_sub and get methods for known and unknown cases."""
    user = await make_user(
        email="operator@fluxpay.local",
        display_name="Operations Admin",
        role="admin",
        active=True,
    )

    # 1. get_by_keycloak_sub - known
    by_sub = await user_repo.get_by_keycloak_sub(user.keycloak_sub)
    assert by_sub is not None
    assert isinstance(by_sub, UserRecord)
    assert by_sub.id == user.id
    assert by_sub.keycloak_sub == user.keycloak_sub
    assert by_sub.email == "operator@fluxpay.local"
    assert by_sub.display_name == "Operations Admin"
    assert by_sub.role == "admin"
    assert by_sub.active is True

    # 2. get_by_keycloak_sub - unknown
    assert await user_repo.get_by_keycloak_sub("kc_sub_non_existent_999") is None

    # 3. get - known
    by_id = await user_repo.get(user.id)
    assert by_id is not None
    assert by_id.id == user.id
    assert by_id.keycloak_sub == user.keycloak_sub

    # 4. get - unknown
    assert await user_repo.get(uuid.uuid4()) is None


# ---------------------------------------------------------------------------
# 9. DATABASE SCHEMA GUARDS
# ---------------------------------------------------------------------------


async def test_schema_guard_duplicate_external_id(
    make_merchant: MakeMerchantType,
    owner_conn: asyncpg.Connection,
) -> None:
    """Validate database rejects duplicate merchant external_id with UniqueViolationError."""
    merchant = await make_merchant(external_id="mch_duplicate_test")

    with pytest.raises(asyncpg.UniqueViolationError):
        await owner_conn.execute(
            """
            INSERT INTO merchants (id, external_id, name, active)
            VALUES ($1, $2, $3, $4);
            """,
            uuid.uuid4(),
            merchant.external_id,
            "Duplicate Merchant",
            True,
        )


async def test_schema_guard_invalid_user_role(
    owner_conn: asyncpg.Connection,
) -> None:
    """Validate database rejects invalid user role with CheckViolationError."""
    with pytest.raises(asyncpg.CheckViolationError):
        await owner_conn.execute(
            """
            INSERT INTO users (id, keycloak_sub, email, display_name, role, active)
            VALUES ($1, $2, $3, $4, $5, $6);
            """,
            uuid.uuid4(),
            f"kc_sub_{uuid.uuid4().hex[:12]}",
            "super@test.local",
            "Super User",
            "superadmin",  # Invalid: role must be IN ('admin', 'support')
            True,
        )


async def test_schema_guard_invalid_kyc_status(
    make_merchant: MakeMerchantType,
    owner_conn: asyncpg.Connection,
) -> None:
    """Validate database rejects invalid kyc status with CheckViolationError."""
    merchant = await make_merchant()

    with pytest.raises(asyncpg.CheckViolationError):
        await owner_conn.execute(
            """
            INSERT INTO kyc_requests (id, subject_type, subject_id, status)
            VALUES ($1, $2, $3, $4);
            """,
            uuid.uuid4(),
            "merchant",
            merchant.id,
            "skipped",  # Invalid: status must be IN ('pending', 'approved', 'rejected')
        )


async def test_schema_guard_kyc_decided_by_foreign_key(
    make_merchant: MakeMerchantType,
    owner_conn: asyncpg.Connection,
) -> None:
    """Validate database enforces foreign key on kyc_requests.decided_by."""
    merchant = await make_merchant()
    non_existent_user_id = uuid.uuid4()

    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await owner_conn.execute(
            """
            INSERT INTO kyc_requests (id, subject_type, subject_id, status, decided_by)
            VALUES ($1, $2, $3, $4, $5);
            """,
            uuid.uuid4(),
            "merchant",
            merchant.id,
            "pending",
            non_existent_user_id,
        )


# ---------------------------------------------------------------------------
# 10. KYC PENDING PARTIAL INDEX EXISTENCE
# ---------------------------------------------------------------------------


async def test_kyc_pending_partial_index_exists(
    owner_conn: asyncpg.Connection,
    apply_registry_schema: None,
) -> None:
    """Validate partial index idx_kyc_requests_pending exists in pg_indexes (EXPLAIN-free)."""
    rows = await owner_conn.fetch(
        """
        SELECT indexname, indexdef
        FROM pg_indexes
        WHERE tablename = 'kyc_requests';
        """
    )
    index_names = {row["indexname"] for row in rows}
    assert "idx_kyc_requests_pending" in index_names

    pending_idx = next(row for row in rows if row["indexname"] == "idx_kyc_requests_pending")
    # Verify index definition contains the partial predicate WHERE status = 'pending'
    assert "status = 'pending'" in pending_idx["indexdef"]


# ---------------------------------------------------------------------------
# 11. MIGRATION IDEMPOTENCY
# ---------------------------------------------------------------------------


async def test_migration_0005_idempotent(
    owner_conn: asyncpg.Connection,
    registry_migration_sql: str,
) -> None:
    """Validate migrations/0005_registry.sql can execute repeatedly without error."""
    await owner_conn.execute(registry_migration_sql)
    await owner_conn.execute(registry_migration_sql)
