"""Pure unit tests for merchant registry and admin user models (zero I/O).

Verifies:
- MERCHANT_ID_PATTERN grammar mirror between Task 24 contract and migrations/0005_registry.sql.
- Merchant cache key composition: hash-tag law and external-id single-key decision.
- Merchant envelope pack/parse roundtrip, schema validation, and fail-closed drift defense.
- MerchantRecord redaction-by-absence (zero balance / ledger fields) and immutability.
- UserRecord immutability and attributes.
- Mock-based MerchantRepo execution branches:
  * Grammar validation FIRST (short-circuits before cache or DB).
  * Cache hit path (returns MerchantRecord, including active=False honest reporting).
  * Tampered / corrupt cache entry (fails closed, logs alarm, self-heals by DEL).
  * Cache miss DB absent (returns None with zero negative caching).
  * Cache miss DB present (populates cache with 300s TTL and returns record).
  * Invalidation path (deletes single external-id key idempotently).
"""

from __future__ import annotations

import inspect
import re
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import orjson
import pytest
import structlog

from fluxpay.contracts.schemas import MERCHANT_ID_PATTERN
from fluxpay.registry.merchants import (
    MERCHANT_CACHE_TTL_S,
    MERCHANT_KEY_PREFIX,
    MerchantRecord,
    MerchantRepo,
    _pack_merchant,
    _parse_merchant,
    compose_merchant_cache_key,
)
from fluxpay.registry.users import UserRecord, UserRepo

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _setup_structlog_stdlib() -> None:
    """Ensure structlog routes through stdlib logging so caplog captures records."""
    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory())


# ---------------------------------------------------------------------------
# 1. GRAMMAR MIRROR & CROSS-LANGUAGE DRIFT GUARD (Task 24 Law)
# ---------------------------------------------------------------------------


def test_merchant_id_pattern_sql_meta_test() -> None:
    """Meta-test: assert migrations/0005_registry.sql contains the frozen pattern literal.

    Applies Task 24's cross-language drift-guard philosophy: Python contract and
    PostgreSQL schema CHECK constraint must share the byte-exact pattern string.
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    migration_path = repo_root / "migrations" / "0005_registry.sql"
    assert migration_path.is_file(), f"Migration file missing: {migration_path}"

    sql_text = migration_path.read_text(encoding="utf-8")
    assert MERCHANT_ID_PATTERN in sql_text
    expected_check = f"CHECK (external_id ~ '{MERCHANT_ID_PATTERN}')"
    assert expected_check in sql_text


@pytest.mark.parametrize(
    "valid_id",
    [
        "acme-corp",
        "mch_01",
        "sub.domain-123",
        "abc",
        "a" * 64,
        "valid_handle.99",
        "007agent_merchant",
    ],
)
def test_merchant_id_pattern_valid_matches(valid_id: str) -> None:
    """Validate that valid merchant handles match the frozen pattern."""
    assert re.fullmatch(MERCHANT_ID_PATTERN, valid_id) is not None


@pytest.mark.parametrize(
    "invalid_id",
    [
        "ab",  # 2 chars: too short (< 3)
        "a" * 65,  # 65 chars: too long (> 64)
        "Acme-Corp",  # Uppercase forbidden
        "has space",  # Spaces forbidden
        "special@char",  # Special characters forbidden
        "slash/not/allowed",  # Slash forbidden
        "",  # Empty string
        "   ",  # Whitespace only
    ],
)
def test_merchant_id_pattern_invalid_rejected(invalid_id: str) -> None:
    """Validate that invalid merchant handles are rejected by the pattern."""
    assert re.fullmatch(MERCHANT_ID_PATTERN, invalid_id) is None


# ---------------------------------------------------------------------------
# 2. CACHE KEY COMPOSITION & TTL CONTRACT
# ---------------------------------------------------------------------------


def test_compose_merchant_cache_key_hash_tag_law() -> None:
    """Validate Redis cluster hash tag `{...}` surrounds the merchant external_id."""
    external_id = "acme-corp-001"
    key = compose_merchant_cache_key(external_id)
    expected = f"flx:merchant:ext:{{{external_id}}}"
    assert key == expected
    assert f"{{{external_id}}}" in key
    assert key.startswith(MERCHANT_KEY_PREFIX)


def test_merchant_cache_key_single_key_decision() -> None:
    """Validate documented decision: ONE key under external_id, NOT uuid-keyed.

    The payments path (Task 31) resolves external_id -> uuid FIRST.
    Caching under external_id allows single-hop resolution without doubling miss cost.
    """
    ext_id = "test_merchant_handle"
    key = compose_merchant_cache_key(ext_id)
    assert "flx:merchant:ext:" in key
    assert ext_id in key


def test_merchant_cache_ttl_contract() -> None:
    """Validate MERCHANT_CACHE_TTL_S constant equals frozen 300-second bound."""
    assert MERCHANT_CACHE_TTL_S == 300


# ---------------------------------------------------------------------------
# 3. ENVELOPE SERIALIZATION & VALIDATION (Fail-Closed Drift Guard)
# ---------------------------------------------------------------------------


def test_pack_and_parse_merchant_roundtrip() -> None:
    """Validate exact roundtrip of valid merchant record."""
    m_id = uuid4()
    now = datetime.now(tz=UTC)
    record = MerchantRecord(
        id=m_id,
        external_id="acme_corp_99",
        name="Acme Corporation",
        active=True,
        version=1,
        created_at=now,
        updated_at=now,
    )
    packed = _pack_merchant(record)
    assert isinstance(packed, bytes)

    parsed = _parse_merchant(packed)
    assert isinstance(parsed, MerchantRecord)
    assert parsed.id == m_id
    assert parsed.external_id == "acme_corp_99"
    assert parsed.name == "Acme Corporation"
    assert parsed.active is True
    assert parsed.version == 1
    assert parsed.created_at == now
    assert parsed.updated_at == now


def test_parse_merchant_rejects_missing_keys() -> None:
    """Validate that missing any required envelope key raises ValueError."""
    now_iso = datetime.now(tz=UTC).isoformat()
    valid_dict = {
        "id": str(uuid4()),
        "external_id": "mch_test_01",
        "name": "Test Merchant",
        "active": True,
        "version": 1,
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    for key in valid_dict:
        mutated = dict(valid_dict)
        del mutated[key]
        with pytest.raises(ValueError, match="schema violation"):
            _parse_merchant(orjson.dumps(mutated))


def test_parse_merchant_rejects_unknown_extra_keys() -> None:
    """Validate protocol drift guard: unknown extra keys are rejected with ValueError."""
    now_iso = datetime.now(tz=UTC).isoformat()
    payload = {
        "id": str(uuid4()),
        "external_id": "mch_test_01",
        "name": "Test Merchant",
        "active": True,
        "version": 1,
        "created_at": now_iso,
        "updated_at": now_iso,
        "unexpected_injected_field": "danger",
    }
    with pytest.raises(ValueError, match="schema violation"):
        _parse_merchant(orjson.dumps(payload))


@pytest.mark.parametrize(
    ("field", "bad_value", "err_match"),
    [
        ("id", "not-a-valid-uuid", "UUID"),
        ("external_id", "AB", "MERCHANT_ID_PATTERN"),
        ("external_id", 12345, "MERCHANT_ID_PATTERN"),
        ("name", 999, "name"),
        ("active", "true", "active"),
        ("active", 1, "active"),
        ("version", 0, "version"),
        ("version", -1, "version"),
        ("version", True, "version"),
        ("version", "1", "version"),
        ("created_at", "not-iso-timestamp", "created_at"),
        ("updated_at", 123456789, "updated_at"),
    ],
)
def test_parse_merchant_type_validations(field: str, bad_value: object, err_match: str) -> None:
    """Validate strict type checking on envelope fields."""
    now_iso = datetime.now(tz=UTC).isoformat()
    valid_dict: dict[str, object] = {
        "id": str(uuid4()),
        "external_id": "mch_test_01",
        "name": "Test Merchant",
        "active": True,
        "version": 1,
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    valid_dict[field] = bad_value
    with pytest.raises(ValueError, match=err_match):
        _parse_merchant(orjson.dumps(valid_dict))


def test_parse_merchant_corrupted_json() -> None:
    """Validate that non-JSON bytes raise ValueError."""
    with pytest.raises(ValueError, match="Invalid JSON"):
        _parse_merchant(b"not-valid-json-bytes")


def test_parse_merchant_non_dict_json() -> None:
    """Validate that JSON primitive or array payload raises ValueError."""
    with pytest.raises(ValueError, match="must be a JSON object"):
        _parse_merchant(orjson.dumps(["not", "a", "dict"]))


# ---------------------------------------------------------------------------
# 4. REDACTION BY ABSENCE & IMMUTABILITY (Separation of Identity & Money)
# ---------------------------------------------------------------------------


def test_merchant_record_no_balance_or_account_fields() -> None:
    """Validate that MerchantRecord contains NO balance, account, or ledger fields.

    Per Task 16's cache philosophy: identity and money must stay separated.
    The ledger is the sole money truth.
    """
    assert not hasattr(MerchantRecord, "balance")
    assert not hasattr(MerchantRecord, "account")
    assert not hasattr(MerchantRecord, "account_id")
    assert not hasattr(MerchantRecord, "ledger_account_id")
    assert not hasattr(MerchantRecord, "currency")

    record_fields = set(inspect.signature(MerchantRecord).parameters.keys())
    assert record_fields == {
        "id",
        "external_id",
        "name",
        "active",
        "version",
        "created_at",
        "updated_at",
    }


def test_merchant_record_is_frozen() -> None:
    """Validate MerchantRecord is immutable (frozen dataclass)."""
    now = datetime.now(tz=UTC)
    record = MerchantRecord(
        id=uuid4(),
        external_id="mch_immutable",
        name="Immutable Merchant",
        active=True,
        version=1,
        created_at=now,
        updated_at=now,
    )
    with pytest.raises(FrozenInstanceError):
        record.active = False  # type: ignore[misc]


def test_user_record_is_frozen() -> None:
    """Validate UserRecord is immutable (frozen dataclass)."""
    user = UserRecord(
        id=uuid4(),
        keycloak_sub="kc_sub_123",
        email="admin@test.local",
        display_name="Admin",
        role="admin",
        active=True,
    )
    with pytest.raises(FrozenInstanceError):
        user.role = "support"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 5. MOCK-BASED EXECUTION TESTS (Full Branch & Error Path Verification)
# ---------------------------------------------------------------------------


class _MockConn:
    def __init__(self, fetchrow_result: Any = None) -> None:
        self.fetchrow = AsyncMock(return_value=fetchrow_result)


class _MockPool:
    def __init__(self, conn: _MockConn) -> None:
        self.conn = conn

    def acquire(self) -> Any:
        conn = self.conn

        class _Context:
            async def __aenter__(self) -> _MockConn:
                return conn

            async def __aexit__(self, *args: Any) -> None:
                pass

        return _Context()


class _MockValkey:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}
        self.get = AsyncMock(side_effect=lambda k: self.store.get(k))
        self.set = AsyncMock(side_effect=self._set)
        self.delete = AsyncMock(side_effect=self._delete)

    def _set(self, k: str, v: bytes, ex: int | None = None) -> bool:
        self.store[k] = v
        return True

    def _delete(self, k: str) -> int:
        return 1 if self.store.pop(k, None) is not None else 0


async def test_repo_resolve_invalid_grammar_short_circuits() -> None:
    """Validate that invalid external_id grammar returns None BEFORE Redis or DB call."""
    valkey = _MockValkey()
    conn = _MockConn()
    repo = MerchantRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    for bad_id in ["AB", "a" * 65, "has space", "invalid@handle", ""]:
        result = await repo.resolve(bad_id)
        assert result is None

    # Neither Redis nor DB must have been called
    valkey.get.assert_not_called()
    conn.fetchrow.assert_not_called()


async def test_repo_resolve_cache_hit_returns_merchant_record() -> None:
    """Validate cache hit returns MerchantRecord without querying DB."""
    m_id = uuid4()
    now = datetime.now(tz=UTC)
    ext_id = "mch_hit_01"
    record = MerchantRecord(
        id=m_id,
        external_id=ext_id,
        name="Hit Corp",
        active=True,
        version=1,
        created_at=now,
        updated_at=now,
    )
    valkey = _MockValkey()
    valkey.store[compose_merchant_cache_key(ext_id)] = _pack_merchant(record)

    conn = _MockConn()
    repo = MerchantRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    resolved = await repo.resolve(ext_id)
    assert resolved is not None
    assert resolved == record
    conn.fetchrow.assert_not_called()


async def test_repo_resolve_cache_hit_inactive_returns_record() -> None:
    """Validate cached envelope with active=False returns MerchantRecord with active=False.

    Layering discipline: repo reports truth, caller (Task 31) evaluates policy.
    """
    m_id = uuid4()
    now = datetime.now(tz=UTC)
    ext_id = "mch_inactive_hit"
    record = MerchantRecord(
        id=m_id,
        external_id=ext_id,
        name="Suspended Corp",
        active=False,
        version=2,
        created_at=now,
        updated_at=now,
    )
    valkey = _MockValkey()
    valkey.store[compose_merchant_cache_key(ext_id)] = _pack_merchant(record)

    conn = _MockConn()
    repo = MerchantRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    resolved = await repo.resolve(ext_id)
    assert resolved is not None
    assert resolved.active is False
    assert resolved.name == "Suspended Corp"
    conn.fetchrow.assert_not_called()


async def test_repo_resolve_corrupt_cache_fails_closed_and_deletes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Validate corrupted cache envelope fails closed, logs alarm, and deletes key."""
    ext_id = "mch_corrupt"
    key = compose_merchant_cache_key(ext_id)
    valkey = _MockValkey()
    valkey.store[key] = b"NOT_VALID_JSON"

    conn = _MockConn()
    repo = MerchantRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    with caplog.at_level("ERROR"):
        resolved = await repo.resolve(ext_id)

    assert resolved is None
    assert key not in valkey.store  # Self-healed
    assert (
        "merchant_cache_corrupt" in caplog.text
        or "tamper" in caplog.text
        or any("tamper" in r.message.lower() for r in caplog.records)
    )
    conn.fetchrow.assert_not_called()


async def test_repo_resolve_miss_absent_in_db_no_negative_cache() -> None:
    """Validate absent row in DB returns None and does NOT populate cache."""
    ext_id = "mch_absent_db"
    key = compose_merchant_cache_key(ext_id)
    valkey = _MockValkey()
    conn = _MockConn(fetchrow_result=None)
    repo = MerchantRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    resolved = await repo.resolve(ext_id)
    assert resolved is None
    assert key not in valkey.store
    valkey.set.assert_not_called()


async def test_repo_resolve_miss_active_populates_cache_and_returns() -> None:
    """Validate active DB row populates cache with 300s TTL and returns record."""
    m_id = uuid4()
    now = datetime.now(tz=UTC)
    ext_id = "mch_db_active"
    key = compose_merchant_cache_key(ext_id)

    valkey = _MockValkey()
    conn = _MockConn(
        fetchrow_result={
            "id": m_id,
            "external_id": ext_id,
            "name": "DB Active Merchant",
            "active": True,
            "version": 1,
            "created_at": now,
            "updated_at": now,
        }
    )
    repo = MerchantRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    resolved = await repo.resolve(ext_id)
    assert resolved is not None
    assert resolved.id == m_id
    assert resolved.external_id == ext_id
    assert resolved.active is True

    # Cache populated
    assert key in valkey.store
    valkey.set.assert_called_once_with(key, _pack_merchant(resolved), ex=300)


async def test_repo_resolve_miss_inactive_in_db_populates_cache_and_returns() -> None:
    """Validate inactive DB row populates cache with active=False and returns record.

    Layering discipline: repo reports truth, caller evaluates policy.
    """
    m_id = uuid4()
    now = datetime.now(tz=UTC)
    ext_id = "mch_db_inactive"
    key = compose_merchant_cache_key(ext_id)

    valkey = _MockValkey()
    conn = _MockConn(
        fetchrow_result={
            "id": m_id,
            "external_id": ext_id,
            "name": "DB Inactive Merchant",
            "active": False,
            "version": 1,
            "created_at": now,
            "updated_at": now,
        }
    )
    repo = MerchantRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    resolved = await repo.resolve(ext_id)
    assert resolved is not None
    assert resolved.active is False

    # Cache populated with active=False record
    assert key in valkey.store
    valkey.set.assert_called_once()


async def test_repo_invalidate_idempotent() -> None:
    """Validate invalidate deletes key from valkey and does not raise on absent key."""
    valkey = _MockValkey()
    ext_id = "mch_to_invalidate"
    key = compose_merchant_cache_key(ext_id)
    valkey.store[key] = b"some_data"

    repo = MerchantRepo(pool=_MockPool(_MockConn()), valkey=valkey)  # type: ignore[arg-type]

    await repo.invalidate(ext_id)
    assert key not in valkey.store

    # Second call idempotent
    await repo.invalidate(ext_id)
    assert key not in valkey.store


async def test_user_repo_get_by_keycloak_sub_and_get() -> None:
    """Validate UserRepo get_by_keycloak_sub and get methods."""
    u_id = uuid4()
    now = datetime.now(tz=UTC)
    conn = _MockConn(
        fetchrow_result={
            "id": u_id,
            "keycloak_sub": "kc_sub_admin_1",
            "email": "admin@fluxpay.local",
            "display_name": "Ops Admin",
            "role": "admin",
            "active": True,
            "created_at": now,
        }
    )
    user_repo = UserRepo(pool=_MockPool(conn))

    # Known sub
    user = await user_repo.get_by_keycloak_sub("kc_sub_admin_1")
    assert user is not None
    assert user.id == u_id
    assert user.keycloak_sub == "kc_sub_admin_1"
    assert user.role == "admin"
    assert user.active is True

    # Known ID
    user_by_id = await user_repo.get(u_id)
    assert user_by_id is not None
    assert user_by_id.id == u_id

    # Unknown
    conn.fetchrow.return_value = None
    assert await user_repo.get_by_keycloak_sub("unknown_sub") is None
    assert await user_repo.get(uuid4()) is None
