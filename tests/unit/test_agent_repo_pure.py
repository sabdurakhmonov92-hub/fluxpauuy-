"""Pure unit tests for AgentRepo and registry helpers (zero I/O).

Verifies:
- agent_secret_context determinism, prefix law, byte-exact invariance (no normalization).
- _pack_agent and _parse_agent roundtrip, validation, and protocol drift defense.
- Unknown extra keys, missing keys, and invalid types rejected with ValueError.
- Key composition hash-tag law (Task 20) and CACHE_TTL_S contract.
- AgentRecord absence of secret fields (admin plane read safety).
- AgentResolver Protocol conformance (isinstance and method signature).
"""

from __future__ import annotations

import inspect
from uuid import UUID, uuid4

import orjson
import pytest

from fluxpay.gateway.middleware import AgentResolver, AuthenticatedAgent
from fluxpay.registry.repo import (
    AGENT_SECRET_CONTEXT_PREFIX,
    CACHE_TTL_S,
    AgentRecord,
    AgentRepo,
    CachedAgentEnvelope,
    _pack_agent,
    _parse_agent,
    agent_secret_context,
    compose_agent_cache_key,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# 1. CONTEXT COMPOSITION CONTRACT (Task 7 Law)
# ---------------------------------------------------------------------------


def test_agent_secret_context_prefix_law() -> None:
    """Validate prefix constant and composition prefix law."""
    assert AGENT_SECRET_CONTEXT_PREFIX == "agent_secret:"  # noqa: S105
    ctx = agent_secret_context("agt_alpha_001")
    assert ctx.startswith(AGENT_SECRET_CONTEXT_PREFIX)
    assert ctx == "agent_secret:agt_alpha_001"


def test_agent_secret_context_deterministic() -> None:
    """Validate that identical inputs yield identical context strings."""
    external_id = "agent-xyz-987"
    assert agent_secret_context(external_id) == agent_secret_context(external_id)


def test_agent_secret_context_byte_exact_no_normalization() -> None:
    """Validate byte-exact preservation: no trimming, lowercasing, or character mutation.

    Task 7 law: Context strings are frozen per record type; changing breaks decryption
    of existing database records.
    """
    raw_external = "  Agent_Special.99-XY_ "
    ctx = agent_secret_context(raw_external)
    assert ctx == f"agent_secret:{raw_external}"
    assert ctx.endswith(raw_external)


# ---------------------------------------------------------------------------
# 2. KEY COMPOSITION & TTL (Task 20 Hash-Tag Law)
# ---------------------------------------------------------------------------


def test_compose_agent_cache_key_hash_tag() -> None:
    """Validate Redis cluster hash tag `{...}` surrounds the agent UUID."""
    agent_id = uuid4()
    key = compose_agent_cache_key(agent_id)
    expected = f"flx:agent:{{{agent_id}}}"
    assert key == expected
    assert f"{{{agent_id}}}" in key


def test_compose_agent_cache_key_accepts_str() -> None:
    """Validate key composition accepts string representation."""
    raw_id = "018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e"
    assert compose_agent_cache_key(raw_id) == f"flx:agent:{{{raw_id}}}"


def test_cache_ttl_contract() -> None:
    """Validate CACHE_TTL_S constant equals frozen 30-second fallback bound."""
    assert CACHE_TTL_S == 30


# ---------------------------------------------------------------------------
# 3. ENVELOPE SERIALIZATION & VALIDATION (Fail-Closed Drift Guard)
# ---------------------------------------------------------------------------


def test_pack_and_parse_agent_roundtrip() -> None:
    """Validate exact roundtrip of valid agent envelope."""
    packed = _pack_agent(
        external_id="agt_valid_123",
        name="Finance Agent",
        active=True,
        rate_limit_max=200,
        daily_quota_max=50000,
        secret_encrypted="AQEB940jf...",  # noqa: S106
    )
    assert isinstance(packed, bytes)

    parsed = _parse_agent(packed)
    assert isinstance(parsed, CachedAgentEnvelope)
    assert parsed.external_id == "agt_valid_123"
    assert parsed.name == "Finance Agent"
    assert parsed.active is True
    assert parsed.rate_limit_max == 200
    assert parsed.daily_quota_max == 50000
    assert parsed.secret_encrypted == "AQEB940jf..."  # noqa: S105


def test_parse_agent_rejects_missing_keys() -> None:
    """Validate that missing any required envelope key raises ValueError."""
    valid_dict = {
        "external_id": "agt_1",
        "name": "N",
        "active": True,
        "rate_limit_max": 100,
        "daily_quota_max": 1000,
        "secret_encrypted": "enc",
    }
    for key in valid_dict:
        mutated = dict(valid_dict)
        del mutated[key]
        with pytest.raises(ValueError, match="schema violation"):
            _parse_agent(orjson.dumps(mutated))


def test_parse_agent_rejects_unknown_extra_keys() -> None:
    """Validate protocol drift guard: unknown extra keys are rejected with ValueError."""
    payload = {
        "external_id": "agt_1",
        "name": "N",
        "active": True,
        "rate_limit_max": 100,
        "daily_quota_max": 1000,
        "secret_encrypted": "enc",
        "unknown_extra_field": "injected",
    }
    with pytest.raises(ValueError, match="schema violation"):
        _parse_agent(orjson.dumps(payload))


@pytest.mark.parametrize(
    ("field", "bad_value", "err_match"),
    [
        ("external_id", "", "external_id"),
        ("external_id", 12345, "external_id"),
        ("name", 999, "name"),
        ("active", "true", "active"),
        ("active", 1, "active"),
        ("rate_limit_max", 0, "rate_limit_max"),
        ("rate_limit_max", -5, "rate_limit_max"),
        ("rate_limit_max", True, "rate_limit_max"),
        ("rate_limit_max", "100", "rate_limit_max"),
        ("daily_quota_max", 0, "daily_quota_max"),
        ("daily_quota_max", -10, "daily_quota_max"),
        ("daily_quota_max", True, "daily_quota_max"),
        ("secret_encrypted", "", "secret_encrypted"),
        ("secret_encrypted", 1234, "secret_encrypted"),
    ],
)
def test_parse_agent_type_validations(field: str, bad_value: object, err_match: str) -> None:
    """Validate strict type checking and positive limit bounds on envelope fields."""
    valid_dict: dict[str, object] = {
        "external_id": "agt_1",
        "name": "N",
        "active": True,
        "rate_limit_max": 100,
        "daily_quota_max": 1000,
        "secret_encrypted": "enc",
    }
    valid_dict[field] = bad_value
    with pytest.raises(ValueError, match=err_match):
        _parse_agent(orjson.dumps(valid_dict))


def test_parse_agent_corrupted_json() -> None:
    """Validate that non-JSON or malformed bytes raise ValueError."""
    with pytest.raises(ValueError, match="Invalid JSON"):
        _parse_agent(b"not-json-at-all")


def test_parse_agent_non_dict_json() -> None:
    """Validate that JSON primitive or array payload raises ValueError."""
    with pytest.raises(ValueError, match="must be a JSON object"):
        _parse_agent(orjson.dumps([1, 2, 3]))


# ---------------------------------------------------------------------------
# 4. AGENT RECORD ADMIN VIEW SAFETY
# ---------------------------------------------------------------------------


def test_agent_record_redaction_by_absence() -> None:
    """Validate that AgentRecord has NO secret or secret_encrypted attribute.

    The admin plane never needs secret material; absence is the safest redaction.
    """
    assert not hasattr(AgentRecord, "secret")
    assert not hasattr(AgentRecord, "secret_encrypted")

    record_fields = set(inspect.signature(AgentRecord).parameters.keys())
    assert "secret" not in record_fields
    assert "secret_encrypted" not in record_fields
    assert record_fields == {
        "id",
        "external_id",
        "name",
        "active",
        "rate_limit_max",
        "daily_quota_max",
        "version",
        "created_at",
        "updated_at",
    }


# ---------------------------------------------------------------------------
# 5. PROTOCOL CONFORMANCE (AgentResolver Contract)
# ---------------------------------------------------------------------------


def test_agent_repo_implements_agent_resolver_protocol() -> None:
    """Validate AgentRepo satisfies the runtime_checkable AgentResolver Protocol."""
    assert issubclass(AgentRepo, AgentResolver)

    # Dummy pool and valkey for structural verification
    dummy_repo = AgentRepo(pool=None, valkey=None)  # type: ignore[arg-type]
    assert isinstance(dummy_repo, AgentResolver)


def test_agent_repo_resolve_signature() -> None:
    """Validate resolve method signature matches AgentResolver Protocol exactly."""
    sig = inspect.signature(AgentRepo.resolve)
    params = list(sig.parameters.keys())
    assert params == ["self", "agent_id"]

    import typing

    type_hints = typing.get_type_hints(AgentRepo.resolve)
    assert type_hints["agent_id"] is UUID
    assert type_hints["return"] == AuthenticatedAgent | None


# ---------------------------------------------------------------------------
# 6. MOCK-BASED EXECUTION TESTS (Full Branch and Error Path Verification)
# ---------------------------------------------------------------------------

import base64  # noqa: E402
from datetime import UTC, datetime  # noqa: E402
from typing import Any  # noqa: E402
from unittest.mock import AsyncMock  # noqa: E402

import structlog  # noqa: E402

from fluxpay.config import get_settings  # noqa: E402
from fluxpay.shared.vault import encrypt_secret, reset_vault_cache  # noqa: E402


@pytest.fixture(autouse=True)
def _setup_structlog_stdlib() -> None:
    """Ensure structlog routes through stdlib logging so pytest caplog fixture captures records."""
    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory())


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


@pytest.fixture(autouse=True)
def _setup_vault_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure vault master key is configured for pure unit tests using encrypt/decrypt."""
    raw_key = b"\x42" * 32
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", base64.b64encode(raw_key).decode("ascii"))
    monkeypatch.setenv("FLX_PG_DSN", "postgresql://test:test@localhost:5432/test")
    monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", "0" * 32)
    get_settings.cache_clear()
    reset_vault_cache()


async def test_repo_resolve_cache_hit_happy_path() -> None:
    """Validate cache hit path decrypts and returns AuthenticatedAgent."""
    agent_id = uuid4()
    ext_id = "agent_test_hit"
    secret_hex = "0123456789abcdef" * 4
    enc_secret = encrypt_secret(secret_hex, context=agent_secret_context(ext_id))

    valkey = _MockValkey()
    packed = _pack_agent(
        external_id=ext_id,
        name="Cache Hit Agent",
        active=True,
        rate_limit_max=150,
        daily_quota_max=20000,
        secret_encrypted=enc_secret,
    )
    valkey.store[compose_agent_cache_key(agent_id)] = packed

    conn = _MockConn()
    repo = AgentRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    resolved = await repo.resolve(agent_id)
    assert resolved is not None
    assert resolved.agent_id == agent_id
    assert resolved.external_id == ext_id
    assert bytes(resolved.secret) == secret_hex.encode("ascii")
    assert resolved.rate_limit_max == 150
    assert resolved.daily_quota_max == 20000

    # PostgreSQL must NOT be queried on cache hit
    conn.fetchrow.assert_not_called()


async def test_repo_resolve_cache_hit_inactive_returns_none() -> None:
    """Validate cached envelope with active=False returns None without decrypting."""
    agent_id = uuid4()
    valkey = _MockValkey()
    packed = _pack_agent(
        external_id="agent_inactive",
        name="Inactive",
        active=False,
        rate_limit_max=100,
        daily_quota_max=10000,
        secret_encrypted="bogus_secret",  # noqa: S106
    )
    valkey.store[compose_agent_cache_key(agent_id)] = packed

    conn = _MockConn()
    repo = AgentRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    assert await repo.resolve(agent_id) is None
    conn.fetchrow.assert_not_called()


async def test_repo_resolve_cache_hit_corrupt_fails_closed_and_deletes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Validate corrupted JSON in cache fails closed, deletes key, and logs alarm."""
    agent_id = uuid4()
    key = compose_agent_cache_key(agent_id)
    valkey = _MockValkey()
    valkey.store[key] = b"not_a_valid_json_payload"

    conn = _MockConn()
    repo = AgentRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    with caplog.at_level("ERROR"):
        res = await repo.resolve(agent_id)

    assert res is None
    assert key not in valkey.store  # Key deleted
    assert (
        "agent_cache_corrupt" in caplog.text
        or "tamper" in caplog.text
        or any("tamper" in r.message.lower() for r in caplog.records)
    )


async def test_repo_resolve_cache_hit_decrypt_failure_fails_closed_and_deletes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Validate decrypt failure on cache hit deletes bad entry and logs alarm."""
    agent_id = uuid4()
    key = compose_agent_cache_key(agent_id)
    valkey = _MockValkey()
    # Construct envelope with valid base64 but invalid cipher payload
    bad_enc = base64.b64encode(b"\x01" + b"\x00" * 40).decode("ascii")
    valkey.store[key] = _pack_agent(
        external_id="agt_dec_fail",
        name="Fail",
        active=True,
        rate_limit_max=100,
        daily_quota_max=1000,
        secret_encrypted=bad_enc,
    )

    conn = _MockConn()
    repo = AgentRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    with caplog.at_level("ERROR"):
        res = await repo.resolve(agent_id)

    assert res is None
    assert key not in valkey.store  # Key deleted
    assert (
        "agent_decrypt_failed" in caplog.text
        or "decrypt" in caplog.text
        or any("decrypt" in r.message.lower() for r in caplog.records)
    )


async def test_repo_resolve_miss_absent_in_db_no_negative_cache() -> None:
    """Validate absent row in DB returns None and does NOT populate cache."""
    agent_id = uuid4()
    key = compose_agent_cache_key(agent_id)
    valkey = _MockValkey()
    conn = _MockConn(fetchrow_result=None)
    repo = AgentRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    assert await repo.resolve(agent_id) is None
    assert key not in valkey.store
    valkey.set.assert_not_called()


async def test_repo_resolve_miss_inactive_in_db_no_negative_cache() -> None:
    """Validate inactive DB row returns None and does NOT populate cache."""
    agent_id = uuid4()
    key = compose_agent_cache_key(agent_id)
    valkey = _MockValkey()
    conn = _MockConn(
        fetchrow_result={
            "external_id": "agt_db_inactive",
            "name": "Inactive DB",
            "secret_encrypted": "enc",
            "active": False,
            "rate_limit_max": 100,
            "daily_quota_max": 1000,
        }
    )
    repo = AgentRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    assert await repo.resolve(agent_id) is None
    assert key not in valkey.store
    valkey.set.assert_not_called()


async def test_repo_resolve_miss_active_populates_cache_and_returns() -> None:
    """Validate active DB row decrypts, populates cache (EX 30), and returns agent."""
    agent_id = uuid4()
    ext_id = "agt_db_active"
    secret_hex = "fedcba9876543210" * 4
    enc_secret = encrypt_secret(secret_hex, context=agent_secret_context(ext_id))

    key = compose_agent_cache_key(agent_id)
    valkey = _MockValkey()
    conn = _MockConn(
        fetchrow_result={
            "external_id": ext_id,
            "name": "Active DB Agent",
            "secret_encrypted": enc_secret,
            "active": True,
            "rate_limit_max": 300,
            "daily_quota_max": 50000,
        }
    )
    repo = AgentRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    res = await repo.resolve(agent_id)
    assert res is not None
    assert res.agent_id == agent_id
    assert res.external_id == ext_id
    assert bytes(res.secret) == secret_hex.encode("ascii")
    assert res.rate_limit_max == 300
    assert res.daily_quota_max == 50000

    # Cache must now contain the envelope
    assert key in valkey.store
    valkey.set.assert_called_once()


async def test_repo_resolve_miss_decrypt_failure_fails_closed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Validate DB row with corrupt ciphertext fails closed and logs alarm."""
    agent_id = uuid4()
    key = compose_agent_cache_key(agent_id)
    valkey = _MockValkey()
    conn = _MockConn(
        fetchrow_result={
            "external_id": "agt_bad_cipher",
            "name": "Bad Cipher",
            "secret_encrypted": "AQEBcorrupted...",
            "active": True,
            "rate_limit_max": 100,
            "daily_quota_max": 1000,
        }
    )
    repo = AgentRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    with caplog.at_level("ERROR"):
        res = await repo.resolve(agent_id)

    assert res is None
    assert key not in valkey.store
    assert (
        "agent_decrypt_failed" in caplog.text
        or "decrypt" in caplog.text
        or any("decrypt" in r.message.lower() for r in caplog.records)
    )


async def test_repo_get_by_external_id_present_and_absent() -> None:
    """Validate get_by_external_id returns AgentRecord without secrets, or None."""
    agent_id = uuid4()
    now = datetime.now(tz=UTC)
    conn = _MockConn(
        fetchrow_result={
            "id": agent_id,
            "external_id": "agt_admin_01",
            "name": "Admin Test",
            "active": True,
            "rate_limit_max": 250,
            "daily_quota_max": 60000,
            "version": 1,
            "created_at": now,
            "updated_at": now,
        }
    )
    repo = AgentRepo(pool=_MockPool(conn), valkey=_MockValkey())  # type: ignore[arg-type]

    record = await repo.get_by_external_id("agt_admin_01")
    assert record is not None
    assert isinstance(record, AgentRecord)
    assert record.id == agent_id
    assert record.external_id == "agt_admin_01"
    assert record.name == "Admin Test"
    assert record.active is True
    assert record.rate_limit_max == 250
    assert record.daily_quota_max == 60000
    assert record.version == 1
    assert not hasattr(record, "secret")
    assert not hasattr(record, "secret_encrypted")

    # When absent
    conn.fetchrow.return_value = None
    assert await repo.get_by_external_id("non_existent") is None


async def test_repo_suspend_active_deletes_cache_returns_true() -> None:
    """Validate suspend on active agent deletes cache key, logs info, and returns True."""
    agent_id = uuid4()
    key = compose_agent_cache_key(agent_id)
    valkey = _MockValkey()
    valkey.store[key] = b"cached_envelope"

    conn = _MockConn(fetchrow_result={"id": agent_id})
    repo = AgentRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    result = await repo.suspend(agent_id)
    assert result is True
    assert key not in valkey.store  # Actively deleted
    valkey.delete.assert_called_once_with(key)


async def test_repo_suspend_already_inactive_returns_false() -> None:
    """Validate suspend on inactive agent returns False and does not delete key."""
    agent_id = uuid4()
    valkey = _MockValkey()
    conn = _MockConn(fetchrow_result=None)  # UPDATE returned no row
    repo = AgentRepo(pool=_MockPool(conn), valkey=valkey)  # type: ignore[arg-type]

    result = await repo.suspend(agent_id)
    assert result is False
    valkey.delete.assert_not_called()
