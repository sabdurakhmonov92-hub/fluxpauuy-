"""Integration tests verifying AgentRepo auth-path read-through cache and agents schema.

Exercises:
- Resolve miss -> hit: cache population with TTL (0, 30_000] ms.
- Cache serves without DB: stale-without-DEL and fresh-after-DEL semantics proven.
- Secret chain: AuthenticatedAgent.secret verified via canonical.verify with original secret.
- Ciphertext-only in Redis: raw secret bytes and plaintext absent from cached JSON envelope.
- Unknown UUID: returns None with zero negative caching (cache key absent).
- Inactive agent: returns None on both fresh DB read and cached path.
- Immediate suspension: active DEL clears cache instantly (0 TTL wait) + idempotent second call.
- Tampered cache: fail-closed (None) + alarm logged + corrupt key self-healed (deleted).
- Decrypt failure: DB-path wrong master key fail-closed (None) + alarm logged.
- Admin read path: get_by_external_id returns AgentRecord without secret material.
- Protocol conformance: isinstance(agent_repo, AgentResolver) proven.
"""

from __future__ import annotations

import base64
import os
import time
import uuid
from collections.abc import Callable, Coroutine
from typing import Any, Protocol

import asyncpg  # type: ignore[import-untyped]
import orjson
import pytest
import redis.asyncio as redis_async
import structlog

from fluxpay.config import get_settings
from fluxpay.gateway import canonical
from fluxpay.gateway.middleware import AgentResolver, AuthenticatedAgent
from fluxpay.registry.repo import (
    AgentRecord,
    AgentRepo,
    _pack_agent,
    compose_agent_cache_key,
)
from fluxpay.shared.vault import reset_vault_cache


@pytest.fixture(autouse=True)
def _setup_structlog_stdlib() -> None:
    """Ensure structlog routes through stdlib logging so pytest caplog fixture captures records."""
    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory())


class AgentCredentials(Protocol):
    """Protocol for credentials returned by make_agent fixture."""

    agent_id: uuid.UUID
    external_id: str
    secret_bytes: bytes


MakeAgentType = Callable[..., Coroutine[Any, Any, AgentCredentials]]

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# 1. RESOLVE MISS -> HIT WITH PTTL ASSERTION
# ---------------------------------------------------------------------------


async def test_resolve_miss_to_hit(
    agent_repo: AgentRepo,
    make_agent: MakeAgentType,
    valkey: redis_async.Redis,
) -> None:
    """Validate that first resolve hits DB, caches ciphertext, and subsequent resolve hits cache."""
    agent = await make_agent(rate_limit_max=150, daily_quota_max=25000)
    cache_key = compose_agent_cache_key(agent.agent_id)

    # Key must be ABSENT before resolution
    assert await valkey.exists(cache_key) == 0

    # First resolve (Cache Miss -> DB read -> Cache populate)
    auth1 = await agent_repo.resolve(agent.agent_id)
    assert auth1 is not None
    assert isinstance(auth1, AuthenticatedAgent)
    assert auth1.agent_id == agent.agent_id
    assert auth1.external_id == agent.external_id
    assert bytes(auth1.secret) == agent.secret_bytes
    assert auth1.rate_limit_max == 150
    assert auth1.daily_quota_max == 25000

    # Key must now exist with PTTL in (0, 30_000] ms
    pttl = await valkey.pttl(cache_key)
    assert 0 < pttl <= 30_000

    # Second resolve (Cache Hit path)
    auth2 = await agent_repo.resolve(agent.agent_id)
    assert auth2 is not None
    assert auth2.agent_id == agent.agent_id
    assert bytes(auth2.secret) == agent.secret_bytes
    assert auth2.rate_limit_max == 150
    assert auth2.daily_quota_max == 25000


# ---------------------------------------------------------------------------
# 2. CACHE SERVES WITHOUT DB (STALE-WITHOUT-DEL / FRESH-AFTER-DEL)
# ---------------------------------------------------------------------------


async def test_cache_serves_without_db(
    agent_repo: AgentRepo,
    make_agent: MakeAgentType,
    owner_conn: asyncpg.Connection,
    valkey: redis_async.Redis,
) -> None:
    """Validate that cache serves without DB roundtrip, and manual DEL fetches fresh DB state."""
    agent = await make_agent(rate_limit_max=100)
    cache_key = compose_agent_cache_key(agent.agent_id)

    # Warm the cache
    auth1 = await agent_repo.resolve(agent.agent_id)
    assert auth1 is not None
    assert auth1.rate_limit_max == 100

    # Direct database modification via owner connection WITHOUT cache DEL
    await owner_conn.execute(
        "UPDATE agents SET rate_limit_max = 999 WHERE id = $1;",
        agent.agent_id,
    )

    # Cache hit proof: resolve still returns OLD limit from Redis
    auth_stale = await agent_repo.resolve(agent.agent_id)
    assert auth_stale is not None
    assert auth_stale.rate_limit_max == 100

    # Manually delete cache key
    await valkey.delete(cache_key)
    assert await valkey.exists(cache_key) == 0

    # Fresh read proof: resolve re-queries DB and returns NEW limit
    auth_fresh = await agent_repo.resolve(agent.agent_id)
    assert auth_fresh is not None
    assert auth_fresh.rate_limit_max == 999


# ---------------------------------------------------------------------------
# 3. CIPHERTEXT-ONLY IN REDIS PROOF (Threat Model Defense)
# ---------------------------------------------------------------------------


async def test_ciphertext_only_in_redis(
    agent_repo: AgentRepo,
    make_agent: MakeAgentType,
    valkey: redis_async.Redis,
) -> None:
    """Prove that Redis holds vault ciphertext only; raw secret bytes NEVER touch cache."""
    agent = await make_agent()
    cache_key = compose_agent_cache_key(agent.agent_id)

    await agent_repo.resolve(agent.agent_id)

    raw_cached = await valkey.get(cache_key)
    assert raw_cached is not None
    assert isinstance(raw_cached, bytes)

    # Raw secret bytes must NOT be present in cached Redis envelope
    assert agent.secret_bytes not in raw_cached
    assert agent.secret_bytes.decode("ascii") not in raw_cached.decode("utf-8")

    # Envelope structure checks
    envelope = orjson.loads(raw_cached)
    assert "secret_encrypted" in envelope
    assert "secret" not in envelope
    assert envelope["secret_encrypted"].startswith("AQ")  # Vault envelope version 1 header


# ---------------------------------------------------------------------------
# 4. SECRET CHAIN VERIFICATION (Vault -> Repo -> Gateway)
# ---------------------------------------------------------------------------


async def test_secret_chain_canonical_verify(
    agent_repo: AgentRepo,
    make_agent: MakeAgentType,
) -> None:
    """Prove that secret resolved from repo authenticates requests signed by client secret."""
    agent = await make_agent()

    # Sign canonical request with client-side original secret
    timestamp = str(int(time.time() * 1000))
    nonce = "noncesecchain0001"
    method = "POST"
    path = "/v1/transfers"
    body = b'{"recipient":"acct_123","amount":5000}'

    sig = canonical.sign(
        secret=agent.secret_bytes,
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )

    # Resolve agent through repository read-through cache
    auth_agent = await agent_repo.resolve(agent.agent_id)
    assert auth_agent is not None

    # Verify signature using resolved agent secret
    valid = canonical.verify(
        secret=auth_agent.secret,
        provided_sig=sig,
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    assert valid is True

    # Tampered body must fail verification
    assert not canonical.verify(
        secret=auth_agent.secret,
        provided_sig=sig,
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body=b'{"recipient":"acct_123","amount":9999}',
    )


# ---------------------------------------------------------------------------
# 5. UNKNOWN AGENT & NO NEGATIVE CACHING
# ---------------------------------------------------------------------------


async def test_unknown_uuid_returns_none_and_no_negative_cache(
    agent_repo: AgentRepo,
    valkey: redis_async.Redis,
) -> None:
    """Validate that unknown UUID returns None and does NOT create a negative cache entry."""
    unknown_id = uuid.uuid4()
    cache_key = compose_agent_cache_key(unknown_id)

    res = await agent_repo.resolve(unknown_id)
    assert res is None

    # Prove NO negative cache entry was created
    assert await valkey.exists(cache_key) == 0


# ---------------------------------------------------------------------------
# 6. INACTIVE AGENT RESOLUTION (Fresh and Cached)
# ---------------------------------------------------------------------------


async def test_inactive_agent_returns_none_fresh_and_cached(
    agent_repo: AgentRepo,
    make_agent: MakeAgentType,
    valkey: redis_async.Redis,
) -> None:
    """Validate that inactive agents return None on both fresh DB read and cached path."""
    inactive_agent = await make_agent(active=False)
    cache_key = compose_agent_cache_key(inactive_agent.agent_id)

    # Fresh path: DB query detects active=false -> returns None WITHOUT negative caching
    res1 = await agent_repo.resolve(inactive_agent.agent_id)
    assert res1 is None
    assert await valkey.exists(cache_key) == 0

    # Cached path: Manually inject envelope with active=False
    packed = _pack_agent(
        external_id=inactive_agent.external_id,
        name="Inactive Agent",
        active=False,
        rate_limit_max=100,
        daily_quota_max=10000,
        secret_encrypted="AQEB940jfdummy...",  # noqa: S106
    )
    await valkey.set(cache_key, packed, ex=30)
    assert await valkey.exists(cache_key) == 1

    # Cached resolve: returns None immediately without decrypting
    res2 = await agent_repo.resolve(inactive_agent.agent_id)
    assert res2 is None


# ---------------------------------------------------------------------------
# 7. SUSPENSION IMMEDIACY AND IDEMPOTENCY
# ---------------------------------------------------------------------------


async def test_suspend_immediate_del_and_idempotent(
    agent_repo: AgentRepo,
    make_agent: MakeAgentType,
    valkey: redis_async.Redis,
    owner_conn: asyncpg.Connection,
) -> None:
    """Validate that suspend() actively deletes cache key immediately and is idempotent."""
    agent = await make_agent(active=True)
    cache_key = compose_agent_cache_key(agent.agent_id)

    # Warm cache
    auth = await agent_repo.resolve(agent.agent_id)
    assert auth is not None
    assert await valkey.exists(cache_key) == 1

    # Suspend active agent: returns True
    suspended = await agent_repo.suspend(agent.agent_id)
    assert suspended is True

    # Immediate revocation proof: cache key DELETED instantly (0 TTL wait)
    assert await valkey.exists(cache_key) == 0

    # Immediate resolve returns None
    assert await agent_repo.resolve(agent.agent_id) is None

    # Idempotent second suspension: returns False
    suspended_again = await agent_repo.suspend(agent.agent_id)
    assert suspended_again is False

    # Check database state via owner connection: active=false, version bumped
    row = await owner_conn.fetchrow(
        "SELECT active, version FROM agents WHERE id = $1;",
        agent.agent_id,
    )
    assert row is not None
    assert row["active"] is False
    assert row["version"] == 2  # Started at 1, incremented to 2


# ---------------------------------------------------------------------------
# 8. TAMPERED CACHE FAILS CLOSED & SELF-HEALS (DEL)
# ---------------------------------------------------------------------------


async def test_tamper_cache_fails_closed_and_deletes_garbage(
    agent_repo: AgentRepo,
    make_agent: MakeAgentType,
    valkey: redis_async.Redis,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Validate that tampered cache entry returns None, logs alarm, and deletes bad key."""
    agent = await make_agent()
    cache_key = compose_agent_cache_key(agent.agent_id)

    # Manually poison the cache key with non-JSON garbage
    await valkey.set(cache_key, b"GARBAGE_PAYLOAD_NOT_JSON", ex=30)
    assert await valkey.exists(cache_key) == 1

    with caplog.at_level("ERROR"):
        result = await agent_repo.resolve(agent.agent_id)

    # Fail closed: must return None
    assert result is None

    # Security alarm logged
    assert (
        "agent_cache_corrupt" in caplog.text
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
# 9. DECRYPT FAILURE VIA WRONG MASTER KEY (Fail-Closed)
# ---------------------------------------------------------------------------


async def test_decrypt_fail_wrong_master_key_fails_closed(
    agent_repo: AgentRepo,
    make_agent: MakeAgentType,
    valkey: redis_async.Redis,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Validate that wrong master key on DB read fails closed, deletes cache, and logs alarm."""
    agent = await make_agent()
    cache_key = compose_agent_cache_key(agent.agent_id)

    # Ensure cache is absent so resolve hits DB
    await valkey.delete(cache_key)

    # Monkeypatch to a DIFFERENT valid 32-byte AES master key
    different_key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", different_key_b64)
    get_settings.cache_clear()
    reset_vault_cache()

    try:
        with caplog.at_level("ERROR"):
            result = await agent_repo.resolve(agent.agent_id)

        # Fail closed: returns None on cryptographic decryption failure
        assert result is None

        # Alarm logged
        assert (
            "agent_decrypt_failed" in caplog.text
            or "decrypt" in caplog.text
            or any("decrypt" in r.message.lower() or r.levelname == "ERROR" for r in caplog.records)
        )

        # Corrupt key must NOT exist in cache
        assert await valkey.exists(cache_key) == 0

    finally:
        # Fixture self-cleaning: restore original environment and caches
        monkeypatch.undo()
        get_settings.cache_clear()
        reset_vault_cache()


# ---------------------------------------------------------------------------
# 10. GET BY EXTERNAL ID (Admin Read Path)
# ---------------------------------------------------------------------------


async def test_get_by_external_id(
    agent_repo: AgentRepo,
    make_agent: MakeAgentType,
) -> None:
    """Validate get_by_external_id returns AgentRecord without secret material, or None."""
    agent = await make_agent(rate_limit_max=250, daily_quota_max=75000, name="Admin Query Agent")

    record = await agent_repo.get_by_external_id(agent.external_id)
    assert record is not None
    assert isinstance(record, AgentRecord)
    assert record.id == agent.agent_id
    assert record.external_id == agent.external_id
    assert record.name == "Admin Query Agent"
    assert record.active is True
    assert record.rate_limit_max == 250
    assert record.daily_quota_max == 75000
    assert record.version >= 1

    # Critical security assertion: AgentRecord must NOT have secret attributes
    assert not hasattr(record, "secret")
    assert not hasattr(record, "secret_encrypted")

    # Unknown external_id returns None
    assert await agent_repo.get_by_external_id("non_existent_external_id_999") is None


# ---------------------------------------------------------------------------
# 11. PROTOCOL CONFORMANCE (AgentResolver Isinstance)
# ---------------------------------------------------------------------------


def test_agent_repo_isinstance_conformance(agent_repo: AgentRepo) -> None:
    """Prove AgentResolver Protocol conformance via isinstance."""
    assert isinstance(agent_repo, AgentResolver)
