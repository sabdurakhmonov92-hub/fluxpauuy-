"""Agent repository and auth-path read-through cache for FluxPay.

Blueprint §3 Credential Vault + §7 Agent Metadata Store.

=============================================================================
CACHE VALUE & SECURITY DESIGN DECISIONS (WHY THE SYSTEM IS BUILT THIS WAY)
=============================================================================

1. WHY CIPHERTEXT-ONLY IN REDIS (The Security Decision):
-------------------------------------------------------
Redis holds a flat orjson envelope containing the vault ciphertext envelope:
    {"external_id", "name", "active", "rate_limit_max", "daily_quota_max", "secret_encrypted"}
under key `flx:agent:{<agent_uuid>}` (hash-tag law, Task 20) with a 30s TTL.
THE SECRET STORED IN REDIS IS THE VAULT ENVELOPE (CIPHERTEXT) — NEVER PLAINTEXT.
Threat analysis:
A memory dump, RDB snapshot, or unauthorized replica connection of Redis yields
ciphertext only. Ciphertext is cryptographically useless without the master key
`FLX_VAULT_MASTER_KEY` (env-only, stored in process memory / Doppler; Task 3/7).
Caching plaintext would promote Redis into a cryptographic key-custodian — rejected.
Caching nothing would force every incoming signed API request to pay a PostgreSQL
disk/network roundtrip — rejected (the auth path is the hottest path in the system).

2. WHY DECRYPT PER REQUEST:
---------------------------
`resolve()` decrypts the cached ciphertext envelope on EVERY invocation.
AES-256-GCM hardware-accelerated decryption (AES-NI / SHA-NI) requires approximately
1 microsecond of CPU time. The database network roundtrip (~0.5-1.0ms) is what we
eliminate (a 500x-1000x latency reduction), not the crypto.
Decryption produces an ephemeral `SecretBytes` buffer whose plaintext lifetime in RAM
is tightly constrained, avoiding long-lived plaintext residency in cache memory.

3. WHY NO NEGATIVE CACHING:
---------------------------
When an agent ID is not found in PostgreSQL, or is present but inactive, `resolve()`
returns `None` WITHOUT writing anything to Redis.
UUID primary key lookups in PostgreSQL are sub-millisecond and B-tree index backed.
Negative caching would turn "agent not yet activated" into a 30-second unusable state
immediately following administrative activation. Correctness beats premature
micro-optimization. Denial-of-service flood mitigation against non-existent UUIDs
belongs at the WAF and perimeter gate layers, not in the auth-path cache.

4. WHY FAIL-CLOSED ON TAMPER OR CORRUPT CACHE:
----------------------------------------------
If a cached entry contains malformed JSON, missing/extra fields, or corrupted
ciphertext that fails AES-GCM authentication verification (InvalidTag / VaultError),
the repository MUST fail closed:
1. It immediately deletes the poisoned or corrupted key from Redis (self-healing).
2. It returns `None` (authentication rejected).
3. It emits a structured security alarm log (`agent_cache_corrupt` / `agent_decrypt_failed`).
Under no circumstances may a corrupted cache entry authenticate a caller, nor may it
raise an unhandled 500 exception that crashes the gateway HTTP pipeline.

5. WHY SUSPEND ACTIVELY DELETES CACHE KEY (IMMEDIACY):
------------------------------------------------------
`suspend(agent_id)` executes an atomic conditional update:
    UPDATE agents SET active=false, updated_at=now(), version=version+1
    WHERE id=$1 AND active=true RETURNING id
When a row is modified, `suspend()` actively deletes the Redis cache key immediately.
Suspension is a security intervention: revoked agents must be barred instantly on this
node without waiting for the 30-second TTL to expire.

6. WHY CACHE_TTL_S = 30s (THE SAFETY NET):
------------------------------------------
Active key deletion on `suspend()` provides immediate local invalidation. The 30-second
TTL serves strictly as the FALLBACK safety net for multi-instance deployments prior to
Redis pub/sub invalidation (Phase 2), or in case of manual database edits or missed
invalidation events.

7. WHY REGISTRY VERSION OCC SPLIT:
----------------------------------
The `version` column on the `agents` table provides optimistic concurrency control (OCC)
for administrative lifecycle updates (Task 27 / Task 28). It is completely independent
of the financial ledger OCC `version` column on `ledger_accounts` (Task 16).
Administrative changes to metadata or rate limits must never contend with financial
transaction processing.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import orjson
import redis.asyncio as redis_async

from fluxpay.gateway.middleware import AgentResolver, AuthenticatedAgent
from fluxpay.shared.logging import get_logger
from fluxpay.shared.vault import decrypt_secret

__all__ = [
    "AGENT_SECRET_CONTEXT_PREFIX",
    "CACHE_TTL_S",
    "AgentRecord",
    "AgentRepo",
    "CachedAgentEnvelope",
    "agent_secret_context",
    "compose_agent_cache_key",
]

logger = get_logger(__name__)

# FROZEN CONVENTION: AAD context prefix per Task 7 law.
# Context strings are frozen per record type; changing breaks decryption of existing records.
AGENT_SECRET_CONTEXT_PREFIX: Final[str] = "agent_secret:"  # noqa: S105

# Task 28 handoff: 30s is the fallback safety bound for multi-instance cache drift.
CACHE_TTL_S: Final[int] = 30

# Exact required envelope keys stored in Redis cache. Extra or missing keys trigger ValueError.
REQUIRED_ENVELOPE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "external_id",
        "name",
        "active",
        "rate_limit_max",
        "daily_quota_max",
        "secret_encrypted",
    }
)


def agent_secret_context(external_id: str) -> str:
    """Compose the byte-exact AAD context string bound during vault encryption.

    Task 12 single-source principle: this is the ONLY composer of this context.
    Duplicating this format string elsewhere creates catastrophic fork risk.
    Byte-exact law: no trimming, lowercase transformation, or normalization.
    """
    return f"{AGENT_SECRET_CONTEXT_PREFIX}{external_id}"


def compose_agent_cache_key(agent_id: UUID | str) -> str:
    """Compose Redis read-through cache key with hash tag for cluster co-location.

    Task 20 law: `{agent_id}` hash tag guarantees all keys belonging to this agent
    map to the identical Redis cluster hash slot.
    """
    return f"flx:agent:{{{agent_id}}}"


@dataclass(frozen=True, slots=True)
class CachedAgentEnvelope:
    """Structured envelope parsed from flat Redis JSON cache entry.

    Stores ciphertext ONLY; plaintext secrets NEVER touch cache memory.
    """

    external_id: str
    name: str
    active: bool
    rate_limit_max: int
    daily_quota_max: int
    secret_encrypted: str


def _pack_agent(
    *,
    external_id: str,
    name: str,
    active: bool,
    rate_limit_max: int,
    daily_quota_max: int,
    secret_encrypted: str,
) -> bytes:
    """Serialize agent cache envelope to compact binary JSON via orjson.

    Pure function exposed for testability.
    """
    data = {
        "external_id": external_id,
        "name": name,
        "active": active,
        "rate_limit_max": rate_limit_max,
        "daily_quota_max": daily_quota_max,
        "secret_encrypted": secret_encrypted,
    }
    return orjson.dumps(data)


def _parse_agent(payload: bytes | str) -> CachedAgentEnvelope:
    """Deserialize and strictly validate a cached agent envelope.

    Protocol drift guard: rejects unknown extra keys, missing keys, or invalid types
    with ValueError, mirroring Task 20 fail-closed philosophy.
    """
    try:
        data: Any = orjson.loads(payload)
    except Exception as exc:
        raise ValueError(f"Invalid JSON in agent cache envelope: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Agent cache envelope payload must be a JSON object")

    keys = set(data.keys())
    if keys != REQUIRED_ENVELOPE_KEYS:
        missing = REQUIRED_ENVELOPE_KEYS - keys
        extra = keys - REQUIRED_ENVELOPE_KEYS
        raise ValueError(
            f"Agent cache envelope schema violation (missing: {missing}, extra: {extra})"
        )

    external_id = data["external_id"]
    if not isinstance(external_id, str) or not external_id:
        raise ValueError("external_id must be a non-empty string")

    name = data["name"]
    if not isinstance(name, str):
        raise ValueError("name must be a string")

    active = data["active"]
    if not isinstance(active, bool):
        raise ValueError("active must be a boolean")

    rate_limit_max = data["rate_limit_max"]
    if (
        isinstance(rate_limit_max, bool)
        or not isinstance(rate_limit_max, int)
        or rate_limit_max <= 0
    ):
        raise ValueError("rate_limit_max must be a positive integer")

    daily_quota_max = data["daily_quota_max"]
    if (
        isinstance(daily_quota_max, bool)
        or not isinstance(daily_quota_max, int)
        or daily_quota_max <= 0
    ):
        raise ValueError("daily_quota_max must be a positive integer")

    secret_encrypted = data["secret_encrypted"]
    if not isinstance(secret_encrypted, str) or not secret_encrypted:
        raise ValueError("secret_encrypted must be a non-empty base64 string")

    return CachedAgentEnvelope(
        external_id=external_id,
        name=name,
        active=active,
        rate_limit_max=rate_limit_max,
        daily_quota_max=daily_quota_max,
        secret_encrypted=secret_encrypted,
    )


@dataclass(frozen=True, slots=True)
class AgentRecord:
    """Read-only view of agent registry record for administrative and control plane reads.

    Absence is the safest redaction: NO secret or secret_encrypted field exists here.
    The admin plane never needs cryptographic key material.
    """

    id: UUID
    external_id: str
    name: str
    active: bool
    rate_limit_max: int
    daily_quota_max: int
    version: int
    created_at: datetime
    updated_at: datetime


class AgentRepo(AgentResolver):
    """PostgreSQL repository with Redis read-through cache implementing AgentResolver.

    Implements the AgentResolver Protocol (runtime_checkable / isinstance-proof).
    Provides auth-path credential resolution with sub-millisecond cached latency,
    fail-closed tamper resilience, and active invalidation on suspension.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        valkey: redis_async.Redis,
        *,
        cache_ttl_s: int = CACHE_TTL_S,
    ) -> None:
        self._pool = pool
        self._valkey = valkey
        self._cache_ttl_s = cache_ttl_s

    async def resolve(self, agent_id: UUID) -> AuthenticatedAgent | None:
        """Resolve an agent by UUID, returning AuthenticatedAgent or None.

        Auth-path resolution algorithm:
        1. Cache Check: GET flx:agent:{<agent_id>}
           - Hit: parse envelope. If active is False -> return None (no resurrection).
           - Decrypt ciphertext under agent_secret_context(external_id).
           - On tamper or decrypt failure -> DELETE key, log alarm, return None (fail closed).
        2. Cache Miss: Query PostgreSQL by primary key.
           - Absent or inactive -> return None (NO negative caching).
           - Active: decrypt secret, write ciphertext envelope to Redis (EX 30s), return.
        """
        key = compose_agent_cache_key(agent_id)

        # -------------------------------------------------------------------------
        # 1. READ-THROUGH CACHE HIT PATH
        # -------------------------------------------------------------------------
        try:
            cached = await self._valkey.get(key)
        except Exception:
            # Redis unavailable: fall back directly to authoritative DB path
            cached = None

        if cached is not None:
            try:
                envelope = _parse_agent(cached)
            except Exception:
                # Tampered or corrupted cache payload: fail closed and self-heal
                logger.error(
                    "agent_cache_corrupt",
                    agent_id=str(agent_id),
                    outcome="tamper_detected",
                )
                with contextlib.suppress(Exception):
                    await self._valkey.delete(key)
                return None

            if not envelope.active:
                # Documented invariant: cached-inactive stays None — no resurrection
                return None

            context = agent_secret_context(envelope.external_id)
            try:
                secret_bytes = decrypt_secret(envelope.secret_encrypted, context=context)
            except Exception:
                # Cryptographic authentication failure (key rotation / corrupted payload)
                logger.error(
                    "agent_decrypt_failed",
                    agent_id=str(agent_id),
                    outcome="decrypt_failed",
                )
                with contextlib.suppress(Exception):
                    await self._valkey.delete(key)
                return None

            return AuthenticatedAgent(
                agent_id=agent_id,
                external_id=envelope.external_id,
                secret=secret_bytes,
                rate_limit_max=envelope.rate_limit_max,
                daily_quota_max=envelope.daily_quota_max,
            )

        # -------------------------------------------------------------------------
        # 2. AUTHORITATIVE POSTGRESQL MISS PATH
        # -------------------------------------------------------------------------
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT external_id, name, secret_encrypted, active,
                       rate_limit_max, daily_quota_max
                FROM agents
                WHERE id = $1;
                """,
                agent_id,
            )

        if row is None or not row["active"]:
            # NO negative caching — UUID PK lookups are cheap; negative caching
            # turns unactivated agents into 30s unusable state post-activation.
            return None

        # -------------------------------------------------------------------------
        # 3. FRESH DECRYPT & CACHE POPULATION
        # -------------------------------------------------------------------------
        context = agent_secret_context(row["external_id"])
        try:
            secret_bytes = decrypt_secret(row["secret_encrypted"], context=context)
        except Exception:
            logger.error(
                "agent_decrypt_failed",
                agent_id=str(agent_id),
                outcome="decrypt_failed",
            )
            with contextlib.suppress(Exception):
                await self._valkey.delete(key)
            return None

        packed = _pack_agent(
            external_id=row["external_id"],
            name=row["name"],
            active=row["active"],
            rate_limit_max=row["rate_limit_max"],
            daily_quota_max=row["daily_quota_max"],
            secret_encrypted=row["secret_encrypted"],
        )
        with contextlib.suppress(Exception):
            await self._valkey.set(key, packed, ex=self._cache_ttl_s)

        return AuthenticatedAgent(
            agent_id=agent_id,
            external_id=row["external_id"],
            secret=secret_bytes,
            rate_limit_max=row["rate_limit_max"],
            daily_quota_max=row["daily_quota_max"],
        )

    async def get_by_external_id(self, external_id: str) -> AgentRecord | None:
        """Fetch agent record by external_id without caching (cold admin read path).

        Returns AgentRecord without secret material, or None if absent.
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, external_id, name, active, rate_limit_max,
                       daily_quota_max, version, created_at, updated_at
                FROM agents
                WHERE external_id = $1;
                """,
                external_id,
            )

        if row is None:
            return None

        return AgentRecord(
            id=row["id"],
            external_id=row["external_id"],
            name=row["name"],
            active=row["active"],
            rate_limit_max=row["rate_limit_max"],
            daily_quota_max=row["daily_quota_max"],
            version=row["version"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    async def suspend(self, agent_id: UUID) -> bool:
        """Suspend an agent actively, updating PostgreSQL and deleting the Redis cache key.

        Enforcement is IMMEDIATE for this node via DEL. Idempotent: returns True if
        the agent was previously active and successfully deactivated; False otherwise.
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE agents
                SET active = false, updated_at = now(), version = version + 1
                WHERE id = $1 AND active = true
                RETURNING id;
                """,
                agent_id,
            )

        if row is not None:
            key = compose_agent_cache_key(agent_id)
            with contextlib.suppress(Exception):
                await self._valkey.delete(key)
            logger.info(
                "agent_suspended",
                agent_id=str(agent_id),
                outcome="suspended",
            )
            return True

        return False

    # --- Task 27 append
    async def invalidate(self, agent_id: UUID) -> None:
        """Invalidate the agent cache entry by agent_id (idempotent).

        Called by Task 27 (lifecycle provisioning and activation) and Task 29 (admin updates)
        immediately following database mutations.
        """
        key = compose_agent_cache_key(agent_id)
        with contextlib.suppress(Exception):
            await self._valkey.delete(key)
