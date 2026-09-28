"""Agent and Merchant Lifecycle Management Service for FluxPay.

Blueprint §0 Dashboard Rule ("Secret faqat 1 marta ko'rinadi") &
Blueprint §1 Third-Party Merchants & §3 Credential Vault & §7 Registry Lifecycle.

=============================================================================
LIFECYCLE DESIGN INVARIANTS & ARCHITECTURAL BOUNDARIES
=============================================================================

1. THE ORPHAN-PROOF INVARIANT (ONE UoW COMMIT):
------------------------------------------------
An identity without a money account is a support ticket; a money account without
an identity is an orphan holding funds. This service makes both corrupt states
unreachable by construction: the identity row (agents / merchants) and its
associated financial ledger account row (ledger_accounts) are inserted inside
EXACTLY ONE Unit of Work transaction. They commit atomically or not at all.

2. BOUNDARY RULE BETWEEN LIFECYCLE AND LEDGER STORE:
----------------------------------------------------
LedgerStore (Task 16) owns its own internal transactions and serializes hash-chain
tip locks exclusively for financial movements (ledger_entries).
In contrast, ledger_accounts provisioning is ordinary business DML: plain INSERT
with balance=0 and version=0. It requires NO chain lock, NO tip mutation, and NO
ledger entries. Keeping this boundary clean prevents transaction deadlocks and
preserves LedgerStore's strict OCC isolation.

3. ONE-TIME SECRET CUSTODY (THE CUSTODY DECISION):
--------------------------------------------------
Plaintext secrets exist in memory for exactly one fleeting moment: creation.
This service generates 256 bits of entropy via os.urandom(32), encodes it as 64-hex,
encrypts it into an authenticated AES-256-GCM vault envelope bound to the agent's
external_id (AAD), commits the envelope to PostgreSQL, and returns the plaintext
secret exactly ONCE in `CreatedAgent`.
Zero plaintext copies are retained in memory; plaintext is NEVER logged (silence
beats redaction). Every subsequent read path (Task 23 / Task 29) sees ONLY the
vault ciphertext envelope.

4. WHY HEX INSTEAD OF BASE64 FOR SECRETS:
-----------------------------------------
Hex encoding produces a clean 64-character alphanumeric string `[0-9a-f]{64}`.
Standard base64 contains `+`, `/`, and `=` characters, which frequently cause
copy-paste errors in terminal environments, markdown renderers, and URL query strings.
Hex provides identical 256-bit cryptographic entropy while guaranteeing friction-free
copy-paste safety in operator dashboards.

5. WHY BALANCE=0 AND VERSION=0 AT PROVISIONING:
-----------------------------------------------
Agents and merchants are provisioned completely EMPTY. Funding is an explicit
DEPOSIT ENTRY through the double-entry ledger (Task 16/31 seed discipline:
treasury -> agent balanced pair), never an out-of-band direct database UPDATE.
Provisioning creates the financial envelope; the ledger fills it.

6. SIBLING LIFECYCLES VS GOD-SERVICE (AgentLifecycle & MerchantLifecycle):
-------------------------------------------------------------------------
AgentLifecycle and MerchantLifecycle are sibling classes rather than a unified
god-service. Why siblings:
- Invariants differ: Agents authenticate callers and hold sensitive encrypted API
  secrets; merchants receive webhooks and hold NO API secret in Phase 1.
- Invalidation differs: Agents invalidate by agent_id (UUID); merchants invalidate
  by external_id (business handle string).
- Audit posture differs: Agent provisioning is a machine credential issuance;
  merchant provisioning is a legal business onboarding.
The Admin router (Task 29) composes both as separate dependencies.

7. DEPENDENCY DIRECTION (CLEAN DAG):
------------------------------------
Lifecycle services depend on repositories (for cache invalidation and delegations).
Repositories NEVER depend on lifecycle services. This preserves a strict, acyclic
dependency graph: shared/ -> registry/repo.py -> registry/agents.py -> admin/ (Task 29).

8. POST-COMMIT CACHE INVALIDATION:
----------------------------------
Cache invalidation executes strictly POST-COMMIT. A failed database transaction
must never purge or corrupt valid cached records. On a newly provisioned handle,
post-commit invalidation is a cheap, safe no-op.

9. MERCHANT SECRET POSTURE & PHASE 2 SKETCH:
--------------------------------------------
In Phase 1, merchants have NO API secret. Agents execute payments; merchants
receive webhooks and access the administrative dashboard.
Phase 2 sketch: When merchant-initiated refunds or server-to-server merchant APIs
are introduced, a `merchant_keys` table with `MERCHANT_SECRET_CONTEXT_PREFIX = "merchant_secret:"`
will follow the identical AAD envelope pattern established for agents in Task 7/23.

10. LIFECYCLE STATUS (ACTIVE BOOLEAN AS HONEST LIFECYCLE):
----------------------------------------------------------
Phase 1 uses an `active` boolean honestly representing operational availability.
Full status enums ('pending', 'approved', 'suspended', 'rejected') belong to
Phase 2 automated KYC workflows (Task 55). Introducing synthetic status enums in
Phase 1 would create protocol drift against the frozen schema.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Final
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import redis.asyncio as redis_async

from fluxpay.contracts.schemas import CURRENCY_PATTERN, MERCHANT_ID_PATTERN
from fluxpay.registry.merchants import MerchantRepo
from fluxpay.registry.repo import AgentRepo, agent_secret_context
from fluxpay.shared.uow import UnitOfWork
from fluxpay.shared.vault import encrypt_secret

__all__ = [
    "AgentLifecycle",
    "CreateAgentCommand",
    "CreateMerchantCommand",
    "CreatedAgent",
    "CreatedMerchant",
    "MerchantLifecycle",
]

# Grammar compiled patterns
_HANDLE_RE: Final[re.Pattern[str]] = re.compile(MERCHANT_ID_PATTERN)
_CURRENCY_RE: Final[re.Pattern[str]] = re.compile(CURRENCY_PATTERN)
_MAX_NAME_LENGTH: Final[int] = 128


@dataclass(frozen=True, slots=True)
class CreateAgentCommand:
    """Input command for atomic agent and ledger account provisioning.

    external_id: Matches ^[a-z0-9_.-]{3,64}$, identical to merchant handles across the platform.
    name: Human-readable display label (stripped, max 128 characters).
    currency: Single-currency default 'USDC' (Task 12 L1 pattern).
    rate_limit_max: Per-agent gateway rate limit default (domain layer authority).
    daily_quota_max: Per-agent daily transaction quota default (domain layer authority).
    """

    external_id: str
    name: str = ""
    currency: str = "USDC"
    rate_limit_max: int = 100
    daily_quota_max: int = 10000


@dataclass(frozen=True, slots=True)
class CreatedAgent:
    """Agent provisioning result containing the one-time plaintext secret.

    CRITICAL SECURITY NOTICE:
    Consume once, never persist, never log — response rendering (Task 29/63)
    is the only permitted materialization.
    """

    agent_id: UUID
    external_id: str
    secret: str


@dataclass(frozen=True, slots=True)
class CreateMerchantCommand:
    """Input command for atomic merchant and ledger account provisioning.

    external_id: Canonical business handle matching ^[a-z0-9_.-]{3,64}$.
    name: Legal business name or display name (stripped, max 128 characters).
    currency: Settlement currency default 'USDC'.
    """

    external_id: str
    name: str = ""
    currency: str = "USDC"


@dataclass(frozen=True, slots=True)
class CreatedMerchant:
    """Merchant provisioning result.

    Note: In Phase 1, merchants do not have an API secret (agents pay, merchants receive).
    """

    merchant_id: UUID
    external_id: str


class AgentLifecycle:
    """Agent lifecycle service owning atomic provisioning and activation transitions.

    Delegates reads and suspensions to AgentRepo, preserving single-source responsibility.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        agent_repo: AgentRepo,
        valkey: redis_async.Redis | None = None,
    ) -> None:
        """Initialize AgentLifecycle with database connection pool and AgentRepo."""
        self._pool: asyncpg.Pool = pool
        self._agent_repo: AgentRepo = agent_repo
        self._valkey: redis_async.Redis | None = valkey

    async def create_agent(self, cmd: CreateAgentCommand) -> CreatedAgent:
        """Atomically provision an agent identity and its initial ledger account.

        Steps:
        0. Strictly validate domain inputs.
        1. Generate 256-bit cryptographic secret via os.urandom(32) as 64-hex string.
        2. Encrypt secret with AES-256-GCM vault envelope bound to agent's external_id (AAD).
        3. Insert agent and ledger_accounts rows atomically within ONE Unit of Work.
        4. Return CreatedAgent with plaintext secret (never logged, never persisted).

        Raises:
            ValueError: If input validation fails or external_id is already registered.
        """
        # 0. Domain validation
        if not isinstance(cmd.external_id, str) or not _HANDLE_RE.fullmatch(cmd.external_id):
            raise ValueError(f"external_id: must match pattern '{MERCHANT_ID_PATTERN}'")

        clean_name = cmd.name.strip()
        if len(clean_name) > _MAX_NAME_LENGTH:
            raise ValueError(f"name: length cannot exceed {_MAX_NAME_LENGTH} characters")

        if not isinstance(cmd.currency, str) or not _CURRENCY_RE.fullmatch(cmd.currency):
            raise ValueError(f"currency: must match pattern '{CURRENCY_PATTERN}'")

        if cmd.rate_limit_max <= 0:
            raise ValueError("rate_limit_max: must be greater than 0")

        if cmd.daily_quota_max <= 0:
            raise ValueError("daily_quota_max: must be greater than 0")

        # 1. Generate 256-bit cryptographic secret (hex format for copy-paste safety)
        secret_bytes = os.urandom(32)
        secret_hex = secret_bytes.hex()

        # 2. Vault envelope encryption with byte-exact AAD context binding
        envelope = encrypt_secret(
            secret_hex,
            context=agent_secret_context(cmd.external_id),
        )

        # 3. Atomic database provisioning in ONE Unit of Work
        try:
            async with UnitOfWork(self._pool) as uow:
                row = await uow.connection.fetchrow(
                    """
                    INSERT INTO agents (
                        external_id,
                        name,
                        secret_encrypted,
                        rate_limit_max,
                        daily_quota_max,
                        active
                    )
                    VALUES ($1, $2, $3, $4, $5, true)
                    RETURNING id, created_at;
                    """,
                    cmd.external_id,
                    clean_name,
                    envelope,
                    cmd.rate_limit_max,
                    cmd.daily_quota_max,
                )
                if row is None:
                    raise RuntimeError("Failed to insert agent record")
                agent_id: UUID = row["id"]

                await uow.connection.execute(
                    """
                    INSERT INTO ledger_accounts (
                        owner_type,
                        owner_id,
                        currency,
                        balance,
                        version
                    )
                    VALUES ('agent', $1, $2, 0, 0);
                    """,
                    agent_id,
                    cmd.currency,
                )
        except asyncpg.UniqueViolationError as exc:
            raise ValueError("external_id already registered") from exc

        # 4. Return CreatedAgent containing the one-time plaintext secret
        return CreatedAgent(
            agent_id=agent_id,
            external_id=cmd.external_id,
            secret=secret_hex,
        )

    async def activate_agent(self, agent_id: UUID) -> bool:
        """Activate an inactive agent, incrementing version and invalidating cache.

        Returns True if the agent was previously inactive and successfully activated;
        False if already active or non-existent (idempotent no-op).
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE agents
                SET active = true, version = version + 1, updated_at = now()
                WHERE id = $1 AND active = false
                RETURNING id;
                """,
                agent_id,
            )

        if row is not None:
            await self._agent_repo.invalidate(agent_id)
            return True

        return False

    async def suspend_agent(self, agent_id: UUID) -> bool:
        """Suspend an active agent via AgentRepo delegation."""
        return await self._agent_repo.suspend(agent_id)


class MerchantLifecycle:
    """Merchant lifecycle service owning atomic provisioning and suspension transitions."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        merchant_repo: MerchantRepo,
        valkey: redis_async.Redis | None = None,
    ) -> None:
        """Initialize MerchantLifecycle with database connection pool and MerchantRepo."""
        self._pool: asyncpg.Pool = pool
        self._merchant_repo: MerchantRepo = merchant_repo
        self._valkey: redis_async.Redis | None = valkey

    async def create_merchant(self, cmd: CreateMerchantCommand) -> CreatedMerchant:
        """Atomically provision a merchant identity and its initial ledger account.

        In Phase 1, merchants do not receive an API secret (agents pay, merchants receive).
        Invalidation executes post-commit to ensure cache freshness without poisoning.

        Raises:
            ValueError: If input validation fails or external_id is already registered.
        """
        # 0. Domain validation
        if not isinstance(cmd.external_id, str) or not _HANDLE_RE.fullmatch(cmd.external_id):
            raise ValueError(f"external_id: must match pattern '{MERCHANT_ID_PATTERN}'")

        clean_name = cmd.name.strip()
        if len(clean_name) > _MAX_NAME_LENGTH:
            raise ValueError(f"name: length cannot exceed {_MAX_NAME_LENGTH} characters")

        if not isinstance(cmd.currency, str) or not _CURRENCY_RE.fullmatch(cmd.currency):
            raise ValueError(f"currency: must match pattern '{CURRENCY_PATTERN}'")

        # 1. Atomic database provisioning in ONE Unit of Work
        try:
            async with UnitOfWork(self._pool) as uow:
                row = await uow.connection.fetchrow(
                    """
                    INSERT INTO merchants (
                        external_id,
                        name,
                        active
                    )
                    VALUES ($1, $2, true)
                    RETURNING id, created_at;
                    """,
                    cmd.external_id,
                    clean_name,
                )
                if row is None:
                    raise RuntimeError("Failed to insert merchant record")
                merchant_id: UUID = row["id"]

                await uow.connection.execute(
                    """
                    INSERT INTO ledger_accounts (
                        owner_type,
                        owner_id,
                        currency,
                        balance,
                        version
                    )
                    VALUES ('merchant', $1, $2, 0, 0);
                    """,
                    merchant_id,
                    cmd.currency,
                )
        except asyncpg.UniqueViolationError as exc:
            raise ValueError("external_id already registered") from exc

        # 2. Post-commit cache invalidation
        await self._merchant_repo.invalidate(cmd.external_id)

        return CreatedMerchant(
            merchant_id=merchant_id,
            external_id=cmd.external_id,
        )

    async def suspend_merchant(self, external_id: str) -> bool:
        """Suspend an active merchant, updating DB and invalidating cache.

        Returns True if merchant was previously active and successfully deactivated;
        False if already inactive or not found (idempotent no-op).
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE merchants
                SET active = false, version = version + 1, updated_at = now()
                WHERE external_id = $1 AND active = true
                RETURNING id;
                """,
                external_id,
            )

        if row is not None:
            await self._merchant_repo.invalidate(external_id)
            return True

        return False

    async def activate_merchant(self, external_id: str) -> bool:
        """Activate an inactive merchant, updating DB and invalidating cache."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE merchants
                SET active = true, version = version + 1, updated_at = now()
                WHERE external_id = $1 AND active = false
                RETURNING id;
                """,
                external_id,
            )

        if row is not None:
            await self._merchant_repo.invalidate(external_id)
            return True

        return False
