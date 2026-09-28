"""Account directory and resolver for FluxPay ledger accounts.

Blueprint §5 Account Topology & Task 31 Resolver.

=============================================================================
DESIGN DECISIONS & INVARIANTS (WHY THE SYSTEM IS BUILT THIS WAY)
=============================================================================

1. WHY IN-PROCESS CACHE FOR SYSTEM/FEES/TREASURY (Zero Network Hops):
--------------------------------------------------------------------
System, fees, and treasury accounts are immutable platform anchors provisioned
once at deployment time (via deploy/sql/bootstrap.sql). Their owner IDs and
account records never change. Caching these 3 records in-process (module-level
dictionary with TTL):
- Eliminates Redis or PostgreSQL network hops on the hottest read path in payments.
- Per-process 60-second staleness is completely harmless because the rows are
  immutable by design.
- Multi-instance trade-off: Each application worker process caches independently.
  Because accounts are never deleted or relocated, per-worker cache divergence is
  impossible.

2. WHY UUIDv5 DETERMINISM IS A PRECONDITION (No Split-Brain Balances):
-----------------------------------------------------------------------
The cache key and lookups rely on deterministic owner IDs derived from
`uuid5(FLXPAY_NAMESPACE_UUID, 'system'|'fees'|'treasury')`.
If treasury or fees were provisioned with non-deterministic random UUIDs across
different deployments or worker nodes, lookups would resolve to divergent accounts,
silently forking ledger balances and corrupting reconciliation (Task 41).
The bootstrap seed's UUIDv5 determinism is the directory's correctness precondition.

3. WHY LOOKUPERROR WITH ALARM-GRADE MESSAGES:
---------------------------------------------
An agent or merchant identity without a corresponding ledger account violates the
core provisioning invariant of Task 27 ("an identity without a money account is
a support ticket"). If `get_agent_account()` or `get_merchant_account()` fails to find
the account, it indicates a catastrophic invariant violation (e.g. out-of-band DB
edits, broken migration, or partial rollback). A loud `LookupError` is raised so
the gateway / payment orchestrator (Task 31) can immediately reject the transaction
and fire operational alarms.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Final
from uuid import UUID, uuid5

import asyncpg  # type: ignore[import-untyped]

__all__ = [
    "FEES_OWNER_ID",
    "FLXPAY_NAMESPACE_UUID",
    "SYSTEM_OWNER_ID",
    "TREASURY_OWNER_ID",
    "AccountDirectory",
    "LedgerAccountRef",
    "reset_fees_cache",
]

# single source: bootstrap.sql; this constant mirrors it — guarded by test_bootstrap_determinism
FLXPAY_NAMESPACE_UUID: Final[UUID] = UUID("f1047a71-0000-5000-8000-000000000000")

# Deterministic owner IDs for singleton platform accounts (mirrors deploy/sql/bootstrap.sql).
SYSTEM_OWNER_ID: Final[UUID] = uuid5(FLXPAY_NAMESPACE_UUID, "system")
FEES_OWNER_ID: Final[UUID] = uuid5(FLXPAY_NAMESPACE_UUID, "fees")
TREASURY_OWNER_ID: Final[UUID] = uuid5(FLXPAY_NAMESPACE_UUID, "treasury")

# Module-level in-process cache:
# (owner_type, owner_id, currency) -> (LedgerAccountRef, expires_at_monotonic)
_IN_PROCESS_ACCOUNT_CACHE: dict[tuple[str, UUID, str], tuple[LedgerAccountRef, float]] = {}


def reset_fees_cache() -> None:
    """Clear the in-process system/fees/treasury account cache.

    Exposed strictly for test isolation and post-migration cache invalidation.
    """
    _IN_PROCESS_ACCOUNT_CACHE.clear()


@dataclass(frozen=True, slots=True)
class LedgerAccountRef:
    """Immutable reference to an authoritative ledger account."""

    account_id: UUID
    owner_type: str
    owner_id: UUID
    currency: str


class AccountDirectory:
    """Authoritative ledger account directory and resolver (Task 31 dependency).

    Provides sub-millisecond account resolution for agents, merchants, and platform
    system accounts with strict provisioning invariant enforcement.
    """

    def __init__(self, pool: asyncpg.Pool, *, fees_cache_ttl_s: int = 60) -> None:
        """Initialize AccountDirectory with database connection pool.

        Args:
            pool: asyncpg connection pool.
            fees_cache_ttl_s: TTL in seconds for the in-process platform accounts cache.
        """
        self._pool: asyncpg.Pool = pool
        self._fees_cache_ttl_s: int = fees_cache_ttl_s

    async def get_agent_account(self, agent_id: UUID, currency: str = "USDC") -> LedgerAccountRef:
        """Resolve ledger account reference for an agent by agent UUID.

        Raises:
            LookupError: If the account is missing (indicates broken provisioning invariant).
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id AS account_id, owner_type, owner_id, currency
                FROM ledger_accounts
                WHERE owner_type = 'agent' AND owner_id = $1 AND currency = $2;
                """,
                agent_id,
                currency,
            )

        if row is None:
            raise LookupError(
                f"Agent ledger account not found for agent_id='{agent_id}', currency='{currency}'. "
                "Alarm-grade provisioning invariant broken: agent exists without a ledger account."
            )

        return LedgerAccountRef(
            account_id=row["account_id"],
            owner_type=row["owner_type"],
            owner_id=row["owner_id"],
            currency=row["currency"],
        )

    async def get_merchant_account(
        self, external_id: str, currency: str = "USDC"
    ) -> LedgerAccountRef:
        """Resolve ledger account reference for a merchant by external_id handle.

        Raises:
            LookupError: If the account is missing (indicates broken provisioning invariant).
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT la.id AS account_id, la.owner_type, la.owner_id, la.currency
                FROM ledger_accounts la
                JOIN merchants m ON m.id = la.owner_id
                WHERE m.external_id = $1 AND la.owner_type = 'merchant' AND la.currency = $2;
                """,
                external_id,
                currency,
            )

        if row is None:
            raise LookupError(
                f"Merchant ledger account not found for external_id='{external_id}', "
                f"currency='{currency}'. "
                "Invariant broken: active merchant must have an associated ledger account."
            )

        return LedgerAccountRef(
            account_id=row["account_id"],
            owner_type=row["owner_type"],
            owner_id=row["owner_id"],
            currency=row["currency"],
        )

    async def _get_platform_account(
        self, owner_type: str, owner_id: UUID, currency: str
    ) -> LedgerAccountRef:
        """Fetch platform account with in-process caching."""
        cache_key = (owner_type, owner_id, currency)
        now = time.monotonic()

        cached_entry = _IN_PROCESS_ACCOUNT_CACHE.get(cache_key)
        if cached_entry is not None:
            ref, expires_at = cached_entry
            if now < expires_at:
                return ref

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id AS account_id, owner_type, owner_id, currency
                FROM ledger_accounts
                WHERE owner_type = $1 AND owner_id = $2 AND currency = $3;
                """,
                owner_type,
                owner_id,
                currency,
            )

        if row is None:
            raise LookupError(
                f"Bootstrap ledger account not found for owner_type='{owner_type}', "
                f"currency='{currency}'. "
                "Ensure deploy/sql/bootstrap.sql was applied during system initialization."
            )

        ref = LedgerAccountRef(
            account_id=row["account_id"],
            owner_type=row["owner_type"],
            owner_id=row["owner_id"],
            currency=row["currency"],
        )
        _IN_PROCESS_ACCOUNT_CACHE[cache_key] = (ref, now + self._fees_cache_ttl_s)
        return ref

    async def get_system_account(self, currency: str = "USDC") -> LedgerAccountRef:
        """Resolve system platform account."""
        return await self._get_platform_account("system", SYSTEM_OWNER_ID, currency)

    async def get_fees_account(self, currency: str = "USDC") -> LedgerAccountRef:
        """Resolve fees platform account."""
        return await self._get_platform_account("fees", FEES_OWNER_ID, currency)

    async def get_treasury_account(self, currency: str = "USDC") -> LedgerAccountRef:
        """Resolve treasury platform account."""
        return await self._get_platform_account("treasury", TREASURY_OWNER_ID, currency)
