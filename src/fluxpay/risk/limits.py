"""Effective financial limits policy, repository, and risk decision engine.

==============================================================================
THE THREE-TIER RISK PHILOSOPHY (ALLOW / TRANSIENT-REJECT / HUMAN-QUARANTINE)
==============================================================================
In autonomous AI agent payment systems, automated transfers occur at high
velocity without direct human keystrokes for each transaction. When an agent
submits a payment, risk evaluation partitions traffic into exactly three tiers:

1. TIER 1 — ALLOW:
   The payment satisfies all velocity constraints, does not breach single
   transaction ceilings, and remains within the daily cumulative outflow budget.
   Execution proceeds directly to double-entry ledger mutation (Task 31).

2. TIER 2 — TRANSIENT REJECT (VELOCITY EXCEEDED):
   When an agent exceeds its payment velocity threshold (e.g. > 5 payments / 60s),
   the transfer is immediately rejected with reason='velocity'.
   WHY hard-reject instead of quarantine:
   Velocity bursts are inherently transient conditions caused by agent retry loops
   or micro-batching bursts. An agent stuck in a tight loop should back off and
   retry after the time window rolls over. Pushing transient loop iterations into
   a human approval queue would drown operators in noise and produce severe operational
   fatigue. The client receives a distinct, non-retryable policy rejection (422)
   indicating that backoff is required before re-attempting.

3. TIER 3 — HUMAN QUARANTINE (CEILINGS & CAPS BREACHED):
   When a payment exceeds the single transaction ceiling (e.g. > $100) or breaches
   the cumulative daily outflow cap (e.g. > $500/day), it is placed on HOLD.
   WHY quarantine instead of hard-reject:
   A high-ticket transfer or high daily outflow is frequently a completely legitimate
   business transaction (e.g. monthly settlement, wholesale purchase, or high-tier
   subscription). Hard-rejecting valid high-value payments damages merchant revenue
   and platform trust. By routing these transactions to Human-In-The-Loop (HITL)
   quarantine (payment_holds), the system safeguards capital while enabling
   authorized operators to approve legitimate business transfers safely.

==============================================================================
SUPERSEDING TASK 20'S HANDOFF NOTE (VELOCITY PLACEMENT DOCTRINE)
==============================================================================
Task 20's gate.lua handoff note suggested extending the Lua gateway script to
incorporate financial velocity checks.
DECISION: This earlier design draft is explicitly SUPERSEDED. Velocity enforcement
belongs strictly inside the RISK ENGINE, not the gateway Lua gate:
(a) Gateway Lua is an HTTP-time ingress stability barrier (anti-replay, rate throttle,
    quota envelope). It runs pre-auth-completion on EVERY request (including read paths
    and admin calls). Injecting financial logic into gate.lua couples ingress stability
    to payment-domain rules.
(b) Financial velocity is a post-HMAC, post-idempotency, pre-ledger financial control.
    It must evaluate inside the payment orchestration pipeline where the database is
    reachable, agent financial policy is known, and the audit trail is preserved.
(c) gate.lua remains untouched and frozen.

==============================================================================
FIXED-BUCKET APPROXIMATION & COMPENSATING CONTROL (TASK 41 HANDOFF)
==============================================================================
Velocity uses a fixed-bucket time window: bucket = now_s // velocity_window_s.
This is a conscious design trade-off: financial velocity is a soft risk guard
(hard stability guarantees are enforced upstream by the rate gate). A boundary
burst of up to 2x limit across bucket boundaries is fully acceptable compared
to the O(N) memory and compute costs of per-agent sliding ZSETs in Redis.

Similarly, daily outflow cap enforcement in Phase 1 reads a fast, approximate
Redis counter (flx:outflow:{agent_id}:{yyyymmdd}). Querying PostgreSQL ledger
tables directly from the risk engine would violate domain layering (risk must not
query ledger internals).
COMPENSATING CONTROL: Task 41's daily reconciliation worker compares Redis outflow
counters against PostgreSQL double-entry ledger truth and raises alerts on drift.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import redis.asyncio as redis_async

from fluxpay.shared.logging import get_logger

logger = get_logger("fluxpay.risk")


# ==============================================================================
# a) LIMITS MODEL
# ==============================================================================


@dataclass(frozen=True, slots=True)
class AgentLimits:
    """Financial policy limits for an agent."""

    agent_id: UUID | None
    velocity_limit: int
    velocity_window_s: int
    max_single_tx_minor: int
    daily_outflow_cap_minor: int


# Default financial limits matching 0007_limits.sql schema defaults exactly.
DEFAULT_LIMITS: Final[AgentLimits] = AgentLimits(
    agent_id=None,
    velocity_limit=5,
    velocity_window_s=60,
    max_single_tx_minor=100_000_000,
    daily_outflow_cap_minor=500_000_000,
)


# ==============================================================================
# b) LIMIT REPOSITORY
# ==============================================================================


class LimitRepo:
    """PostgreSQL repository for per-agent financial policy limits."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def get(self, agent_id: UUID) -> AgentLimits:
        """Fetch effective limits for an agent.

        WHY absent row -> DEFAULT_LIMITS:
        Decoupled provisioning philosophy. When an agent is provisioned (Task 27),
        it immediately inherits platform default limits without requiring a synchronous
        write to agent_limits. An absent row is NORMAL and expected.
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT agent_id, velocity_limit, velocity_window_s,
                       max_single_tx_minor, daily_outflow_cap_minor
                FROM agent_limits
                WHERE agent_id = $1;
                """,
                agent_id,
            )

        if row is None:
            return DEFAULT_LIMITS

        return AgentLimits(
            agent_id=row["agent_id"],
            velocity_limit=row["velocity_limit"],
            velocity_window_s=row["velocity_window_s"],
            max_single_tx_minor=row["max_single_tx_minor"],
            daily_outflow_cap_minor=row["daily_outflow_cap_minor"],
        )

    async def upsert(self, agent_id: UUID, limits: AgentLimits) -> None:
        """Upsert agent limits with defensive range validation."""
        if not (1 <= limits.velocity_limit <= 100):
            raise ValueError(
                f"velocity_limit must be between 1 and 100, got {limits.velocity_limit}"
            )
        if not (10 <= limits.velocity_window_s <= 3600):
            raise ValueError(
                f"velocity_window_s must be between 10 and 3600, got {limits.velocity_window_s}"
            )
        if limits.max_single_tx_minor <= 0:
            raise ValueError(f"max_single_tx_minor must be > 0, got {limits.max_single_tx_minor}")
        if limits.daily_outflow_cap_minor <= 0:
            raise ValueError(
                f"daily_outflow_cap_minor must be > 0, got {limits.daily_outflow_cap_minor}"
            )

        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO agent_limits (
                    agent_id, velocity_limit, velocity_window_s,
                    max_single_tx_minor, daily_outflow_cap_minor,
                    created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, now(), now())
                ON CONFLICT (agent_id) DO UPDATE SET
                    velocity_limit = EXCLUDED.velocity_limit,
                    velocity_window_s = EXCLUDED.velocity_window_s,
                    max_single_tx_minor = EXCLUDED.max_single_tx_minor,
                    daily_outflow_cap_minor = EXCLUDED.daily_outflow_cap_minor,
                    updated_at = now();
                """,
                agent_id,
                limits.velocity_limit,
                limits.velocity_window_s,
                limits.max_single_tx_minor,
                limits.daily_outflow_cap_minor,
            )

    async def ensure_row(self, agent_id: UUID) -> None:
        """Idempotently seed default limits row for an agent if not present."""
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO agent_limits (
                    agent_id, velocity_limit, velocity_window_s,
                    max_single_tx_minor, daily_outflow_cap_minor
                ) VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (agent_id) DO NOTHING;
                """,
                agent_id,
                DEFAULT_LIMITS.velocity_limit,
                DEFAULT_LIMITS.velocity_window_s,
                DEFAULT_LIMITS.max_single_tx_minor,
                DEFAULT_LIMITS.daily_outflow_cap_minor,
            )


# ==============================================================================
# c) THE ENGINE (PURE CLASSIFIER + I/O SHELL)
# ==============================================================================


@dataclass(frozen=True, slots=True)
class RiskDecision:
    """Outcome of risk policy evaluation."""

    allowed: bool
    quarantined: bool
    reason: str | None


def evaluate(
    *,
    limits: AgentLimits,
    amount_minor: int,
    outflow_today_minor: int,
    recent_count: int,
    now: datetime,
) -> RiskDecision:
    """Pure classifier evaluating financial policy limits against a proposed transfer.

    Precedence Order & Rationale:
    1. Single transaction ceiling check:
       amount > max_single_tx_minor -> Quarantine ('single_tx_ceiling').
       FIRST MATCH WINS: If both single-ceiling and daily-cap are breached,
       single_tx_ceiling is prioritized because it is the more specific root-cause reason.
    2. Daily cumulative outflow cap check:
       outflow_today + amount > daily_outflow_cap -> Quarantine ('daily_cap').
    3. Transient velocity check:
       recent_count >= velocity_limit -> Hard Reject ('velocity').
    4. Allowed.
    """
    if amount_minor <= 0:
        raise ValueError(f"amount_minor must be > 0, got {amount_minor}")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")
    if outflow_today_minor < 0:
        raise ValueError(f"outflow_today_minor must be >= 0, got {outflow_today_minor}")
    if recent_count < 0:
        raise ValueError(f"recent_count must be >= 0, got {recent_count}")

    # 1. Single transaction ceiling (quarantined)
    if amount_minor > limits.max_single_tx_minor:
        return RiskDecision(allowed=False, quarantined=True, reason="single_tx_ceiling")

    # 2. Daily cumulative outflow cap (quarantined)
    if outflow_today_minor + amount_minor > limits.daily_outflow_cap_minor:
        return RiskDecision(allowed=False, quarantined=True, reason="daily_cap")

    # 3. Velocity limit (transient hard reject)
    if recent_count >= limits.velocity_limit:
        return RiskDecision(allowed=False, quarantined=False, reason="velocity")

    return RiskDecision(allowed=True, quarantined=False, reason=None)


class RiskEngine:
    """I/O shell orchestrating Redis velocity/outflow queries and risk evaluation."""

    def __init__(
        self,
        pool: asyncpg.Pool | None = None,
        valkey: redis_async.Redis | None = None,
    ) -> None:
        self._pool = pool
        self._valkey = valkey

    async def check_payment(
        self,
        pool: asyncpg.Pool | None = None,
        valkey: redis_async.Redis | None = None,
        *,
        agent_id: UUID,
        limits: AgentLimits,
        amount_minor: int,
        currency: str,
        now: datetime,
    ) -> RiskDecision:
        """Check proposed payment against effective limits using Redis counters."""
        v = valkey if valkey is not None else self._valkey
        if v is None:
            raise ValueError("Valkey client must be provided")

        now_s = int(now.timestamp())
        bucket = now_s // limits.velocity_window_s
        vel_key = f"flx:vel:{{{agent_id}}}:{bucket}"

        # 1. Increment velocity counter for fixed bucket
        recent_count = int(await v.incr(vel_key))
        # PEXPIRE window_s*2 + 1s to safely cover cross-node clock skew
        ttl_ms = (limits.velocity_window_s * 2 + 1) * 1000
        await v.pexpire(vel_key, ttl_ms)

        # 2. Read daily cumulative outflow counter
        yyyymmdd = now.astimezone(UTC).strftime("%Y%m%d")
        outflow_key = f"flx:outflow:{{{agent_id}}}:{yyyymmdd}"
        raw_outflow = await v.get(outflow_key)
        outflow_today = int(raw_outflow) if raw_outflow is not None else 0

        # 3. Pure evaluation
        decision = evaluate(
            limits=limits,
            amount_minor=amount_minor,
            outflow_today_minor=outflow_today,
            recent_count=recent_count,
            now=now,
        )

        # 4. Structured logging on adverse outcomes only
        if decision.quarantined or not decision.allowed:
            logger.warning(
                "risk_decision_adverse",
                agent_id=str(agent_id),
                allowed=decision.allowed,
                quarantined=decision.quarantined,
                reason=decision.reason,
                amount_minor=amount_minor,
                currency=currency,
                recent_count=recent_count,
                outflow_today_minor=outflow_today,
            )

        return decision


async def check_payment(
    pool: asyncpg.Pool | None,
    valkey: redis_async.Redis,
    *,
    agent_id: UUID,
    limits: AgentLimits,
    amount_minor: int,
    currency: str,
    now: datetime,
) -> RiskDecision:
    """Convenience function delegating to RiskEngine."""
    engine = RiskEngine(pool=pool, valkey=valkey)
    return await engine.check_payment(
        pool=pool,
        valkey=valkey,
        agent_id=agent_id,
        limits=limits,
        amount_minor=amount_minor,
        currency=currency,
        now=now,
    )
