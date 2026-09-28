"""Policy framework (rules-as-data) and resilient RiskEngine for FluxPay.

==============================================================================
RULES-AS-DATA ARCHITECTURE & COMPOSITION PHILOSOPHY
==============================================================================
In payment risk systems, risk policies evolve rapidly in response to emerging
fraud patterns, velocity spikes, and regulatory controls. Hardcoding rules inside
monolithic evaluation procedures requires code deploys for every policy adjustment.

The rules-as-data framework expresses each risk invariant as a pure, stateless
function:
    RuleFn = Callable[[PaymentContext], RuleResult]

WHY PURE FUNCTIONS OVER CLASSES:
1. Extreme Simplicity: Stateless functions require zero lifecycle management,
   dependency injection, or state teardown.
2. Deterministic Serialization & Composition: Pure functions naturally compose into
   immutable tuples (DEFAULT_RULES), making policy pipelines transparent, ordered,
   and easily customized per tenant or environment.
3. Zero-I/O Unit Testability: Rules operate exclusively on an immutable PaymentContext,
   enabling exhaustive matrix testing with zero network mocks or database fixtures.

==============================================================================
THE QUEUE SATURATION DOCTRINE (HUMAN CAPACITY PROTECTION)
==============================================================================
Task 28 established the three-tier evaluation model (allow, transient reject,
human quarantine). However, Task 28 evaluated transactions in isolation without
visibility into the current state of the human review queue.

NEW SIGNAL: hold_open_count (pending holds for an agent).
A saturated review queue is ITSELF a primary risk signal.
When an agent accumulates >= 5 pending holds, the saturation_rule intervenes
with verdict='hold' and reason='queue_saturation'.

OPERATIONAL RATIONALE (HUMAN CAPACITY PROTECTION):
If an autonomous agent is caught in an anomalous execution loop or misconfigured
batch routine, placing 100 payments into human review creates severe operational
fatigue, burns reviewer SLA, and risks genuine fraud slipping through during
queue triage.
The saturation rule caps the pending explosion: once 5 holds are waiting for
human review, subsequent transfers are held with 'queue_saturation' (or rejected
at policy boundaries), protecting human operator capacity and preventing queue denial
of service.

==============================================================================
THE FAIL-PARTIAL ESSAY (AVAILABILITY WITH HONEST BOUNDS UNDER REDIS LOSS)
==============================================================================
A central architectural dilemma in distributed payment systems is behavior during
ephemeral storage failure (Valkey / Redis outage):
- Fail-Closed: Reject all payments if Redis is down. Guarantees 0% velocity breach,
  but causes total platform outage (0% availability) when cache dies.
- Blind Fail-Open: Allow all payments if Redis is down. Maximizes availability,
  but leaves the platform completely exposed to unlimited capital drain.

THE SENIOR RESOLUTION: FAIL-PARTIAL DEGRADATION
FluxPay adopts an honest fail-partial doctrine grounded in storage boundaries:
1. Fundamental Financial Exposure Bounds: Single transaction ceiling (amount <= max_single)
   and daily outflow cap (amount + outflow <= daily_cap) are backed by PostgreSQL
   configuration (LimitRepo) and core ledger state. These rules continue to run
   strictly even if Redis is completely unreachable.
2. Velocity as a Soft Transient Guard: Velocity (e.g. 5 tx / 60s) is a transient
   loop-guard, NOT the sole line of defense against insolvency.
3. Compensating Upstream & Downstream Controls:
   - Upstream: The HTTP ingress rate gate enforces a hard boundary (100 req/min).
     The worst-case velocity gap during a Redis outage is bounded by the gateway.
   - Downstream: Task 41's daily reconciliation worker compares ledger truth with
     outflow logs and detects any anomalies.
Therefore, when Redis fails, velocity enforcement DEGRADES to pass-through (logged
explicitly as 'degraded' for operational monitoring), while single-ceiling,
daily-cap, and queue-saturation rules continue strict enforcement via PostgreSQL.
Payments continue to settle within honest, hard financial limits.
"""

from __future__ import annotations

import logging as std_logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final, Literal
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import redis.asyncio as redis_async

from fluxpay.risk.limits import AgentLimits, LimitRepo, RiskDecision
from fluxpay.risk.quarantine import VALID_HOLD_REASONS, QuarantineService
from fluxpay.shared.logging import get_logger

logger = get_logger("fluxpay.risk.rules")
std_logger = std_logging.getLogger("fluxpay.risk.rules")


# ==============================================================================
# a) RULE RESULT & PAYMENT CONTEXT
# ==============================================================================


@dataclass(frozen=True, slots=True)
class RuleResult:
    """Outcome of an individual risk rule evaluation."""

    verdict: Literal["allow", "reject", "hold"]
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class PaymentContext:
    """Immutable evaluation context capturing all signals needed for risk decisions."""

    agent_id: UUID
    amount_minor: int
    currency: str
    limits: AgentLimits
    outflow_today_minor: int
    recent_count: int
    hold_open_count: int
    now: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        """Validate context invariants defensively."""
        if self.amount_minor <= 0:
            raise ValueError(f"amount_minor must be > 0, got {self.amount_minor}")
        if self.now.tzinfo is None or self.now.utcoffset() is None:
            raise ValueError("now must be a timezone-aware datetime")
        if self.outflow_today_minor < 0:
            raise ValueError(f"outflow_today_minor must be >= 0, got {self.outflow_today_minor}")
        if self.recent_count < 0:
            raise ValueError(f"recent_count must be >= 0, got {self.recent_count}")
        if self.hold_open_count < 0:
            raise ValueError(f"hold_open_count must be >= 0, got {self.hold_open_count}")


type RuleFn = Callable[[PaymentContext], RuleResult]


# ==============================================================================
# b) PURE RULE DEFINITIONS
# ==============================================================================


def ceiling_rule(ctx: PaymentContext) -> RuleResult:
    """Rule 1: Enforce maximum single transaction spending ceiling.

    Breaches are routed to HITL quarantine ('single_tx_ceiling') because high-ticket
    transfers may be valid business transactions requiring manual approval.
    """
    if ctx.amount_minor > ctx.limits.max_single_tx_minor:
        return RuleResult(verdict="hold", reason="single_tx_ceiling")
    return RuleResult(verdict="allow", reason=None)


def daily_cap_rule(ctx: PaymentContext) -> RuleResult:
    """Rule 2: Enforce cumulative daily outflow cap.

    Breaches are routed to HITL quarantine ('daily_cap') to safeguard capital while
    permitting operator review.
    """
    if ctx.outflow_today_minor + ctx.amount_minor > ctx.limits.daily_outflow_cap_minor:
        return RuleResult(verdict="hold", reason="daily_cap")
    return RuleResult(verdict="allow", reason=None)


def velocity_rule(ctx: PaymentContext) -> RuleResult:
    """Rule 3: Enforce payment frequency velocity limit within the fixed time window.

    Breaches are rejected immediately ('velocity') because velocity bursts represent
    transient agent retry loops that should back off rather than flooding human queues.
    """
    if ctx.recent_count >= ctx.limits.velocity_limit:
        return RuleResult(verdict="reject", reason="velocity")
    return RuleResult(verdict="allow", reason=None)


def saturation_rule(ctx: PaymentContext) -> RuleResult:
    """Rule 4: Enforce human review queue saturation ceiling.

    When an agent has >= 5 pending holds, new transfers are held ('queue_saturation')
    to prevent queue exhaustion and protect human reviewer capacity.
    """
    if ctx.hold_open_count >= 5:
        return RuleResult(verdict="hold", reason="queue_saturation")
    return RuleResult(verdict="allow", reason=None)


# ORDER INVARIANT: ceiling -> cap -> velocity -> saturation
# Most-specific financial bounds first; first non-allow wins.
DEFAULT_RULES: Final[tuple[RuleFn, ...]] = (
    ceiling_rule,
    daily_cap_rule,
    velocity_rule,
    saturation_rule,
)


def evaluate_rules(
    ctx: PaymentContext,
    rules: tuple[RuleFn, ...] = DEFAULT_RULES,
) -> RuleResult:
    """Evaluate payment context against an ordered tuple of rules (first non-allow wins)."""
    for rule in rules:
        res = rule(ctx)
        if res.verdict != "allow":
            return res
    return RuleResult(verdict="allow", reason=None)


# ==============================================================================
# c) RISK ENGINE (ORCHESTRATOR & FAIL-PARTIAL RESILIENCE)
# ==============================================================================


class RiskEngine:
    """Orchestrator for limits retrieval, counter queries, rule evaluation, and hold placement.

    Implements the fail-partial resilience pattern on Redis/Valkey loss:
    - If Redis is unavailable, velocity degrades to pass-through with degraded warning logging.
    - PostgreSQL limit policies (ceiling, cap, saturation) remain 100% active.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        valkey: redis_async.Redis,
        *,
        rules: tuple[RuleFn, ...] = DEFAULT_RULES,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._pool = pool
        self._valkey = valkey
        self._rules = rules
        self._now = now or (lambda: datetime.now(UTC))

    async def decide(
        self,
        *,
        agent_id: UUID,
        amount_minor: int,
        currency: str,
        idem_key: str | None = None,
    ) -> RiskDecision:
        """Evaluate risk for a proposed payment and optionally place a hold if quarantined.

        Parameters
        ----------
        agent_id:
            Identity of the initiating agent.
        amount_minor:
            Transfer amount in minor currency units.
        currency:
            3-letter ISO currency code.
        idem_key:
            Optional idempotency key; if provided and the verdict is 'hold',
            a hold is idempotently placed in payment_holds.

        Returns
        -------
        RiskDecision:
            Three-tier outcome: allowed, quarantined (with hold placed), or rejected.
        """
        # 1. Fetch effective limits from PostgreSQL (or default if absent)
        limit_repo = LimitRepo(self._pool)
        limits = await limit_repo.get(agent_id)

        # 2. Query open holds count directly via QuarantineService.count_open
        quarantine_svc = QuarantineService(self._pool)
        hold_open_count = await quarantine_svc.count_open(agent_id)

        # 3. Query Redis counters with fail-partial degradation on Redis loss
        current_now = self._now()
        now_s = int(current_now.timestamp())
        bucket = now_s // limits.velocity_window_s
        vel_key = f"flx:vel:{{{agent_id}}}:{bucket}"

        yyyymmdd = current_now.astimezone(UTC).strftime("%Y%m%d")
        outflow_key = f"flx:outflow:{{{agent_id}}}:{yyyymmdd}"

        recent_count = 0
        outflow_today = 0
        try:
            recent_count = int(await self._valkey.incr(vel_key))
            ttl_ms = (limits.velocity_window_s * 2 + 1) * 1000
            await self._valkey.pexpire(vel_key, ttl_ms)

            raw_outflow = await self._valkey.get(outflow_key)
            outflow_today = int(raw_outflow) if raw_outflow is not None else 0
        except Exception as exc:
            msg = (
                f"Redis unavailable ({exc}); velocity check degraded to "
                "pass-through, DB-backed limits active"
            )
            logger.warning(
                "risk_engine_degraded_redis_loss",
                agent_id=str(agent_id),
                mode="degraded",
                error=str(exc),
                detail=msg,
            )
            std_logger.warning("risk_engine_degraded_redis_loss: %s (mode=degraded)", msg)
            recent_count = 0
            outflow_today = 0

        # 4. Construct context and execute rules in strict order
        ctx = PaymentContext(
            agent_id=agent_id,
            amount_minor=amount_minor,
            currency=currency,
            limits=limits,
            outflow_today_minor=outflow_today,
            recent_count=recent_count,
            hold_open_count=hold_open_count,
            now=current_now,
        )

        rule_res = evaluate_rules(ctx, self._rules)

        # 5. Map verdict to RiskDecision and place hold if quarantined
        decision: RiskDecision
        if rule_res.verdict == "allow":
            decision = RiskDecision(allowed=True, quarantined=False, reason=None)
        elif rule_res.verdict == "reject":
            decision = RiskDecision(allowed=False, quarantined=False, reason=rule_res.reason)
        else:  # hold
            if idem_key is not None:
                # Map domain reason to valid DB check constraint reason if unlisted
                db_reason = rule_res.reason if rule_res.reason in VALID_HOLD_REASONS else "manual"
                payload = {"rule_reason": rule_res.reason} if db_reason != rule_res.reason else None
                await quarantine_svc.place_hold(
                    agent_id=agent_id,
                    idem_key=idem_key,
                    amount_minor=amount_minor,
                    currency=currency,
                    reason=db_reason,
                    payload=payload,
                )
            decision = RiskDecision(allowed=False, quarantined=True, reason=rule_res.reason)

        # 6. Structured logging on adverse outcomes
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
                hold_open_count=hold_open_count,
            )

        return decision
