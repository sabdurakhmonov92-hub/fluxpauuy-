"""Integration tests for RiskEngine, fail-partial Redis resilience, and count_open.

Exercises:
1. engine.decide happy, quarantine, and reject paths end-to-end:
   - Hold rows created in payment_holds for hold verdicts.
   - NO hold rows created for allowed or rejected transfers.
2. QuarantineService.count_open append proven:
   - Pending holds tracked accurately; status transitions (approve/reject) decrement count.
3. REDIS LOSS & FAIL-PARTIAL DEGRADATION:
   - Dead Valkey endpoint -> decide() degrades velocity to pass-through and logs 'degraded'.
   - DB-backed ceiling and saturation limits remain 100% operational.
4. Composition-Safety Contract:
   - Task 28 check_payment and Task 34 engine.decide produce identical decisions.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable, Coroutine
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]
import pytest
import pytest_asyncio
import redis.asyncio as redis_async

from fluxpay.risk.limits import (
    DEFAULT_LIMITS,
    RiskDecision,
    check_payment,
)
from fluxpay.risk.quarantine import QuarantineService
from fluxpay.risk.rules import RiskEngine

pytestmark = pytest.mark.integration

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
MIGRATION_0007_PATH: Path = REPO_ROOT / "migrations" / "0007_limits.sql"


class AgentCredentials(Protocol):
    agent_id: UUID
    external_id: str
    secret_bytes: bytes


MakeAgentType = Callable[..., Coroutine[Any, Any, AgentCredentials]]


@pytest.fixture(scope="session")
def limits_migration_sql() -> str:
    """Read migrations/0007_limits.sql once per session."""
    assert MIGRATION_0007_PATH.is_file(), f"Missing migration file: {MIGRATION_0007_PATH}"
    return MIGRATION_0007_PATH.read_text(encoding="utf-8")


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def apply_limits_schema(
    db_pool: asyncpg.Pool,
    limits_migration_sql: str,
    apply_agents_schema: None,
) -> None:
    """Execute migrations/0007_limits.sql once per session."""
    async with db_pool.acquire() as conn:
        await conn.execute(limits_migration_sql)


@pytest_asyncio.fixture
async def cleanup_holds(
    db_pool: asyncpg.Pool,
    apply_limits_schema: None,
) -> AsyncGenerator[Callable[[UUID], Coroutine[Any, Any, None]], None]:
    """Track and delete payment_holds rows created during test runs."""
    tracked_agents: list[UUID] = []

    async def _track(agent_id: UUID) -> None:
        tracked_agents.append(agent_id)

    try:
        yield _track
    finally:
        if tracked_agents:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM payment_holds WHERE agent_id = ANY($1::uuid[]);",
                    tracked_agents,
                )


# ==============================================================================
# 1. ENGINE DECIDE END-TO-END (HAPPY / QUARANTINE / REJECT)
# ==============================================================================


async def test_engine_decide_happy_path_no_hold_row(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    make_agent: MakeAgentType,
    cleanup_holds: Callable[[UUID], Coroutine[Any, Any, None]],
    apply_limits_schema: None,
) -> None:
    """Happy path allows payment and does NOT insert a hold into payment_holds."""
    agent = await make_agent()
    await cleanup_holds(agent.agent_id)

    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    engine = RiskEngine(pool=db_pool, valkey=valkey, now=lambda: now)

    decision = await engine.decide(
        agent_id=agent.agent_id,
        amount_minor=10_000_000,  # $10
        currency="USD",
        idem_key="idem-happy-1",
    )

    assert decision == RiskDecision(allowed=True, quarantined=False, reason=None)

    # Verify NO row created in payment_holds
    async with db_pool.acquire() as conn:
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM payment_holds WHERE agent_id = $1;",
            agent.agent_id,
        )
    assert count == 0


async def test_engine_decide_quarantine_path_creates_hold_row(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    make_agent: MakeAgentType,
    cleanup_holds: Callable[[UUID], Coroutine[Any, Any, None]],
    apply_limits_schema: None,
) -> None:
    """Quarantine path holds payment and creates pending row in payment_holds."""
    agent = await make_agent()
    await cleanup_holds(agent.agent_id)

    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    engine = RiskEngine(pool=db_pool, valkey=valkey, now=lambda: now)

    decision = await engine.decide(
        agent_id=agent.agent_id,
        amount_minor=150_000_000,  # $150 > $100 ceiling
        currency="USD",
        idem_key="idem-hold-1",
    )

    assert decision == RiskDecision(allowed=False, quarantined=True, reason="single_tx_ceiling")

    # Verify row created in payment_holds
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT status, reason, amount_minor
            FROM payment_holds
            WHERE agent_id = $1 AND idem_key = $2;
            """,
            agent.agent_id,
            "idem-hold-1",
        )
    assert row is not None
    assert row["status"] == "pending"
    assert row["reason"] == "single_tx_ceiling"
    assert row["amount_minor"] == 150_000_000


async def test_engine_decide_reject_path_no_hold_row(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    make_agent: MakeAgentType,
    cleanup_holds: Callable[[UUID], Coroutine[Any, Any, None]],
    apply_limits_schema: None,
) -> None:
    """Velocity burst rejection does NOT create hold in payment_holds."""
    agent = await make_agent()
    await cleanup_holds(agent.agent_id)

    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    engine = RiskEngine(pool=db_pool, valkey=valkey, now=lambda: now)

    # Exhaust velocity limit (default 5)
    for _ in range(5):
        await engine.decide(
            agent_id=agent.agent_id,
            amount_minor=1_000_000,
            currency="USD",
            idem_key=f"idem-vel-{uuid4()}",
        )

    # 6th attempt should be rejected for velocity
    decision = await engine.decide(
        agent_id=agent.agent_id,
        amount_minor=1_000_000,
        currency="USD",
        idem_key="idem-vel-blocked",
    )

    assert decision == RiskDecision(allowed=False, quarantined=False, reason="velocity")

    # Confirm NO hold row created for blocked attempt
    async with db_pool.acquire() as conn:
        count = await conn.fetchval(
            """
            SELECT COUNT(*) FROM payment_holds
            WHERE agent_id = $1 AND idem_key = 'idem-vel-blocked';
            """,
            agent.agent_id,
        )
    assert count == 0


# ==============================================================================
# 2. QUARANTINE SERVICE COUNT_OPEN APPEND
# ==============================================================================


async def test_quarantine_count_open_lifecycle(
    db_pool: asyncpg.Pool,
    make_agent: MakeAgentType,
    cleanup_holds: Callable[[UUID], Coroutine[Any, Any, None]],
    apply_limits_schema: None,
) -> None:
    """Validate QuarantineService.count_open tracks pending holds across decisions."""
    agent = await make_agent()
    await cleanup_holds(agent.agent_id)

    quarantine = QuarantineService(db_pool)

    # 0 initially
    assert await quarantine.count_open(agent.agent_id) == 0

    # Place hold 1
    h1 = await quarantine.place_hold(
        agent_id=agent.agent_id,
        idem_key="idem-q1",
        amount_minor=200_000_000,
        currency="USD",
        reason="single_tx_ceiling",
    )
    assert await quarantine.count_open(agent.agent_id) == 1

    # Place hold 2
    h2 = await quarantine.place_hold(
        agent_id=agent.agent_id,
        idem_key="idem-q2",
        amount_minor=300_000_000,
        currency="USD",
        reason="daily_cap",
    )
    assert await quarantine.count_open(agent.agent_id) == 2

    # Approve hold 1 -> pending count drops to 1
    await quarantine.decide(h1.hold_id, approved=True)
    assert await quarantine.count_open(agent.agent_id) == 1

    # Reject hold 2 -> pending count drops to 0
    await quarantine.decide(h2.hold_id, approved=False)
    assert await quarantine.count_open(agent.agent_id) == 0


async def test_engine_queue_saturation_triggered_at_five_holds(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    make_agent: MakeAgentType,
    cleanup_holds: Callable[[UUID], Coroutine[Any, Any, None]],
    apply_limits_schema: None,
) -> None:
    """When an agent accumulates 5 pending holds, saturation rule triggers hold."""
    agent = await make_agent()
    await cleanup_holds(agent.agent_id)

    quarantine = QuarantineService(db_pool)
    for i in range(5):
        await quarantine.place_hold(
            agent_id=agent.agent_id,
            idem_key=f"idem-sat-{i}",
            amount_minor=10_000_000,
            currency="USD",
            reason="single_tx_ceiling",
        )

    assert await quarantine.count_open(agent.agent_id) == 5

    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    engine = RiskEngine(pool=db_pool, valkey=valkey, now=lambda: now)

    # Proposed payment is within normal ceilings, but queue is saturated
    decision = await engine.decide(
        agent_id=agent.agent_id,
        amount_minor=5_000_000,
        currency="USD",
        idem_key="idem-sat-6th",
    )

    assert decision == RiskDecision(allowed=False, quarantined=True, reason="queue_saturation")


# ==============================================================================
# 3. REDIS LOSS & FAIL-PARTIAL ESSAY PROOF
# ==============================================================================


async def test_redis_loss_fail_partial_degrades_gracefully(
    db_pool: asyncpg.Pool,
    make_agent: MakeAgentType,
    cleanup_holds: Callable[[UUID], Coroutine[Any, Any, None]],
    apply_limits_schema: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When Redis is dead, velocity degrades to pass-through while DB limits hold."""
    agent = await make_agent()
    await cleanup_holds(agent.agent_id)

    # Dead Redis client pointing to dead/unused port
    dead_valkey = redis_async.Redis.from_url(
        "redis://127.0.0.1:59999/0",
        socket_connect_timeout=0.05,
        socket_timeout=0.05,
    )

    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    engine = RiskEngine(pool=db_pool, valkey=dead_valkey, now=lambda: now)

    try:
        # A) Normal payment under Redis outage: allowed via degraded velocity pass-through
        caplog.clear()
        decision_allowed = await engine.decide(
            agent_id=agent.agent_id,
            amount_minor=10_000_000,  # $10 within ceiling
            currency="USD",
            idem_key="idem-dead-redis-1",
        )
        assert decision_allowed == RiskDecision(allowed=True, quarantined=False, reason=None)
        assert "degraded" in caplog.text

        # B) Ceiling breach under Redis outage: STILL QUARANTINED via PostgreSQL limits!
        caplog.clear()
        decision_held = await engine.decide(
            agent_id=agent.agent_id,
            amount_minor=200_000_000,  # $200 > $100 ceiling
            currency="USD",
            idem_key="idem-dead-redis-2",
        )
        assert decision_held == RiskDecision(
            allowed=False, quarantined=True, reason="single_tx_ceiling"
        )
        assert "degraded" in caplog.text
    finally:
        await dead_valkey.aclose()


# ==============================================================================
# 4. COMPOSITION-SAFETY TEST (TASK 28 VS TASK 34 SEMANTICS IDENTICAL)
# ==============================================================================


async def test_composition_safety_identical_decisions(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    make_agent: MakeAgentType,
    cleanup_holds: Callable[[UUID], Coroutine[Any, Any, None]],
    apply_limits_schema: None,
) -> None:
    """Verify Task 28 check_payment and Task 34 engine.decide yield identical results."""
    agent = await make_agent()
    await cleanup_holds(agent.agent_id)

    limits = DEFAULT_LIMITS
    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    engine = RiskEngine(pool=db_pool, valkey=valkey, now=lambda: now)

    # 1. Normal payment: both allow
    dec_28_allow = await check_payment(
        db_pool,
        valkey,
        agent_id=agent.agent_id,
        limits=limits,
        amount_minor=10_000_000,
        currency="USD",
        now=now,
    )
    dec_34_allow = await engine.decide(
        agent_id=agent.agent_id,
        amount_minor=10_000_000,
        currency="USD",
    )
    assert (
        dec_28_allow == dec_34_allow == RiskDecision(allowed=True, quarantined=False, reason=None)
    )

    # 2. Ceiling breach: both quarantine single_tx_ceiling
    dec_28_ceil = await check_payment(
        db_pool,
        valkey,
        agent_id=agent.agent_id,
        limits=limits,
        amount_minor=150_000_000,
        currency="USD",
        now=now,
    )
    dec_34_ceil = await engine.decide(
        agent_id=agent.agent_id,
        amount_minor=150_000_000,
        currency="USD",
    )
    assert (
        dec_28_ceil
        == dec_34_ceil
        == RiskDecision(allowed=False, quarantined=True, reason="single_tx_ceiling")
    )
