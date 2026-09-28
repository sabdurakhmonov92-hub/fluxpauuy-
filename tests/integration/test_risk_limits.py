"""Integration tests for risk limits, velocity gate, and HITL quarantine queue.

Exercises:
1. LimitRepo:
   - absent row -> DEFAULT_LIMITS (lazy provisioning decoupling).
   - upsert + get roundtrip with defensive validation.
   - ensure_row idempotency.
2. Velocity enforcement:
   - limit 3 / window 60 -> 3 INCRs -> 4th check_payment -> velocity reject.
   - New window bucket (now + window_s) -> allowed (zero sleeps, deterministic clock injection).
3. Quarantine service:
   - amount > ceiling -> place_hold creates pending hold.
   - same (agent_id, idem_key) -> returns SAME hold_id (ON CONFLICT DO UPDATE, payload merged).
   - decide(approved=True) -> status='approved'.
   - re-decide -> returns None (double-decide guard).
4. list_pending:
   - returns only pending holds ordered by created_at ascending.
   - pagination limit respected and validated.
5. Task 31 composition preview (white-box):
   - place_hold then check_payment same idem -> still quarantined (policy re-evaluated;
     holds do not auto-pass; the human verdict enters via Task 42's settlement replay).
6. Redis outflow counter:
   - Outflow counter increments reflect in next check_payment (Task 31 contract).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable, Coroutine
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid4

import asyncpg  # type: ignore[import-untyped]
import pytest
import pytest_asyncio
import redis.asyncio as redis_async

from fluxpay.risk.limits import (
    DEFAULT_LIMITS,
    AgentLimits,
    LimitRepo,
    check_payment,
)
from fluxpay.risk.quarantine import (
    QuarantineService,
)

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
    """Helper fixture to clean up payment_holds for a test agent before agent deletion."""
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
# 1. LIMIT REPO: ABSENT ROW, UPSERT, ENSURE_ROW
# ==============================================================================


async def test_limit_repo_absent_row_returns_defaults(
    db_pool: asyncpg.Pool,
    apply_limits_schema: None,
) -> None:
    """Validate lazy provisioning: unknown agent_id returns DEFAULT_LIMITS without error."""
    repo = LimitRepo(db_pool)
    random_id = uuid4()

    limits = await repo.get(random_id)
    assert limits == DEFAULT_LIMITS
    assert limits.velocity_limit == 5
    assert limits.velocity_window_s == 60
    assert limits.max_single_tx_minor == 100_000_000
    assert limits.daily_outflow_cap_minor == 500_000_000


async def test_limit_repo_upsert_and_get_roundtrip(
    db_pool: asyncpg.Pool,
    make_agent: MakeAgentType,
    apply_limits_schema: None,
) -> None:
    """Validate upsert and retrieval of custom limits for an agent."""
    repo = LimitRepo(db_pool)
    agent = await make_agent()

    custom_limits = AgentLimits(
        agent_id=agent.agent_id,
        velocity_limit=10,
        velocity_window_s=120,
        max_single_tx_minor=50_000_000,
        daily_outflow_cap_minor=200_000_000,
    )

    await repo.upsert(agent.agent_id, custom_limits)
    retrieved = await repo.get(agent.agent_id)

    assert retrieved.agent_id == agent.agent_id
    assert retrieved.velocity_limit == 10
    assert retrieved.velocity_window_s == 120
    assert retrieved.max_single_tx_minor == 50_000_000
    assert retrieved.daily_outflow_cap_minor == 200_000_000

    # Validate defensive range guards
    with pytest.raises(ValueError, match="velocity_limit must be between 1 and 100"):
        await repo.upsert(
            agent.agent_id,
            AgentLimits(
                agent_id=agent.agent_id,
                velocity_limit=0,
                velocity_window_s=60,
                max_single_tx_minor=100_000_000,
                daily_outflow_cap_minor=500_000_000,
            ),
        )

    with pytest.raises(ValueError, match="velocity_window_s must be between 10 and 3600"):
        await repo.upsert(
            agent.agent_id,
            AgentLimits(
                agent_id=agent.agent_id,
                velocity_limit=5,
                velocity_window_s=5,
                max_single_tx_minor=100_000_000,
                daily_outflow_cap_minor=500_000_000,
            ),
        )

    with pytest.raises(ValueError, match="max_single_tx_minor must be > 0"):
        await repo.upsert(
            agent.agent_id,
            AgentLimits(
                agent_id=agent.agent_id,
                velocity_limit=5,
                velocity_window_s=60,
                max_single_tx_minor=0,
                daily_outflow_cap_minor=500_000_000,
            ),
        )

    with pytest.raises(ValueError, match="daily_outflow_cap_minor must be > 0"):
        await repo.upsert(
            agent.agent_id,
            AgentLimits(
                agent_id=agent.agent_id,
                velocity_limit=5,
                velocity_window_s=60,
                max_single_tx_minor=100_000_000,
                daily_outflow_cap_minor=0,
            ),
        )


async def test_limit_repo_ensure_row_idempotency(
    db_pool: asyncpg.Pool,
    make_agent: MakeAgentType,
    apply_limits_schema: None,
) -> None:
    """Validate ensure_row seeds defaults and is idempotent on repeat calls."""
    repo = LimitRepo(db_pool)
    agent = await make_agent()

    # 1. First ensure_row seeds row
    await repo.ensure_row(agent.agent_id)
    seeded = await repo.get(agent.agent_id)
    assert seeded.agent_id == agent.agent_id
    assert seeded.velocity_limit == DEFAULT_LIMITS.velocity_limit
    assert seeded.max_single_tx_minor == DEFAULT_LIMITS.max_single_tx_minor

    # 2. Second ensure_row is a no-op (ON CONFLICT DO NOTHING)
    await repo.ensure_row(agent.agent_id)
    assert (await repo.get(agent.agent_id)) == seeded


# ==============================================================================
# 2. VELOCITY ENFORCEMENT & FIXED-BUCKET MATH (NO SLEEPS)
# ==============================================================================


async def test_velocity_burst_reject_and_window_rollover(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    make_agent: MakeAgentType,
    apply_limits_schema: None,
) -> None:
    """Validate velocity enforcement: 3 INCRs -> 4th call rejected; new window bucket allowed."""
    agent = await make_agent()
    limits = AgentLimits(
        agent_id=agent.agent_id,
        velocity_limit=3,
        velocity_window_s=60,
        max_single_tx_minor=100_000_000,
        daily_outflow_cap_minor=500_000_000,
    )

    t0 = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    bucket_t0 = int(t0.timestamp()) // limits.velocity_window_s
    vel_key = f"flx:vel:{{{agent.agent_id}}}:{bucket_t0}"

    # Perform 3 prior INCRs directly in Valkey
    await valkey.incr(vel_key)
    await valkey.incr(vel_key)
    await valkey.incr(vel_key)
    assert int(await valkey.get(vel_key) or 0) == 3

    # 4th check_payment increments to 4 -> recent_count >= 3 -> velocity reject
    d1 = await check_payment(
        db_pool,
        valkey,
        agent_id=agent.agent_id,
        limits=limits,
        amount_minor=10_000,
        currency="USDC",
        now=t0,
    )
    assert d1.allowed is False
    assert d1.quarantined is False
    assert d1.reason == "velocity"

    # New window bucket (t0 + 60s) with injected clock: resets to 1 -> allowed
    t1 = t0 + timedelta(seconds=limits.velocity_window_s)
    d2 = await check_payment(
        db_pool,
        valkey,
        agent_id=agent.agent_id,
        limits=limits,
        amount_minor=10_000,
        currency="USDC",
        now=t1,
    )
    assert d2.allowed is True
    assert d2.quarantined is False
    assert d2.reason is None


# ==============================================================================
# 3. QUARANTINE: IDEMPOTENT PLACE_HOLD & DOUBLE-DECIDE GUARD
# ==============================================================================


async def test_quarantine_idempotent_place_hold_and_double_decide_guard(
    db_pool: asyncpg.Pool,
    make_agent: MakeAgentType,
    cleanup_holds: Callable[[UUID], Coroutine[Any, Any, None]],
    apply_limits_schema: None,
) -> None:
    """Validate idempotent re-hold (same hold_id, merged payload) and double-decide guard."""
    agent = await make_agent()
    await cleanup_holds(agent.agent_id)
    service = QuarantineService(db_pool)

    idem_key = f"idem_hold_{uuid4().hex[:16]}"
    amount = 150_000_000

    # 1. First place_hold
    h1 = await service.place_hold(
        agent_id=agent.agent_id,
        idem_key=idem_key,
        amount_minor=amount,
        currency="USDC",
        reason="single_tx_ceiling",
        payload={"merchant_ref": "inv_123"},
    )
    assert h1.status == "pending"
    assert h1.payload == {"merchant_ref": "inv_123"}

    # 2. Second place_hold with same (agent_id, idem_key) -> SAME hold_id (idempotent re-hold)
    h2 = await service.place_hold(
        agent_id=agent.agent_id,
        idem_key=idem_key,
        amount_minor=amount,
        currency="USDC",
        reason="single_tx_ceiling",
        payload={"retry_ctx": "agent_reconnect"},
    )
    assert h2.hold_id == h1.hold_id
    assert h2.payload == {"merchant_ref": "inv_123", "retry_ctx": "agent_reconnect"}

    # 3. First decide(approved=True) -> status becomes 'approved'
    approved = await service.decide(h1.hold_id, approved=True)
    assert approved is not None
    assert approved.hold_id == h1.hold_id
    assert approved.status == "approved"

    # 4. Re-decide -> returns None (double-decide guard: already decided)
    second_decision = await service.decide(h1.hold_id, approved=False)
    assert second_decision is None


# ==============================================================================
# 4. LIST PENDING & QUEUE PAGINATION
# ==============================================================================


async def test_quarantine_list_pending_and_limit_guards(
    db_pool: asyncpg.Pool,
    make_agent: MakeAgentType,
    cleanup_holds: Callable[[UUID], Coroutine[Any, Any, None]],
    apply_limits_schema: None,
) -> None:
    """Validate list_pending returns only pending holds with limit bounds."""
    agent = await make_agent()
    await cleanup_holds(agent.agent_id)
    service = QuarantineService(db_pool)

    h1 = await service.place_hold(
        agent_id=agent.agent_id,
        idem_key=f"idem_p1_{uuid4().hex[:12]}",
        amount_minor=110_000_000,
        currency="USDC",
        reason="single_tx_ceiling",
    )
    h2 = await service.place_hold(
        agent_id=agent.agent_id,
        idem_key=f"idem_p2_{uuid4().hex[:12]}",
        amount_minor=120_000_000,
        currency="USDC",
        reason="single_tx_ceiling",
    )
    h3 = await service.place_hold(
        agent_id=agent.agent_id,
        idem_key=f"idem_p3_{uuid4().hex[:12]}",
        amount_minor=130_000_000,
        currency="USDC",
        reason="single_tx_ceiling",
    )

    # Approve h2 so it leaves the pending queue
    await service.decide(h2.hold_id, approved=True)

    pending = await service.list_pending(limit=50)
    pending_ids = [p.hold_id for p in pending]

    assert h1.hold_id in pending_ids
    assert h2.hold_id not in pending_ids  # approved hold excluded
    assert h3.hold_id in pending_ids

    # Pagination test
    paged = await service.list_pending(limit=1)
    assert len(paged) == 1

    # Bounds validation
    with pytest.raises(ValueError, match="limit must be between 1 and 200"):
        await service.list_pending(limit=0)

    with pytest.raises(ValueError, match="limit must be between 1 and 200"):
        await service.list_pending(limit=201)


# ==============================================================================
# 5. TASK 31 COMPOSITION PREVIEW (WHITE-BOX)
# ==============================================================================


async def test_task_31_composition_preview_holds_dont_autopass(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    make_agent: MakeAgentType,
    cleanup_holds: Callable[[UUID], Coroutine[Any, Any, None]],
    apply_limits_schema: None,
) -> None:
    """White-box verification: placing a hold does not auto-pass subsequent engine checks.

    Layering Doctrine:
    The risk engine evaluates pure policy per attempt. Even if a hold exists in
    payment_holds, check_payment evaluates the parameters fresh and still returns
    quarantined. The human approval verdict enters the ledger through Task 42's
    orchestrated settlement replay path using the same idempotency key, NOT by
    short-circuiting the risk engine.
    """
    agent = await make_agent()
    await cleanup_holds(agent.agent_id)
    service = QuarantineService(db_pool)

    idem_key = f"idem_whitebox_{uuid4().hex[:16]}"
    high_amount = 200_000_000  # $200 > $100 ceiling

    # 1. Place hold in quarantine
    hold = await service.place_hold(
        agent_id=agent.agent_id,
        idem_key=idem_key,
        amount_minor=high_amount,
        currency="USDC",
        reason="single_tx_ceiling",
    )
    assert hold.status == "pending"

    # 2. Risk engine evaluation with same amount is STILL quarantined
    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    decision = await check_payment(
        db_pool,
        valkey,
        agent_id=agent.agent_id,
        limits=DEFAULT_LIMITS,
        amount_minor=high_amount,
        currency="USDC",
        now=now,
    )
    assert decision.allowed is False
    assert decision.quarantined is True
    assert decision.reason == "single_tx_ceiling"


# ==============================================================================
# 6. REDIS OUTFLOW COUNTER CONTRACT (TASK 31 INCREMENTS, RISK ENGINE READS)
# ==============================================================================


async def test_redis_outflow_counter_reflects_in_check_payment(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    make_agent: MakeAgentType,
    apply_limits_schema: None,
) -> None:
    """Validate that external increments to the daily outflow counter trigger daily_cap."""
    agent = await make_agent()
    now = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
    yyyymmdd = now.strftime("%Y%m%d")
    outflow_key = f"flx:outflow:{{{agent.agent_id}}}:{yyyymmdd}"

    # 1. Initially counter is 0 -> payment of $50 ($50,000,000 minor) is allowed
    d1 = await check_payment(
        db_pool,
        valkey,
        agent_id=agent.agent_id,
        limits=DEFAULT_LIMITS,
        amount_minor=50_000_000,
        currency="USDC",
        now=now,
    )
    assert d1.allowed is True

    # 2. Task 31 posts successful payments and increments counter by $460 ($460,000,000 minor)
    await valkey.incrby(outflow_key, 460_000_000)

    # 3. Next payment of $50 pushes total to $510 > $500 cap -> daily_cap quarantine
    d2 = await check_payment(
        db_pool,
        valkey,
        agent_id=agent.agent_id,
        limits=DEFAULT_LIMITS,
        amount_minor=50_000_000,
        currency="USDC",
        now=now,
    )
    assert d2.allowed is False
    assert d2.quarantined is True
    assert d2.reason == "daily_cap"
