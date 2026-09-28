"""Integration tests verifying atomic gate Lua script against real Valkey (DB 15).

Tests exercise anti-replay, sliding-window rate limiting, and daily quota caps in
a single roundtrip with zero sleeps (deterministic clock injection).
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator
from typing import Final

import pytest
import pytest_asyncio
import redis.asyncio as redis_async

from fluxpay.gateway.gate import (
    GateResult,
    GateRunner,
    GateUnavailable,
    compose_day,
    compose_gate_keys,
    run_gate,
)

pytestmark = pytest.mark.integration

DEFAULT_AGENT_ID: Final[str] = "018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e"
DEFAULT_WINDOW_MS: Final[int] = 60000
DEFAULT_RATE_MAX: Final[int] = 5
DEFAULT_DAILY_MAX: Final[int] = 100
DEFAULT_NONCE_TTL_MS: Final[int] = 120000
DEFAULT_DAY_TTL_S: Final[int] = 90000


@pytest_asyncio.fixture
async def valkey() -> AsyncGenerator[redis_async.Redis, None]:
    """Provide a function-scoped Redis/Valkey client connected to DB 15 with flushdb teardown.

    Precedent from Task 9 conftest: real Valkey on DB 15, flushdb teardown, fail-loud.
    Explicitly managed per-test event loop to avoid cross-loop socket reuse.
    """
    url = os.environ.get("FLX_VALKEY_URL", "redis://localhost:6379/15")
    client: redis_async.Redis = redis_async.Redis.from_url(url)
    try:
        yield client
    finally:
        await client.flushdb()
        await client.aclose()


async def _call(
    valkey: redis_async.Redis | GateRunner,
    nonce: str,
    now_ms: int,
    *,
    agent_id: str = DEFAULT_AGENT_ID,
    window_ms: int = DEFAULT_WINDOW_MS,
    rate_max: int = DEFAULT_RATE_MAX,
    daily_max: int = DEFAULT_DAILY_MAX,
    nonce_ttl_ms: int = DEFAULT_NONCE_TTL_MS,
    day_ttl_s: int = DEFAULT_DAY_TTL_S,
) -> GateResult:
    """Thin helper wrapper with test-suite defaults."""
    return await run_gate(
        valkey,
        agent_id=agent_id,
        nonce=nonce,
        now_ms=now_ms,
        window_ms=window_ms,
        rate_max=rate_max,
        daily_max=daily_max,
        nonce_ttl_ms=nonce_ttl_ms,
        day_ttl_s=day_ttl_s,
    )


# =============================================================================
# 1. HAPPY PATH & MONOTONICITY
# =============================================================================


async def test_gate_happy_path_monotonic_counters(valkey: redis_async.Redis) -> None:
    """Validate successful sequential gate passes with monotonic rate and quota increments."""
    now = 1774483200000

    res1 = await _call(valkey, "noncehappy001aaa", now)
    assert res1.ok is True
    assert res1.replayed is False
    assert res1.rate_limited is False
    assert res1.quota_exceeded is False
    assert res1.rate_count == 1
    assert res1.quota_used == 1

    res2 = await _call(valkey, "noncehappy002bbb", now + 100)
    assert res2.ok is True
    assert res2.rate_count == 2
    assert res2.quota_used == 2

    res3 = await _call(valkey, "noncehappy003ccc", now + 200)
    assert res3.ok is True
    assert res3.rate_count == 3
    assert res3.quota_used == 3


# =============================================================================
# 2. ANTI-REPLAY PRECEDENCE & BUDGET CONSERVATION
# =============================================================================


async def test_replay_rejects_before_consuming_rate_or_quota(valkey: redis_async.Redis) -> None:
    """Validate that replayed nonces are rejected without consuming rate or quota budget.

    ORDER SEMANTICS PROOF:
    Step 1 (Replay check) must reject before Step 2 (Rate) and Step 3 (Quota).
    An adversary replaying old requests must not exhaust the legitimate agent's limits.
    """
    now = 1774483200000
    nonce = "noncereplay001xyz"

    # 1. First legitimate call succeeds
    res1 = await _call(valkey, nonce, now)
    assert res1.ok is True
    assert res1.rate_count == 1
    assert res1.quota_used == 1

    # 2. Replay of same nonce is rejected
    res2 = await _call(valkey, nonce, now + 1000)
    assert res2.ok is False
    assert res2.replayed is True
    assert res2.rate_limited is False
    assert res2.quota_exceeded is False
    assert res2.rate_count == 0
    assert res2.quota_used == 0

    # Verify directly in Valkey that counters were NOT incremented
    day = compose_day(now)
    rate_key, _, quota_key = compose_gate_keys(DEFAULT_AGENT_ID, nonce, day)

    quota_val = await valkey.get(quota_key)
    quota_int = int(quota_val) if quota_val else 0
    assert quota_int == 1, "Quota must not increase on replay reject"

    zcard_val = await valkey.zcard(rate_key)
    assert zcard_val == 1, "Rate zset count must not increase on replay reject"

    # 3. Subsequent distinct nonce succeeds and consumes exactly the next budget unit
    res3 = await _call(valkey, "noncereplay002uvw", now + 2000)
    assert res3.ok is True
    assert res3.rate_count == 2
    assert res3.quota_used == 2


# =============================================================================
# 3. SLIDING WINDOW & INJECTED CLOCK
# =============================================================================


async def test_sliding_window_rate_limiting_with_injected_clock(
    valkey: redis_async.Redis,
) -> None:
    """Validate sliding-window rate limit rejection and recovery via clock injection (no sleeps)."""
    now = 1774483200000
    rate_max = 5

    # Consume all 5 allowed slots at timestamp T
    for i in range(rate_max):
        nonce = f"nonceslide{i:02d}{'a' * 20}"
        res = await _call(valkey, nonce, now, rate_max=rate_max)
        assert res.ok is True
        assert res.rate_count == i + 1

    # 6th request at exact same timestamp T is rate limited
    res6 = await _call(valkey, "nonceslide06overflow", now, rate_max=rate_max)
    assert res6.ok is False
    assert res6.rate_limited is True
    assert res6.replayed is False
    assert res6.quota_exceeded is False
    assert res6.rate_count == 5

    # Move clock forward past sliding window: now + window_ms + 1
    future_ms = now + DEFAULT_WINDOW_MS + 1
    res7 = await _call(valkey, "nonceslide07cleared", future_ms, rate_max=rate_max)
    assert res7.ok is True
    assert res7.rate_count == 1  # Previous 5 pruned by ZREMRANGEBYSCORE


async def test_sliding_window_boundary_semantics(valkey: redis_async.Redis) -> None:
    """Validate boundary inclusivity semantics: entry at score == now_ms - window_ms is pruned.

    INCLUSIVITY DECISION:
    ZREMRANGEBYSCORE is executed with range 0 to (now_ms - window_ms).
    Because the upper bound is inclusive, an entry timestamped T is pruned when
    now_ms reaches exactly T + window_ms.
    """
    now = 1774483200000
    rate_max = 1

    # First call at timestamp T consumes the single slot
    res1 = await _call(valkey, "noncebound0001aaa", now, rate_max=rate_max)
    assert res1.ok is True

    # Call at T + window_ms: now_ms - window_ms == T, so score T is pruned (inclusive)
    exact_boundary_ms = now + DEFAULT_WINDOW_MS
    res2 = await _call(valkey, "noncebound0002bbb", exact_boundary_ms, rate_max=rate_max)
    assert res2.ok is True, "Old entry at score T must be pruned at exact boundary T + window_ms"
    assert res2.rate_count == 1


# =============================================================================
# 4. DAILY QUOTA ISOLATION (Per-Agent & Per-UTC-Day)
# =============================================================================


async def test_quota_exhaustion_per_agent_and_utc_day_isolation(
    valkey: redis_async.Redis,
) -> None:
    """Validate quota rejection at cap, agent isolation, and natural UTC day rollover."""
    now = 1774483200000
    daily_max = 2

    res1 = await _call(valkey, "noncequota0001aaa", now, daily_max=daily_max)
    assert res1.ok is True
    assert res1.quota_used == 1

    res2 = await _call(valkey, "noncequota0002bbb", now + 100, daily_max=daily_max)
    assert res2.ok is True
    assert res2.quota_used == 2

    # 3rd request for agent 1 hits daily quota cap
    res3 = await _call(valkey, "noncequota0003ccc", now + 200, daily_max=daily_max)
    assert res3.ok is False
    assert res3.quota_exceeded is True
    assert res3.quota_used == 2

    # Same day key, DIFFERENT agent ID -> unaffected (per-agent isolation)
    other_agent = "018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9f"
    res_other = await _call(
        valkey,
        "noncequota0004oth",
        now + 300,
        agent_id=other_agent,
        daily_max=daily_max,
    )
    assert res_other.ok is True
    assert res_other.quota_used == 1

    # Next UTC day (now + 86,400,000 ms) -> natural quota reset for agent 1
    next_day_ms = now + 86400000
    res_next_day = await _call(
        valkey,
        "noncequota0005day",
        next_day_ms,
        agent_id=DEFAULT_AGENT_ID,
        daily_max=daily_max,
    )
    assert res_next_day.ok is True
    assert res_next_day.quota_used == 1


# =============================================================================
# 5. KEY TTL CONTRACTS (Asserted Without Sleeping)
# =============================================================================


async def test_ttl_contracts_asserted_via_pttl(valkey: redis_async.Redis) -> None:
    """Validate TTLs for nonce, rate zset, and daily quota keys directly via PTTL/TTL."""
    now = 1774483200000
    nonce = "noncettltest00001"

    res = await _call(valkey, nonce, now)
    assert res.ok is True

    day = compose_day(now)
    rate_key, nonce_key, quota_key = compose_gate_keys(DEFAULT_AGENT_ID, nonce, day)

    # 1. Nonce tombstone PTTL: in (0, nonce_ttl_ms]
    nonce_pttl = await valkey.pttl(nonce_key)
    assert 0 < nonce_pttl <= DEFAULT_NONCE_TTL_MS

    # 2. Rate zset PTTL: in (0, window_ms]
    rate_pttl = await valkey.pttl(rate_key)
    assert 0 < rate_pttl <= DEFAULT_WINDOW_MS

    # 3. Daily quota TTL: in (0, day_ttl_s]
    quota_ttl = await valkey.ttl(quota_key)
    assert 0 < quota_ttl <= DEFAULT_DAY_TTL_S


# =============================================================================
# 6. ATOMICITY UNDER HIGH CONCURRENCY
# =============================================================================


async def test_atomicity_concurrent_gather_exact_split(valkey: redis_async.Redis) -> None:
    """Validate that 20 concurrent requests with rate_max=10 yield exactly 10 ok + 10 rate_limited.

    ATOMICITY PROOF:
    Redis Lua executes as a single transaction. Under simultaneous async contention,
    there must be zero oversubscription or race condition bypass.
    """
    now = 1774483200000
    rate_max = 10
    total_calls = 20

    tasks = [
        _call(valkey, f"nonceconc{i:02d}{'x' * 20}", now, rate_max=rate_max)
        for i in range(total_calls)
    ]
    results = await asyncio.gather(*tasks)

    ok_results = [r for r in results if r.ok]
    rate_limited_results = [r for r in results if r.rate_limited]

    assert len(ok_results) == rate_max, f"Expected exactly {rate_max} ok, got {len(ok_results)}"
    assert len(rate_limited_results) == total_calls - rate_max, (
        f"Expected exactly {total_calls - rate_max} rate_limited, got {len(rate_limited_results)}"
    )


# =============================================================================
# 7. SCRIPT_FLUSH & NOSCRIPT RESILIENCE
# =============================================================================


async def test_noscript_resilience_after_script_flush(valkey: redis_async.Redis) -> None:
    """Validate that register_script automatically falls back to EVAL after SCRIPT FLUSH."""
    runner = GateRunner(valkey)
    now = 1774483200000

    # Initial call caches script SHA in Redis
    res1 = await runner.run(
        agent_id=DEFAULT_AGENT_ID,
        nonce="nonceflush0001aaa",
        now_ms=now,
        window_ms=DEFAULT_WINDOW_MS,
        rate_max=DEFAULT_RATE_MAX,
        nonce_ttl_ms=DEFAULT_NONCE_TTL_MS,
        daily_max=DEFAULT_DAILY_MAX,
        day_ttl_s=DEFAULT_DAY_TTL_S,
    )
    assert res1.ok is True

    # Simulate cache wipe / Redis failover
    await valkey.script_flush()

    # Next call must succeed seamlessly via automatic redis-py NOSCRIPT fallback
    res2 = await runner.run(
        agent_id=DEFAULT_AGENT_ID,
        nonce="nonceflush0002bbb",
        now_ms=now + 100,
        window_ms=DEFAULT_WINDOW_MS,
        rate_max=DEFAULT_RATE_MAX,
        nonce_ttl_ms=DEFAULT_NONCE_TTL_MS,
        daily_max=DEFAULT_DAILY_MAX,
        day_ttl_s=DEFAULT_DAY_TTL_S,
    )
    assert res2.ok is True
    assert res2.rate_count == 2


# =============================================================================
# 8. RATE ZSET MEMBER FORMAT IN THE WILD
# =============================================================================


async def test_rate_zset_member_uniqueness_format(valkey: redis_async.Redis) -> None:
    """Validate member string format in rate zset: starts with '<now_ms>:<nonce>'."""
    now = 1774483200000
    nonce = "noncememberfmt001"

    res = await _call(valkey, nonce, now)
    assert res.ok is True

    day = compose_day(now)
    rate_key, _, _ = compose_gate_keys(DEFAULT_AGENT_ID, nonce, day)

    members = await valkey.zrange(rate_key, 0, -1)
    assert len(members) == 1

    raw_member = members[0]
    member_str = raw_member.decode("utf-8") if isinstance(raw_member, bytes) else raw_member
    expected_prefix = f"{now}:"
    assert member_str.startswith(expected_prefix)
    assert member_str == f"{now}:{nonce}"


# =============================================================================
# 9. FAIL-CLOSED ON CONNECTION ERROR
# =============================================================================


async def test_gate_fails_closed_on_connection_error() -> None:
    """Validate that connection errors raise GateUnavailable with details phase='gate'."""
    unreachable_client: redis_async.Redis = redis_async.Redis.from_url(
        "redis://127.0.0.1:1/15",
        socket_connect_timeout=0.1,
        socket_timeout=0.1,
    )
    try:
        with pytest.raises(GateUnavailable) as exc_info:
            await run_gate(
                unreachable_client,
                agent_id=DEFAULT_AGENT_ID,
                nonce="nonceconnfail0001",
                now_ms=1774483200000,
                window_ms=DEFAULT_WINDOW_MS,
                rate_max=DEFAULT_RATE_MAX,
                nonce_ttl_ms=DEFAULT_NONCE_TTL_MS,
                daily_max=DEFAULT_DAILY_MAX,
                day_ttl_s=DEFAULT_DAY_TTL_S,
            )
        assert exc_info.value.status == 503
        assert exc_info.value.retryable is True
        assert exc_info.value.details.get("phase") == "gate"
    finally:
        await unreachable_client.aclose()
