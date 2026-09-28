"""Atomic decision gate: Lua-based anti-replay, sliding-window rate limit, and daily quota.

Blueprint §3 & Task 20:
Single roundtrip atomic gate decision combining:
1. Anti-Replay: Nonce tombstone presence check (security barrier).
2. Rate Limit: Sliding-window sorted set cardinality check (stability barrier).
3. Daily Quota: Calendar-day spend cap check (financial policy barrier).
4. Atomic Commit: All three state reservations committed in one atomic Lua script.

Key Composition Law (Cluster-Readiness):
All three keys for a given agent share the Redis hash tag `{<agent_id>}`:
    flx:gate:{<agent_id>}:rate
    flx:gate:{<agent_id>}:nonce:<nonce>
    flx:gate:{<agent_id>}:quota:<yyyymmdd>
In Redis Cluster (Phase 2), slot placement is determined by CRC16 of the substring
inside braces `{...}`. Using `{<agent_id>}` guarantees that all three keys co-locate
on the exact same cluster node / slot, eliminating CROSSSLOT errors during multi-key
Lua script evaluation. Hash-tagging today is free; re-keying live production data later
is a high-risk migration incident.

Fail-Closed Philosophy:
The gate enforces security (anti-replay) and financial risk controls (daily quota).
If Redis/Valkey suffers an outage or network partition, the gate MUST fail closed
by raising GateUnavailable (HTTP 503 retryable). While database-level idempotency
(Task 11) prevents duplicate money creation, bypassing the rate and quota gate would
expose the system to runaway spend and resource exhaustion. Halting traffic is the
correct, regulated fintech posture.
"""

from __future__ import annotations

import contextlib
import importlib.resources
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Final

import redis.asyncio as redis_async
from redis.commands.core import AsyncScript
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

from fluxpay.gateway.canonical import validate_nonce
from fluxpay.shared.errors import GateUnavailable
from fluxpay.shared.metrics import FLX_GATE_TOTAL

__all__ = [
    "GateResult",
    "GateRunner",
    "GateUnavailable",
    "compose_day",
    "compose_gate_keys",
    "run_gate",
]

_UUID_REGEX: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_DAY_REGEX: Final[re.Pattern[str]] = re.compile(r"^[0-9]{8}$")

_DEFAULT_LUA_TEXT: str | None = None


def _get_default_lua() -> str:
    """Load and cache the default ratelimit.lua resource text once per process."""
    global _DEFAULT_LUA_TEXT
    if _DEFAULT_LUA_TEXT is None:
        resource = importlib.resources.files("fluxpay.gateway").joinpath("ratelimit.lua")
        _DEFAULT_LUA_TEXT = resource.read_text(encoding="utf-8")
    return _DEFAULT_LUA_TEXT


def compose_day(now_ms: int) -> str:
    """Format epoch millisecond timestamp as UTC calendar date YYYYMMDD.

    WHY UTC-ONLY (LOCAL TIMEZONE REJECTED):
    Daily quota counters reset at UTC midnight (00:00:00.000 UTC).
    Local timezone quota calculation was explicitly rejected: across a distributed
    cluster with servers located in different geographic regions, servers would
    disagree on the definition of 'today'. Using UTC establishes a single, unambiguous
    global reference frame for daily reset boundaries.

    Args:
        now_ms: Milliseconds since Unix epoch (non-negative integer).

    Returns:
        8-character date string in 'YYYYMMDD' format.

    Raises:
        ValueError: If now_ms is negative or not an integer.
    """
    if type(now_ms) is bool or not isinstance(now_ms, int) or now_ms < 0:
        raise ValueError(f"now_ms: must be non-negative integer, got {now_ms!r}")

    # Convert milliseconds to seconds and construct UTC-aware datetime
    dt = datetime.fromtimestamp(now_ms / 1000.0, tz=UTC)
    return dt.strftime("%Y%m%d")


def compose_gate_keys(agent_id: str, nonce: str, day: str) -> tuple[str, str, str]:
    """Compose Redis keys for rate zset, nonce marker, and daily quota counter.

    CLUSTER-READINESS LAW (HASH TAGS):
    All three keys use the hash-tag form `flx:gate:{<agent_uuid>}:...`.
    In Redis Cluster, the hash tag `{<agent_uuid>}` forces all three keys to map
    to the identical CRC16 hash slot. Multi-key Lua scripts in Redis Cluster fail
    immediately with CROSSSLOT errors if all target keys do not map to the same slot.
    Applying hash tags now costs nothing and prevents an operational re-keying incident
    during Phase 2 cluster migration.

    DEFENSIVE VALIDATION:
    Compose functions trust nothing:
    - agent_id is strictly verified as canonical lowercase hyphenated UUID.
    - nonce is validated using canonical.validate_nonce (^[A-Za-z0-9]{16,64}$).
    - day is verified as 8-digit decimal string (YYYYMMDD).

    Args:
        agent_id: Canonical lowercase UUID string representing the authenticated agent.
        nonce: Cryptographic nonce generated by the client (16-64 chars [A-Za-z0-9]).
        day: 8-digit UTC calendar day string (YYYYMMDD).

    Returns:
        tuple[str, str, str]: (rate_key, nonce_key, quota_key)

    Raises:
        ValueError: If any input fails structural or format validation.
    """
    if not isinstance(agent_id, str):
        raise ValueError("agent_id: must be a string")
    if not _UUID_REGEX.fullmatch(agent_id):
        raise ValueError(f"agent_id: must be canonical lowercase hyphenated UUID, got {agent_id!r}")

    # Re-use canonical nonce validation: ^[A-Za-z0-9]{16,64}$
    validate_nonce(nonce)

    if not isinstance(day, str) or not _DAY_REGEX.fullmatch(day):
        raise ValueError(f"day: must be 8-digit date string (YYYYMMDD), got {day!r}")

    rate_key = f"flx:gate:{{{agent_id}}}:rate"
    nonce_key = f"flx:gate:{{{agent_id}}}:nonce:{nonce}"
    quota_key = f"flx:gate:{{{agent_id}}}:quota:{day}"

    return rate_key, nonce_key, quota_key


@dataclass(frozen=True, slots=True)
class GateResult:
    """Immutable result of an atomic gate decision.

    Attributes:
        ok: True if all three checks passed and reservations were committed.
        replayed: True if request was rejected because the nonce was already observed.
        rate_limited: True if agent exceeded sliding-window rate limit.
        quota_exceeded: True if agent exceeded daily request quota cap.
        rate_count: Current request count in active sliding window.
        quota_used: Current daily requests used including this one (if ok).
    """

    ok: bool
    replayed: bool
    rate_limited: bool
    quota_exceeded: bool
    rate_count: int
    quota_used: int

    @classmethod
    def from_code(cls, seq: int, rate: int, quota: int) -> GateResult:
        """Map raw Lua script return code to typed GateResult.

        Contract mapping:
             1 -> OK (committed)
            -1 -> Replay reject (security barrier, unconsumed)
            -2 -> Rate limit exceeded (stability barrier, unconsumed)
            -3 -> Quota exceeded (financial policy barrier)
            Other -> Unknown code raises GateUnavailable (protocol drift)

        Args:
            seq: Return code integer from Lua script.
            rate: Rate count in sliding window.
            quota: Daily quota used count.

        Returns:
            GateResult instance with exact decision flags.

        Raises:
            GateUnavailable: If return code is unrecognized (protocol drift guard).
        """
        if seq == 1:
            return cls(
                ok=True,
                replayed=False,
                rate_limited=False,
                quota_exceeded=False,
                rate_count=rate,
                quota_used=quota,
            )
        if seq == -1:
            return cls(
                ok=False,
                replayed=True,
                rate_limited=False,
                quota_exceeded=False,
                rate_count=rate,
                quota_used=quota,
            )
        if seq == -2:
            return cls(
                ok=False,
                replayed=False,
                rate_limited=True,
                quota_exceeded=False,
                rate_count=rate,
                quota_used=quota,
            )
        if seq == -3:
            return cls(
                ok=False,
                replayed=False,
                rate_limited=False,
                quota_exceeded=True,
                rate_count=rate,
                quota_used=quota,
            )

        # Defensive protocol guard: unexpected return code indicates script/client divergence
        raise GateUnavailable(
            details={
                "phase": "gate_protocol",
                "reason": "unknown_script_code",
                "code": str(seq),
            }
        )


class GateRunner:
    """Atomic decision gate executor for anti-replay, rate limiting, and daily quota.

    WHY GateRunner CLASS:
    Script registration in redis-py binds a compiled script SHA to a specific client
    connection instance via `valkey.register_script()`. Registering scripts at global
    module import time fails because client connection pools are instantiated per
    lifespan / test context. GateRunner reads the Lua resource from the package once
    at initialization and registers the Script instance against the specific client.

    WHY register_script OVER MANUAL EVALSHA:
    redis-py's `Script` class automatically manages `EVALSHA` caching and seamlessly
    handles `NOSCRIPT` exceptions (e.g. after SCRIPT FLUSH or Redis restart) by
    transparently falling back to `EVAL` and re-caching the SHA. Implementing manual
    `EVALSHA` with `NOSCRIPT` error parsing reinvents driver code and introduces footguns.
    """

    def __init__(
        self,
        valkey: redis_async.Redis,
        *,
        lua_path: Path | Traversable | None = None,
    ) -> None:
        self._valkey = valkey

        if lua_path is None:
            lua_code = _get_default_lua()
        elif isinstance(lua_path, Path):
            lua_code = lua_path.read_text(encoding="utf-8")
        else:
            lua_code = lua_path.read_text(encoding="utf-8")

        self._script: AsyncScript = valkey.register_script(lua_code)

    async def run(
        self,
        *,
        agent_id: str,
        nonce: str,
        now_ms: int,
        window_ms: int,
        rate_max: int,
        nonce_ttl_ms: int,
        daily_max: int,
        day_ttl_s: int,
    ) -> GateResult:
        """Execute the atomic gate decision script in one Valkey roundtrip.

        Args:
            agent_id: Authenticated agent UUID string.
            nonce: Client-supplied unique request nonce.
            now_ms: Injected current epoch milliseconds.
            window_ms: Sliding window length in ms.
            rate_max: Max requests allowed in sliding window.
            nonce_ttl_ms: Nonce tombstone TTL in ms.
            daily_max: Max requests allowed per UTC calendar day.
            day_ttl_s: Daily counter key TTL in seconds.

        Returns:
            GateResult: Atomic decision result.

        Raises:
            GateUnavailable: On connection failure, timeout, or script protocol violation.
        """
        day = compose_day(now_ms)
        rate_key, nonce_key, quota_key = compose_gate_keys(agent_id, nonce, day)

        keys: list[str] = [rate_key, nonce_key, quota_key]
        args: list[str | int] = [
            now_ms,
            window_ms,
            rate_max,
            nonce_ttl_ms,
            daily_max,
            day_ttl_s,
            nonce,
        ]

        # Fail-closed guard: connection or timeout failures immediately raise GateUnavailable.
        # No retries inside the gate: retry policy belongs to higher-level middleware (Task 21/38).
        try:
            raw_result = await self._script(keys=keys, args=args)
        except (RedisConnectionError, RedisTimeoutError, TimeoutError, OSError) as exc:
            FLX_GATE_TOTAL.labels(outcome="unavail").inc()
            raise GateUnavailable(details={"phase": "gate", "reason": type(exc).__name__}) from exc

        # Defensive protocol verification: ensure script returned exactly [code, rate, quota]
        if not isinstance(raw_result, (list, tuple)) or len(raw_result) != 3:
            raise GateUnavailable(
                details={
                    "phase": "gate_protocol",
                    "reason": "malformed_return_shape",
                }
            )

        try:
            code = int(raw_result[0])
            rate_count = int(raw_result[1])
            quota_used = int(raw_result[2])
        except (ValueError, TypeError) as exc:
            raise GateUnavailable(
                details={
                    "phase": "gate_protocol",
                    "reason": "non_integer_return_elements",
                }
            ) from exc

        res = GateResult.from_code(code, rate_count, quota_used)
        # --- Task 69 append ---
        outcome = (
            "ok"
            if res.ok
            else ("replay" if res.replayed else ("rate" if res.rate_limited else "quota"))
        )
        FLX_GATE_TOTAL.labels(outcome=outcome).inc()
        return res

    async def run_gate(
        self,
        *,
        agent_id: str,
        nonce: str,
        now_ms: int,
        window_ms: int,
        rate_max: int,
        nonce_ttl_ms: int,
        daily_max: int,
        day_ttl_s: int,
    ) -> GateResult:
        """Alias for run() to provide interface symmetry across invocation styles."""
        return await self.run(
            agent_id=agent_id,
            nonce=nonce,
            now_ms=now_ms,
            window_ms=window_ms,
            rate_max=rate_max,
            nonce_ttl_ms=nonce_ttl_ms,
            daily_max=daily_max,
            day_ttl_s=day_ttl_s,
        )


async def run_gate(
    valkey: redis_async.Redis | GateRunner,
    *,
    agent_id: str,
    nonce: str,
    now_ms: int,
    window_ms: int,
    rate_max: int,
    nonce_ttl_ms: int,
    daily_max: int,
    day_ttl_s: int,
) -> GateResult:
    """Execute atomic gate decision against Valkey.

    Adapts either an existing GateRunner instance or a raw async Redis/Valkey client.
    When passed a raw client, attaches or reuses an instance-cached GateRunner.

    Args:
        valkey: Active redis.asyncio.Redis client or pre-constructed GateRunner.
        agent_id: Canonical agent UUID string.
        nonce: Client cryptographic nonce string.
        now_ms: Injected wall-clock epoch milliseconds.
        window_ms: Sliding rate limit window length in milliseconds.
        rate_max: Maximum allowed requests in the sliding window.
        nonce_ttl_ms: Replay tombstone retention in milliseconds.
        daily_max: Maximum allowed transactions per UTC calendar day.
        day_ttl_s: Expiration for daily quota keys in seconds (e.g. 90000 = 25h).

    Returns:
        GateResult: Strongly-typed decision result.

    Raises:
        GateUnavailable: If Valkey is unreachable, times out, or protocol drifts.
    """
    if isinstance(valkey, GateRunner):
        runner = valkey
    else:
        cached = getattr(valkey, "_flx_gate_runner", None)
        if isinstance(cached, GateRunner):
            runner = cached
        else:
            runner = GateRunner(valkey)
            with contextlib.suppress(AttributeError, TypeError):
                valkey._flx_gate_runner = runner  # type: ignore[attr-defined]

    return await runner.run(
        agent_id=agent_id,
        nonce=nonce,
        now_ms=now_ms,
        window_ms=window_ms,
        rate_max=rate_max,
        nonce_ttl_ms=nonce_ttl_ms,
        daily_max=daily_max,
        day_ttl_s=day_ttl_s,
    )
