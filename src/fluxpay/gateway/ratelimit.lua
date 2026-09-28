-- =============================================================================
-- FluxPay Gateway Rate Limiting, Anti-Replay & Daily Quota Atomic Decision Gate
-- =============================================================================
--
-- PURE ALGORITHM CONTRACT:
-- Key composition lives strictly in Python (flx:gate:{<agent_uuid>}:...).
-- All keys arrive via KEYS, and all inputs arrive via ARGV.
-- The algorithm is 100% deterministic: wall-clock milliseconds are injected
-- via ARGV[1]. There is NO call to the server clock and NO non-deterministic logic.
--
-- RETURN-CODE CONTRACT TABLE:
-- -----------------------------------------------------------------------------
--  Code | Outcome        | Rate Count               | Daily Quota Used
-- -----------------------------------------------------------------------------
--   1   | OK (Committed) | new rate count (count+1) | new quota count (used+1)
--  -1   | Replay Reject  | 0 (unconsumed)           | 0 (unconsumed)
--  -2   | Rate Limited   | current window count     | 0 (unconsumed)
--  -3   | Quota Exceeded | current window count     | current daily used
-- -----------------------------------------------------------------------------
--
-- EXTENSION POINT FOR TASK 35 (Velocity Limits):
-- Per-agent transaction velocity limits (e.g. 5 tx / 60s) will EXTEND this script
-- additively via new ARGV parameters and a 4th check position placed AFTER quota
-- and before commit.
-- Rationale for check order:
--   1. Replay (security) -> 2. Rate (stability) -> 3. Quota (daily financial cap)
--   -> 4. Velocity (short-term fraud/burst risk) -> 5. Commit.
-- Placing velocity after quota ensures high-cost velocity windows are only evaluated
-- for requests that already satisfy daily budget policy.
--
-- KEYS:
--   KEYS[1] = rate zset      flx:gate:{<agent_uuid>}:rate
--   KEYS[2] = nonce marker   flx:gate:{<agent_uuid>}:nonce:<nonce>
--   KEYS[3] = daily counter  flx:gate:{<agent_uuid>}:quota:<yyyymmdd>
--
-- ARGV:
--   ARGV[1] = now_ms         (int: current epoch milliseconds from caller)
--   ARGV[2] = window_ms      (int: sliding window length in ms, e.g. 60000)
--   ARGV[3] = rate_max       (int: max requests allowed per sliding window)
--   ARGV[4] = nonce_ttl_ms   (int: replay tombstone TTL in ms, e.g. 120000)
--   ARGV[5] = daily_max      (int: max requests allowed per UTC calendar day)
--   ARGV[6] = day_ttl_s      (int: daily counter key TTL in seconds, e.g. 90000 = 25h)
--   ARGV[7] = nonce          (str: client nonce for unique zset member composition)
-- =============================================================================

local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local rate_max = tonumber(ARGV[3])
local nonce_ttl_ms = tonumber(ARGV[4])
local daily_max = tonumber(ARGV[5])
local day_ttl_s = tonumber(ARGV[6])
local nonce = tostring(ARGV[7])

-- -----------------------------------------------------------------------------
-- 1) REPLAY CHECK (Security Guard)
-- -----------------------------------------------------------------------------
-- WHY first: Replay is an adversarial security violation. An attacker replaying
-- a captured or stale request must NEVER consume the legitimate agent's rate or
-- quota budget. A replay storm must not lock out the legitimate agent by
-- consuming its window. Evaluating replay first rejects the attack immediately
-- with zero side effects.
if redis.call('EXISTS', KEYS[2]) == 1 then
    return {-1, 0, 0}
end

-- -----------------------------------------------------------------------------
-- 2) RATE LIMIT CHECK (Stability Control - Sliding Window)
-- -----------------------------------------------------------------------------
-- WHY zset not fixed-window counter: Fixed windows allow 2x burst at boundaries
-- (a classic throttle bypass where an agent spends max quota at 00:59 and again
-- at 01:00). A sorted set sliding window provides strictly monotone-fair rate
-- limiting across any arbitrary continuous window.
--
-- WHY prune-then-count: Without pruning expired entries (scores <= now_ms - window_ms),
-- the zset would grow unbounded on low-traffic agents because whole-key TTL only
-- expires after a full silent window of complete inactivity. Pruning before ZCARD
-- guarantees O(log N) amortized maintenance and ensures ZCARD reflects exactly
-- the active window.
--
-- Boundary inclusivity: ZREMRANGEBYSCORE with range 0 to (now_ms - window_ms)
-- is inclusive. A request recorded at timestamp T is pruned exactly when
-- now_ms >= T + window_ms, freeing capacity at the boundary.
local cutoff = now_ms - window_ms
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, cutoff)
local count = redis.call('ZCARD', KEYS[1])
if count >= rate_max then
    return {-2, count, 0}
end

-- -----------------------------------------------------------------------------
-- 3) DAILY QUOTA CHECK (Financial Policy Control)
-- -----------------------------------------------------------------------------
-- WHY after rate: Quota is the FINANCIAL control (daily spend cap); rate is the
-- STABILITY control (protecting system throughput). A request that passes rate
-- but hits quota is a policy event — still rejected, still atomic. Placing rate
-- before quota prevents high-velocity DDoS bursts from thrashing quota counters.
local current_quota_raw = redis.call('GET', KEYS[3])
local used = current_quota_raw and tonumber(current_quota_raw) or 0
if used >= daily_max then
    return {-3, count, used}
end

-- -----------------------------------------------------------------------------
-- 4) COMMIT (Atomic State Mutation)
-- -----------------------------------------------------------------------------
-- All three reservations commit atomically: Redis executes this script as a
-- single uninterruptible transaction. A crash or failure leaves no partial state.
--
-- Member uniqueness: ARGV[7] (nonce) is already verified unique per agent in
-- step 1. Member = now_ms .. ':' .. nonce guarantees unique elements in the zset
-- even when multiple requests arrive within the same millisecond timestamp.
local member = tostring(now_ms) .. ':' .. nonce
redis.call('ZADD', KEYS[1], now_ms, member)

-- PEXPIRE window_ms (refresh-on-write):
-- The zset TTL is refreshed on every write so it automatically dies only after
-- a full silent window of complete inactivity — bounded memory, zero janitor tasks.
redis.call('PEXPIRE', KEYS[1], window_ms)

-- SET KEYS[2] '1' PX nonce_ttl_ms:
-- The replay tombstone is stored with millisecond TTL. In accordance with Task 3
-- config validators, nonce_ttl_ms >= 2x replay_window_ms, ensuring the tombstone
-- outlives the timestamp freshness window in both directions (covering clock skew).
redis.call('SET', KEYS[2], '1', 'PX', nonce_ttl_ms)

-- INCR KEYS[3] & EXPIRE day_ttl_s:
-- Increment daily quota counter. If result == 1, this is the first transaction
-- of the day: set key expiry to day_ttl_s (25 hours = 90,000s) to cleanly cross
-- UTC midnight boundaries without premature expiration.
local new_used = redis.call('INCR', KEYS[3])
if new_used == 1 then
    redis.call('EXPIRE', KEYS[3], day_ttl_s)
end

-- -----------------------------------------------------------------------------
-- 5) SUCCESS
-- -----------------------------------------------------------------------------
return {1, count + 1, new_used}
