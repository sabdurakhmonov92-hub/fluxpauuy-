"""Daily Reconciliation Worker: Daily Truth Audit (Block H, Part 3).

Blueprint §9: Daily Reconciliation Worker.
Independent cross-check matching Ledger DB sums against live wallet states,
auditing Redis daily outflow counters against ledger truth, reporting dead webhook
deliveries, and pruning expired terminal idempotency records.

DESIGN LAWS & ARCHITECTURAL DISCIPLINE:
--------------------------------------
1. ZERO AUTO-FIX DOCTRINE:
   Reconciliation is the platform's conscience. Every approximate control
   (Redis counters, cached account balances) eventually drifts. When drift
   or corruption is detected, this worker NEVER auto-repairs, adjusts balances,
   or modifies ledger entries. Automated repairs hide bugs and destroy audit
   trails. Every mismatch is REPORTED with exact numbers so a human engineer
   can investigate with facts under the sanctioned runbook
   (docs/ledger.md §reconciliation-runbook).
2. ONE-QUERY BALANCE COMPUTATION (NO N+1):
   Per-account computed balance is evaluated via a SINGLE aggregated query
   joining ledger_accounts with the partitioned ledger_entries table using
   GROUP BY. In Phase 1, this completes in milliseconds/seconds over BRIN + account
   indexes. (Phase 2 incremental path: restrict daily check to accounts with activity
   in the last 7 days, with a full weekly partition sweep).
3. AGENT/MERCHANT EXACT EQUALITY VS. SYSTEM IMPLIED GENESIS:
   - agent & merchant accounts must match entry mathematics EXACTLY (Task 16 invariant).
     Any difference is a hard alarm (BalanceMismatch).
   - system, fees, and treasury platform accounts hold OUT-OF-LEDGER genesis balances
     (Task 16/27 bootstrap direct balance). Their delta (cached - computed) represents
     the implied genesis funding and is reported informationally in system_accounts.
   - THE NEGATIVE GENESIS ALARM: If a system account's implied genesis is negative
     (cached < computed), money appeared from nowhere or was phantom-debited.
     This is a critical financial anomaly treated as a hard BalanceMismatch.
4. COUPLING CONTRACT WITH TASK 31 OUTFLOW SEMANTICS:
   Task 31 increments the daily outflow counter (flx:outflow:{agent}:{yyyymmdd})
   by quote.total_minor (principal amount + fee). The agent's ledger account records
   a corresponding DEBIT entry for the exact same total_minor. The DB audit query
   mirrors this by summing all DEBIT entries for the agent on that UTC calendar day.
   A change to Task 31 increment semantics MUST be mirrored in this worker.
5. 7-DAY COUNTER AUDIT WINDOW:
   Redis daily outflow counters have a 25-hour TTL and naturally expire.
   The counter audit scans active Redis keys and DB debit activity over the last
   7 days. Older keys are already evicted by design; auditing beyond 7 days against
   ephemeral storage would yield false 'under' alarms.
6. DOUBLE-ANGLE CORRUPTION DETECTION:
   Global double-entry (SUM(debits) == SUM(credits) across ALL entries) catches
   database-level tampering or split transactions. If an entry is corrupted, it is
   caught from two independent angles: globally (global_balanced = False) and locally
   (the affected account's BalanceMismatch).
7. PENDING-NEVER-PURGE LAW:
   Terminal idempotency keys (COMPLETED with completed_at < 30d, FAILED with created_at < 30d)
   are pruned to keep index trees compact. PENDING keys are NEVER purged. PENDING records
   represent active reservations or holds held under risk review (up to 7 days).
   Purging a PENDING record would orphan held money and invite replay double-spends.
   The idempotency table is the sole mutable exception in FluxPay: DELETE is sanctioned
   HERE only.
8. THE SPEAKING CONTRACT & TWO-STREAM LOGGING:
   One-shot process invoked daily via systemd timer at 04:00 UTC (after the hourly validator grid).
   Every run emits exactly ONE single-line JSON report to stdout (mode="reconciliation").
   stdout is reserved exclusively for the Loki/alert-engine report.
   stderr receives error traces on operational failure and runbook pointers on mismatch.
   Exit code 0 = healthy, 1 = mismatches found, 2 = operational failure.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from urllib.parse import urlsplit

import asyncpg  # type: ignore[import-untyped]
import redis.asyncio as redis_async

from fluxpay.config import get_settings

__all__ = [
    "EXIT_MISMATCHES",
    "EXIT_MISMATCH_FOUND",
    "EXIT_OK",
    "EXIT_OPS_FAILURE",
    "IDEMPOTENCY_RETENTION_DAYS",
    "RETENTION_COMPLETED_DAYS",
    "RETENTION_FAILED_DAYS",
    "RUNBOOK_POINTER",
    "BalanceMismatch",
    "CounterMismatch",
    "ReconcileReport",
    "SystemAccountState",
    "build_report",
    "classify_counter_mismatch",
    "compute_healthy",
    "determine_exit_code",
    "main",
    "map_exit_code",
    "run_once",
]

# Exit code contract inherited from Task 18 / Task 40 CLI family
EXIT_OK: Final[int] = 0
EXIT_MISMATCHES: Final[int] = 1
EXIT_MISMATCH_FOUND: Final[int] = 1
EXIT_OPS_FAILURE: Final[int] = 2

# Operational runbook pointer for financial responders
RUNBOOK_POINTER: Final[str] = "RUNBOOK: docs/ledger.md §reconciliation-runbook\n"

# Retention policy for terminal idempotency records (Task 11 deferred policy).
# 30 days is Stripe-comparable, memory-safe, and covers any realistic HTTP client retry window
# while preserving a full forensic month for customer support disputes.
IDEMPOTENCY_RETENTION_DAYS: Final[int] = 30
RETENTION_COMPLETED_DAYS: Final[int] = 30
RETENTION_FAILED_DAYS: Final[int] = 30

# Outflow key regex: flx:outflow:{agent_id}:yyyymmdd or flx:outflow:agent_id:yyyymmdd
_OUTFLOW_KEY_REGEX = re.compile(r"^flx:outflow:\{?([0-9a-fA-F-]+)\}?:(\d{8})$")


@dataclass(frozen=True, slots=True)
class BalanceMismatch:
    """Discrepancy between ledger_accounts.balance cache and ledger_entries sum."""

    account_id: str
    owner_type: str
    cached_balance: int
    computed_balance: int
    delta: int  # cached_balance - computed_balance


@dataclass(frozen=True, slots=True)
class CounterMismatch:
    """Discrepancy between ephemeral Redis daily outflow counter and DB debit truth."""

    agent_id: str
    day: str  # yyyymmdd
    redis_value: int
    db_value: int
    delta: int  # redis_value - db_value
    reason: str  # 'under' (lost counter/restart) | 'over' (double-incr/severe)


@dataclass(frozen=True, slots=True)
class SystemAccountState:
    """Informational accounting of bootstrap out-of-ledger balances on platform accounts."""

    account_id: str
    cached: int
    computed: int
    implied_genesis: int  # cached - computed (must be >= 0)
    owner_type: str = ""


@dataclass(frozen=True, slots=True)
class ReconcileReport:
    """The immutable reconciliation audit report."""

    checked_at: str  # ISO8601Z
    accounts_checked: int
    balance_mismatches: tuple[BalanceMismatch, ...]
    counter_mismatches: tuple[CounterMismatch, ...]
    global_debits: int  # minor units, all time
    global_credits: int  # minor units, all time
    global_balanced: bool  # debits == credits
    purged_idempotency: int
    dead_deliveries: int
    system_accounts: tuple[SystemAccountState, ...] = ()
    healthy: bool = True

    def __post_init__(self) -> None:
        expected_healthy = (
            len(self.balance_mismatches) == 0
            and len(self.counter_mismatches) == 0
            and self.global_balanced
        )
        if not expected_healthy and self.healthy:
            object.__setattr__(self, "healthy", False)


def classify_counter_mismatch(redis_value: int, db_value: int) -> str:
    """Classify counter mismatch severity and reason.

    - 'under': Redis < DB. Lost increments due to Redis restart, crash, or eviction.
      Benign-ish (fails open on spending limit), but reported for counter resynchronization.
    - 'over': Redis > DB. Double increment or orphaned settle. SEVERE financial fault,
      indicating a transaction was counted twice or settled outside DB transactions.
    - 'clean': Redis == DB.
    """
    if redis_value < db_value:
        return "under"
    if redis_value > db_value:
        return "over"
    return "clean"


def compute_healthy(
    balance_mismatches: Sequence[BalanceMismatch],
    counter_mismatches: Sequence[CounterMismatch],
    global_balanced: bool,
) -> bool:
    """Determine whether reconciliation state is healthy (no hard mismatches)."""
    return len(balance_mismatches) == 0 and len(counter_mismatches) == 0 and global_balanced


def build_report(
    report: ReconcileReport | None = None,
    *,
    checked_at: str | None = None,
    accounts_checked: int = 0,
    balance_mismatches: Sequence[BalanceMismatch] = (),
    counter_mismatches: Sequence[CounterMismatch] = (),
    global_debits: int = 0,
    global_credits: int = 0,
    global_balanced: bool = True,
    purged_idempotency: int = 0,
    dead_deliveries: int = 0,
    system_accounts: Sequence[SystemAccountState] = (),
    healthy: bool | None = None,
    now: datetime | None = None,
) -> str:
    """Construct the single-line JSON report for Loki and monitoring ingestion.

    Guaranteed single-line format: no internal unescaped newlines.
    """
    rep_balance_mismatches: Sequence[BalanceMismatch]
    rep_counter_mismatches: Sequence[CounterMismatch]
    rep_system_accounts: Sequence[SystemAccountState]

    if report is not None:
        rep_checked_at = report.checked_at
        rep_accounts_checked = report.accounts_checked
        rep_balance_mismatches = report.balance_mismatches
        rep_counter_mismatches = report.counter_mismatches
        rep_global_debits = report.global_debits
        rep_global_credits = report.global_credits
        rep_global_balanced = report.global_balanced
        rep_purged = report.purged_idempotency
        rep_dead = report.dead_deliveries
        rep_system_accounts = report.system_accounts
        rep_healthy = report.healthy if healthy is None else healthy
    else:
        if checked_at is not None:
            rep_checked_at = checked_at
        else:
            if now is None:
                now = datetime.now(UTC)
            elif now.tzinfo is None:
                now = now.replace(tzinfo=UTC)
            else:
                now = now.astimezone(UTC)
            rep_checked_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        rep_accounts_checked = accounts_checked
        rep_balance_mismatches = balance_mismatches
        rep_counter_mismatches = counter_mismatches
        rep_global_debits = global_debits
        rep_global_credits = global_credits
        rep_global_balanced = global_balanced
        rep_purged = purged_idempotency
        rep_dead = dead_deliveries
        rep_system_accounts = system_accounts
        rep_healthy = (
            compute_healthy(balance_mismatches, counter_mismatches, global_balanced)
            if healthy is None
            else healthy
        )

    payload: dict[str, Any] = {
        "mode": "reconciliation",
        "checked_at": rep_checked_at,
        "healthy": rep_healthy,
        "accounts_checked": rep_accounts_checked,
        "balance_mismatches": [
            {
                "account_id": m.account_id,
                "owner_type": m.owner_type,
                "cached_balance": m.cached_balance,
                "computed_balance": m.computed_balance,
                "delta": m.delta,
            }
            if isinstance(m, BalanceMismatch)
            else m
            for m in rep_balance_mismatches
        ],
        "counter_mismatches": [
            {
                "agent_id": m.agent_id,
                "day": m.day,
                "redis_value": m.redis_value,
                "db_value": m.db_value,
                "delta": m.delta,
                "reason": m.reason,
            }
            if isinstance(m, CounterMismatch)
            else m
            for m in rep_counter_mismatches
        ],
        "global_debits": rep_global_debits,
        "global_credits": rep_global_credits,
        "global_balanced": rep_global_balanced,
        "purged_idempotency": rep_purged,
        "dead_deliveries": rep_dead,
        "system_accounts": [
            {
                "account_id": s.account_id,
                "cached": s.cached,
                "computed": s.computed,
                "implied_genesis": s.implied_genesis,
            }
            if isinstance(s, SystemAccountState)
            else s
            for s in rep_system_accounts
        ],
    }

    return json.dumps(payload, separators=(",", ":"))


def map_exit_code(
    report: ReconcileReport | None = None,
    error: type[BaseException] | BaseException | None = None,
    *,
    healthy: bool | None = None,
) -> int:
    """Map reconciliation outcome or exception to operational exit code.

    0 = OK: Zero hard mismatches, ledger balanced.
    1 = Mismatch Found: Balance mismatch, counter drift, or global imbalance.
    2 = Operational Failure: DB/Redis unreachable, configuration error, or exception.
    """
    if error is not None:
        return EXIT_OPS_FAILURE
    if healthy is not None:
        return EXIT_OK if healthy else EXIT_MISMATCHES
    if report is None:
        return EXIT_OPS_FAILURE
    return EXIT_OK if report.healthy else EXIT_MISMATCHES


determine_exit_code = map_exit_code


async def run_once(
    pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    now: datetime | None = None,
) -> ReconcileReport:
    """Execute a single complete daily reconciliation audit pass.

    Orchestrates all 5 truth checks and hygiene purge:
    1. Per-account balance audit (cached balance vs ledger_entries sum).
    2. Global double-entry balance audit (SUM(debit) == SUM(credit)).
    3. Ephemeral Redis outflow counter audit vs PostgreSQL debit truth.
    4. Dead webhook deliveries visibility counter.
    5. Terminal idempotency records purge.
    """
    if now is None:
        now = datetime.now(UTC)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    else:
        now = now.astimezone(UTC)

    checked_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # =========================================================================
    # CHECK 1: PER-ACCOUNT BALANCE TRUTH (THE CORE)
    # =========================================================================
    # ONE single query over ledger_accounts joined with partitioned ledger_entries.
    # Evaluates cached balance vs sum of credits minus debits.
    balance_sql = """
        SELECT
            la.id AS account_id,
            la.owner_type,
            la.currency,
            la.balance AS cached_balance,
            COALESCE(
                SUM(
                    CASE le.direction
                        WHEN 'CREDIT' THEN le.amount
                        WHEN 'DEBIT' THEN -le.amount
                        ELSE 0
                    END
                ),
                0
            ) AS computed_balance
        FROM ledger_accounts la
        LEFT JOIN ledger_entries le ON la.id = le.account_id
        GROUP BY la.id, la.owner_type, la.currency, la.balance
        ORDER BY la.created_at ASC, la.id ASC;
    """

    balance_mismatches_list: list[BalanceMismatch] = []
    system_accounts_list: list[SystemAccountState] = []

    async with pool.acquire() as conn:
        account_rows = await conn.fetch(balance_sql)

    accounts_checked = len(account_rows)

    for row in account_rows:
        acc_id = str(row["account_id"])
        owner_type = str(row["owner_type"])
        cached = int(row["cached_balance"])
        computed = int(row["computed_balance"])
        delta = cached - computed

        if owner_type in ("agent", "merchant"):
            # Strict equality invariant: agent and merchant accounts must equal entry math exactly
            if cached != computed:
                balance_mismatches_list.append(
                    BalanceMismatch(
                        account_id=acc_id,
                        owner_type=owner_type,
                        cached_balance=cached,
                        computed_balance=computed,
                        delta=delta,
                    )
                )
        else:
            # Platform accounts (system, fees, treasury) carry out-of-ledger genesis balances.
            implied_genesis = delta
            system_accounts_list.append(
                SystemAccountState(
                    account_id=acc_id,
                    cached=cached,
                    computed=computed,
                    implied_genesis=implied_genesis,
                    owner_type=owner_type,
                )
            )
            # CRITICAL ALARM: If implied genesis is negative, cached < computed.
            # This proves money appeared from nowhere or phantom debit occurred.
            if implied_genesis < 0:
                balance_mismatches_list.append(
                    BalanceMismatch(
                        account_id=acc_id,
                        owner_type=owner_type,
                        cached_balance=cached,
                        computed_balance=computed,
                        delta=implied_genesis,
                    )
                )

    # =========================================================================
    # CHECK 2: GLOBAL DOUBLE-ENTRY (SUM(debit) vs SUM(credit))
    # =========================================================================
    global_sql = """
        SELECT
            COALESCE(SUM(CASE WHEN direction = 'DEBIT' THEN amount ELSE 0 END), 0)
                AS global_debits,
            COALESCE(SUM(CASE WHEN direction = 'CREDIT' THEN amount ELSE 0 END), 0)
                AS global_credits
        FROM ledger_entries;
    """

    async with pool.acquire() as conn:
        global_row = await conn.fetchrow(global_sql)

    global_debits = int(global_row["global_debits"]) if global_row else 0
    global_credits = int(global_row["global_credits"]) if global_row else 0
    global_balanced = global_debits == global_credits

    # =========================================================================
    # CHECK 3: REDIS COUNTER AUDIT (COMPENSATING CONTROL)
    # =========================================================================
    # Discovers all active (agent_id, yyyymmdd) pairs within the 7-day window
    # from BOTH Redis keys and DB debit activity.
    audit_pairs: set[tuple[str, str]] = set()

    # 3a. Discover keys in Redis
    try:
        async for key in valkey.scan_iter(match="flx:outflow:*", count=100):
            key_str = key.decode("utf-8") if isinstance(key, bytes) else str(key)
            match = _OUTFLOW_KEY_REGEX.match(key_str)
            if match:
                agent_id_str = match.group(1).lower()
                day_str = match.group(2)
                audit_pairs.add((agent_id_str, day_str))
    except Exception as exc:
        # Re-raise operational errors to trip dead-man switch
        raise RuntimeError(f"Valkey scan failed during counter reconciliation: {exc}") from exc

    # 3b. Discover active days in Postgres DB for the last 7 days
    seven_days_ago = (now - timedelta(days=7)).replace(hour=0, minute=0, second=0, microsecond=0)
    db_activity_sql = """
        SELECT DISTINCT
            la.owner_id AS agent_id,
            to_char(le.created_at AT TIME ZONE 'UTC', 'YYYYMMDD') AS day
        FROM ledger_entries le
        JOIN ledger_accounts la ON la.id = le.account_id
        WHERE la.owner_type = 'agent'
          AND le.direction = 'DEBIT'
          AND le.created_at >= $1;
    """
    async with pool.acquire() as conn:
        active_db_rows = await conn.fetch(db_activity_sql, seven_days_ago)

    for row in active_db_rows:
        audit_pairs.add((str(row["agent_id"]).lower(), str(row["day"])))

    # 3c. Compare Redis counter vs DB sum per pair
    counter_mismatches_list: list[CounterMismatch] = []
    db_outflow_sum_sql = """
        SELECT COALESCE(SUM(le.amount), 0) AS total_debit
        FROM ledger_entries le
        JOIN ledger_accounts la ON la.id = le.account_id
        WHERE la.owner_type = 'agent'
          AND la.owner_id = $1::uuid
          AND le.direction = 'DEBIT'
          AND le.created_at >= $2
          AND le.created_at < $3;
    """

    for agent_id_str, day_str in sorted(audit_pairs):
        # Read Redis
        raw_val = await valkey.get(f"flx:outflow:{{{agent_id_str}}}:{day_str}")
        if raw_val is None:
            raw_val = await valkey.get(f"flx:outflow:{agent_id_str}:{day_str}")
        redis_val = int(raw_val) if raw_val is not None else 0

        # Read DB sum for that UTC day
        try:
            day_start = datetime.strptime(day_str, "%Y%m%d").replace(tzinfo=UTC)
            day_end = day_start + timedelta(days=1)
        except ValueError:
            continue

        async with pool.acquire() as conn:
            db_sum_row = await conn.fetchrow(db_outflow_sum_sql, agent_id_str, day_start, day_end)

        db_val = int(db_sum_row["total_debit"]) if db_sum_row else 0

        if redis_val != db_val:
            reason = classify_counter_mismatch(redis_val, db_val)
            delta = redis_val - db_val
            counter_mismatches_list.append(
                CounterMismatch(
                    agent_id=agent_id_str,
                    day=day_str,
                    redis_value=redis_val,
                    db_value=db_val,
                    delta=delta,
                    reason=reason,
                )
            )

    # =========================================================================
    # CHECK 4: DEAD WEBHOOK DELIVERIES VISIBILITY (HYGIENE)
    # =========================================================================
    dead_sql = "SELECT COUNT(*) AS dead_count FROM webhook_deliveries WHERE status = 'dead';"
    async with pool.acquire() as conn:
        dead_row = await conn.fetchrow(dead_sql)
    dead_deliveries = int(dead_row["dead_count"]) if dead_row else 0

    # =========================================================================
    # HYGIENE: TERMINAL IDEMPOTENCY PURGE (TASK 11 DEFERRED POLICY)
    # =========================================================================
    # Deletes COMPLETED and FAILED records older than 30 days.
    # PENDING records are NEVER deleted (held money / reservation law).
    purge_cutoff = now - timedelta(days=IDEMPOTENCY_RETENTION_DAYS)
    purge_sql = """
        DELETE FROM idempotency_keys
        WHERE (state = 'COMPLETED' AND completed_at < $1)
           OR (state = 'FAILED' AND created_at < $1);
    """
    async with pool.acquire() as conn:
        purge_status = await conn.execute(purge_sql, purge_cutoff)

    purged_count = 0
    if purge_status.startswith("DELETE "):
        try:
            purged_count = int(purge_status.split()[-1])
        except (ValueError, IndexError):
            purged_count = 0

    healthy = compute_healthy(balance_mismatches_list, counter_mismatches_list, global_balanced)

    return ReconcileReport(
        checked_at=checked_at,
        accounts_checked=accounts_checked,
        balance_mismatches=tuple(balance_mismatches_list),
        counter_mismatches=tuple(counter_mismatches_list),
        global_debits=global_debits,
        global_credits=global_credits,
        global_balanced=global_balanced,
        purged_idempotency=purged_count,
        dead_deliveries=dead_deliveries,
        system_accounts=tuple(system_accounts_list),
        healthy=healthy,
    )


async def main() -> int:
    """Operational entrypoint for the daily reconciliation worker one-shot job.

    1. Loads configuration and extracts DB host/name for leak-free error diagnostics.
    2. Creates asyncpg connection pool and connects to Valkey.
    3. Verifies PostgreSQL connection timezone (must be UTC).
    4. Invokes run_once(pool, valkey).
    5. THE SPEAKING CONTRACT: Emits exactly one single-line JSON report to stdout.
    6. Returns exit code 0 (healthy), 1 (mismatches found), or 2 (operational failure).
       On mismatches found, prints RUNBOOK pointer to stderr.
       On operational failure, stdout is kept SILENT (tripping dead-man switch) and
       diagnostics are written to stderr.
    """
    try:
        settings = get_settings()
        parsed_dsn = urlsplit(settings.pg_dsn)
        db_host = parsed_dsn.hostname or "unknown"
        db_name = parsed_dsn.path.lstrip("/") or "unknown"
    except Exception as exc:
        sys.stderr.write(f"Configuration failure: {exc.__class__.__name__}: {exc}\n")
        sys.stderr.flush()
        return EXIT_OPS_FAILURE

    pool: asyncpg.Pool | None = None
    valkey: redis_async.Redis | None = None

    try:
        pool = await asyncpg.create_pool(
            settings.pg_dsn,
            min_size=1,
            max_size=2,
            server_settings={"TimeZone": "UTC"},
            command_timeout=60.0,
        )

        async with pool.acquire() as conn:
            tz = await conn.fetchval("SHOW timezone")
            if tz not in ("UTC", "Etc/UTC"):
                raise RuntimeError(
                    f"PostgreSQL connection timezone must be 'UTC' or 'Etc/UTC', got '{tz}'. "
                    "Ensure server_settings={'TimeZone': 'UTC'} is configured in "
                    "asyncpg.create_pool."
                )

        valkey_client: redis_async.Redis = redis_async.Redis.from_url(
            settings.valkey_url, decode_responses=True
        )
        valkey = valkey_client
        await valkey_client.ping()

        report = await run_once(pool, valkey_client)
    except Exception as exc:
        # Operational Failure: Unreachable DB/Valkey, network partition, or pool error.
        # CRITICAL DESIGN LAW: Silence on stdout = death alarm for Loki dead-man switch.
        # Diagnostics go to stderr with zero leaked secrets.
        sys.stderr.write(
            f"Operational failure in reconciliation worker (host='{db_host}', db='{db_name}'): "
            f"{exc.__class__.__name__}: {exc}\n"
        )
        sys.stderr.flush()
        # --- Task 69 append ---
        from fluxpay.alerts.router import send_heartbeat

        send_heartbeat("reconciliation", ok=False, reason=f"{exc.__class__.__name__}: {exc}")
        return EXIT_OPS_FAILURE
    finally:
        if valkey is not None:
            await valkey.aclose()
        if pool is not None:
            await pool.close()

    # The speaking contract: Always emit exactly one single-line JSON report to stdout
    report_json = build_report(report)
    sys.stdout.write(report_json + "\n")
    sys.stdout.flush()

    if not report.healthy:
        sys.stderr.write(RUNBOOK_POINTER)
        sys.stderr.flush()
        # --- Task 69 append ---
        from fluxpay.alerts.router import send_heartbeat

        send_heartbeat("reconciliation", ok=False, reason="reconciliation_mismatches")
        return EXIT_MISMATCHES

    # --- Task 69 append ---
    from fluxpay.alerts.router import send_heartbeat

    send_heartbeat("reconciliation", ok=True)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
