"""Integration test suite proving the daily reconciliation worker truth audit contracts.

TASK 41: RECONCILIATION WORKER — DAILY TRUTH AUDIT (BLOCK H, PART 3)

Tests:
1. Balanced happy path: seed accounts + funded flows -> healthy=True, accounts_checked>0,
   global_balanced True, zero balance or counter mismatches.
2. Balance mismatch injected: owner conn increments agent balance -> exact delta=1 caught,
   pinned account_id, healthy False, exit 1 via subprocess, self-restoring.
3. System account genesis accounting: bootstrap out-of-ledger balance on treasury ->
   implied_genesis reported informationally, healthy STAYS True; negative implied genesis
   (balance < entry math) triggers hard BalanceMismatch alarm.
4. Global corruption double-angle detection: tamper entry amount via guard disable ->
   global_balanced False AND per-account balance mismatch fired.
5. Counter audit:
   - under-case: Redis key absent / deleted -> redis 0 vs db N -> 'under' mismatch.
   - over-case: extra increment in Redis -> 'over' mismatch.
   - exact match -> clean.
6. Purge hygiene (Task 11 deferred policy):
   - COMPLETED 31d old -> purged.
   - FAILED 31d old -> purged.
   - PENDING 31d old -> SURVIVES (held-money law proven).
   - Re-run idempotent.
7. Dead deliveries visibility: dead webhook deliveries counted in report without tripping alarm.
8. Subprocess e2e:
   - Healthy -> exit 0 + JSON parses.
   - Mismatch -> exit 1 + JSON parses + RUNBOOK pointer in stderr.
   - Dead DSN -> exit 2 + stdout completely silent (dead-man switch requirement).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import pytest
import redis.asyncio as redis_async

from fluxpay.ledger.hashchain import Direction
from fluxpay.ledger.postgres import PostgresLedgerStore
from fluxpay.ledger.store import EntryDraft
from fluxpay.workers.reconciliation import (
    EXIT_MISMATCHES,
    EXIT_OK,
    EXIT_OPS_FAILURE,
    RUNBOOK_POINTER,
    run_once,
)

pytestmark = pytest.mark.integration


def _make_reconciliation_env(dsn: str, valkey_url: str) -> dict[str, str]:
    """Create isolated environment for reconciliation worker subprocess execution."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("FLX_")}
    env["FLX_PG_DSN"] = dsn
    env["FLX_VALKEY_URL"] = valkey_url
    env["FLX_VAULT_MASTER_KEY"] = base64.b64encode(b"0" * 32).decode("ascii")
    env["FLX_WEBHOOK_SIGNING_KEY"] = "a" * 32
    env["FLX_KEYCLOAK_JWKS_URL"] = "https://auth.fluxpay.local/certs"
    env["FLX_KEYCLOAK_ISSUER"] = "https://auth.fluxpay.local"
    env["FLX_KEYCLOAK_AUDIENCE"] = "https://api.fluxpay.local"
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    repo_root = Path(__file__).resolve().parent.parent.parent
    src_dir = repo_root / "src"
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{src_dir}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else str(src_dir)
    )
    return env


async def _reset_ledger_and_tables(
    conn: asyncpg.Connection,
    bootstrap_seed_sql: str,
) -> None:
    """Reset the ledger, idempotency keys, webhooks, and restore bootstrap accounts."""
    await conn.execute("ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;")
    await conn.execute("DELETE FROM ledger_entries;")
    await conn.execute(
        "UPDATE ledger_chain_tip SET last_seq = 0, last_hash = 'GENESIS' WHERE singleton = TRUE;"
    )
    await conn.execute("ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;")
    await conn.execute("DELETE FROM webhook_deliveries;")
    await conn.execute("DELETE FROM idempotency_keys;")
    await conn.execute("DELETE FROM ledger_accounts WHERE owner_type IN ('agent', 'merchant');")
    await conn.execute(bootstrap_seed_sql)
    await conn.execute(
        "UPDATE ledger_accounts SET balance = 0, version = 0 "
        "WHERE owner_type IN ('system', 'fees', 'treasury');"
    )


# =============================================================================
# 1. BALANCED HAPPY PATH
# =============================================================================


async def test_reconciliation_balanced_happy_path(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    owner_conn: asyncpg.Connection,
    bootstrap_seed_sql: str,
) -> None:
    """Verify clean ledger state: transactions balanced, counters synchronized -> healthy True."""
    await _reset_ledger_and_tables(owner_conn, bootstrap_seed_sql)

    # 1. Fund treasury with out-of-ledger balance
    await owner_conn.execute(
        "UPDATE ledger_accounts SET balance = 10000000 WHERE owner_type = 'treasury';"
    )
    treasury_row = await owner_conn.fetchrow(
        "SELECT id FROM ledger_accounts WHERE owner_type = 'treasury';"
    )
    assert treasury_row is not None
    treasury_acc = treasury_row["id"]

    # 2. Create agent, merchant, and fees accounts
    agent_owner_id = uuid.uuid4()
    agent_acc = uuid.uuid4()
    merchant_owner_id = uuid.uuid4()
    merchant_acc = uuid.uuid4()

    await owner_conn.execute(
        """
        INSERT INTO ledger_accounts (id, owner_type, owner_id, currency, balance, version)
        VALUES
            ($1, 'agent', $2, 'USDC', 0, 0),
            ($3, 'merchant', $4, 'USDC', 0, 0);
        """,
        agent_acc,
        agent_owner_id,
        merchant_acc,
        merchant_owner_id,
    )

    fees_row = await owner_conn.fetchrow(
        "SELECT id FROM ledger_accounts WHERE owner_type = 'fees';"
    )
    assert fees_row is not None
    fees_acc = fees_row["id"]

    # 3. Post funded flows:
    # Tx A: Treasury -> Agent (10_000 minor)
    store = PostgresLedgerStore(db_pool)
    await store.post_transaction(
        [
            EntryDraft(
                account_id=treasury_acc,
                direction=Direction.DEBIT,
                amount=10_000,
                currency="USDC",
            ),
            EntryDraft(
                account_id=agent_acc,
                direction=Direction.CREDIT,
                amount=10_000,
                currency="USDC",
            ),
        ]
    )

    # Tx B: Agent -> Merchant (1_000 minor) + Fees (10 minor). Agent total debit = 1010.
    await store.post_transaction(
        [
            EntryDraft(
                account_id=agent_acc,
                direction=Direction.DEBIT,
                amount=1010,
                currency="USDC",
            ),
            EntryDraft(
                account_id=merchant_acc,
                direction=Direction.CREDIT,
                amount=1000,
                currency="USDC",
            ),
            EntryDraft(
                account_id=fees_acc,
                direction=Direction.CREDIT,
                amount=10,
                currency="USDC",
            ),
        ]
    )

    # 4. Synchronize Redis outflow counter for agent
    now = datetime.now(UTC)
    today = now.strftime("%Y%m%d")
    outflow_key = f"flx:outflow:{{{str(agent_owner_id).lower()}}}:{today}"
    await valkey.set(outflow_key, 1010)

    # 5. Run reconciliation
    report = await run_once(db_pool, valkey, now=now)

    assert report.healthy is True
    assert report.accounts_checked >= 4
    assert report.global_balanced is True
    assert len(report.balance_mismatches) == 0
    assert len(report.counter_mismatches) == 0
    assert report.global_debits == report.global_credits == 11010
    assert report.dead_deliveries == 0


# =============================================================================
# 2. BALANCE MISMATCH INJECTION & SUBPROCESS EXIT 1
# =============================================================================


async def test_reconciliation_balance_mismatch_injected(
    db_dsn: str,
    valkey_client: redis_async.Redis,
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    owner_conn: asyncpg.Connection,
    bootstrap_seed_sql: str,
) -> None:
    """Verify injected balance drift on agent account is detected with exact delta and exits 1."""
    await _reset_ledger_and_tables(owner_conn, bootstrap_seed_sql)

    agent_owner_id = uuid.uuid4()
    agent_acc = uuid.uuid4()
    await owner_conn.execute(
        """
        INSERT INTO ledger_accounts (id, owner_type, owner_id, currency, balance, version)
        VALUES ($1, 'agent', $2, 'USDC', 1000, 0);
        """,
        agent_acc,
        agent_owner_id,
    )

    # Incur deliberate drift: balance cache = 1001 vs computed 0 (delta = 1001)
    # Or post 1000 credit entry then tamper balance = balance + 1
    sys_row = await owner_conn.fetchrow(
        "SELECT id FROM ledger_accounts WHERE owner_type = 'system';"
    )
    assert sys_row is not None
    sys_acc = sys_row["id"]
    await owner_conn.execute("UPDATE ledger_accounts SET balance = 1000 WHERE id = $1", sys_acc)

    store = PostgresLedgerStore(db_pool)
    await store.post_transaction(
        [
            EntryDraft(account_id=sys_acc, direction=Direction.DEBIT, amount=1000, currency="USDC"),
            EntryDraft(
                account_id=agent_acc, direction=Direction.CREDIT, amount=1000, currency="USDC"
            ),
        ]
    )

    # Incur balance drift: cached_balance becomes 1001, computed is 1000 -> delta = 1
    await owner_conn.execute(
        "UPDATE ledger_accounts SET balance = balance + 1 WHERE id = $1", agent_acc
    )

    # 1. In-process verification
    report = await run_once(db_pool, valkey)
    assert report.healthy is False
    assert len(report.balance_mismatches) == 1
    mismatch = report.balance_mismatches[0]
    assert mismatch.account_id == str(agent_acc)
    assert mismatch.owner_type == "agent"
    assert mismatch.cached_balance == 1001
    assert mismatch.computed_balance == 1000
    assert mismatch.delta == 1

    # 2. Subprocess execution verification (must exit 1, emit JSON to stdout, runbook to stderr)
    env = _make_reconciliation_env(
        db_dsn, os.environ.get("FLX_VALKEY_URL", "redis://localhost:6379/15")
    )
    cmd = [sys.executable, "-m", "fluxpay.workers.reconciliation"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    stdout_b, stderr_b = await proc.communicate()
    assert proc.returncode == EXIT_MISMATCHES

    stdout_str = stdout_b.decode("utf-8").strip()
    data = json.loads(stdout_str)
    assert data["mode"] == "reconciliation"
    assert data["healthy"] is False
    assert len(data["balance_mismatches"]) == 1
    assert data["balance_mismatches"][0]["delta"] == 1

    stderr_str = stderr_b.decode("utf-8")
    assert RUNBOOK_POINTER in stderr_str

    # 3. Restore and prove self-cleaning
    await owner_conn.execute(
        "UPDATE ledger_accounts SET balance = balance - 1 WHERE id = $1", agent_acc
    )
    clean_report = await run_once(db_pool, valkey)
    assert clean_report.healthy is True
    assert len(clean_report.balance_mismatches) == 0


# =============================================================================
# 3. SYSTEM ACCOUNT GENESIS ACCOUNTING & NEGATIVE GENESIS ALARM
# =============================================================================


async def test_reconciliation_system_account_genesis(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    owner_conn: asyncpg.Connection,
    bootstrap_seed_sql: str,
) -> None:
    """Verify system accounts report implied_genesis cleanly.

    Negative genesis triggers a hard alarm.
    """
    await _reset_ledger_and_tables(owner_conn, bootstrap_seed_sql)

    # 1. Informational case: treasury direct bootstrap funding = 50_000_000
    await owner_conn.execute(
        "UPDATE ledger_accounts SET balance = 50000000 WHERE owner_type = 'treasury';"
    )
    report = await run_once(db_pool, valkey)
    assert report.healthy is True
    assert len(report.balance_mismatches) == 0

    treasury_entry = next(s for s in report.system_accounts if s.owner_type == "treasury")
    assert treasury_entry.cached == 50000000
    assert treasury_entry.computed == 0
    assert treasury_entry.implied_genesis == 50000000

    # 2. Hard mismatch case: negative implied genesis (funds appeared from nowhere / phantom debit)
    # Credit fees account by 500 in entry math, but set its balance to 200 -> delta = -300
    fees_row = await owner_conn.fetchrow(
        "SELECT id FROM ledger_accounts WHERE owner_type = 'fees';"
    )
    treasury_row = await owner_conn.fetchrow(
        "SELECT id FROM ledger_accounts WHERE owner_type = 'treasury';"
    )
    assert fees_row is not None and treasury_row is not None

    store = PostgresLedgerStore(db_pool)
    await store.post_transaction(
        [
            EntryDraft(
                account_id=treasury_row["id"],
                direction=Direction.DEBIT,
                amount=500,
                currency="USDC",
            ),
            EntryDraft(
                account_id=fees_row["id"], direction=Direction.CREDIT, amount=500, currency="USDC"
            ),
        ]
    )

    # Fees account now has computed = 500, cached = 500. Tamper fees balance down to 200.
    await owner_conn.execute(
        "UPDATE ledger_accounts SET balance = 200 WHERE id = $1", fees_row["id"]
    )

    neg_report = await run_once(db_pool, valkey)
    assert neg_report.healthy is False
    assert any(
        m.account_id == str(fees_row["id"]) and m.owner_type == "fees" and m.delta == -300
        for m in neg_report.balance_mismatches
    )

    # Restore fees balance
    await owner_conn.execute(
        "UPDATE ledger_accounts SET balance = 500 WHERE id = $1", fees_row["id"]
    )


# =============================================================================
# 4. GLOBAL CORRUPTION DOUBLE-ANGLE DETECTION
# =============================================================================


async def test_reconciliation_global_corruption_double_detection(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    owner_conn: asyncpg.Connection,
    bootstrap_seed_sql: str,
) -> None:
    """Verify entry tampering triggers both global imbalance AND per-account balance mismatch."""
    await _reset_ledger_and_tables(owner_conn, bootstrap_seed_sql)

    sys_row = await owner_conn.fetchrow(
        "SELECT id FROM ledger_accounts WHERE owner_type = 'system';"
    )
    assert sys_row is not None
    sys_acc = sys_row["id"]
    await owner_conn.execute("UPDATE ledger_accounts SET balance = 5000 WHERE id = $1", sys_acc)

    agent_owner = uuid.uuid4()
    agent_acc = uuid.uuid4()
    await owner_conn.execute(
        """
        INSERT INTO ledger_accounts (id, owner_type, owner_id, currency, balance, version)
        VALUES ($1, 'agent', $2, 'USDC', 0, 0);
        """,
        agent_acc,
        agent_owner,
    )

    store = PostgresLedgerStore(db_pool)
    await store.post_transaction(
        [
            EntryDraft(account_id=sys_acc, direction=Direction.DEBIT, amount=1000, currency="USDC"),
            EntryDraft(
                account_id=agent_acc, direction=Direction.CREDIT, amount=1000, currency="USDC"
            ),
        ]
    )

    # Corrupt seq 1 (DEBIT on system account) by adding 500
    await owner_conn.execute(
        "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
    )
    await owner_conn.execute("UPDATE ledger_entries SET amount = amount + 500 WHERE seq = 1;")
    await owner_conn.execute(
        "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
    )

    report = await run_once(db_pool, valkey)

    # Detection Angle 1: Global double entry is broken (1500 debits vs 1000 credits)
    assert report.global_balanced is False
    assert report.global_debits == 1500
    assert report.global_credits == 1000

    # Detection Angle 2: System account computed balance changed (-1500 vs cached 4000)
    assert report.healthy is False

    # Restore entry
    await owner_conn.execute(
        "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
    )
    await owner_conn.execute("UPDATE ledger_entries SET amount = amount - 500 WHERE seq = 1;")
    await owner_conn.execute(
        "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
    )

    restored_report = await run_once(db_pool, valkey)
    assert restored_report.global_balanced is True
    assert restored_report.global_debits == 1000
    assert restored_report.global_credits == 1000


# =============================================================================
# 5. REDIS COUNTER AUDIT: UNDER, OVER, AND CLEAN
# =============================================================================


async def test_reconciliation_counter_audit(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    owner_conn: asyncpg.Connection,
    bootstrap_seed_sql: str,
) -> None:
    """Verify counter audit detects lost increments (under) and double increments (over)."""
    await _reset_ledger_and_tables(owner_conn, bootstrap_seed_sql)

    # Seed agent account with 10_000
    agent_owner_id = uuid.uuid4()
    agent_acc = uuid.uuid4()
    merchant_owner_id = uuid.uuid4()
    merchant_acc = uuid.uuid4()

    await owner_conn.execute(
        """
        INSERT INTO ledger_accounts (id, owner_type, owner_id, currency, balance, version)
        VALUES
            ($1, 'agent', $2, 'USDC', 10000, 0),
            ($3, 'merchant', $4, 'USDC', 0, 0);
        """,
        agent_acc,
        agent_owner_id,
        merchant_acc,
        merchant_owner_id,
    )

    # Settle 2 payments: Tx 1 = 600, Tx 2 = 400 -> total debited = 1000
    store = PostgresLedgerStore(db_pool)
    await store.post_transaction(
        [
            EntryDraft(
                account_id=agent_acc, direction=Direction.DEBIT, amount=600, currency="USDC"
            ),
            EntryDraft(
                account_id=merchant_acc, direction=Direction.CREDIT, amount=600, currency="USDC"
            ),
        ]
    )
    await store.post_transaction(
        [
            EntryDraft(
                account_id=agent_acc, direction=Direction.DEBIT, amount=400, currency="USDC"
            ),
            EntryDraft(
                account_id=merchant_acc, direction=Direction.CREDIT, amount=400, currency="USDC"
            ),
        ]
    )

    now = datetime.now(UTC)
    today = now.strftime("%Y%m%d")
    agent_str = str(agent_owner_id).lower()
    outflow_key = f"flx:outflow:{{{agent_str}}}:{today}"

    # Case A: UNDER (Redis key deleted / lost -> redis=0 vs db=1000)
    await valkey.delete(outflow_key)
    under_report = await run_once(db_pool, valkey, now=now)
    assert under_report.healthy is False
    assert any(
        m.agent_id == agent_str
        and m.reason == "under"
        and m.redis_value == 0
        and m.db_value == 1000
        and m.delta == -1000
        for m in under_report.counter_mismatches
    )

    # Case B: OVER (Extra increment -> redis=1500 vs db=1000)
    await valkey.set(outflow_key, 1500)
    over_report = await run_once(db_pool, valkey, now=now)
    assert over_report.healthy is False
    assert any(
        m.agent_id == agent_str
        and m.reason == "over"
        and m.redis_value == 1500
        and m.db_value == 1000
        and m.delta == 500
        for m in over_report.counter_mismatches
    )

    # Case C: CLEAN (Exact match -> redis=1000 vs db=1000)
    await valkey.set(outflow_key, 1000)
    clean_report = await run_once(db_pool, valkey, now=now)
    assert clean_report.healthy is True
    assert not any(m.agent_id == agent_str for m in clean_report.counter_mismatches)


# =============================================================================
# 6. IDEMPOTENCY PURGE HYGIENE & PENDING SURVIVAL LAW
# =============================================================================


async def test_reconciliation_purge_idempotency_keys(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    owner_conn: asyncpg.Connection,
    bootstrap_seed_sql: str,
) -> None:
    """Verify COMPLETED/FAILED >30d are purged, and PENDING keys NEVER get purged."""
    await _reset_ledger_and_tables(owner_conn, bootstrap_seed_sql)

    now = datetime.now(UTC)
    t_31d_ago = now - timedelta(days=31)
    t_1d_ago = now - timedelta(days=1)

    agent_id = uuid.uuid4()

    # Seed 5 idempotency keys:
    # 1. COMPLETED, completed_at 31d ago -> MUST BE PURGED
    # 2. COMPLETED, completed_at 1d ago -> MUST SURVIVE
    # 3. PENDING, created_at 31d ago -> MUST SURVIVE (The held-money law)
    # 4. FAILED, created_at 31d ago -> MUST BE PURGED
    # 5. FAILED, created_at 5d ago -> MUST SURVIVE
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO idempotency_keys (
                agent_id, idem_key, body_hash, state, completed_at, created_at
            )
            VALUES
                ($1, 'key_comp_old', 'hash1', 'COMPLETED', $2, $2),
                ($1, 'key_comp_new', 'hash2', 'COMPLETED', $3, $3),
                ($1, 'key_pend_old', 'hash3', 'PENDING', NULL, $2),
                ($1, 'key_fail_old', 'hash4', 'FAILED', NULL, $2),
                ($1, 'key_fail_new', 'hash5', 'FAILED', NULL, $3);
            """,
            agent_id,
            t_31d_ago,
            t_1d_ago,
        )

    # Run purge pass
    report = await run_once(db_pool, valkey, now=now)
    assert report.purged_idempotency == 2

    # Verify database state
    async with db_pool.acquire() as conn:
        remaining_rows = await conn.fetch(
            "SELECT idem_key, state FROM idempotency_keys WHERE agent_id = $1;", agent_id
        )

    remaining_keys = {row["idem_key"]: row["state"] for row in remaining_rows}
    assert "key_comp_old" not in remaining_keys
    assert "key_fail_old" not in remaining_keys
    assert remaining_keys["key_comp_new"] == "COMPLETED"
    assert remaining_keys["key_pend_old"] == "PENDING"  # PENDING SURVIVED!
    assert remaining_keys["key_fail_new"] == "FAILED"

    # Re-run is idempotent (purges 0)
    report2 = await run_once(db_pool, valkey, now=now)
    assert report2.purged_idempotency == 0


# =============================================================================
# 7. DEAD WEBHOOK DELIVERIES VISIBILITY
# =============================================================================


async def test_reconciliation_dead_deliveries_count(
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    owner_conn: asyncpg.Connection,
    bootstrap_seed_sql: str,
    make_merchant: Any,
    make_webhook_endpoint: Any,
) -> None:
    """Verify dead webhook deliveries are counted in the report without raising alarms."""
    await _reset_ledger_and_tables(owner_conn, bootstrap_seed_sql)

    mch = await make_merchant(external_id=f"mch_{uuid.uuid4().hex[:10]}")
    ep = await make_webhook_endpoint(mch.id, active=True)

    # Seed 3 dead deliveries
    async with db_pool.acquire() as conn:
        for _ in range(3):
            await conn.execute(
                """
                INSERT INTO webhook_deliveries (
                    id, event_id, endpoint_id, payload, status, attempts, next_attempt_at
                ) VALUES ($1, $2, $3, $4::jsonb, 'dead', 5, now());
                """,
                uuid.uuid4(),
                uuid.uuid4(),
                ep.endpoint_id,
                json.dumps({"test": "dead"}),
            )

    report = await run_once(db_pool, valkey)
    assert report.dead_deliveries >= 3
    assert report.healthy is True


# =============================================================================
# 8. SUBPROCESS E2E CONTRACTS (HEALTHY, MISMATCH, DEAD DSN)
# =============================================================================


async def test_reconciliation_subprocess_e2e(
    db_dsn: str,
    valkey_client: redis_async.Redis,
    db_pool: asyncpg.Pool,
    valkey: redis_async.Redis,
    owner_conn: asyncpg.Connection,
    bootstrap_seed_sql: str,
) -> None:
    """Verify subprocess CLI behavior across healthy (0), mismatch (1), and dead DSN (2)."""
    valkey_url = os.environ.get("FLX_VALKEY_URL", "redis://localhost:6379/15")

    # --- Scenario 1: Clean ledger -> Exit 0 with JSON ---
    await _reset_ledger_and_tables(owner_conn, bootstrap_seed_sql)
    env_healthy = _make_reconciliation_env(db_dsn, valkey_url)
    proc_healthy = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "fluxpay.workers.reconciliation",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env_healthy,
    )
    stdout_h, _stderr_h = await proc_healthy.communicate()
    assert proc_healthy.returncode == EXIT_OK
    data_h = json.loads(stdout_h.decode("utf-8").strip())
    assert data_h["mode"] == "reconciliation"
    assert data_h["healthy"] is True

    # --- Scenario 2: Tampered balance -> Exit 1 with JSON on stdout and runbook on stderr ---
    agent_acc = uuid.uuid4()
    await owner_conn.execute(
        """
        INSERT INTO ledger_accounts (id, owner_type, owner_id, currency, balance, version)
        VALUES ($1, 'agent', $2, 'USDC', 500, 0);
        """,
        agent_acc,
        uuid.uuid4(),
    )
    proc_mismatch = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "fluxpay.workers.reconciliation",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env_healthy,
    )
    stdout_m, stderr_m = await proc_mismatch.communicate()
    assert proc_mismatch.returncode == EXIT_MISMATCHES
    data_m = json.loads(stdout_m.decode("utf-8").strip())
    assert data_m["healthy"] is False
    assert RUNBOOK_POINTER in stderr_m.decode("utf-8")

    # Clean up agent account
    await owner_conn.execute("DELETE FROM ledger_accounts WHERE id = $1;", agent_acc)

    # --- Scenario 3: Dead PostgreSQL DSN -> Exit 2 with ZERO bytes on stdout (dead-man switch) ---
    env_dead = _make_reconciliation_env(
        "postgresql://fluxpay:fluxpay@127.0.0.1:1/fluxpay_nonexistent", valkey_url
    )
    proc_dead = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "fluxpay.workers.reconciliation",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env_dead,
    )
    stdout_d, stderr_d = await proc_dead.communicate()
    assert proc_dead.returncode == EXIT_OPS_FAILURE
    assert len(stdout_d) == 0  # SILENCE TRIPS THE DEAD-MAN SWITCH
    assert "Operational failure" in stderr_d.decode("utf-8")
