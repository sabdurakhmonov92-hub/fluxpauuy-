"""Integration tests for Treasury Custody Schema and Hot Wallet Monitor.

TASK 44: TREASURY FOUNDATION: CUSTODY SCHEMA + HOT WALLET MONITOR (BLOCK I)

Exercises real PostgreSQL against 0011_treasury.sql with FakeReader:
1. sync happy: FakeReader(hot=150, cold=1000 minor-scaled) -> run -> caches updated,
   last_synced set, verdict ok, exit 0 JSON parses.
2. topup: FakeReader(hot=10 < low=50) -> alert captured; message contains balance +
   suggested amount; NO payout row created.
3. sweep: FakeReader(hot=300 > high=200) -> cold_payouts row EXISTS (reason surplus_sweep,
   to_address == cold_address, amount == expected midpoint math, requested_by='system',
   status 'requested') + alert mentions approvals needed; SECOND run -> NO duplicate row
   (active-sweep guard — idempotency proven).
4. sweep-dedup vs terminal: existing CONFIRMED sweep + hot still high -> new request ALLOWED
   (terminal doesn't block — hysteresis vs dedup interplay tested both sides).
5. reader failure: FakeReader raises -> sync_status='reader_error', alert fired, exit 0
   (observation fail-open), report synced=False; STALENESS: backdate last_synced 40 min +
   reader down -> stale alert text (both-alert case).
6. state-guard trigger: direct SQL illegal transition (requested -> confirmed) -> exception
   from DB (the machine is law at DB level); terminal immutability tested.
7. subprocess e2e contract: in-process main() test with FakeReader; stdout parses as locked JSON;
   returns exit 0.
8. seed row: placeholder addresses present; CHECK violations (bad address, high <= low) ->
   CheckViolationError.
"""

from __future__ import annotations

import contextlib
import io
import json
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg  # type: ignore[import-untyped]
import pytest
import pytest_asyncio

from fluxpay.treasury.monitor import (
    EXIT_OK,
    HotWalletMonitor,
    main,
)
from fluxpay.treasury.reader import FakeReader

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_0011_PATH = REPO_ROOT / "migrations" / "0011_treasury.sql"

# Minor unit scale for test amounts ($1 = 1_000_000_000 minor units to match seed)
SCALE = 1_000_000_000
LOW_WATER = 50 * SCALE  # 50_000_000000 ($50)
HIGH_WATER = 200 * SCALE  # 200_000_000000 ($200)


@pytest_asyncio.fixture
async def apply_treasury_schema(db_pool: asyncpg.Pool) -> None:
    """Execute migrations/0011_treasury.sql idempotently."""
    sql = MIGRATION_0011_PATH.read_text(encoding="utf-8")
    async with db_pool.acquire() as conn:
        await conn.execute(sql)


@pytest_asyncio.fixture(autouse=True)
async def clean_treasury_tables(
    db_pool: asyncpg.Pool,
    apply_treasury_schema: None,
) -> AsyncGenerator[None, None]:
    """Isolate tests by purging cold_payouts and restoring wallet_state seed."""
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM payout_approvals;")
        await conn.execute("DELETE FROM cold_payouts;")
        await conn.execute(
            """
            UPDATE wallet_state
            SET hot_balance_minor = 0,
                cold_balance_minor = 0,
                low_water_minor = $1,
                high_water_minor = $2,
                last_synced_at = NULL,
                sync_status = 'never'
            WHERE rail = 'base_usdc';
            """,
            LOW_WATER,
            HIGH_WATER,
        )
    yield
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM payout_approvals;")
        await conn.execute("DELETE FROM cold_payouts;")


# =============================================================================
# 1. HAPPY PATH SYNC
# =============================================================================


@pytest.mark.asyncio
async def test_sync_happy_path(db_pool: asyncpg.Pool) -> None:
    """FakeReader(hot=150, cold=1000) -> caches updated, last_synced set, verdict ok."""
    hot = 150 * SCALE
    cold = 1000 * SCALE
    reader = FakeReader(hot=hot, cold=cold)
    alerts: list[str] = []

    async def _capture_alert(msg: str) -> None:
        alerts.append(msg)

    fixed_now = datetime(2026, 9, 27, 14, 0, 0, tzinfo=UTC).timestamp()

    monitor = HotWalletMonitor(
        pool=db_pool,
        reader=reader,
        alert=_capture_alert,
        now=lambda: fixed_now,
        rail="base_usdc",
    )

    report = await monitor.run_once()

    assert report.synced is True
    assert report.alerted is False
    assert report.verdict.action == "ok"
    assert report.hot_balance == hot
    assert report.cold_balance == cold
    assert report.sweep_request_id is None
    assert len(alerts) == 0

    # Verify database caches updated
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM wallet_state WHERE rail = 'base_usdc';")
        assert row is not None
        assert row["hot_balance_minor"] == hot
        assert row["cold_balance_minor"] == cold
        assert row["sync_status"] == "ok"
        assert row["last_synced_at"] is not None


# =============================================================================
# 2. TOP-UP CONDITION
# =============================================================================


@pytest.mark.asyncio
async def test_topup_required_alert_and_no_payout(db_pool: asyncpg.Pool) -> None:
    """FakeReader(hot=10 < low=50) -> alert captured with balance + suggested; no payout."""
    hot = 10 * SCALE
    cold = 1000 * SCALE
    reader = FakeReader(hot=hot, cold=cold)
    alerts: list[str] = []

    async def _capture_alert(msg: str) -> None:
        alerts.append(msg)

    monitor = HotWalletMonitor(
        pool=db_pool,
        reader=reader,
        alert=_capture_alert,
        rail="base_usdc",
    )

    report = await monitor.run_once()

    expected_topup = (LOW_WATER * 2) - hot  # (50*2 - 10) * SCALE = 90 * SCALE
    assert report.synced is True
    assert report.alerted is True
    assert report.verdict.action == "topup_required"
    assert report.verdict.amount == expected_topup
    assert report.sweep_request_id is None

    # Alert fired with balance and suggested amount
    assert len(alerts) == 1
    assert str(hot) in alerts[0]
    assert str(expected_topup) in alerts[0]
    assert "topup" in alerts[0].lower()

    # Invariant: NO payout row created on top-up
    async with db_pool.acquire() as conn:
        count = await conn.fetchval("SELECT count(*) FROM cold_payouts;")
        assert count == 0


# =============================================================================
# 3. SURPLUS SWEEP & ACTIVE-SWEEP IDEMPOTENCY
# =============================================================================


@pytest.mark.asyncio
async def test_surplus_sweep_creation_and_idempotent_suppression(
    db_pool: asyncpg.Pool,
) -> None:
    """FakeReader(hot=300 > high=200) -> cold_payouts row exists; second run does not duplicate."""
    hot = 300 * SCALE
    cold = 1000 * SCALE
    reader = FakeReader(hot=hot, cold=cold)
    alerts: list[str] = []

    async def _capture_alert(msg: str) -> None:
        alerts.append(msg)

    monitor = HotWalletMonitor(
        pool=db_pool,
        reader=reader,
        alert=_capture_alert,
        rail="base_usdc",
    )

    # First run: creates surplus sweep request
    report1 = await monitor.run_once()

    midpoint = (LOW_WATER + HIGH_WATER) // 2  # 125 * SCALE
    expected_sweep = hot - midpoint  # 175 * SCALE

    assert report1.synced is True
    assert report1.alerted is True
    assert report1.verdict.action == "sweep_due"
    assert report1.verdict.amount == expected_sweep
    assert report1.sweep_request_id is not None
    assert len(alerts) == 1
    assert "approvals" in alerts[0].lower()
    assert str(expected_sweep) in alerts[0]

    # Verify DB row
    async with db_pool.acquire() as conn:
        payout = await conn.fetchrow(
            "SELECT * FROM cold_payouts WHERE payout_id = $1;",
            report1.sweep_request_id,
        )
        assert payout is not None
        assert payout["rail"] == "base_usdc"
        assert payout["reason"] == "surplus_sweep"
        assert payout["status"] == "requested"
        assert payout["amount_minor"] == expected_sweep
        assert payout["requested_by_sub"] == "system"

        cold_addr = await conn.fetchval(
            "SELECT cold_address FROM wallet_state WHERE rail = 'base_usdc';"
        )
        assert payout["to_address"] == cold_addr

    # Second run: hot balance is still 300 > 200, but active sweep is in flight
    report2 = await monitor.run_once()

    assert report2.synced is True
    assert report2.alerted is False  # suppressed
    assert report2.sweep_request_id == report1.sweep_request_id
    assert len(alerts) == 1  # no second alert

    # Invariant: exactly ONE row in cold_payouts (idempotency proven)
    async with db_pool.acquire() as conn:
        count = await conn.fetchval("SELECT count(*) FROM cold_payouts;")
        assert count == 1


# =============================================================================
# 4. SWEEP-DEDUP VS TERMINAL UNBLOCKING
# =============================================================================


@pytest.mark.asyncio
async def test_confirmed_sweep_unblocks_subsequent_sweep(db_pool: asyncpg.Pool) -> None:
    """Existing CONFIRMED sweep + hot still high -> new request ALLOWED (terminal doesn't block)."""
    hot = 300 * SCALE
    reader = FakeReader(hot=hot, cold=1000 * SCALE)
    alerts: list[str] = []

    async def _capture_alert(msg: str) -> None:
        alerts.append(msg)

    monitor = HotWalletMonitor(
        pool=db_pool,
        reader=reader,
        alert=_capture_alert,
        rail="base_usdc",
    )

    # Run 1: creates first sweep
    report1 = await monitor.run_once()
    first_id = report1.sweep_request_id
    assert first_id is not None

    # Transition first payout through legal states to 'confirmed'
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE cold_payouts SET status = 'approved' WHERE payout_id = $1;",
            first_id,
        )
        await conn.execute(
            "UPDATE cold_payouts SET status = 'executed' WHERE payout_id = $1;",
            first_id,
        )
        await conn.execute(
            "UPDATE cold_payouts SET status = 'confirmed' WHERE payout_id = $1;",
            first_id,
        )

    # Run 2: balance is still high, but previous sweep is confirmed (terminal)
    report2 = await monitor.run_once()
    second_id = report2.sweep_request_id

    assert second_id is not None
    assert second_id != first_id
    assert report2.alerted is True
    assert len(alerts) == 2

    async with db_pool.acquire() as conn:
        total_payouts = await conn.fetchval("SELECT count(*) FROM cold_payouts;")
        assert total_payouts == 2


# =============================================================================
# 5. READER FAILURE & STALENESS GUARD
# =============================================================================


@pytest.mark.asyncio
async def test_reader_failure_fail_open_and_staleness_alert(db_pool: asyncpg.Pool) -> None:
    """Reader exception -> sync_status='reader_error', alert fired, report synced=False.

    Staleness: backdate last_synced > 30 min + reader down -> stale alert text also fires.
    """
    reader = FakeReader(error=ConnectionResetError("Base RPC unreachable"))
    alerts: list[str] = []

    async def _capture_alert(msg: str) -> None:
        alerts.append(msg)

    # Case A: Recent sync (< 30 min ago)
    now_dt = datetime(2026, 9, 27, 12, 40, 0, tzinfo=UTC)
    recent_sync = now_dt - timedelta(minutes=10)

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE wallet_state
            SET last_synced_at = $1, sync_status = 'ok'
            WHERE rail = 'base_usdc';
            """,
            recent_sync,
        )

    monitor = HotWalletMonitor(
        pool=db_pool,
        reader=reader,
        alert=_capture_alert,
        now=lambda: now_dt.timestamp(),
        rail="base_usdc",
    )

    report = await monitor.run_once()

    assert report.synced is False
    assert report.alerted is True
    assert len(alerts) == 1
    assert "sync FAILED" in alerts[0]

    async with db_pool.acquire() as conn:
        status = await conn.fetchval(
            "SELECT sync_status FROM wallet_state WHERE rail = 'base_usdc';"
        )
        assert status == "reader_error"

    # Case B: Stale previous sync (> 30 min ago, e.g. 40 min)
    alerts.clear()
    stale_sync = now_dt - timedelta(minutes=40)

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE wallet_state
            SET last_synced_at = $1, sync_status = 'ok'
            WHERE rail = 'base_usdc';
            """,
            stale_sync,
        )

    report_stale = await monitor.run_once()

    assert report_stale.synced is False
    assert report_stale.alerted is True
    # Both alerts must fire: sync failed AND custody data STALE
    assert len(alerts) == 2
    assert any("sync FAILED" in a for a in alerts)
    assert any("STALE" in a for a in alerts)


# =============================================================================
# 6. DATABASE-LEVEL STATE-TRANSITION GUARD
# =============================================================================


@pytest.mark.asyncio
async def test_cold_payouts_state_transition_guard(db_pool: asyncpg.Pool) -> None:
    """Direct SQL illegal transition (requested -> confirmed) raises exception from DB trigger."""
    async with db_pool.acquire() as conn:
        cold_addr = await conn.fetchval(
            "SELECT cold_address FROM wallet_state WHERE rail = 'base_usdc';"
        )
        payout_id = await conn.fetchval(
            """
            INSERT INTO cold_payouts (
                rail, to_address, amount_minor, currency,
                reason, status, requested_by_sub
            ) VALUES (
                'base_usdc', $1, 1000, 'USDC', 'operational', 'requested', 'admin'
            ) RETURNING payout_id;
            """,
            cold_addr,
        )

        # Illegal skip: requested -> confirmed must fail
        with pytest.raises(asyncpg.CheckViolationError, match="illegal cold_payouts transition"):
            await conn.execute(
                "UPDATE cold_payouts SET status = 'confirmed' WHERE payout_id = $1;",
                payout_id,
            )

        # Illegal skip: requested -> executed must fail
        with pytest.raises(asyncpg.CheckViolationError, match="illegal cold_payouts transition"):
            await conn.execute(
                "UPDATE cold_payouts SET status = 'executed' WHERE payout_id = $1;",
                payout_id,
            )

        # Legal: requested -> approved
        await conn.execute(
            "UPDATE cold_payouts SET status = 'approved' WHERE payout_id = $1;",
            payout_id,
        )

        # Legal: approved -> executed
        await conn.execute(
            "UPDATE cold_payouts SET status = 'executed' WHERE payout_id = $1;",
            payout_id,
        )

        # Legal: executed -> confirmed
        await conn.execute(
            "UPDATE cold_payouts SET status = 'confirmed' WHERE payout_id = $1;",
            payout_id,
        )

        # Terminal state immutability: modifying confirmed record must fail
        with pytest.raises(asyncpg.CheckViolationError, match="terminal state"):
            await conn.execute(
                "UPDATE cold_payouts SET status = 'rejected' WHERE payout_id = $1;",
                payout_id,
            )


# =============================================================================
# 7. IN-PROCESS MAIN() E2E SMOKE
# =============================================================================


@pytest.mark.asyncio
async def test_main_in_process_e2e(db_pool: asyncpg.Pool) -> None:
    """In-process main() executes cleanly, writes single-line JSON to stdout, and exits 0."""
    reader = FakeReader(hot=150 * SCALE, cold=1000 * SCALE)
    alerts: list[str] = []

    async def _capture_alert(msg: str) -> None:
        alerts.append(msg)

    stdout_buf = io.StringIO()
    with contextlib.redirect_stdout(stdout_buf):
        exit_code = await main(
            pool=db_pool,
            reader=reader,
            alert=_capture_alert,
            rail="base_usdc",
        )

    assert exit_code == EXIT_OK
    raw_output = stdout_buf.getvalue().strip()
    assert "\n" not in raw_output

    data = json.loads(raw_output)
    assert data["mode"] == "treasury_monitor"
    assert data["rail"] == "base_usdc"
    assert data["verdict"] == "ok"
    assert data["synced"] is True
    assert data["alerted"] is False
    assert data["checked_at"].endswith("Z")


# =============================================================================
# 8. SEED ROW & DB CHECK CONSTRAINT VIOLATIONS
# =============================================================================


@pytest.mark.asyncio
async def test_seed_row_and_check_constraints(db_pool: asyncpg.Pool) -> None:
    """Verify placeholder seed addresses and assert CHECK violations on bad inputs."""
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM wallet_state WHERE rail = 'base_usdc';")
        assert row is not None
        assert row["hot_address"] == "0x0000000000000000000000000000000000000000"
        assert row["cold_address"] == "0x0000000000000000000000000000000000000000"
        assert row["low_water_minor"] == LOW_WATER
        assert row["high_water_minor"] == HIGH_WATER

        # Check violation: bad hot_address (invalid hex / length)
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                """
                INSERT INTO wallet_state (
                    rail, hot_address, cold_address, low_water_minor, high_water_minor
                ) VALUES (
                    'base_usdc', '0xinvalid', '0x0000000000000000000000000000000000000000', 10, 20
                );
                """
            )

        # Check violation: high_water_minor <= low_water_minor
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                """
                UPDATE wallet_state
                SET high_water_minor = low_water_minor - 1
                WHERE rail = 'base_usdc';
                """
            )
