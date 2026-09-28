"""Integration tests for Treasury Cold Payout Queue and Custody Bridge.

TASK 45 — COLD PAYOUT PIPELINE: 2-MAN QUEUE + EXECUTION RECORDING (BLOCK I CLOSURE)

Exercises real PostgreSQL against 0011_treasury.sql with FakeReader:
1. FULL LOOP: request -> vote A (pending) -> vote B (approved + alert) ->
   record_execution(tx_hash) -> executed + audit rows -> confirm_if_ready (confirmed + audit).
2. INTEGRITY: duplicate vote classified as already_voted; support role raises ForbiddenError;
   vote on approved payout raises PayoutNotOpenError; concurrent voting race produces single winner.
3. REJECT PATH: reject terminates regardless of approvals; record_execution on rejected fails.
4. DB STATE-GUARD: illegal state transition skipping approval raises CheckViolationError.
5. CONFIRMATION READ: reader confirmed=False stays executed; confirmed=True advances.
6. STUCK DETECTION: approved / executed > 24h triggers stuck alert with age context.
7. SWEEPER E2E: run_once processes batch, confirms, detects stuck, reports JSON; dead DSN exits 2.
8. CUSTODY SNAPSHOT: calculates in-flight total and drift between on-chain truth and cache.
"""

from __future__ import annotations

import asyncio
import io
import json
import sys
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg  # type: ignore[import-untyped]
import pytest
import pytest_asyncio

from fluxpay.shared.errors import ForbiddenError, PayoutNotOpenError
from fluxpay.treasury.cli import run_cli
from fluxpay.treasury.payouts import (
    EXIT_OK,
    EXIT_OPS_FAILURE,
    PayoutService,
    PayoutSweeper,
    VoteOutcome,
    custody_snapshot,
    main,
)
from fluxpay.treasury.reader import FakeReader, TxStatus

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_0011_PATH = REPO_ROOT / "migrations" / "0011_treasury.sql"
MIGRATION_0006_PATH = REPO_ROOT / "migrations" / "0006_audit.sql"

SCALE = 1_000_000_000
LOW_WATER = 50 * SCALE
HIGH_WATER = 200 * SCALE


@pytest_asyncio.fixture
async def apply_treasury_schema(db_pool: asyncpg.Pool) -> None:
    """Execute migrations/0006_audit.sql and 0011_treasury.sql idempotently."""
    async with db_pool.acquire() as conn:
        if MIGRATION_0006_PATH.exists():
            await conn.execute(MIGRATION_0006_PATH.read_text(encoding="utf-8"))
        await conn.execute(MIGRATION_0011_PATH.read_text(encoding="utf-8"))


@pytest_asyncio.fixture(autouse=True)
async def clean_treasury_tables(
    db_pool: asyncpg.Pool,
    apply_treasury_schema: None,
) -> AsyncGenerator[None, None]:
    """Isolate tests by purging cold_payouts, approvals, and audit rows."""
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM payout_approvals;")
        await conn.execute("DELETE FROM cold_payouts;")
        await conn.execute(
            """
            UPDATE wallet_state
            SET hot_balance_minor = 150000000000,
                cold_balance_minor = 1000000000000,
                low_water_minor = $1,
                high_water_minor = $2,
                last_synced_at = NULL,
                sync_status = 'ok'
            WHERE rail = 'base_usdc';
            """,
            LOW_WATER,
            HIGH_WATER,
        )
    yield
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM payout_approvals;")
        await conn.execute("DELETE FROM cold_payouts;")


class AlertRecorder:
    """In-memory alert sink capturing operational alerts."""

    def __init__(self) -> None:
        self.alerts: list[str] = []

    async def alert(self, msg: str) -> None:
        self.alerts.append(msg)


# ==============================================================================
# 1. FULL LOOP TEST (ACCEPTANCE CRITERIA)
# ==============================================================================
@pytest.mark.asyncio
async def test_full_loop_payout_lifecycle(db_pool: asyncpg.Pool) -> None:
    """Full lifecycle: request -> 2 votes -> approved -> record_execution -> confirm_if_ready."""
    recorder = AlertRecorder()
    tx_hash = "0x" + "a" * 64
    reader = FakeReader(tx_status=TxStatus(confirmed=True, confirmations=12))

    service = PayoutService(pool=db_pool, reader=reader, alert=recorder.alert)

    # 1. Request payout (system sweep)
    dest_address = "0x" + "1" * 40
    payout = await service.request(
        rail="base_usdc",
        to_address=dest_address,
        amount_minor=50 * SCALE,
        currency="USDC",
        reason="surplus_sweep",
        requested_by_sub="system",
    )
    assert payout.status == "requested"
    assert payout.amount_minor == 50 * SCALE
    assert len(recorder.alerts) == 1
    assert "payout REQUESTED (2 approvals needed)" in recorder.alerts[0]

    # 2. Vote A (pending)
    v1 = await service.vote(
        payout_id=payout.payout_id,
        voter_sub="admin_alice",
        voter_role="admin",
        vote="approve",
        note="Approved by alice",
    )
    assert v1.status == "pending"
    assert v1.votes_for == 1
    assert v1.votes_against == 0
    assert len(recorder.alerts) == 1  # No alert on first vote

    # 3. Vote B (approved)
    v2 = await service.vote(
        payout_id=payout.payout_id,
        voter_sub="admin_bob",
        voter_role="admin",
        vote="approve",
        note="Approved by bob",
    )
    assert v2.status == "approved"
    assert v2.votes_for == 2
    assert len(recorder.alerts) == 2
    assert "READY FOR EXECUTION (Safe — 2-of-3)" in recorder.alerts[1]

    # Verify audit row for payout.approved
    async with db_pool.acquire() as conn:
        approved_audit = await conn.fetchrow(
            """
            SELECT * FROM audit_log
            WHERE action = 'payout.approved' AND target_id = $1;
            """,
            str(payout.payout_id),
        )
        assert approved_audit is not None
        assert approved_audit["actor_sub"] == "admin_bob"

    # 4. Record execution (the receipt moment)
    executed = await service.record_execution(
        payout_id=payout.payout_id,
        tx_hash=tx_hash,
        recorded_by_sub="admin_bob",
    )
    assert executed.status == "executed"
    assert executed.tx_hash == tx_hash
    assert executed.executed_at is not None
    assert len(recorder.alerts) == 3
    assert "EXECUTED — awaiting confirmations" in recorder.alerts[2]

    # Verify audit row for payout.executed
    async with db_pool.acquire() as conn:
        exec_audit = await conn.fetchrow(
            """
            SELECT * FROM audit_log
            WHERE action = 'payout.executed' AND target_id = $1;
            """,
            str(payout.payout_id),
        )
        assert exec_audit is not None
        assert exec_audit["actor_sub"] == "admin_bob"
        details = json.loads(exec_audit["details"])
        assert details["tx_hash"] == tx_hash

    # 5. Confirm if ready
    confirmed = await service.confirm_if_ready(payout_id=payout.payout_id)
    assert confirmed is not None
    assert confirmed.status == "confirmed"
    assert confirmed.confirmed_at is not None
    assert len(recorder.alerts) == 4
    assert "payout CONFIRMED" in recorder.alerts[3]

    # Verify audit row for payout.confirmed
    async with db_pool.acquire() as conn:
        conf_audit = await conn.fetchrow(
            """
            SELECT * FROM audit_log
            WHERE action = 'payout.confirmed' AND target_id = $1;
            """,
            str(payout.payout_id),
        )
        assert conf_audit is not None
        assert conf_audit["actor_sub"] == "system"


# ==============================================================================
# 2. INTEGRITY & AUTHORIZATION TESTS
# ==============================================================================
@pytest.mark.asyncio
async def test_duplicate_vote_returns_already_voted(db_pool: asyncpg.Pool) -> None:
    """Duplicate vote by same admin is classified as already_voted without altering counts."""
    recorder = AlertRecorder()
    service = PayoutService(pool=db_pool, reader=FakeReader(), alert=recorder.alert)

    payout = await service.request(
        to_address="0x" + "2" * 40,
        amount_minor=10 * SCALE,
        requested_by_sub="admin_test",
    )

    out1 = await service.vote(
        payout_id=payout.payout_id,
        voter_sub="admin_alice",
        voter_role="admin",
        vote="approve",
    )
    assert out1.status == "pending"
    assert out1.votes_for == 1

    # Second vote by same admin
    out2 = await service.vote(
        payout_id=payout.payout_id,
        voter_sub="admin_alice",
        voter_role="admin",
        vote="approve",
    )
    assert out2.status == "already_voted"
    assert out2.votes_for == 1
    assert out2.votes_against == 0

    # Ensure DB has exactly 1 approval row
    async with db_pool.acquire() as conn:
        cnt = await conn.fetchval(
            "SELECT count(*) FROM payout_approvals WHERE payout_id = $1;",
            payout.payout_id,
        )
        assert cnt == 1


@pytest.mark.asyncio
async def test_support_role_forbidden_to_vote(db_pool: asyncpg.Pool) -> None:
    """Support role must be rejected with ForbiddenError (separation of duties)."""
    service = PayoutService(pool=db_pool, reader=FakeReader(), alert=AlertRecorder().alert)

    payout = await service.request(
        to_address="0x" + "2" * 40,
        amount_minor=10 * SCALE,
        requested_by_sub="admin_test",
    )

    with pytest.raises(ForbiddenError):
        await service.vote(
            payout_id=payout.payout_id,
            voter_sub="support_sam",
            voter_role="support",
            vote="approve",
        )


@pytest.mark.asyncio
async def test_vote_on_approved_payout_raises_payout_not_open(db_pool: asyncpg.Pool) -> None:
    """Voting on an already approved payout raises PayoutNotOpenError (door closed)."""
    service = PayoutService(pool=db_pool, reader=FakeReader(), alert=AlertRecorder().alert)

    payout = await service.request(
        to_address="0x" + "2" * 40,
        amount_minor=10 * SCALE,
        requested_by_sub="admin_test",
    )
    await service.vote(
        payout_id=payout.payout_id,
        voter_sub="admin_a",
        voter_role="admin",
        vote="approve",
    )
    await service.vote(
        payout_id=payout.payout_id,
        voter_sub="admin_b",
        voter_role="admin",
        vote="approve",
    )

    # Third vote when payout is approved
    with pytest.raises(PayoutNotOpenError):
        await service.vote(
            payout_id=payout.payout_id,
            voter_sub="admin_c",
            voter_role="admin",
            vote="approve",
        )


@pytest.mark.asyncio
async def test_concurrent_votes_race_condition(db_pool: asyncpg.Pool) -> None:
    """Concurrent voting race: exactly ONE approved transition occurs via FOR UPDATE."""
    service = PayoutService(pool=db_pool, reader=FakeReader(), alert=AlertRecorder().alert)

    payout = await service.request(
        to_address="0x" + "3" * 40,
        amount_minor=10 * SCALE,
        requested_by_sub="admin_test",
    )

    # First vote
    await service.vote(
        payout_id=payout.payout_id,
        voter_sub="admin_lead",
        voter_role="admin",
        vote="approve",
    )

    # Two concurrent second votes racing
    res1, res2 = await asyncio.gather(
        service.vote(
            payout_id=payout.payout_id,
            voter_sub="admin_racer_1",
            voter_role="admin",
            vote="approve",
        ),
        service.vote(
            payout_id=payout.payout_id,
            voter_sub="admin_racer_2",
            voter_role="admin",
            vote="approve",
        ),
        return_exceptions=True,
    )

    # Exactly one must have status 'approved'; the other raises PayoutNotOpenError or handles lock
    outcomes = [r for r in (res1, res2) if isinstance(r, VoteOutcome)]
    errors = [r for r in (res1, res2) if isinstance(r, PayoutNotOpenError)]

    # Either one won and the other got PayoutNotOpenError, or both succeeded under serial order
    # (first became approved, second got PayoutNotOpenError)
    assert len(errors) == 1
    assert len(outcomes) == 1
    assert outcomes[0].status == "approved"


# ==============================================================================
# 3. REJECT PATH TESTS
# ==============================================================================
@pytest.mark.asyncio
async def test_reject_path_terminates_and_closes_door(db_pool: asyncpg.Pool) -> None:
    """Reject vote immediately terminates payout; execution recording subsequently fails."""
    recorder = AlertRecorder()
    service = PayoutService(pool=db_pool, reader=FakeReader(), alert=recorder.alert)

    payout = await service.request(
        to_address="0x" + "4" * 40,
        amount_minor=10 * SCALE,
        requested_by_sub="admin_test",
    )

    # Admin A approves
    await service.vote(
        payout_id=payout.payout_id,
        voter_sub="admin_a",
        voter_role="admin",
        vote="approve",
    )

    # Admin B rejects
    v_rej = await service.vote(
        payout_id=payout.payout_id,
        voter_sub="admin_b",
        voter_role="admin",
        vote="reject",
        note="suspicious address",
    )
    assert v_rej.status == "rejected"
    assert v_rej.votes_against == 1

    # Verify audit row
    async with db_pool.acquire() as conn:
        rej_audit = await conn.fetchrow(
            "SELECT * FROM audit_log WHERE action = 'payout.reject' AND target_id = $1;",
            str(payout.payout_id),
        )
        assert rej_audit is not None

    # Attempting to record execution on rejected payout must fail
    with pytest.raises(PayoutNotOpenError):
        await service.record_execution(
            payout_id=payout.payout_id,
            tx_hash="0x" + "b" * 64,
            recorded_by_sub="admin_b",
        )


# ==============================================================================
# 4. DATABASE STATE-GUARD TRIGGER TEST
# ==============================================================================
@pytest.mark.asyncio
async def test_db_state_guard_blocks_illegal_transition(db_pool: asyncpg.Pool) -> None:
    """Direct SQL illegal transition (requested -> executed) raises check_violation."""
    service = PayoutService(pool=db_pool, reader=FakeReader(), alert=AlertRecorder().alert)

    payout = await service.request(
        to_address="0x" + "5" * 40,
        amount_minor=10 * SCALE,
        requested_by_sub="admin_test",
    )

    # Attempt skipping 'approved' via direct SQL
    with pytest.raises(asyncpg.CheckViolationError) as exc_info:
        async with db_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE cold_payouts
                SET status = 'executed', tx_hash = $1
                WHERE payout_id = $2;
                """,
                "0x" + "e" * 64,
                payout.payout_id,
            )
    assert "illegal cold_payouts transition" in str(exc_info.value)


# ==============================================================================
# 5. CONFIRMATION READ & FAIL-OPEN
# ==============================================================================
@pytest.mark.asyncio
async def test_confirmation_reader_semantics(db_pool: asyncpg.Pool) -> None:
    """Reader confirmed=False returns None; confirmed=True advances; reader failure fails open."""
    recorder = AlertRecorder()
    unconfirmed_reader = FakeReader(tx_status=TxStatus(confirmed=False, confirmations=2))
    service = PayoutService(pool=db_pool, reader=unconfirmed_reader, alert=recorder.alert)

    payout = await service.request(
        to_address="0x" + "6" * 40,
        amount_minor=10 * SCALE,
        requested_by_sub="admin_test",
    )
    await service.vote(
        payout_id=payout.payout_id,
        voter_sub="admin_1",
        voter_role="admin",
        vote="approve",
    )
    await service.vote(
        payout_id=payout.payout_id,
        voter_sub="admin_2",
        voter_role="admin",
        vote="approve",
    )
    await service.record_execution(
        payout_id=payout.payout_id,
        tx_hash="0x" + "f" * 64,
        recorded_by_sub="admin_1",
    )

    # 1. Unconfirmed on-chain -> stays executed, returns None
    res = await service.confirm_if_ready(payout_id=payout.payout_id)
    assert res is None

    # 2. Reader network error -> returns None without exception (fail-open)
    failing_reader = FakeReader(error=ConnectionResetError("EVM node reset"))
    failing_service = PayoutService(pool=db_pool, reader=failing_reader, alert=recorder.alert)
    res_fail = await failing_service.confirm_if_ready(payout_id=payout.payout_id)
    assert res_fail is None

    # 3. Confirmed on-chain -> advances to confirmed
    confirmed_reader = FakeReader(tx_status=TxStatus(confirmed=True, confirmations=10))
    ready_service = PayoutService(pool=db_pool, reader=confirmed_reader, alert=recorder.alert)
    res_ok = await ready_service.confirm_if_ready(payout_id=payout.payout_id)
    assert res_ok is not None
    assert res_ok.status == "confirmed"


# ==============================================================================
# 6. STUCK DETECTION & SWEPPER ALERTS
# ==============================================================================
@pytest.mark.asyncio
async def test_stuck_payout_detection_and_sweeper_alert(db_pool: asyncpg.Pool) -> None:
    """Approved or executed payout backdated 25h triggers stuck alert with age."""
    recorder = AlertRecorder()
    service = PayoutService(pool=db_pool, reader=FakeReader(), alert=recorder.alert)

    # Payout 1: approved and stuck
    p1 = await service.request(
        to_address="0x" + "7" * 40,
        amount_minor=10 * SCALE,
        requested_by_sub="admin_test",
    )
    await service.vote(
        payout_id=p1.payout_id, voter_sub="admin_1", voter_role="admin", vote="approve"
    )
    await service.vote(
        payout_id=p1.payout_id, voter_sub="admin_2", voter_role="admin", vote="approve"
    )

    # Payout 2: executed and stuck
    p2 = await service.request(
        to_address="0x" + "8" * 40,
        amount_minor=20 * SCALE,
        requested_by_sub="admin_test",
    )
    await service.vote(
        payout_id=p2.payout_id, voter_sub="admin_1", voter_role="admin", vote="approve"
    )
    await service.vote(
        payout_id=p2.payout_id, voter_sub="admin_2", voter_role="admin", vote="approve"
    )
    await service.record_execution(
        payout_id=p2.payout_id,
        tx_hash="0x" + "9" * 64,
        recorded_by_sub="admin_1",
    )

    # Backdate updated_at by 25 hours
    backdate = datetime.now(tz=UTC) - timedelta(hours=25)
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE cold_payouts SET updated_at = $1 WHERE payout_id IN ($2, $3);",
            backdate,
            p1.payout_id,
            p2.payout_id,
        )

    # Run sweeper
    sweeper_recorder = AlertRecorder()
    sweeper = PayoutSweeper(
        pool=db_pool,
        reader=FakeReader(),
        alert=sweeper_recorder.alert,
    )
    report = await sweeper.run_once()

    assert report.stuck == 2
    assert len(sweeper_recorder.alerts) == 2
    for alert_msg in sweeper_recorder.alerts:
        assert "payout STUCK" in alert_msg
        assert "age=25." in alert_msg or "age=24." in alert_msg or "age=2" in alert_msg


# ==============================================================================
# 7. SWEEPER E2E CONTRACT & DEAD DSN
# ==============================================================================
@pytest.mark.asyncio
async def test_sweeper_e2e_contract_and_dead_dsn(
    db_pool: asyncpg.Pool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sweeper confirms executed payouts, outputs valid JSON report, and handles dead DSN."""
    reader = FakeReader(tx_status=TxStatus(confirmed=True, confirmations=10))
    recorder = AlertRecorder()
    service = PayoutService(pool=db_pool, reader=reader, alert=recorder.alert)

    # Seed an executed payout
    p = await service.request(to_address="0x" + "a" * 40, amount_minor=15 * SCALE)
    await service.vote(
        payout_id=p.payout_id, voter_sub="admin_1", voter_role="admin", vote="approve"
    )
    await service.vote(
        payout_id=p.payout_id, voter_sub="admin_2", voter_role="admin", vote="approve"
    )
    await service.record_execution(
        payout_id=p.payout_id,
        tx_hash="0x" + "7" * 64,
        recorded_by_sub="admin_1",
    )

    # Test main() with injected pool
    captured_stdout = io.StringIO()
    monkeypatch.setattr(sys, "stdout", captured_stdout)

    exit_code = await main(pool=db_pool, reader=reader, alert=recorder.alert)
    assert exit_code == EXIT_OK

    output = captured_stdout.getvalue().strip()
    report_dict = json.loads(output)
    assert report_dict["mode"] == "treasury_payout_sweep"
    assert report_dict["confirmed"] == 1

    # Verify dead DSN exits 2 with silent stdout
    captured_stdout_dead = io.StringIO()
    captured_stderr_dead = io.StringIO()
    monkeypatch.setattr(sys, "stdout", captured_stdout_dead)
    monkeypatch.setattr(sys, "stderr", captured_stderr_dead)
    monkeypatch.setenv("FLX_PG_DSN", "postgresql://invalid:invalid@localhost:9999/dead")

    # Clear cached settings
    from fluxpay.config import get_settings

    get_settings.cache_clear()

    dead_exit = await main(pool=None, reader=reader)
    assert dead_exit == EXIT_OPS_FAILURE
    assert captured_stdout_dead.getvalue() == ""
    assert "Operational failure" in captured_stderr_dead.getvalue()

    get_settings.cache_clear()


# ==============================================================================
# 8. CUSTODY SNAPSHOT IN-FLIGHT & DRIFT TEST
# ==============================================================================
@pytest.mark.asyncio
async def test_custody_snapshot_in_flight_and_drift(db_pool: asyncpg.Pool) -> None:
    """Custody snapshot reports exact in-flight totals and on-chain reader drift."""
    service = PayoutService(pool=db_pool, reader=FakeReader(), alert=AlertRecorder().alert)

    # Seed 3 in-flight payouts: requested ($10), approved ($20), executed ($30)
    await service.request(to_address="0x" + "1" * 40, amount_minor=10 * SCALE)

    p2 = await service.request(to_address="0x" + "2" * 40, amount_minor=20 * SCALE)
    await service.vote(
        payout_id=p2.payout_id, voter_sub="admin_1", voter_role="admin", vote="approve"
    )
    await service.vote(
        payout_id=p2.payout_id, voter_sub="admin_2", voter_role="admin", vote="approve"
    )

    p3 = await service.request(to_address="0x" + "3" * 40, amount_minor=30 * SCALE)
    await service.vote(
        payout_id=p3.payout_id, voter_sub="admin_1", voter_role="admin", vote="approve"
    )
    await service.vote(
        payout_id=p3.payout_id, voter_sub="admin_2", voter_role="admin", vote="approve"
    )
    await service.record_execution(
        payout_id=p3.payout_id,
        tx_hash="0x" + "8" * 64,
        recorded_by_sub="admin_1",
    )

    # Seed 1 confirmed payout (not in-flight)
    p4 = await service.request(to_address="0x" + "4" * 40, amount_minor=40 * SCALE)
    await service.vote(
        payout_id=p4.payout_id, voter_sub="admin_1", voter_role="admin", vote="approve"
    )
    await service.vote(
        payout_id=p4.payout_id, voter_sub="admin_2", voter_role="admin", vote="approve"
    )
    await service.record_execution(
        payout_id=p4.payout_id,
        tx_hash="0x" + "4" * 64,
        recorded_by_sub="admin_1",
    )
    conf_reader = FakeReader(tx_status=TxStatus(confirmed=True, confirmations=10))
    conf_service = PayoutService(pool=db_pool, reader=conf_reader, alert=AlertRecorder().alert)
    await conf_service.confirm_if_ready(payout_id=p4.payout_id)

    # Set up reader with drift
    # Cached: hot=150, cold=1000
    # Truth: hot=160 (drift +10), cold=990 (drift -10)
    reader = FakeReader(hot=160 * SCALE, cold=990 * SCALE)

    snap = await custody_snapshot(pool=db_pool, reader=reader, rail="base_usdc")

    assert snap.hot_drift == 10 * SCALE
    assert snap.cold_drift == -10 * SCALE
    # In flight sum: 10 + 20 + 30 = 60
    assert snap.in_flight_total == 60 * SCALE
    assert len(snap.oldest_in_flight) == 3


# ==============================================================================
# 9. CLI SUBCOMMAND E2E TESTS
# ==============================================================================
@pytest.mark.asyncio
async def test_cli_subcommands_e2e(db_pool: asyncpg.Pool, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise CLI subcommands via run_cli with --json flags."""
    reader = FakeReader(
        hot=150 * SCALE,
        cold=1000 * SCALE,
        tx_status=TxStatus(confirmed=True, confirmations=5),
    )

    # 1. request via CLI
    cap = io.StringIO()
    monkeypatch.setattr(sys, "stdout", cap)
    to_addr = "0x" + "9" * 40
    code = await run_cli(
        [
            "request",
            "--to-address",
            to_addr,
            "--amount-minor",
            str(25 * SCALE),
            "--json",
        ],
        pool=db_pool,
        reader=reader,
    )
    assert code == EXIT_OK
    req_json = json.loads(cap.getvalue().strip())
    payout_id = req_json["payout_id"]
    assert req_json["amount_minor"] == 25 * SCALE

    # 2. vote via CLI (first vote)
    cap = io.StringIO()
    monkeypatch.setattr(sys, "stdout", cap)
    code = await run_cli(
        [
            "vote",
            "--payout-id",
            payout_id,
            "--voter-sub",
            "admin_1",
            "--vote",
            "approve",
            "--json",
        ],
        pool=db_pool,
        reader=reader,
    )
    assert code == EXIT_OK
    v1_json = json.loads(cap.getvalue().strip())
    assert v1_json["status"] == "pending"

    # 3. vote via CLI (second vote -> approved)
    cap = io.StringIO()
    monkeypatch.setattr(sys, "stdout", cap)
    code = await run_cli(
        [
            "vote",
            "--payout-id",
            payout_id,
            "--voter-sub",
            "admin_2",
            "--vote",
            "approve",
            "--json",
        ],
        pool=db_pool,
        reader=reader,
    )
    assert code == EXIT_OK
    v2_json = json.loads(cap.getvalue().strip())
    assert v2_json["status"] == "approved"

    # 4. record execution via CLI
    tx_hash = "0x" + "3" * 64
    cap = io.StringIO()
    monkeypatch.setattr(sys, "stdout", cap)
    code = await run_cli(
        [
            "record",
            "--payout-id",
            payout_id,
            "--tx-hash",
            tx_hash,
            "--recorded-by-sub",
            "admin_ops",
            "--json",
        ],
        pool=db_pool,
        reader=reader,
    )
    assert code == EXIT_OK
    rec_json = json.loads(cap.getvalue().strip())
    assert rec_json["status"] == "executed"
    assert rec_json["tx_hash"] == tx_hash

    # 5. confirm via CLI
    cap = io.StringIO()
    monkeypatch.setattr(sys, "stdout", cap)
    code = await run_cli(
        [
            "confirm",
            "--payout-id",
            payout_id,
            "--json",
        ],
        pool=db_pool,
        reader=reader,
    )
    assert code == EXIT_OK
    conf_json = json.loads(cap.getvalue().strip())
    assert conf_json["status"] == "confirmed"

    # 6. snapshot via CLI
    cap = io.StringIO()
    monkeypatch.setattr(sys, "stdout", cap)
    code = await run_cli(
        ["snapshot", "--rail", "base_usdc", "--json"],
        pool=db_pool,
        reader=reader,
    )
    assert code == EXIT_OK
    snap_json = json.loads(cap.getvalue().strip())
    assert snap_json["rail"] == "base_usdc"
