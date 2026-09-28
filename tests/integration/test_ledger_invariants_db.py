"""Integration test suite for FluxPay Database Invariants.

Verifies Task 14 double-entry balance trigger (DEFERRABLE INITIALLY DEFERRED)
and append-only guard trigger against live PostgreSQL 17 per Blueprint §5 & §7.
"""

import hashlib
import uuid
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import pytest

pytestmark = pytest.mark.integration

AccountsFactory = Callable[..., Coroutine[Any, Any, list[uuid.UUID]]]


def _fake_hash(seed: str) -> str:
    """Generate a deterministic 64-character lowercase hex SHA-256 hash."""
    return hashlib.sha256(seed.encode("utf-8")).hexdigest().lower()


async def _next_seq_and_prev_hash(conn: asyncpg.Connection) -> tuple[int, str]:
    """Retrieve the next monotonically increasing sequence number and valid prev_hash."""
    row = await conn.fetchrow(
        "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
    )
    if row is None or row["last_seq"] == 0:
        return 1, "GENESIS"
    last_seq: int = row["last_seq"]
    return last_seq + 1, _fake_hash(f"seed-{last_seq}")


async def _insert_entry(
    conn: asyncpg.Connection,
    *,
    seq: int,
    tx_id: uuid.UUID,
    account_id: uuid.UUID,
    direction: str,
    amount: int,
    currency: str,
    balance_after: int,
    version: int,
    prev_hash: str,
    entry_hash: str,
    created_at: datetime,
) -> None:
    """Raw SQL insertion helper exercising database-level constraints standalone."""
    await conn.execute(
        """
        INSERT INTO ledger_entries (
            seq, tx_id, account_id, direction, amount, currency,
            balance_after, version, prev_hash, entry_hash, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
        """,
        seq,
        tx_id,
        account_id,
        direction,
        amount,
        currency,
        balance_after,
        version,
        prev_hash,
        entry_hash,
        created_at,
    )
    # Maintain tip state to preserve seq sequence uniqueness across tests
    await conn.execute(
        """
        UPDATE ledger_chain_tip
        SET last_seq = $1, last_hash = $2
        WHERE singleton = TRUE;
        """,
        seq,
        entry_hash,
    )


# =============================================================================
# 1. BALANCED SINGLE-CURRENCY TRANSACTION COMMITS
# =============================================================================


async def test_balanced_single_currency_commits(
    owner_conn: asyncpg.Connection,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify balanced single-currency tx (1 debit 100 + 1 credit 100) commits cleanly."""
    acc_ids = await ledger_accounts_factory(count=2, initial_balance=50000)
    acc1, acc2 = acc_ids[0], acc_ids[1]

    tx_id = uuid.uuid4()
    now_utc = datetime.now(UTC)

    async with owner_conn.transaction():
        seq1, prev1 = await _next_seq_and_prev_hash(owner_conn)
        h1 = _fake_hash("sc-tx-1")
        await _insert_entry(
            owner_conn,
            seq=seq1,
            tx_id=tx_id,
            account_id=acc1,
            direction="DEBIT",
            amount=100,
            currency="USDC",
            balance_after=49900,
            version=1,
            prev_hash=prev1,
            entry_hash=h1,
            created_at=now_utc,
        )

        seq2, _ = await _next_seq_and_prev_hash(owner_conn)
        h2 = _fake_hash("sc-tx-2")
        await _insert_entry(
            owner_conn,
            seq=seq2,
            tx_id=tx_id,
            account_id=acc2,
            direction="CREDIT",
            amount=100,
            currency="USDC",
            balance_after=50100,
            version=1,
            prev_hash=h1,
            entry_hash=h2,
            created_at=now_utc,
        )

    # After transaction commits, both rows are visible in the database
    rows = await owner_conn.fetch(
        "SELECT seq, direction, amount FROM ledger_entries WHERE tx_id = $1 ORDER BY seq ASC;",
        tx_id,
    )
    assert len(rows) == 2
    assert rows[0]["direction"] == "DEBIT" and rows[0]["amount"] == 100
    assert rows[1]["direction"] == "CREDIT" and rows[1]["amount"] == 100


# =============================================================================
# 2. UNBALANCED SINGLE-CURRENCY TRANSACTION REJECTION AT COMMIT
# =============================================================================


async def test_unbalanced_single_currency_rejection(
    owner_conn: asyncpg.Connection,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify unbalanced tx (debit 100, credit 99) fails at commit and persists nothing."""
    acc_ids = await ledger_accounts_factory(count=2, initial_balance=50000)
    acc1, acc2 = acc_ids[0], acc_ids[1]

    tx_id = uuid.uuid4()
    now_utc = datetime.now(UTC)

    with pytest.raises((asyncpg.CheckViolationError, asyncpg.PostgresError)) as exc_info:
        async with owner_conn.transaction():
            seq1, prev1 = await _next_seq_and_prev_hash(owner_conn)
            h1 = _fake_hash("unbal-1")
            await _insert_entry(
                owner_conn,
                seq=seq1,
                tx_id=tx_id,
                account_id=acc1,
                direction="DEBIT",
                amount=100,
                currency="USDC",
                balance_after=49900,
                version=1,
                prev_hash=prev1,
                entry_hash=h1,
                created_at=now_utc,
            )

            seq2, _ = await _next_seq_and_prev_hash(owner_conn)
            h2 = _fake_hash("unbal-2")
            # Intentionally unbalanced: credit 99 != debit 100
            await _insert_entry(
                owner_conn,
                seq=seq2,
                tx_id=tx_id,
                account_id=acc2,
                direction="CREDIT",
                amount=99,
                currency="USDC",
                balance_after=50099,
                version=1,
                prev_hash=h1,
                entry_hash=h2,
                created_at=now_utc,
            )

    # Invariant verified: check_violation raised on commit and 0 rows persisted
    assert exc_info.value.sqlstate == "23514"
    assert "unbalanced transaction" in str(exc_info.value)
    count = await owner_conn.fetchval(
        "SELECT count(*) FROM ledger_entries WHERE tx_id = $1;", tx_id
    )
    assert count == 0


# =============================================================================
# 3. BALANCED MULTI-ENTRY TRANSACTION (1 DEBIT, 2 CREDITS)
# =============================================================================


async def test_balanced_multi_entry_commits(
    owner_conn: asyncpg.Connection,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify balanced multi-entry tx (1 debit 100; credits 60 + 40) commits cleanly."""
    acc_ids = await ledger_accounts_factory(count=3, initial_balance=50000)
    src, dest1, dest2 = acc_ids[0], acc_ids[1], acc_ids[2]

    tx_id = uuid.uuid4()
    now_utc = datetime.now(UTC)

    async with owner_conn.transaction():
        s1, p1 = await _next_seq_and_prev_hash(owner_conn)
        h1 = _fake_hash("multi-bal-1")
        await _insert_entry(
            owner_conn,
            seq=s1,
            tx_id=tx_id,
            account_id=src,
            direction="DEBIT",
            amount=100,
            currency="USDC",
            balance_after=49900,
            version=1,
            prev_hash=p1,
            entry_hash=h1,
            created_at=now_utc,
        )

        s2, _ = await _next_seq_and_prev_hash(owner_conn)
        h2 = _fake_hash("multi-bal-2")
        await _insert_entry(
            owner_conn,
            seq=s2,
            tx_id=tx_id,
            account_id=dest1,
            direction="CREDIT",
            amount=60,
            currency="USDC",
            balance_after=50060,
            version=1,
            prev_hash=h1,
            entry_hash=h2,
            created_at=now_utc,
        )

        s3, _ = await _next_seq_and_prev_hash(owner_conn)
        h3 = _fake_hash("multi-bal-3")
        await _insert_entry(
            owner_conn,
            seq=s3,
            tx_id=tx_id,
            account_id=dest2,
            direction="CREDIT",
            amount=40,
            currency="USDC",
            balance_after=50040,
            version=1,
            prev_hash=h2,
            entry_hash=h3,
            created_at=now_utc,
        )

    count = await owner_conn.fetchval(
        "SELECT count(*) FROM ledger_entries WHERE tx_id = $1;", tx_id
    )
    assert count == 3


# =============================================================================
# 4. UNBALANCED MULTI-ENTRY TRANSACTION (1 DEBIT, 2 CREDITS)
# =============================================================================


async def test_unbalanced_multi_entry_rejection(
    owner_conn: asyncpg.Connection,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify unbalanced multi-entry tx (1 debit 100; credits 60 + 39) fails at commit."""
    acc_ids = await ledger_accounts_factory(count=3, initial_balance=50000)
    src, dest1, dest2 = acc_ids[0], acc_ids[1], acc_ids[2]

    tx_id = uuid.uuid4()
    now_utc = datetime.now(UTC)

    with pytest.raises((asyncpg.CheckViolationError, asyncpg.PostgresError)) as exc_info:
        async with owner_conn.transaction():
            s1, p1 = await _next_seq_and_prev_hash(owner_conn)
            h1 = _fake_hash("multi-unbal-1")
            await _insert_entry(
                owner_conn,
                seq=s1,
                tx_id=tx_id,
                account_id=src,
                direction="DEBIT",
                amount=100,
                currency="USDC",
                balance_after=49900,
                version=1,
                prev_hash=p1,
                entry_hash=h1,
                created_at=now_utc,
            )

            s2, _ = await _next_seq_and_prev_hash(owner_conn)
            h2 = _fake_hash("multi-unbal-2")
            await _insert_entry(
                owner_conn,
                seq=s2,
                tx_id=tx_id,
                account_id=dest1,
                direction="CREDIT",
                amount=60,
                currency="USDC",
                balance_after=50060,
                version=1,
                prev_hash=h1,
                entry_hash=h2,
                created_at=now_utc,
            )

            s3, _ = await _next_seq_and_prev_hash(owner_conn)
            h3 = _fake_hash("multi-unbal-3")
            # Unbalanced: 60 + 39 = 99 != 100
            await _insert_entry(
                owner_conn,
                seq=s3,
                tx_id=tx_id,
                account_id=dest2,
                direction="CREDIT",
                amount=39,
                currency="USDC",
                balance_after=50039,
                version=1,
                prev_hash=h2,
                entry_hash=h3,
                created_at=now_utc,
            )

    assert exc_info.value.sqlstate == "23514"
    assert "unbalanced transaction" in str(exc_info.value)
    count = await owner_conn.fetchval(
        "SELECT count(*) FROM ledger_entries WHERE tx_id = $1;", tx_id
    )
    assert count == 0


# =============================================================================
# 5. PER-CURRENCY ISOLATION
# =============================================================================


async def test_per_currency_isolation(
    owner_conn: asyncpg.Connection,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify multi-currency transaction balances in each currency independently."""
    usdc_accs = await ledger_accounts_factory(count=2, currency="USDC", initial_balance=50000)
    eth_accs = await ledger_accounts_factory(count=2, currency="ETH", initial_balance=50000)

    now_utc = datetime.now(UTC)

    # 1. Balanced multi-currency tx (USDC 100==100, ETH 50==50) commits
    tx_ok = uuid.uuid4()
    async with owner_conn.transaction():
        # USDC Leg
        s1, p1 = await _next_seq_and_prev_hash(owner_conn)
        h1 = _fake_hash("curr-1")
        await _insert_entry(
            owner_conn,
            seq=s1,
            tx_id=tx_ok,
            account_id=usdc_accs[0],
            direction="DEBIT",
            amount=100,
            currency="USDC",
            balance_after=49900,
            version=1,
            prev_hash=p1,
            entry_hash=h1,
            created_at=now_utc,
        )

        s2, _ = await _next_seq_and_prev_hash(owner_conn)
        h2 = _fake_hash("curr-2")
        await _insert_entry(
            owner_conn,
            seq=s2,
            tx_id=tx_ok,
            account_id=usdc_accs[1],
            direction="CREDIT",
            amount=100,
            currency="USDC",
            balance_after=50100,
            version=1,
            prev_hash=h1,
            entry_hash=h2,
            created_at=now_utc,
        )

        # ETH Leg
        s3, _ = await _next_seq_and_prev_hash(owner_conn)
        h3 = _fake_hash("curr-3")
        await _insert_entry(
            owner_conn,
            seq=s3,
            tx_id=tx_ok,
            account_id=eth_accs[0],
            direction="DEBIT",
            amount=50,
            currency="ETH",
            balance_after=49950,
            version=1,
            prev_hash=h2,
            entry_hash=h3,
            created_at=now_utc,
        )

        s4, _ = await _next_seq_and_prev_hash(owner_conn)
        h4 = _fake_hash("curr-4")
        await _insert_entry(
            owner_conn,
            seq=s4,
            tx_id=tx_ok,
            account_id=eth_accs[1],
            direction="CREDIT",
            amount=50,
            currency="ETH",
            balance_after=50050,
            version=1,
            prev_hash=h3,
            entry_hash=h4,
            created_at=now_utc,
        )

    count_ok = await owner_conn.fetchval(
        "SELECT count(*) FROM ledger_entries WHERE tx_id = $1;", tx_ok
    )
    assert count_ok == 4

    # 2. Mixed: USDC balanced (100 vs 100), but ETH unbalanced (50 vs 49)
    tx_bad = uuid.uuid4()
    with pytest.raises((asyncpg.CheckViolationError, asyncpg.PostgresError)) as exc_info:
        async with owner_conn.transaction():
            # USDC balanced
            s1, p1 = await _next_seq_and_prev_hash(owner_conn)
            h1 = _fake_hash("curr-bad-1")
            await _insert_entry(
                owner_conn,
                seq=s1,
                tx_id=tx_bad,
                account_id=usdc_accs[0],
                direction="DEBIT",
                amount=100,
                currency="USDC",
                balance_after=49900,
                version=1,
                prev_hash=p1,
                entry_hash=h1,
                created_at=now_utc,
            )

            s2, _ = await _next_seq_and_prev_hash(owner_conn)
            h2 = _fake_hash("curr-bad-2")
            await _insert_entry(
                owner_conn,
                seq=s2,
                tx_id=tx_bad,
                account_id=usdc_accs[1],
                direction="CREDIT",
                amount=100,
                currency="USDC",
                balance_after=50100,
                version=1,
                prev_hash=h1,
                entry_hash=h2,
                created_at=now_utc,
            )

            # ETH unbalanced: debit 50, credit 49
            s3, _ = await _next_seq_and_prev_hash(owner_conn)
            h3 = _fake_hash("curr-bad-3")
            await _insert_entry(
                owner_conn,
                seq=s3,
                tx_id=tx_bad,
                account_id=eth_accs[0],
                direction="DEBIT",
                amount=50,
                currency="ETH",
                balance_after=49950,
                version=1,
                prev_hash=h2,
                entry_hash=h3,
                created_at=now_utc,
            )

            s4, _ = await _next_seq_and_prev_hash(owner_conn)
            h4 = _fake_hash("curr-bad-4")
            await _insert_entry(
                owner_conn,
                seq=s4,
                tx_id=tx_bad,
                account_id=eth_accs[1],
                direction="CREDIT",
                amount=49,
                currency="ETH",
                balance_after=50049,
                version=1,
                prev_hash=h3,
                entry_hash=h4,
                created_at=now_utc,
            )

    assert exc_info.value.sqlstate == "23514"
    # Exception text explicitly identifies ETH as the failing currency
    assert "currency ETH" in str(exc_info.value)


# =============================================================================
# 6. DEFERRED TIMING PROOF (Both halves asserted)
# =============================================================================


async def test_deferred_timing_proof(
    owner_conn: asyncpg.Connection,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify deferred timing: row visible inside tx before commit, commit raises."""
    acc_ids = await ledger_accounts_factory(count=1, initial_balance=50000)
    acc = acc_ids[0]

    tx_id = uuid.uuid4()
    now_utc = datetime.now(UTC)

    with pytest.raises((asyncpg.CheckViolationError, asyncpg.PostgresError)) as exc_info:
        async with owner_conn.transaction():
            s1, p1 = await _next_seq_and_prev_hash(owner_conn)
            h1 = _fake_hash("defer-time-1")
            # 1. Insertion succeeds without immediate trigger error
            await _insert_entry(
                owner_conn,
                seq=s1,
                tx_id=tx_id,
                account_id=acc,
                direction="DEBIT",
                amount=100,
                currency="USDC",
                balance_after=49900,
                version=1,
                prev_hash=p1,
                entry_hash=h1,
                created_at=now_utc,
            )

            # Half 1 proven: row is visible inside the uncommitted transaction block
            mid_count = await owner_conn.fetchval(
                "SELECT count(*) FROM ledger_entries WHERE tx_id = $1;", tx_id
            )
            assert mid_count == 1

            # Exiting block triggers COMMIT -> Half 2: deferred trigger fires and fails

    assert exc_info.value.sqlstate == "23514"
    assert "unbalanced transaction" in str(exc_info.value)

    # Post-rollback: nothing persisted
    final_count = await owner_conn.fetchval(
        "SELECT count(*) FROM ledger_entries WHERE tx_id = $1;", tx_id
    )
    assert final_count == 0


# =============================================================================
# 7. GUARD TRIGGER: IMMUTABILITY FOR OWNER ON UPDATE AND DELETE
# =============================================================================


async def test_guard_trigger_prevents_mutation_as_owner(
    owner_conn: asyncpg.Connection,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify append-only guard raises restrict_violation on UPDATE/DELETE even for OWNER."""
    acc_ids = await ledger_accounts_factory(count=2, initial_balance=50000)
    acc1, acc2 = acc_ids[0], acc_ids[1]

    tx_id = uuid.uuid4()
    now_utc = datetime.now(UTC)

    # Commit honest balanced entries first
    async with owner_conn.transaction():
        s1, p1 = await _next_seq_and_prev_hash(owner_conn)
        h1 = _fake_hash("guard-test-1")
        await _insert_entry(
            owner_conn,
            seq=s1,
            tx_id=tx_id,
            account_id=acc1,
            direction="DEBIT",
            amount=100,
            currency="USDC",
            balance_after=49900,
            version=1,
            prev_hash=p1,
            entry_hash=h1,
            created_at=now_utc,
        )

        s2, _ = await _next_seq_and_prev_hash(owner_conn)
        h2 = _fake_hash("guard-test-2")
        await _insert_entry(
            owner_conn,
            seq=s2,
            tx_id=tx_id,
            account_id=acc2,
            direction="CREDIT",
            amount=100,
            currency="USDC",
            balance_after=50100,
            version=1,
            prev_hash=h1,
            entry_hash=h2,
            created_at=now_utc,
        )

    # 1. UPDATE raises restrict_violation with 'append-only' message
    with pytest.raises((asyncpg.RestrictViolationError, asyncpg.PostgresError)) as exc_update:
        await owner_conn.execute("UPDATE ledger_entries SET amount = 999 WHERE tx_id = $1;", tx_id)
    assert exc_update.value.sqlstate == "23001"
    assert "append-only" in str(exc_update.value).lower()

    # 2. DELETE raises restrict_violation with 'append-only' message
    with pytest.raises((asyncpg.RestrictViolationError, asyncpg.PostgresError)) as exc_delete:
        await owner_conn.execute("DELETE FROM ledger_entries WHERE tx_id = $1;", tx_id)
    assert exc_delete.value.sqlstate == "23001"
    assert "append-only" in str(exc_delete.value).lower()


# =============================================================================
# 8. PARTITION INHERITANCE: CLONED TRIGGERS IN NEWLY CREATED PARTITION
# =============================================================================


async def test_partition_inheritance_clone_proof(
    owner_conn: asyncpg.Connection,
    ledger_accounts_factory: AccountsFactory,
    db_pool: asyncpg.Pool,
) -> None:
    """Verify triggers are automatically cloned into a newly created future partition."""
    acc_ids = await ledger_accounts_factory(count=2, initial_balance=50000)
    acc1, acc2 = acc_ids[0], acc_ids[1]

    # Dynamically create partition for 5 months ahead
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT (date_trunc('month', now()) + INTERVAL '5 months')::DATE AS future_month;
        """)
        future_month = row["future_month"]
        await conn.execute("SELECT create_month_partition($1);", future_month)

    future_ts = datetime(future_month.year, future_month.month, 10, 12, 0, 0, tzinfo=UTC)
    partition_name = f"ledger_entries_{future_month.strftime('%Y_%m')}"

    try:
        # 1. Balanced insert into future partition succeeds
        tx_ok = uuid.uuid4()
        async with owner_conn.transaction():
            s1, p1 = await _next_seq_and_prev_hash(owner_conn)
            h1 = _fake_hash("fut-clone-1")
            await _insert_entry(
                owner_conn,
                seq=s1,
                tx_id=tx_ok,
                account_id=acc1,
                direction="DEBIT",
                amount=500,
                currency="USDC",
                balance_after=49500,
                version=1,
                prev_hash=p1,
                entry_hash=h1,
                created_at=future_ts,
            )

            s2, _ = await _next_seq_and_prev_hash(owner_conn)
            h2 = _fake_hash("fut-clone-2")
            await _insert_entry(
                owner_conn,
                seq=s2,
                tx_id=tx_ok,
                account_id=acc2,
                direction="CREDIT",
                amount=500,
                currency="USDC",
                balance_after=50500,
                version=1,
                prev_hash=h1,
                entry_hash=h2,
                created_at=future_ts,
            )

        # 2. Cloned guard trigger prevents UPDATE on future partition row
        with pytest.raises((asyncpg.RestrictViolationError, asyncpg.PostgresError)) as exc_upd:
            update_query = f"UPDATE {partition_name} SET amount = 999 WHERE tx_id = $1;"  # noqa: S608
            await owner_conn.execute(update_query, tx_ok)
        assert exc_upd.value.sqlstate == "23001"
        assert "append-only" in str(exc_upd.value).lower()

        # 3. Cloned balance trigger prevents unbalanced transaction on future partition
        tx_bad = uuid.uuid4()
        with pytest.raises((asyncpg.CheckViolationError, asyncpg.PostgresError)) as exc_unbal:
            async with owner_conn.transaction():
                s3, p3 = await _next_seq_and_prev_hash(owner_conn)
                h3 = _fake_hash("fut-clone-3")
                await _insert_entry(
                    owner_conn,
                    seq=s3,
                    tx_id=tx_bad,
                    account_id=acc1,
                    direction="DEBIT",
                    amount=500,
                    currency="USDC",
                    balance_after=49000,
                    version=1,
                    prev_hash=p3,
                    entry_hash=h3,
                    created_at=future_ts,
                )

                s4, _ = await _next_seq_and_prev_hash(owner_conn)
                h4 = _fake_hash("fut-clone-4")
                # Unbalanced: 499 != 500
                await _insert_entry(
                    owner_conn,
                    seq=s4,
                    tx_id=tx_bad,
                    account_id=acc2,
                    direction="CREDIT",
                    amount=499,
                    currency="USDC",
                    balance_after=50999,
                    version=1,
                    prev_hash=h3,
                    entry_hash=h4,
                    created_at=future_ts,
                )
        assert exc_unbal.value.sqlstate == "23514"
        assert "unbalanced transaction" in str(exc_unbal.value)

    finally:
        # Teardown drops test partition
        async with db_pool.acquire() as conn:
            await conn.execute(f"DROP TABLE IF EXISTS {partition_name};")


# =============================================================================
# 9. TRIGGER SURVIVAL ACROSS IDEMPOTENT RE-RUN
# =============================================================================


async def test_migration_idempotent_rerun(
    owner_conn: asyncpg.Connection,
    invariants_migration_sql: str,
) -> None:
    """Verify 0003_ledger_invariants.sql executes twice idempotently without error."""
    await owner_conn.execute(invariants_migration_sql)
    await owner_conn.execute(invariants_migration_sql)


# =============================================================================
# 10. NAMED-CONSTRAINT TRIAGE CONTRACT (3AM readability)
# =============================================================================


async def test_named_constraint_triage_contract(
    owner_conn: asyncpg.Connection,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify exception text explicitly includes tx_id, currency, debit, and credit sums."""
    acc_ids = await ledger_accounts_factory(count=2, initial_balance=50000)
    acc1, acc2 = acc_ids[0], acc_ids[1]

    tx_id = uuid.uuid4()
    now_utc = datetime.now(UTC)

    with pytest.raises((asyncpg.CheckViolationError, asyncpg.PostgresError)) as exc_info:
        async with owner_conn.transaction():
            s1, p1 = await _next_seq_and_prev_hash(owner_conn)
            h1 = _fake_hash("triage-1")
            await _insert_entry(
                owner_conn,
                seq=s1,
                tx_id=tx_id,
                account_id=acc1,
                direction="DEBIT",
                amount=750,
                currency="USDC",
                balance_after=49250,
                version=1,
                prev_hash=p1,
                entry_hash=h1,
                created_at=now_utc,
            )

            s2, _ = await _next_seq_and_prev_hash(owner_conn)
            h2 = _fake_hash("triage-2")
            await _insert_entry(
                owner_conn,
                seq=s2,
                tx_id=tx_id,
                account_id=acc2,
                direction="CREDIT",
                amount=700,
                currency="USDC",
                balance_after=50700,
                version=1,
                prev_hash=h1,
                entry_hash=h2,
                created_at=now_utc,
            )

    msg = str(exc_info.value)
    # 3AM contract: triage reads error directly without querying schema or code
    assert str(tx_id) in msg
    assert "currency USDC" in msg
    assert "debit=750" in msg
    assert "credit=700" in msg
