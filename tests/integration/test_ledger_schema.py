"""Integration test suite for FluxPay Partitioned Append-Only Ledger Schema.

Verifies Task 13 laws (L1-L6), database-level CHECK guards, partition pruning/fail-loud,
and append-only role permissions against a live PostgreSQL 17 database.
"""

import hashlib
import uuid
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import pytest

pytestmark = pytest.mark.integration

AccountsFactory = Callable[..., Coroutine[Any, Any, list[uuid.UUID]]]


def _fake_hash(seed: str) -> str:
    """Generate a deterministic 64-character lowercase hex SHA-256 hash."""
    return hashlib.sha256(seed.encode("utf-8")).hexdigest().lower()


# =============================================================================
# 1. TIP BOOTSTRAP
# =============================================================================


async def test_tip_bootstrap(
    db_pool: asyncpg.Pool,
    apply_ledger_schema: None,
) -> None:
    """Verify ledger_chain_tip singleton row exists with initial state."""
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT singleton, last_seq, last_hash FROM ledger_chain_tip;")
        assert row is not None
        assert row["singleton"] is True
        assert row["last_seq"] == 0
        assert row["last_hash"] == "GENESIS"


# =============================================================================
# 2. PARTITION AUTOMATION & IDEMPOTENCY
# =============================================================================


async def test_create_month_partition_idempotent(
    db_pool: asyncpg.Pool,
    apply_ledger_schema: None,
) -> None:
    """Verify create_month_partition is idempotent and 3-month runway exists."""
    async with db_pool.acquire() as conn:
        # Calling create_month_partition for current month twice must not error
        await conn.execute("SELECT create_month_partition(date_trunc('month', now())::DATE);")
        await conn.execute("SELECT create_month_partition(date_trunc('month', now())::DATE);")

        # Verify current and next 2 month partitions exist in pg_class
        rows = await conn.fetch("""
            SELECT relname
            FROM pg_class
            WHERE relname LIKE 'ledger_entries_%'
              AND relkind = 'r'
            ORDER BY relname;
        """)
        partition_names = [r["relname"] for r in rows]
        assert len(partition_names) >= 3


# =============================================================================
# 3. HAPPY PATH: CHAINED ENTRIES INSERT & SELECT
# =============================================================================


async def test_happy_path_chained_entries(
    db_pool: asyncpg.Pool,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify standard happy-path insert of two chained entries."""
    acc_ids = await ledger_accounts_factory(count=2, initial_balance=50000)
    acc1, acc2 = acc_ids[0], acc_ids[1]

    tx1 = uuid.uuid4()
    tx2 = uuid.uuid4()
    h1 = _fake_hash("entry-1")
    h2 = _fake_hash("entry-2")
    now_utc = datetime.now(UTC)

    async with db_pool.acquire() as conn:
        # Entry 1: seq=1, prev_hash='GENESIS'
        await conn.execute(
            """
            INSERT INTO ledger_entries (
                seq, tx_id, account_id, direction, amount, currency,
                balance_after, version, prev_hash, entry_hash, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
            """,
            1,
            tx1,
            acc1,
            "DEBIT",
            1000,
            "USDC",
            49000,
            1,
            "GENESIS",
            h1,
            now_utc,
        )

        # Entry 2: seq=2, prev_hash=h1
        await conn.execute(
            """
            INSERT INTO ledger_entries (
                seq, tx_id, account_id, direction, amount, currency,
                balance_after, version, prev_hash, entry_hash, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
            """,
            2,
            tx2,
            acc2,
            "CREDIT",
            1000,
            "USDC",
            51000,
            1,
            h1,
            h2,
            now_utc,
        )

        # Query back and verify field roundtrip fidelity
        rows = await conn.fetch(
            "SELECT * FROM ledger_entries WHERE tx_id IN ($1, $2) ORDER BY seq ASC;",
            tx1,
            tx2,
        )
        assert len(rows) == 2
        r1, r2 = rows[0], rows[1]

        assert r1["seq"] == 1
        assert r1["tx_id"] == tx1
        assert r1["account_id"] == acc1
        assert r1["direction"] == "DEBIT"
        assert r1["amount"] == 1000
        assert r1["currency"] == "USDC"
        assert r1["balance_after"] == 49000
        assert r1["version"] == 1
        assert r1["prev_hash"] == "GENESIS"
        assert r1["entry_hash"] == h1

        assert r2["seq"] == 2
        assert r2["tx_id"] == tx2
        assert r2["account_id"] == acc2
        assert r2["direction"] == "CREDIT"
        assert r2["amount"] == 1000
        assert r2["currency"] == "USDC"
        assert r2["balance_after"] == 51000
        assert r2["version"] == 1
        assert r2["prev_hash"] == h1
        assert r2["entry_hash"] == h2


# =============================================================================
# 4. GUARD TABLE (CheckViolationError on invalid fields)
# =============================================================================


@pytest.mark.parametrize(
    (
        "seq",
        "amount",
        "balance_after",
        "version",
        "direction",
        "currency",
        "prev_hash",
        "entry_hash",
    ),
    [
        (2, 0, 1000, 1, "DEBIT", "USDC", "a" * 64, "b" * 64),  # amount=0
        (2, -5, 1000, 1, "DEBIT", "USDC", "a" * 64, "b" * 64),  # amount=-5
        (2, 100, -1, 1, "DEBIT", "USDC", "a" * 64, "b" * 64),  # balance_after=-1
        (2, 100, 1000, 0, "DEBIT", "USDC", "a" * 64, "b" * 64),  # version=0
        (2, 100, 1000, 1, "debit", "USDC", "a" * 64, "b" * 64),  # direction lowercase
        (2, 100, 1000, 1, "DEBIT", "usdc", "a" * 64, "b" * 64),  # currency lowercase
        (2, 100, 1000, 1, "DEBIT", "A" * 11, "a" * 64, "b" * 64),  # currency 11 chars
        (2, 100, 1000, 1, "DEBIT", "USDC", "a" * 64, "b" * 63),  # entry_hash 63 chars
        (2, 100, 1000, 1, "DEBIT", "USDC", "invalid_prev", "b" * 64),  # prev_hash bad
        (0, 100, 1000, 1, "DEBIT", "USDC", "a" * 64, "b" * 64),  # seq=0
    ],
)
async def test_guard_table_check_violations(
    db_pool: asyncpg.Pool,
    ledger_accounts_factory: AccountsFactory,
    seq: int,
    amount: int,
    balance_after: int,
    version: int,
    direction: str,
    currency: str,
    prev_hash: str,
    entry_hash: str,
) -> None:
    """Verify table CHECK constraints strictly mirror Task 12 validation guards."""
    acc_ids = await ledger_accounts_factory(count=1)
    acc_id = acc_ids[0]
    now_utc = datetime.now(UTC)

    async with db_pool.acquire() as conn:
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                """
                INSERT INTO ledger_entries (
                    seq, tx_id, account_id, direction, amount, currency,
                    balance_after, version, prev_hash, entry_hash, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
                """,
                seq,
                uuid.uuid4(),
                acc_id,
                direction,
                amount,
                currency,
                balance_after,
                version,
                prev_hash,
                entry_hash,
                now_utc,
            )


# =============================================================================
# 5. GENESIS CROSS-FIELD GUARD (L4 bidirectional check)
# =============================================================================


async def test_genesis_cross_field_guard(
    db_pool: asyncpg.Pool,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify CHECK ((seq = 1) = (prev_hash = 'GENESIS')) holds in both directions."""
    acc_ids = await ledger_accounts_factory(count=1)
    acc_id = acc_ids[0]
    now_utc = datetime.now(UTC)
    hex_hash = _fake_hash("test-hash")

    async with db_pool.acquire() as conn:
        # Direction 1 violation: seq=2 with prev_hash='GENESIS' -> rejected
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                """
                INSERT INTO ledger_entries (
                    seq, tx_id, account_id, direction, amount, currency,
                    balance_after, version, prev_hash, entry_hash, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
                """,
                2,
                uuid.uuid4(),
                acc_id,
                "CREDIT",
                500,
                "USDC",
                500,
                1,
                "GENESIS",
                hex_hash,
                now_utc,
            )

        # Direction 2 violation: seq=1 with hex prev_hash -> rejected
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                """
                INSERT INTO ledger_entries (
                    seq, tx_id, account_id, direction, amount, currency,
                    balance_after, version, prev_hash, entry_hash, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
                """,
                1,
                uuid.uuid4(),
                acc_id,
                "CREDIT",
                500,
                "USDC",
                500,
                1,
                _fake_hash("not-genesis"),
                hex_hash,
                now_utc,
            )

        # Honest genesis: seq=1 and prev_hash='GENESIS' -> succeeds
        await conn.execute(
            """
            INSERT INTO ledger_entries (
                seq, tx_id, account_id, direction, amount, currency,
                balance_after, version, prev_hash, entry_hash, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
            """,
            1,
            uuid.uuid4(),
            acc_id,
            "CREDIT",
            500,
            "USDC",
            500,
            1,
            "GENESIS",
            hex_hash,
            now_utc,
        )


# =============================================================================
# 6. FOREIGN KEY & ACCOUNT CONSTRAINTS
# =============================================================================


async def test_foreign_key_violation(
    db_pool: asyncpg.Pool,
    apply_ledger_schema: None,
) -> None:
    """Verify inserting an entry referencing non-existent account raises error."""
    now_utc = datetime.now(UTC)
    random_account_id = uuid.uuid4()

    async with db_pool.acquire() as conn:
        with pytest.raises(asyncpg.ForeignKeyViolationError):
            await conn.execute(
                """
                INSERT INTO ledger_entries (
                    seq, tx_id, account_id, direction, amount, currency,
                    balance_after, version, prev_hash, entry_hash, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
                """,
                1,
                uuid.uuid4(),
                random_account_id,
                "CREDIT",
                100,
                "USDC",
                100,
                1,
                "GENESIS",
                _fake_hash("fk-test"),
                now_utc,
            )


async def test_accounts_constraints(
    db_pool: asyncpg.Pool,
    apply_ledger_schema: None,
) -> None:
    """Verify ledger_accounts balance check and unique constraint."""
    owner_id = uuid.uuid4()
    acc_id = uuid.uuid4()

    async with db_pool.acquire() as conn:
        # Negative balance rejected
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                """
                INSERT INTO ledger_accounts (id, owner_type, owner_id, currency, balance, version)
                VALUES ($1, 'agent', $2, 'USDC', -1, 0);
                """,
                acc_id,
                owner_id,
            )

        # Honest account insert
        await conn.execute(
            """
            INSERT INTO ledger_accounts (id, owner_type, owner_id, currency, balance, version)
            VALUES ($1, 'agent', $2, 'USDC', 1000, 0);
            """,
            acc_id,
            owner_id,
        )

        # Duplicate (owner_type, owner_id, currency) rejected
        with pytest.raises(asyncpg.UniqueViolationError):
            await conn.execute(
                """
                INSERT INTO ledger_accounts (id, owner_type, owner_id, currency, balance, version)
                VALUES ($1, 'agent', $2, 'USDC', 2000, 0);
                """,
                uuid.uuid4(),
                owner_id,
            )

        # Cleanup
        await conn.execute("DELETE FROM ledger_accounts WHERE id = $1;", acc_id)


# =============================================================================
# 7. MISSING PARTITION FAIL-LOUD & SAME-PARTITION PK
# =============================================================================


async def test_missing_partition_fail_loud(
    db_pool: asyncpg.Pool,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify missing partition fails loud rather than silently absorbing stray timestamps."""
    acc_ids = await ledger_accounts_factory(count=1)
    acc_id = acc_ids[0]

    # Timestamp 400 days in the future (well beyond the 3-month partition runway)
    future_utc = datetime.now(UTC) + timedelta(days=400)

    async with db_pool.acquire() as conn:
        with pytest.raises(asyncpg.PostgresError) as exc_info:
            await conn.execute(
                """
                INSERT INTO ledger_entries (
                    seq, tx_id, account_id, direction, amount, currency,
                    balance_after, version, prev_hash, entry_hash, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
                """,
                1,
                uuid.uuid4(),
                acc_id,
                "CREDIT",
                100,
                "USDC",
                100,
                1,
                "GENESIS",
                _fake_hash("future-test"),
                future_utc,
            )
        assert "partition" in str(exc_info.value).lower()


async def test_same_partition_seq_pk_unique_violation(
    db_pool: asyncpg.Pool,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify PRIMARY KEY (seq, created_at) prevents duplicate seq within same month partition."""
    acc_ids = await ledger_accounts_factory(count=1)
    acc_id = acc_ids[0]
    now_utc = datetime.now(UTC)

    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO ledger_entries (
                seq, tx_id, account_id, direction, amount, currency,
                balance_after, version, prev_hash, entry_hash, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
            """,
            10,
            uuid.uuid4(),
            acc_id,
            "CREDIT",
            100,
            "USDC",
            100,
            1,
            "a" * 64,
            _fake_hash("pk-test-1"),
            now_utc,
        )

        with pytest.raises(asyncpg.UniqueViolationError):
            await conn.execute(
                """
                INSERT INTO ledger_entries (
                    seq, tx_id, account_id, direction, amount, currency,
                    balance_after, version, prev_hash, entry_hash, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
                """,
                10,
                uuid.uuid4(),
                acc_id,
                "CREDIT",
                200,
                "USDC",
                300,
                1,
                "a" * 64,
                _fake_hash("pk-test-2"),
                now_utc,
            )


# =============================================================================
# 8. GRANTS PATTERN (Restricted App Role: INSERT+SELECT, No Mutation/Truncate)
# =============================================================================


async def test_grants_pattern_restricted_conn(
    db_pool: asyncpg.Pool,
    restricted_conn: asyncpg.Connection,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify restricted app role can INSERT and SELECT, but cannot UPDATE, DELETE, or TRUNCATE."""
    acc_ids = await ledger_accounts_factory(count=1)
    acc_id = acc_ids[0]
    now_utc = datetime.now(UTC)

    # 1. INSERT valid entry succeeds under restricted role
    entry_tx = uuid.uuid4()
    await restricted_conn.execute(
        """
        INSERT INTO ledger_entries (
            seq, tx_id, account_id, direction, amount, currency,
            balance_after, version, prev_hash, entry_hash, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
        """,
        1,
        entry_tx,
        acc_id,
        "CREDIT",
        500,
        "USDC",
        500,
        1,
        "GENESIS",
        _fake_hash("grant-test"),
        now_utc,
    )

    # 2. SELECT succeeds under restricted role
    rows = await restricted_conn.fetch("SELECT * FROM ledger_entries WHERE tx_id = $1;", entry_tx)
    assert len(rows) == 1
    assert rows[0]["seq"] == 1

    # 3. UPDATE fails with InsufficientPrivilegeError
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await restricted_conn.execute(
            "UPDATE ledger_entries SET amount = 999 WHERE tx_id = $1;", entry_tx
        )

    # 4. DELETE fails with InsufficientPrivilegeError
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await restricted_conn.execute("DELETE FROM ledger_entries WHERE tx_id = $1;", entry_tx)

    # 5. TRUNCATE fails with InsufficientPrivilegeError
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await restricted_conn.execute("TRUNCATE TABLE ledger_entries;")

    # 6. Restricted role CAN UPDATE ledger_chain_tip
    await restricted_conn.execute(
        "UPDATE ledger_chain_tip SET last_seq = 1, last_hash = $1 WHERE singleton = TRUE;",
        _fake_hash("tip-restricted-test"),
    )

    # 7. Restricted role CANNOT DELETE ledger_chain_tip
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await restricted_conn.execute("DELETE FROM ledger_chain_tip WHERE singleton = TRUE;")

    # 8. Restricted role CANNOT TRUNCATE ledger_chain_tip
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await restricted_conn.execute("TRUNCATE TABLE ledger_chain_tip;")

    # Baseline reset for downstream tasks
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE ledger_chain_tip
            SET last_seq = 0, last_hash = 'GENESIS'
            WHERE singleton = TRUE;
            """
        )


# =============================================================================
# 9. DEFAULT PRIVILEGES PROOF (Future Partitions Inherit Grants)
# =============================================================================


async def test_default_privileges_future_partitions(
    db_pool: asyncpg.Pool,
    restricted_conn: asyncpg.Connection,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify ALTER DEFAULT PRIVILEGES enables restricted role to write to future partitions."""
    acc_ids = await ledger_accounts_factory(count=1)
    acc_id = acc_ids[0]

    # Create a partition for 3 months ahead using OWNER connection
    async with db_pool.acquire() as conn:
        future_date_row = await conn.fetchrow("""
            SELECT (date_trunc('month', now()) + INTERVAL '3 months')::DATE AS future_month;
        """)
        future_month = future_date_row["future_month"]
        await conn.execute("SELECT create_month_partition($1);", future_month)

    future_ts = datetime(future_month.year, future_month.month, 15, 12, 0, 0, tzinfo=UTC)

    try:
        # Restricted role can immediately insert into new partition without manual GRANT
        await restricted_conn.execute(
            """
            INSERT INTO ledger_entries (
                seq, tx_id, account_id, direction, amount, currency,
                balance_after, version, prev_hash, entry_hash, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
            """,
            1,
            uuid.uuid4(),
            acc_id,
            "CREDIT",
            2000,
            "USDC",
            2000,
            1,
            "GENESIS",
            _fake_hash("future-partition-test"),
            future_ts,
        )
    finally:
        # Teardown drops the extra test partition
        partition_name = f"ledger_entries_{future_month.strftime('%Y_%m')}"
        async with db_pool.acquire() as conn:
            await conn.execute(f"DROP TABLE IF EXISTS {partition_name};")


# =============================================================================
# 10. TIP MUTABILITY (Owner path update and clean reset)
# =============================================================================


async def test_tip_mutability_owner_path(
    db_pool: asyncpg.Pool,
    apply_ledger_schema: None,
) -> None:
    """Verify tip updater under owner role and enforce baseline reset."""
    test_hash = _fake_hash("tip-update-test")
    async with db_pool.acquire() as conn:
        try:
            await conn.execute(
                """
                UPDATE ledger_chain_tip
                SET last_seq = 5, last_hash = $1
                WHERE singleton = TRUE;
                """,
                test_hash,
            )
            row = await conn.fetchrow(
                "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
            )
            assert row is not None
            assert row["last_seq"] == 5
            assert row["last_hash"] == test_hash
        finally:
            # Baseline reset: Task 16 relies on pristine tip state (last_seq=0, last_hash='GENESIS')
            await conn.execute(
                """
                UPDATE ledger_chain_tip
                SET last_seq = 0, last_hash = 'GENESIS'
                WHERE singleton = TRUE;
                """
            )
