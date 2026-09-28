"""Integration test suite for Ledger Read Models (Task 17).

Verifies the frozen query interfaces against live PostgreSQL 17:
- Cross-validation: Identical 10-tx script executed against PostgresLedgerStore
  and FakeLedgerStore produces byte-equal, field-by-field equal AccountStatement objects.
- Statement against seeded live store matches manual double-entry arithmetic.
- Empty account queries yield empty statements with None balances and True verification.
"""

import sys
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]
import pytest

# Ensure tests root is on sys.path for test imports
_tests_root = str(Path(__file__).resolve().parents[1])
if _tests_root not in sys.path:
    sys.path.insert(0, _tests_root)

from _fakes.ledger import FakeLedgerStore  # noqa: E402

from fluxpay.ledger.hashchain import Direction  # noqa: E402
from fluxpay.ledger.postgres import PostgresLedgerStore  # noqa: E402
from fluxpay.ledger.queries import (  # noqa: E402
    AccountStatement,
    account_statement,
    balance_at,
)
from fluxpay.ledger.store import EntryDraft, LedgerStore  # noqa: E402

pytestmark = pytest.mark.integration

AccountsFactory = Callable[..., Coroutine[Any, Any, list[UUID]]]


async def run_script(
    store: LedgerStore,
    n: int = 10,
    *,
    accounts: tuple[UUID, UUID, UUID],
) -> tuple[UUID, UUID, UUID]:
    """Execute n deterministic, self-balancing transactions across 3 accounts."""
    acc_a, acc_b, acc_c = accounts
    half = n // 2
    for i in range(half):
        amount = 100 * (i + 1)
        await store.post_transaction(
            [
                EntryDraft(
                    account_id=acc_a,
                    direction=Direction.DEBIT,
                    amount=amount,
                    currency="USDC",
                ),
                EntryDraft(
                    account_id=acc_a,
                    direction=Direction.CREDIT,
                    amount=amount,
                    currency="USDC",
                ),
            ]
        )
    for i in range(half, n):
        amount = 50 * (i + 1)
        await store.post_transaction(
            [
                EntryDraft(
                    account_id=acc_b,
                    direction=Direction.DEBIT,
                    amount=amount,
                    currency="USDC",
                ),
                EntryDraft(
                    account_id=acc_c,
                    direction=Direction.CREDIT,
                    amount=amount,
                    currency="USDC",
                ),
            ]
        )
    return acc_a, acc_b, acc_c


# =============================================================================
# 1. CROSS-VALIDATION (The test that keeps the fake honest forever)
# =============================================================================


async def test_cross_validation_fake_vs_real(
    ledger_store: PostgresLedgerStore,
    db_pool: asyncpg.Pool,
    ledger_accounts_factory: AccountsFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify identical 10-tx script on Postgres & Fake stores yields EQUAL statements.

    CROSS-VALIDATION PHILOSOPHY:
    If these ever diverge, either the fake lied or the store drifted — both are
    Block-C-breaking, CI catches it here. The fake is our highest-leverage test
    artifact; this cross-validation test guarantees it remains an exact behavioral
    twin of PostgreSQL production storage forever.
    """
    # 1. Allocate 3 accounts in PostgreSQL with matching initial balances
    acc_ids = await ledger_accounts_factory(count=3, initial_balance=1_000_000, currency="USDC")
    acc_a, acc_b, acc_c = acc_ids[0], acc_ids[1], acc_ids[2]

    # 2. Inspect current tip state from database to initialize the fake at the same chain position
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
        )
        assert row is not None
        start_seq = int(row["last_seq"])
        start_hash = str(row["last_hash"])

    # 3. Synchronize deterministic UUID and timestamp generation across both engines
    deterministic_uuids = [UUID(f"10000000-0000-0000-0000-{i:012d}") for i in range(1, 100)]
    uuid_iter_pg = iter(list(deterministic_uuids))
    uuid_iter_fk = iter(list(deterministic_uuids))

    base_time = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)
    deterministic_times = [base_time + timedelta(seconds=i) for i in range(1, 100)]
    time_iter_pg = iter(list(deterministic_times))
    time_iter_fk = iter(list(deterministic_times))

    class SynchronizedDatetime(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
            return next(time_iter_pg)

    monkeypatch.setattr("fluxpay.ledger.postgres.datetime", SynchronizedDatetime)
    monkeypatch.setattr("fluxpay.ledger.postgres.uuid.uuid4", lambda: next(uuid_iter_pg))

    # 4. Construct FakeLedgerStore seeded with identical initial conditions
    fake_store = FakeLedgerStore(
        initial_seq=start_seq,
        initial_hash=start_hash,
        time_fn=lambda: next(time_iter_fk),
        uuid_fn=lambda: next(uuid_iter_fk),
    )
    fake_store.init_account(acc_a, currency="USDC", initial_balance=1_000_000)
    fake_store.init_account(acc_b, currency="USDC", initial_balance=1_000_000)
    fake_store.init_account(acc_c, currency="USDC", initial_balance=1_000_000)

    # 5. Execute identical 10-tx script against both stores
    await run_script(ledger_store, 10, accounts=(acc_a, acc_b, acc_c))
    await run_script(fake_store, 10, accounts=(acc_a, acc_b, acc_c))

    # 6. Extract statements for the target account on both engines
    from_seq = start_seq + 1
    to_seq = start_seq + 10
    stmt_pg = await account_statement(ledger_store, acc_a, from_seq=from_seq, to_seq=to_seq)
    stmt_fk = await account_statement(fake_store, acc_a, from_seq=from_seq, to_seq=to_seq)

    # 7. Field-by-field equality verification
    assert stmt_pg.account_id == stmt_fk.account_id == acc_a
    assert stmt_pg.currency == stmt_fk.currency == "USDC"
    assert stmt_pg.from_seq == stmt_fk.from_seq == from_seq
    assert stmt_pg.to_seq == stmt_fk.to_seq == to_seq
    assert stmt_pg.opening_balance == stmt_fk.opening_balance
    assert stmt_pg.closing_balance == stmt_fk.closing_balance
    assert stmt_pg.chain_verified is True
    assert stmt_fk.chain_verified is True
    assert stmt_pg.first_entry_hash == stmt_fk.first_entry_hash
    assert stmt_pg.last_entry_hash == stmt_fk.last_entry_hash
    assert len(stmt_pg.entries) == len(stmt_fk.entries) == 10

    # Byte-exact entry comparison
    for e_pg, e_fk in zip(stmt_pg.entries, stmt_fk.entries, strict=True):
        assert e_pg.seq == e_fk.seq
        assert e_pg.direction == e_fk.direction
        assert e_pg.amount == e_fk.amount
        assert e_pg.balance_after == e_fk.balance_after
        assert e_pg.version == e_fk.version
        assert e_pg.prev_hash == e_fk.prev_hash
        assert e_pg.entry_hash == e_fk.entry_hash
        assert e_pg.tx_id == e_fk.tx_id
        assert e_pg.created_at == e_fk.created_at

    # Whole dataclass equality
    assert stmt_pg == stmt_fk


# =============================================================================
# 2. STATEMENT ARITHMETIC AGAINST SEEDED REAL STORE
# =============================================================================


async def test_statement_matches_manual_arithmetic(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify statement balances and entry deltas match manual arithmetic."""
    acc_ids = await ledger_accounts_factory(count=2, initial_balance=50_000, currency="USDC")
    src, dst = acc_ids[0], acc_ids[1]

    # Tx 1: Transfer 10_000 USDC from src to dst (src: 50_000 -> 40_000)
    tx1 = await ledger_store.post_transaction(
        [
            EntryDraft(account_id=src, direction=Direction.DEBIT, amount=10_000, currency="USDC"),
            EntryDraft(account_id=dst, direction=Direction.CREDIT, amount=10_000, currency="USDC"),
        ]
    )

    # Tx 2: Transfer 5_000 USDC from src to dst (src: 40_000 -> 35_000)
    tx2 = await ledger_store.post_transaction(
        [
            EntryDraft(account_id=src, direction=Direction.DEBIT, amount=5_000, currency="USDC"),
            EntryDraft(account_id=dst, direction=Direction.CREDIT, amount=5_000, currency="USDC"),
        ]
    )

    # Tx 3: Transfer 2_000 USDC from src to dst (src: 35_000 -> 33_000)
    tx3 = await ledger_store.post_transaction(
        [
            EntryDraft(account_id=src, direction=Direction.DEBIT, amount=2_000, currency="USDC"),
            EntryDraft(account_id=dst, direction=Direction.CREDIT, amount=2_000, currency="USDC"),
        ]
    )

    # Window slicing: request statement covering tx2 and tx3 only
    seq_tx1_src = tx1.entries[0].seq
    seq_tx2_src = tx2.entries[0].seq
    seq_tx3_src = tx3.entries[0].seq

    bal_prior = await balance_at(ledger_store, src, seq=seq_tx1_src)
    assert bal_prior == 40_000

    stmt = await account_statement(
        ledger_store,
        src,
        from_seq=seq_tx2_src,
        to_seq=seq_tx3_src,
    )

    assert isinstance(stmt, AccountStatement)
    assert stmt.account_id == src
    assert len(stmt.entries) == 2

    # Opening balance prior to tx2 is balance_after of tx1 (40_000)
    assert stmt.opening_balance == bal_prior == 40_000
    # First entry in window: tx2 debits 5_000 -> balance 35_000
    assert stmt.entries[0].seq == seq_tx2_src
    assert stmt.entries[0].amount == 5_000
    assert stmt.entries[0].balance_after == 35_000

    # Second entry in window: tx3 debits 2_000 -> balance 33_000
    assert stmt.entries[1].seq == seq_tx3_src
    assert stmt.entries[1].amount == 2_000
    assert stmt.entries[1].balance_after == 33_000

    # Closing balance matches last entry (33_000)
    assert stmt.closing_balance == 33_000
    assert stmt.chain_verified is True


# =============================================================================
# 3. EMPTY ACCOUNT STATEMENT
# =============================================================================


async def test_empty_account_statement(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
) -> None:
    """Verify empty account query yields empty statement with None balances."""
    acc_ids = await ledger_accounts_factory(count=1, initial_balance=0, currency="USDC")
    empty_acc = acc_ids[0]

    stmt = await account_statement(ledger_store, empty_acc)

    assert isinstance(stmt, AccountStatement)
    assert stmt.account_id == empty_acc
    assert stmt.currency == "USDC"
    assert stmt.entries == ()
    assert stmt.opening_balance is None
    assert stmt.closing_balance is None
    assert stmt.first_entry_hash is None
    assert stmt.last_entry_hash is None
    assert stmt.chain_verified is True
