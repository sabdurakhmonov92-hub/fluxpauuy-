"""Integration test suite for PostgresLedgerStore (Task 16).

Verifies Blueprint §5 & §7 invariants:
- Double-entry zero-sum validation (in-app fail fast + DB trigger backstop).
- Monotonic sequence allocation and hash chaining under singleton tip lock.
- Bounded OCC retry loop with jittered exponential backoff (white-box proof).
- Concurrent serialization without sequence gaps under parallel load.
- Point-in-time balance and keyset pagination query semantics.
- Forensic chain verification: tamper detection, sequence continuity, tip cross-check.
- Canonical timestamp roundtrip byte-exact preservation.
- Task 4 error contract preservation (no registry mutations).
"""

import asyncio
import hashlib
import uuid
from collections.abc import Callable, Coroutine
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import pytest

from fluxpay.ledger.hashchain import (
    Direction,
    format_timestamp,
)
from fluxpay.ledger.postgres import AccountBalanceVersion, PostgresLedgerStore
from fluxpay.ledger.store import (
    Balance,
    EntryDraft,
    LedgerTransaction,
)
from fluxpay.shared.errors import (
    ERROR_REGISTRY,
    InsufficientFunds,
    LedgerNotFoundError,
    OCCConflict,
    UnbalancedTransaction,
)

pytestmark = pytest.mark.integration

AccountsFactory = Callable[..., Coroutine[Any, Any, list[uuid.UUID]]]
SeedAccountCallable = Callable[[uuid.UUID, int, str], Coroutine[Any, Any, LedgerTransaction]]


def _fake_hash(seed: str) -> str:
    """Generate deterministic 64-hex SHA-256 hash for tests."""
    return hashlib.sha256(seed.encode("utf-8")).hexdigest().lower()


# =============================================================================
# 1. HAPPY DOUBLE-ENTRY WRITE PATH
# =============================================================================


async def test_happy_double_entry_post_transaction(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
) -> None:
    """Verify standard balanced transfer (A debit 1000, B credit 1000) commits atomically."""
    acc_ids = await ledger_accounts_factory(count=2)
    acc_a, acc_b = acc_ids[0], acc_ids[1]

    # Honest seed: Mint 1000 USDC into account A via balanced system debit
    await seed_account(acc_a, 1000, "USDC")

    # Post balanced transfer: Account A transfers 1000 to Account B
    tx = await ledger_store.post_transaction(
        [
            EntryDraft(
                account_id=acc_a,
                direction=Direction.DEBIT,
                amount=1000,
                currency="USDC",
            ),
            EntryDraft(
                account_id=acc_b,
                direction=Direction.CREDIT,
                amount=1000,
                currency="USDC",
            ),
        ]
    )

    assert isinstance(tx, LedgerTransaction)
    assert isinstance(tx.tx_id, uuid.UUID)
    assert len(tx.entries) == 2

    e0, e1 = tx.entries[0], tx.entries[1]
    assert e0.account_id == acc_a
    assert e0.direction == Direction.DEBIT
    assert e0.amount == 1000
    assert e0.balance_after == 0
    assert e0.version == 2  # Seed was version 1; transfer incremented to version 2

    assert e1.account_id == acc_b
    assert e1.direction == Direction.CREDIT
    assert e1.amount == 1000
    assert e1.balance_after == 1000
    assert e1.version == 1

    # Verify balance snapshots match entry balance_after
    bal_a = await ledger_store.get_balance(acc_a)
    assert bal_a == Balance(account_id=acc_a, currency="USDC", balance=0, version=2)

    bal_b = await ledger_store.get_balance(acc_b)
    assert bal_b == Balance(account_id=acc_b, currency="USDC", balance=1000, version=1)


# =============================================================================
# 2. HASH CHAIN LINKAGE ACROSS TRANSACTIONS
# =============================================================================


async def test_chain_linkage_across_transactions(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify cryptographic link between consecutive txs and full-scan chain verification."""
    acc_ids = await ledger_accounts_factory(count=3)
    acc_a, acc_b, acc_c = acc_ids[0], acc_ids[1], acc_ids[2]

    await seed_account(acc_a, 2000, "USDC")

    tx1 = await ledger_store.post_transaction(
        [
            EntryDraft(
                account_id=acc_a,
                direction=Direction.DEBIT,
                amount=1000,
                currency="USDC",
            ),
            EntryDraft(
                account_id=acc_b,
                direction=Direction.CREDIT,
                amount=1000,
                currency="USDC",
            ),
        ]
    )

    tx2 = await ledger_store.post_transaction(
        [
            EntryDraft(
                account_id=acc_a,
                direction=Direction.DEBIT,
                amount=500,
                currency="USDC",
            ),
            EntryDraft(
                account_id=acc_c,
                direction=Direction.CREDIT,
                amount=500,
                currency="USDC",
            ),
        ]
    )

    # First entry of tx2 must chain to the last entry of tx1
    assert tx2.entries[0].prev_hash == tx1.entries[-1].entry_hash

    # Verify chain tip in database matches terminal entry of tx2
    tip_row = await owner_conn.fetchrow(
        "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
    )
    assert tip_row is not None
    assert tip_row["last_seq"] == tx2.entries[-1].seq
    assert tip_row["last_hash"] == tx2.entries[-1].entry_hash

    # Full-scan chain verification
    result = await ledger_store.verify_chain(from_seq=1)
    assert result.ok is True
    assert result.last_verified_seq == tip_row["last_seq"]
    assert result.broken_seq is None
    assert result.reason is None


# =============================================================================
# 3. UNBALANCED APP-REJECT FAILS FAST BEFORE LOCK
# =============================================================================


async def test_unbalanced_app_reject_fails_fast_before_lock(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify unbalanced txs fail in-app before touching locks or consuming sequence numbers."""
    acc_ids = await ledger_accounts_factory(count=2)
    acc_a, acc_b = acc_ids[0], acc_ids[1]

    tip_before = await owner_conn.fetchrow(
        "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
    )
    assert tip_before is not None
    seq_before = tip_before["last_seq"]

    # Single-currency imbalance: debit 100 != credit 99
    with pytest.raises(UnbalancedTransaction) as exc_info:
        await ledger_store.post_transaction(
            [
                EntryDraft(
                    account_id=acc_a,
                    direction=Direction.DEBIT,
                    amount=100,
                    currency="USDC",
                ),
                EntryDraft(
                    account_id=acc_b,
                    direction=Direction.CREDIT,
                    amount=99,
                    currency="USDC",
                ),
            ]
        )
    assert exc_info.value.details["currency"] == "USDC"
    assert exc_info.value.details["debit_sum"] == "100"
    assert exc_info.value.details["credit_sum"] == "99"

    # Multi-currency imbalance: 100 USDC debit != 100 EUR credit
    with pytest.raises(UnbalancedTransaction) as exc_info_curr:
        await ledger_store.post_transaction(
            [
                EntryDraft(
                    account_id=acc_a,
                    direction=Direction.DEBIT,
                    amount=100,
                    currency="USDC",
                ),
                EntryDraft(
                    account_id=acc_b,
                    direction=Direction.CREDIT,
                    amount=100,
                    currency="EUR",
                ),
            ]
        )
    assert "currency" in exc_info_curr.value.details

    # Empty entries rejected immediately
    with pytest.raises(UnbalancedTransaction):
        await ledger_store.post_transaction([])

    # Prove zero sequence numbers consumed and tip state completely untouched
    tip_after = await owner_conn.fetchrow(
        "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
    )
    assert tip_after is not None
    assert tip_after["last_seq"] == seq_before
    assert tip_after["last_hash"] == tip_before["last_hash"]


# =============================================================================
# 4. INSUFFICIENT FUNDS LEAVES ZERO TRACE
# =============================================================================


async def test_insufficient_funds_leaves_no_trace(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify attempt to overdraft fails with InsufficientFunds and rolls back completely."""
    acc_ids = await ledger_accounts_factory(count=2)
    acc_a, acc_b = acc_ids[0], acc_ids[1]

    await seed_account(acc_a, 100, "USDC")

    tip_before = await owner_conn.fetchrow(
        "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
    )
    assert tip_before is not None
    seq_before = tip_before["last_seq"]

    entries_count_before = await owner_conn.fetchval("SELECT count(*) FROM ledger_entries;")

    # Overdraft attempt: Account A has 100, attempts to debit 500
    with pytest.raises(InsufficientFunds) as exc_info:
        await ledger_store.post_transaction(
            [
                EntryDraft(
                    account_id=acc_a,
                    direction=Direction.DEBIT,
                    amount=500,
                    currency="USDC",
                ),
                EntryDraft(
                    account_id=acc_b,
                    direction=Direction.CREDIT,
                    amount=500,
                    currency="USDC",
                ),
            ]
        )

    assert exc_info.value.details["account_id"] == str(acc_a)
    assert exc_info.value.details["balance"] == "100"
    assert exc_info.value.details["requested"] == "500"

    # Verify zero persistence: balances, tip, and entry counts unchanged
    bal_a = await ledger_store.get_balance(acc_a)
    assert bal_a.balance == 100
    bal_b = await ledger_store.get_balance(acc_b)
    assert bal_b.balance == 0

    tip_after = await owner_conn.fetchrow(
        "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
    )
    assert tip_after is not None
    assert tip_after["last_seq"] == seq_before

    entries_count_after = await owner_conn.fetchval("SELECT count(*) FROM ledger_entries;")
    assert entries_count_after == entries_count_before


# =============================================================================
# 5. ATOMICITY MID-FAILURE PRESERVES CONSECUTIVE SEQUENCES
# =============================================================================


async def test_atomicity_mid_failure_preserves_consecutive_sequences(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify mid-transaction failure rolls back cleanly without sequence leakage or gaps."""
    acc_ids = await ledger_accounts_factory(count=2)
    acc_a, acc_b = acc_ids[0], acc_ids[1]

    await seed_account(acc_a, 1000, "USDC")

    tip_before = await owner_conn.fetchrow(
        "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
    )
    assert tip_before is not None
    seq_before = tip_before["last_seq"]

    unknown_acc = uuid.uuid4()

    # Fail mid-transaction: Leg 1 (A) succeeds, Leg 2 (unknown) fails
    with pytest.raises(LedgerNotFoundError) as exc_info:
        await ledger_store.post_transaction(
            [
                EntryDraft(
                    account_id=acc_a,
                    direction=Direction.DEBIT,
                    amount=100,
                    currency="USDC",
                ),
                EntryDraft(
                    account_id=unknown_acc,
                    direction=Direction.CREDIT,
                    amount=100,
                    currency="USDC",
                ),
            ]
        )
    assert exc_info.value.details["account_id"] == str(unknown_acc)

    # Sequence number must NOT have been consumed
    tip_mid = await owner_conn.fetchrow(
        "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
    )
    assert tip_mid is not None
    assert tip_mid["last_seq"] == seq_before

    # Subsequent valid transaction must allocate the EXACT next sequence number (no gaps)
    tx_next = await ledger_store.post_transaction(
        [
            EntryDraft(
                account_id=acc_a,
                direction=Direction.DEBIT,
                amount=100,
                currency="USDC",
            ),
            EntryDraft(
                account_id=acc_b,
                direction=Direction.CREDIT,
                amount=100,
                currency="USDC",
            ),
        ]
    )
    assert tx_next.entries[0].seq == seq_before + 1
    assert tx_next.entries[1].seq == seq_before + 2


# =============================================================================
# 6. DETERMINISTIC WHITE-BOX OCC RETRY MACHINERY
# =============================================================================


async def test_occ_machinery_white_box_retry_exhaustion(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
    monkeypatch: pytest.MonkeyPatch,
    store_sleep: Any,
) -> None:
    """Verify bounded OCC retry loop deterministically captures exponential delays with jitter."""
    acc_ids = await ledger_accounts_factory(count=2)
    acc_a, acc_b = acc_ids[0], acc_ids[1]

    await seed_account(acc_a, 1000, "USDC")

    # White-box monkeypatch: simulate concurrent out-of-band writer by returning stale version
    original_read = ledger_store._read_account

    async def _mock_read_account(
        conn: asyncpg.Connection,
        account_id: uuid.UUID,
    ) -> AccountBalanceVersion:
        actual = await original_read(conn, account_id)
        # Return version - 1 so the UPDATE ... WHERE version = $read_version matches 0 rows
        return AccountBalanceVersion(balance=actual.balance, version=actual.version - 1)

    monkeypatch.setattr(ledger_store, "_read_account", _mock_read_account)

    # Attempt transfer: must fail with OCCConflict after max_occ_retries (2 retries = 2 sleeps)
    with pytest.raises(OCCConflict) as exc_info:
        await ledger_store.post_transaction(
            [
                EntryDraft(
                    account_id=acc_a,
                    direction=Direction.DEBIT,
                    amount=100,
                    currency="USDC",
                ),
                EntryDraft(
                    account_id=acc_b,
                    direction=Direction.CREDIT,
                    amount=100,
                    currency="USDC",
                ),
            ]
        )

    assert exc_info.value.retryable is True
    assert exc_info.value.code == "conflict_retry_required"

    # Verify retry count matches max_occ_retries exactly
    assert len(store_sleep.delays) == 2

    # Verify backoff delays grow with jitter bounds:
    # Attempt 0: base 25ms + random 0-10ms -> [0.025, 0.035]
    # Attempt 1: base 50ms + random 0-10ms -> [0.050, 0.060]
    delay0, delay1 = store_sleep.delays[0], store_sleep.delays[1]
    assert 0.025 <= delay0 <= 0.035 + 0.001
    assert 0.050 <= delay1 <= 0.060 + 0.001
    assert delay0 < delay1

    # Restore unmonkeypatched behavior: subsequent transaction must succeed cleanly
    monkeypatch.undo()
    tx_restored = await ledger_store.post_transaction(
        [
            EntryDraft(
                account_id=acc_a,
                direction=Direction.DEBIT,
                amount=100,
                currency="USDC",
            ),
            EntryDraft(
                account_id=acc_b,
                direction=Direction.CREDIT,
                amount=100,
                currency="USDC",
            ),
        ]
    )
    assert len(tx_restored.entries) == 2


# =============================================================================
# 7. CONCURRENT SERIALIZATION UNDER LOAD
# =============================================================================


async def test_concurrent_serialization_load(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
    owner_conn: asyncpg.Connection,
) -> None:
    """Demonstrate Phase 1 global tip serialization: 10 parallel transactions commit gaplessly."""
    pairs_count = 10
    acc_ids = await ledger_accounts_factory(count=pairs_count * 2)

    # Seed each source account
    for i in range(pairs_count):
        src_id = acc_ids[i * 2]
        await seed_account(src_id, 1000, "USDC")

    tip_before = await owner_conn.fetchrow(
        "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
    )
    assert tip_before is not None
    seq_start = tip_before["last_seq"]

    # Execute 10 parallel transfers across distinct account pairs simultaneously
    async def _post_pair(i: int) -> LedgerTransaction:
        src = acc_ids[i * 2]
        dst = acc_ids[i * 2 + 1]
        return await ledger_store.post_transaction(
            [
                EntryDraft(account_id=src, direction=Direction.DEBIT, amount=100, currency="USDC"),
                EntryDraft(account_id=dst, direction=Direction.CREDIT, amount=100, currency="USDC"),
            ]
        )

    results: list[LedgerTransaction] = await asyncio.gather(
        *[_post_pair(i) for i in range(pairs_count)]
    )

    assert len(results) == pairs_count

    # Collect all sequence numbers: must form a strictly contiguous range of 20 integers
    allocated_seqs = sorted(e.seq for tx in results for e in tx.entries)
    expected_seqs = list(range(seq_start + 1, seq_start + (pairs_count * 2) + 1))
    assert allocated_seqs == expected_seqs

    # Verify cryptographic integrity over the entire chain
    verification = await ledger_store.verify_chain(from_seq=1)
    assert verification.ok is True
    assert verification.last_verified_seq == seq_start + (pairs_count * 2)


# =============================================================================
# 8. GET_BALANCE QUERY CONTRACT
# =============================================================================


async def test_get_balance_query_contract(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
) -> None:
    """Verify get_balance succeeds for known accounts and raises LedgerNotFoundError for unknown."""
    acc_ids = await ledger_accounts_factory(count=1)
    acc = acc_ids[0]

    await seed_account(acc, 500, "USDC")

    balance = await ledger_store.get_balance(acc)
    assert balance.account_id == acc
    assert balance.currency == "USDC"
    assert balance.balance == 500
    assert balance.version == 1

    with pytest.raises(LedgerNotFoundError) as exc_info:
        await ledger_store.get_balance(uuid.uuid4())
    assert "account_id" in exc_info.value.details


# =============================================================================
# 9. GET_TRANSACTION QUERY CONTRACT
# =============================================================================


async def test_get_transaction_query_contract(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
) -> None:
    """Verify get_transaction returns exact tuple for committed tx and None for unknown."""
    acc_ids = await ledger_accounts_factory(count=2)
    acc_a, acc_b = acc_ids[0], acc_ids[1]

    await seed_account(acc_a, 1000, "USDC")

    tx = await ledger_store.post_transaction(
        [
            EntryDraft(
                account_id=acc_a,
                direction=Direction.DEBIT,
                amount=250,
                currency="USDC",
            ),
            EntryDraft(
                account_id=acc_b,
                direction=Direction.CREDIT,
                amount=250,
                currency="USDC",
            ),
        ]
    )

    fetched = await ledger_store.get_transaction(tx.tx_id)
    assert fetched is not None
    assert fetched.tx_id == tx.tx_id
    assert fetched.entries == tx.entries

    # Unknown transaction returns None per frozen Protocol specification
    missing = await ledger_store.get_transaction(uuid.uuid4())
    assert missing is None


# =============================================================================
# 10. GET_HISTORY KEYSET PAGINATION & BOUNDS
# =============================================================================


async def test_get_history_pagination_and_bounds(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
) -> None:
    """Verify get_history orders newest-first, keyset pages via before_seq, and guards bounds."""
    acc_ids = await ledger_accounts_factory(count=2)
    acc_a, acc_b = acc_ids[0], acc_ids[1]

    # Seed Account A with enough funds for 25 small transfers
    await seed_account(acc_a, 2500, "USDC")

    # Generate 25 entries for Account A (25 transfers)
    for _ in range(25):
        await ledger_store.post_transaction(
            [
                EntryDraft(
                    account_id=acc_a,
                    direction=Direction.DEBIT,
                    amount=10,
                    currency="USDC",
                ),
                EntryDraft(
                    account_id=acc_b,
                    direction=Direction.CREDIT,
                    amount=10,
                    currency="USDC",
                ),
            ]
        )

    # 1 seed credit + 25 transfer debits = 26 total entries for Account A
    full_history = await ledger_store.get_history(acc_a, limit=50)
    assert len(full_history) == 26

    # Verify newest-first ordering (monotonic descending seq)
    for i in range(len(full_history) - 1):
        assert full_history[i].seq > full_history[i + 1].seq

    # Test Keyset Pagination: Page 1 (limit 10)
    page1 = await ledger_store.get_history(acc_a, limit=10)
    assert len(page1) == 10
    oldest_in_page1 = page1[-1].seq

    # Page 2 (limit 10, before_seq = oldest_in_page1)
    page2 = await ledger_store.get_history(acc_a, limit=10, before_seq=oldest_in_page1)
    assert len(page2) == 10
    assert all(entry.seq < oldest_in_page1 for entry in page2)
    assert page2[0].seq < oldest_in_page1

    # Verify pure validator bounds (1 <= limit <= 100, before_seq >= 1)
    with pytest.raises(ValueError, match="limit: must be between 1 and 100"):
        await ledger_store.get_history(acc_a, limit=0)

    with pytest.raises(ValueError, match="limit: must be between 1 and 100"):
        await ledger_store.get_history(acc_a, limit=101)

    with pytest.raises(ValueError, match="before_seq: must be >= 1"):
        await ledger_store.get_history(acc_a, limit=10, before_seq=0)


# =============================================================================
# 11. FORENSIC TAMPER DETECTION (SELF-CLEANING)
# =============================================================================


async def test_verify_chain_tamper_detection_self_cleaning(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify cryptographic hash mismatch detection on tampered entries with clean restoration."""
    acc_ids = await ledger_accounts_factory(count=2)
    acc_a, acc_b = acc_ids[0], acc_ids[1]

    await seed_account(acc_a, 5000, "USDC")

    # Create several entries
    tx = await ledger_store.post_transaction(
        [
            EntryDraft(
                account_id=acc_a,
                direction=Direction.DEBIT,
                amount=1000,
                currency="USDC",
            ),
            EntryDraft(
                account_id=acc_b,
                direction=Direction.CREDIT,
                amount=1000,
                currency="USDC",
            ),
        ]
    )

    tamper_seq = tx.entries[0].seq

    # Save exact original database row values
    original_row = await owner_conn.fetchrow(
        "SELECT * FROM ledger_entries WHERE seq = $1;",
        tamper_seq,
    )
    assert original_row is not None
    orig_amount: int = original_row["amount"]

    try:
        # Documented DB admin correction procedure: disable trigger -> mutate -> re-enable
        await owner_conn.execute(
            "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
        )
        await owner_conn.execute(
            "UPDATE ledger_entries SET amount = amount + 1 WHERE seq = $1;",
            tamper_seq,
        )
        await owner_conn.execute(
            "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
        )

        # Chain verification must immediately catch the cryptographic mismatch
        verification = await ledger_store.verify_chain(from_seq=1)
        assert verification.ok is False
        assert verification.broken_seq == tamper_seq
        assert verification.reason is not None
        assert (
            "recomputation" in verification.reason.lower()
            or "mismatch" in verification.reason.lower()
        )

    finally:
        # Self-cleaning restore: return exact row values to keep suite green
        await owner_conn.execute(
            "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
        )
        await owner_conn.execute(
            "UPDATE ledger_entries SET amount = $1 WHERE seq = $2;",
            orig_amount,
            tamper_seq,
        )
        await owner_conn.execute(
            "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
        )

    # Prove chain is restored to 100% cryptographic validity
    restored = await ledger_store.verify_chain(from_seq=1)
    assert restored.ok is True


# =============================================================================
# 12. FORENSIC CONTINUITY BREAK (SEQUENCE GAP DETECTION)
# =============================================================================


async def test_verify_chain_continuity_break_self_cleaning(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify detection of sequence gaps when an entry is deleted from the chain."""
    acc_ids = await ledger_accounts_factory(count=2)
    acc_a, acc_b = acc_ids[0], acc_ids[1]

    await seed_account(acc_a, 5000, "USDC")

    tx = await ledger_store.post_transaction(
        [
            EntryDraft(
                account_id=acc_a,
                direction=Direction.DEBIT,
                amount=500,
                currency="USDC",
            ),
            EntryDraft(
                account_id=acc_b,
                direction=Direction.CREDIT,
                amount=500,
                currency="USDC",
            ),
        ]
    )

    delete_seq = tx.entries[0].seq

    saved_row = await owner_conn.fetchrow(
        "SELECT * FROM ledger_entries WHERE seq = $1;",
        delete_seq,
    )
    assert saved_row is not None

    try:
        await owner_conn.execute(
            "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
        )
        await owner_conn.execute(
            "DELETE FROM ledger_entries WHERE seq = $1;",
            delete_seq,
        )
        await owner_conn.execute(
            "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
        )

        # Verification must catch the missing sequence number
        verification = await ledger_store.verify_chain(from_seq=1)
        assert verification.ok is False
        assert verification.broken_seq == delete_seq
        assert verification.reason is not None
        assert "discontinuity" in verification.reason.lower()

    finally:
        # Restore deleted row with exact saved columns
        await owner_conn.execute(
            "ALTER TABLE ledger_entries DISABLE TRIGGER trg_ledger_entries_immutable;"
        )
        await owner_conn.execute(
            """
            INSERT INTO ledger_entries (
                seq, tx_id, account_id, direction, amount, currency,
                balance_after, version, prev_hash, entry_hash, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
            """,
            saved_row["seq"],
            saved_row["tx_id"],
            saved_row["account_id"],
            saved_row["direction"],
            saved_row["amount"],
            saved_row["currency"],
            saved_row["balance_after"],
            saved_row["version"],
            saved_row["prev_hash"],
            saved_row["entry_hash"],
            saved_row["created_at"],
        )
        await owner_conn.execute(
            "ALTER TABLE ledger_entries ENABLE TRIGGER trg_ledger_entries_immutable;"
        )

    restored = await ledger_store.verify_chain(from_seq=1)
    assert restored.ok is True


# =============================================================================
# 13. FORENSIC TIP MISMATCH DETECTION
# =============================================================================


async def test_verify_chain_tip_mismatch_self_cleaning(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify full-scan mode catches out-of-sync mutable tip pointing to an invalid hash."""
    acc_ids = await ledger_accounts_factory(count=1)
    acc_a = acc_ids[0]

    await seed_account(acc_a, 1000, "USDC")

    tip_before = await owner_conn.fetchrow(
        "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
    )
    assert tip_before is not None
    orig_hash: str = tip_before["last_hash"]

    tampered_hash = _fake_hash("rogue-advanced-tip")

    try:
        # Desynchronize the tip pointer
        await owner_conn.execute(
            "UPDATE ledger_chain_tip SET last_hash = $1 WHERE singleton = TRUE;",
            tampered_hash,
        )

        verification = await ledger_store.verify_chain(from_seq=1)
        assert verification.ok is False
        assert verification.reason is not None
        assert "tip_mismatch" in verification.reason

    finally:
        # Restore true tip hash
        await owner_conn.execute(
            "UPDATE ledger_chain_tip SET last_hash = $1 WHERE singleton = TRUE;",
            orig_hash,
        )

    restored = await ledger_store.verify_chain(from_seq=1)
    assert restored.ok is True


# =============================================================================
# 14. TIMESTAMP CANONICAL ROUNDTRIP
# =============================================================================


async def test_timestamp_canonical_roundtrip(
    ledger_store: PostgresLedgerStore,
    ledger_accounts_factory: AccountsFactory,
    seed_account: SeedAccountCallable,
    owner_conn: asyncpg.Connection,
) -> None:
    """Verify entry.created_at matches format_timestamp of the stored PostgreSQL timestamptz."""
    acc_ids = await ledger_accounts_factory(count=2)
    acc_a, acc_b = acc_ids[0], acc_ids[1]

    await seed_account(acc_a, 1000, "USDC")

    tx = await ledger_store.post_transaction(
        [
            EntryDraft(
                account_id=acc_a,
                direction=Direction.DEBIT,
                amount=100,
                currency="USDC",
            ),
            EntryDraft(
                account_id=acc_b,
                direction=Direction.CREDIT,
                amount=100,
                currency="USDC",
            ),
        ]
    )

    entry = tx.entries[0]
    db_row = await owner_conn.fetchrow(
        "SELECT created_at FROM ledger_entries WHERE seq = $1;",
        entry.seq,
    )
    assert db_row is not None

    reconstructed_canonical = format_timestamp(db_row["created_at"])
    assert entry.created_at == reconstructed_canonical


# =============================================================================
# 15. TASK 4 ERROR CONTRACT PRESERVED
# =============================================================================


def test_task4_error_contract_preserved() -> None:
    """Ensure Task 4 errors registry remains frozen and untouched by Task 16."""
    assert len(ERROR_REGISTRY) == 12
    assert "insufficient_funds" in ERROR_REGISTRY
    assert "conflict_retry_required" in ERROR_REGISTRY
    assert "account_not_found" in ERROR_REGISTRY
    assert "internal_ledger_error" in ERROR_REGISTRY
