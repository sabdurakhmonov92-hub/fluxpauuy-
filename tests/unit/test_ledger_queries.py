"""Unit test suite for Ledger Read Models & FakeLedgerStore (Task 17).

Verifies the frozen query interfaces, AccountStatement range proof mechanics,
pure parameter bounds, alarm logging paths, and FakeLedgerStore protocol conformance
without requiring a live database.
"""

import inspect
import logging
import sys
import uuid
from pathlib import Path
from uuid import UUID

# Ensure tests root is on sys.path for test imports
_tests_root = str(Path(__file__).resolve().parents[1])
if _tests_root not in sys.path:
    sys.path.insert(0, _tests_root)

import pytest  # noqa: E402
import structlog  # noqa: E402
from _fakes.ledger import FakeLedgerStore  # noqa: E402

from fluxpay.ledger.hashchain import (  # noqa: E402
    GENESIS,
    Direction,
    EntryFingerprint,
)
from fluxpay.ledger.queries import (  # noqa: E402
    MAX_STATEMENT_ENTRIES,
    AccountStatement,
    account_statement,
    balance_at,
    to_fingerprint,
    validate_statement_range,
)
from fluxpay.ledger.store import (  # noqa: E402
    EntryDraft,
    LedgerEntry,
    LedgerStore,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _setup_structlog_stdlib() -> None:
    """Ensure structlog routes through stdlib logging so pytest caplog fixture captures records."""
    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory())


# =============================================================================
# MODULE-LEVEL SEEDING SCRIPT HELPER
# =============================================================================


async def run_script(
    store: LedgerStore,
    n: int = 10,
    *,
    accounts: tuple[UUID, UUID, UUID] | None = None,
) -> tuple[UUID, UUID, UUID]:
    """Execute n deterministic, self-balancing transactions across 3 accounts.

    Designed to produce consecutive, contiguous entries on account_a (first n // 2 txs
    with 2 legs per tx = n entries on account_a), followed by transfer transactions
    between account_b and account_c.
    """
    if accounts is None:
        acc_a = uuid.uuid4()
        acc_b = uuid.uuid4()
        acc_c = uuid.uuid4()
        if isinstance(store, FakeLedgerStore):
            store.init_account(acc_a, currency="USDC", initial_balance=1_000_000)
            store.init_account(acc_b, currency="USDC", initial_balance=1_000_000)
            store.init_account(acc_c, currency="USDC", initial_balance=1_000_000)
    else:
        acc_a, acc_b, acc_c = accounts

    half = n // 2
    # First half: self-balancing double-entry legs on acc_a (consecutive seq numbers)
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

    # Second half: self-balancing transfers between acc_b and acc_c
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
# 1. STATEMENT HAPPY PATH & WINDOW SLICING
# =============================================================================


async def test_statement_happy_path() -> None:
    """Verify statement happy path: 10 entries, exact balances, chain verified."""
    fake = FakeLedgerStore()
    acc_a, _, _ = await run_script(fake, 10)

    stmt = await account_statement(fake, acc_a)

    assert isinstance(stmt, AccountStatement)
    assert stmt.account_id == acc_a
    assert stmt.currency == "USDC"
    assert stmt.from_seq == 1
    assert stmt.to_seq == 10
    assert len(stmt.entries) == 10

    # from_seq == 1 means pre-genesis opening balance cannot be inferred from entries
    assert stmt.opening_balance is None
    # Closing balance matches last entry's balance_after
    assert stmt.closing_balance == stmt.entries[-1].balance_after

    # Hashes anchor the statement
    assert stmt.first_entry_hash == stmt.entries[0].entry_hash
    assert stmt.last_entry_hash == stmt.entries[-1].entry_hash
    assert stmt.entries[0].prev_hash == GENESIS
    assert stmt.chain_verified is True


async def test_window_slicing() -> None:
    """Verify slicing window from_seq=4 to_seq=7 yields exactly 4 entries with exact bounds."""
    fake = FakeLedgerStore()
    acc_a, _, _ = await run_script(fake, 10)

    full_stmt = await account_statement(fake, acc_a)
    sliced = await account_statement(fake, acc_a, from_seq=4, to_seq=7)

    assert sliced.from_seq == 4
    assert sliced.to_seq == 7
    assert len(sliced.entries) == 4
    assert [e.seq for e in sliced.entries] == [4, 5, 6, 7]

    # Opening balance is balance_after of entry 3
    assert sliced.opening_balance == full_stmt.entries[2].balance_after
    # Closing balance is balance_after of entry 7
    assert sliced.closing_balance == full_stmt.entries[6].balance_after

    assert sliced.first_entry_hash == full_stmt.entries[3].entry_hash
    assert sliced.last_entry_hash == full_stmt.entries[6].entry_hash
    assert sliced.chain_verified is True


async def test_from_seq_1_opening_balance_none() -> None:
    """Verify documented semantics: from_seq == 1 always yields opening_balance None."""
    fake = FakeLedgerStore()
    acc_a, _, _ = await run_script(fake, 10)

    stmt = await account_statement(fake, acc_a, from_seq=1, to_seq=5)
    assert stmt.from_seq == 1
    assert stmt.opening_balance is None
    assert len(stmt.entries) == 5
    assert stmt.closing_balance == stmt.entries[-1].balance_after


# =============================================================================
# 2. BALANCE AT ARITHMETIC & BOUNDS
# =============================================================================


async def test_balance_at_exactness() -> None:
    """Verify balance_at point-in-time calculation at various sequence checkpoints."""
    fake = FakeLedgerStore()
    acc_a, _, _ = await run_script(fake, 10)
    full = await account_statement(fake, acc_a)

    # Point-in-time balance at sequence 3 and 7
    bal_at_3 = await balance_at(fake, acc_a, seq=3)
    assert bal_at_3 == full.entries[2].balance_after

    bal_at_7 = await balance_at(fake, acc_a, seq=7)
    assert bal_at_7 == full.entries[6].balance_after

    # Sequence beyond latest entry returns latest balance
    bal_beyond = await balance_at(fake, acc_a, seq=999)
    assert bal_beyond == full.entries[-1].balance_after

    # Sequence before first entry (seq < 1 or seq=0) returns None
    bal_before_first = await balance_at(fake, acc_a, seq=0)
    assert bal_before_first is None


# =============================================================================
# 3. OVER-CAP & BOUNDS ENFORCEMENT
# =============================================================================


def test_validate_statement_range_direct() -> None:
    """Verify pure validator rejects invalid boundaries and windows exceeding cap."""
    # Legal ranges
    validate_statement_range(1, 10)
    validate_statement_range(1, MAX_STATEMENT_ENTRIES)

    # from_seq < 1
    with pytest.raises(ValueError, match="from_seq"):
        validate_statement_range(0, 10)

    # to_seq < 1
    with pytest.raises(ValueError, match="to_seq"):
        validate_statement_range(1, 0)

    # to_seq < from_seq
    with pytest.raises(ValueError, match="to_seq"):
        validate_statement_range(10, 5)

    # Over cap: 10_001 window size
    with pytest.raises(ValueError, match="exceeds maximum statement entries"):
        validate_statement_range(1, 10_001)


async def test_account_statement_over_cap_before_io() -> None:
    """Verify account_statement enforces cap upfront before any store pagination."""
    fake = FakeLedgerStore()
    acc_id = uuid.uuid4()

    # Even with an uninitialized account, over-cap must fail at validate_statement_range
    # with ValueError, NOT LedgerNotFoundError
    with pytest.raises(ValueError, match="exceeds maximum statement entries"):
        await account_statement(fake, acc_id, from_seq=1, to_seq=10_001)


# =============================================================================
# 4. CHAIN VERIFICATION ALARM PATHS (TAMPER & GAP)
# =============================================================================


async def test_chain_verified_false_on_tamper(caplog: pytest.LogCaptureFixture) -> None:
    """Verify fake.corrupt_entry causes chain_verified=False and logs alarm."""
    fake = FakeLedgerStore()
    acc_a, _, _ = await run_script(fake, 10)

    # Tamper with entry 5
    fake.corrupt_entry(5)

    with caplog.at_level(logging.ERROR):
        stmt = await account_statement(fake, acc_a)

    assert stmt.chain_verified is False
    assert len(stmt.entries) == 10
    # Alarm log verification: account_id and window present
    assert str(acc_a) in caplog.text
    assert "1..10" in caplog.text


async def test_chain_verified_false_on_continuity_gap(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify fake.drop_entry causes chain_verified=False due to sequence/hash gap."""
    fake = FakeLedgerStore()
    acc_a, _, _ = await run_script(fake, 10)

    # Drop entry 5 to create continuity gap (4 -> 6)
    fake.drop_entry(5)

    with caplog.at_level(logging.ERROR):
        stmt = await account_statement(fake, acc_a)

    assert stmt.chain_verified is False
    assert len(stmt.entries) == 9
    assert str(acc_a) in caplog.text


# =============================================================================
# 5. GET_HISTORY CONTRACT CONFORMANCE THROUGH FAKE
# =============================================================================


async def test_fake_get_history_contract_conformance() -> None:
    """Verify FakeLedgerStore reuses validate_history_params and rejects out-of-spec args."""
    fake = FakeLedgerStore()
    acc_id = uuid.uuid4()
    fake.init_account(acc_id, currency="USDC")

    with pytest.raises(ValueError, match="limit"):
        await fake.get_history(acc_id, limit=0)

    with pytest.raises(ValueError, match="limit"):
        await fake.get_history(acc_id, limit=101)

    with pytest.raises(ValueError, match="before_seq"):
        await fake.get_history(acc_id, limit=50, before_seq=0)


# =============================================================================
# 6. PROTOCOL CONFORMANCE (Task 15 Symmetry)
# =============================================================================


def test_fake_protocol_runtime_checkable() -> None:
    """Verify FakeLedgerStore satisfies isinstance(..., LedgerStore)."""
    fake = FakeLedgerStore()
    assert isinstance(fake, LedgerStore)


def test_fake_store_signature_conformance() -> None:
    """Verify method signatures on FakeLedgerStore exactly match the frozen Protocol."""
    for method_name in (
        "post_transaction",
        "get_balance",
        "get_transaction",
        "get_history",
        "verify_chain",
    ):
        protocol_sig = inspect.signature(getattr(LedgerStore, method_name))
        fake_sig = inspect.signature(getattr(FakeLedgerStore, method_name))

        # Check parameter names, order, and kinds
        assert list(protocol_sig.parameters.keys()) == list(fake_sig.parameters.keys())
        for param_name, proto_param in protocol_sig.parameters.items():
            fake_param = fake_sig.parameters[param_name]
            assert proto_param.kind == fake_param.kind
            assert proto_param.default == fake_param.default


# =============================================================================
# 7. DOMAIN -> FINGERPRINT BRIDGE
# =============================================================================


def test_to_fingerprint_mapping() -> None:
    """Verify to_fingerprint bridges domain LedgerEntry to EntryFingerprint correctly."""
    acc_id = uuid.uuid4()
    tx_id = uuid.uuid4()
    entry = LedgerEntry(
        seq=1,
        tx_id=tx_id,
        account_id=acc_id,
        direction=Direction.DEBIT,
        amount=5000,
        currency="USDC",
        balance_after=95000,
        version=2,
        prev_hash=GENESIS,
        entry_hash="a" * 64,
        created_at="2026-09-24T12:00:00.000000Z",
    )

    fp = to_fingerprint(entry)
    assert isinstance(fp, EntryFingerprint)
    assert fp.seq == 1
    assert fp.tx_id == str(tx_id)
    assert fp.account_id == str(acc_id)
    assert fp.direction == Direction.DEBIT
    assert fp.amount == 5000
    assert fp.currency == "USDC"
    assert fp.balance_after == 95000
    assert fp.version == 2
    assert fp.created_at == "2026-09-24T12:00:00.000000Z"
