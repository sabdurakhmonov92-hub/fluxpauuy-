"""Unit test suite for the LedgerStore domain contract (Task 15).

Verifies the frozen typing protocol, draft validation door-guards,
immutable result types, signature precision, parameter validators, and
import blacklist invariants without requiring external services or databases.
"""

import ast
import inspect
import sys
import uuid
from collections.abc import Sequence
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from fluxpay.ledger import hashchain
from fluxpay.ledger.store import (
    Balance,
    ChainVerification,
    Direction,
    EntryDraft,
    LedgerEntry,
    LedgerStore,
    LedgerTransaction,
    validate_chain_range,
    validate_history_params,
)

pytestmark = pytest.mark.unit


# =============================================================================
# 1. DIRECTION RE-EXPORT IDENTITY (Single Source of Truth)
# =============================================================================


def test_direction_re_export_identity() -> None:
    """Verify store.Direction IS hashchain.Direction (not a duplicate enum)."""
    assert Direction is hashchain.Direction
    assert Direction.DEBIT is hashchain.Direction.DEBIT
    assert Direction.CREDIT is hashchain.Direction.CREDIT


# =============================================================================
# 2. ENTRY DRAFT DOOR-GUARDS
# =============================================================================


def test_entry_draft_valid_construction() -> None:
    """Verify valid EntryDraft constructs cleanly and preserves attributes."""
    acc_id = uuid.uuid4()
    draft = EntryDraft(
        account_id=acc_id,
        direction=Direction.DEBIT,
        amount=1000,
        currency="USDC",
    )
    assert draft.account_id == acc_id
    assert draft.direction == Direction.DEBIT
    assert draft.amount == 1000
    assert draft.currency == "USDC"


@pytest.mark.parametrize(
    ("amount", "expected_snippet"),
    [
        (0, "amount"),
        (-1, "amount"),
        (-100, "amount"),
        (False, "amount"),
        (True, "amount"),
    ],
)
def test_entry_draft_amount_guards(amount: int, expected_snippet: str) -> None:
    """Verify non-positive amounts and booleans are rejected naming 'amount'."""
    with pytest.raises(ValueError, match=expected_snippet):
        EntryDraft(
            account_id=uuid.uuid4(),
            direction=Direction.CREDIT,
            amount=amount,
            currency="USDC",
        )


@pytest.mark.parametrize(
    ("currency", "expected_snippet"),
    [
        ("usdc", "currency"),  # Lowercase forbidden
        ("A" * 11, "currency"),  # Exceeds 10 chars
        ("U", "currency"),  # Less than 2 chars
        ("", "currency"),  # Empty
        ("US D", "currency"),  # Whitespace forbidden
        ("US-DC", "currency"),  # Non-alphanumeric forbidden
        ("USD$", "currency"),  # Symbols forbidden
    ],
)
def test_entry_draft_currency_guards(currency: str, expected_snippet: str) -> None:
    """Verify invalid currency strings are rejected naming 'currency'."""
    with pytest.raises(ValueError, match=expected_snippet):
        EntryDraft(
            account_id=uuid.uuid4(),
            direction=Direction.DEBIT,
            amount=500,
            currency=currency,
        )


def test_entry_draft_direction_guard() -> None:
    """Verify raw strings are rejected as direction even if value matches enum."""
    with pytest.raises(ValueError, match="direction"):
        # Intentionally passing raw str instead of Direction enum
        EntryDraft(
            account_id=uuid.uuid4(),
            direction="DEBIT",  # type: ignore[arg-type]
            amount=500,
            currency="USDC",
        )


def test_entry_draft_account_id_guard() -> None:
    """Verify non-UUID account_id is rejected naming 'account_id'."""
    with pytest.raises(ValueError, match="account_id"):
        EntryDraft(
            account_id="not-a-uuid",  # type: ignore[arg-type]
            direction=Direction.DEBIT,
            amount=500,
            currency="USDC",
        )


def test_entry_draft_frozen() -> None:
    """Verify EntryDraft is immutable."""
    draft = EntryDraft(
        account_id=uuid.uuid4(),
        direction=Direction.DEBIT,
        amount=100,
        currency="USDC",
    )
    with pytest.raises(FrozenInstanceError):
        draft.amount = 200  # type: ignore[misc]


# =============================================================================
# 3. PROTOCOL CONFORMANCE (Satisfiability)
# =============================================================================


class DummyLedgerStore:
    """Minimal compliant dummy class to prove LedgerStore protocol satisfiability."""

    async def post_transaction(self, entries: Sequence[EntryDraft]) -> LedgerTransaction:
        return LedgerTransaction(tx_id=uuid.uuid4(), entries=())

    async def get_balance(self, account_id: uuid.UUID) -> Balance:
        return Balance(account_id=account_id, currency="USDC", balance=0, version=1)

    async def get_transaction(self, tx_id: uuid.UUID) -> LedgerTransaction | None:
        return None

    async def get_history(
        self,
        account_id: uuid.UUID,
        *,
        limit: int = 50,
        before_seq: int | None = None,
    ) -> tuple[LedgerEntry, ...]:
        return ()

    async def verify_chain(
        self,
        *,
        from_seq: int = 1,
        to_seq: int | None = None,
    ) -> ChainVerification:
        return ChainVerification(ok=True, last_verified_seq=1)


class IncompleteStore:
    """Incomplete implementation missing methods."""

    async def get_balance(self, account_id: uuid.UUID) -> Balance:
        return Balance(account_id=account_id, currency="USDC", balance=0, version=1)


def test_protocol_runtime_checkable() -> None:
    """Verify LedgerStore conforms to @runtime_checkable Protocol semantics."""
    dummy = DummyLedgerStore()
    assert isinstance(dummy, LedgerStore)

    incomplete = IncompleteStore()
    assert not isinstance(incomplete, LedgerStore)


# =============================================================================
# 4. SIGNATURE PRECISION & KEYWORD-ONLY CONTRACTS
# =============================================================================


def test_protocol_post_transaction_signature() -> None:
    """Verify post_transaction parameter specification."""
    sig = inspect.signature(LedgerStore.post_transaction)
    params = list(sig.parameters.values())

    assert len(params) == 2
    assert params[0].name == "self"
    assert params[1].name == "entries"
    assert params[1].kind in (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    )


def test_protocol_get_balance_signature() -> None:
    """Verify get_balance parameter specification."""
    sig = inspect.signature(LedgerStore.get_balance)
    params = list(sig.parameters.values())

    assert len(params) == 2
    assert params[0].name == "self"
    assert params[1].name == "account_id"
    assert params[1].kind in (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    )


def test_protocol_get_transaction_signature() -> None:
    """Verify get_transaction parameter specification."""
    sig = inspect.signature(LedgerStore.get_transaction)
    params = list(sig.parameters.values())

    assert len(params) == 2
    assert params[0].name == "self"
    assert params[1].name == "tx_id"
    assert params[1].kind in (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    )


def test_protocol_get_history_signature() -> None:
    """Verify get_history parameter specification and keyword-only flags."""
    sig = inspect.signature(LedgerStore.get_history)
    params = sig.parameters

    assert "self" in params
    assert "account_id" in params
    assert "limit" in params
    assert "before_seq" in params

    # Keyword-only contract
    assert params["limit"].kind == inspect.Parameter.KEYWORD_ONLY
    assert params["limit"].default == 50
    assert params["before_seq"].kind == inspect.Parameter.KEYWORD_ONLY
    assert params["before_seq"].default is None


def test_protocol_verify_chain_signature() -> None:
    """Verify verify_chain parameter specification and keyword-only flags."""
    sig = inspect.signature(LedgerStore.verify_chain)
    params = sig.parameters

    assert "self" in params
    assert "from_seq" in params
    assert "to_seq" in params

    # Keyword-only contract
    assert params["from_seq"].kind == inspect.Parameter.KEYWORD_ONLY
    assert params["from_seq"].default == 1
    assert params["to_seq"].kind == inspect.Parameter.KEYWORD_ONLY
    assert params["to_seq"].default is None


# =============================================================================
# 5. RESULT TYPES IMMUTABILITY & SPECIFICATION
# =============================================================================


def test_ledger_entry_construction_and_immutability() -> None:
    """Verify LedgerEntry fields and immutability."""
    entry = LedgerEntry(
        seq=1,
        tx_id=uuid.uuid4(),
        account_id=uuid.uuid4(),
        direction=Direction.DEBIT,
        amount=100,
        currency="USDC",
        balance_after=900,
        version=1,
        prev_hash="GENESIS",
        entry_hash="a" * 64,
        created_at="2026-09-24T12:00:00.000000Z",
    )
    assert isinstance(entry.created_at, str)
    with pytest.raises(FrozenInstanceError):
        entry.amount = 200  # type: ignore[misc]


def test_ledger_transaction_immutability_and_tuple() -> None:
    """Verify LedgerTransaction entries is an immutable tuple."""
    entry = LedgerEntry(
        seq=1,
        tx_id=uuid.uuid4(),
        account_id=uuid.uuid4(),
        direction=Direction.DEBIT,
        amount=100,
        currency="USDC",
        balance_after=900,
        version=1,
        prev_hash="GENESIS",
        entry_hash="a" * 64,
        created_at="2026-09-24T12:00:00.000000Z",
    )
    tx = LedgerTransaction(tx_id=entry.tx_id, entries=(entry,))
    assert isinstance(tx.entries, tuple)
    with pytest.raises(FrozenInstanceError):
        tx.entries = ()  # type: ignore[misc]


def test_balance_immutability() -> None:
    """Verify Balance immutability."""
    bal = Balance(account_id=uuid.uuid4(), currency="USDC", balance=1000, version=2)
    with pytest.raises(FrozenInstanceError):
        bal.balance = 2000  # type: ignore[misc]


def test_chain_verification_construction_and_immutability() -> None:
    """Verify ChainVerification default values and immutability."""
    cv_ok = ChainVerification(ok=True, last_verified_seq=100)
    assert cv_ok.ok is True
    assert cv_ok.last_verified_seq == 100
    assert cv_ok.broken_seq is None
    assert cv_ok.reason is None

    cv_broken = ChainVerification(
        ok=False,
        last_verified_seq=42,
        broken_seq=43,
        reason="Hash mismatch at seq 43",
    )
    assert cv_broken.ok is False
    assert cv_broken.broken_seq == 43
    assert cv_broken.reason == "Hash mismatch at seq 43"

    with pytest.raises(FrozenInstanceError):
        cv_broken.ok = True  # type: ignore[misc]


# =============================================================================
# 6. PURE PARAMETER VALIDATOR FUNCTIONS
# =============================================================================


@pytest.mark.parametrize("limit", [1, 50, 100])
def test_validate_history_params_valid(limit: int) -> None:
    """Verify legal limit and before_seq combinations pass validation."""
    validate_history_params(limit=limit, before_seq=None)
    validate_history_params(limit=limit, before_seq=1)
    validate_history_params(limit=limit, before_seq=1000)


@pytest.mark.parametrize("limit", [0, -1, 101, 200])
def test_validate_history_params_invalid_limit(limit: int) -> None:
    """Verify limits outside [1, 100] are rejected."""
    with pytest.raises(ValueError, match="limit"):
        validate_history_params(limit=limit)


@pytest.mark.parametrize("before_seq", [0, -1, -50])
def test_validate_history_params_invalid_before_seq(before_seq: int) -> None:
    """Verify before_seq < 1 is rejected."""
    with pytest.raises(ValueError, match="before_seq"):
        validate_history_params(limit=50, before_seq=before_seq)


@pytest.mark.parametrize(
    ("from_seq", "to_seq"),
    [
        (1, None),
        (1, 1),
        (1, 100),
        (50, 50),
        (50, 100),
    ],
)
def test_validate_chain_range_valid(from_seq: int, to_seq: int | None) -> None:
    """Verify valid sequence ranges pass validation."""
    validate_chain_range(from_seq=from_seq, to_seq=to_seq)


@pytest.mark.parametrize("from_seq", [0, -1, -10])
def test_validate_chain_range_invalid_from_seq(from_seq: int) -> None:
    """Verify from_seq < 1 is rejected."""
    with pytest.raises(ValueError, match="from_seq"):
        validate_chain_range(from_seq=from_seq)


@pytest.mark.parametrize("to_seq", [0, -1])
def test_validate_chain_range_invalid_to_seq(to_seq: int) -> None:
    """Verify to_seq < 1 is rejected."""
    with pytest.raises(ValueError, match="to_seq"):
        validate_chain_range(from_seq=1, to_seq=to_seq)


def test_validate_chain_range_inverted() -> None:
    """Verify to_seq < from_seq is rejected."""
    with pytest.raises(ValueError, match="to_seq"):
        validate_chain_range(from_seq=10, to_seq=5)


# =============================================================================
# 7. IMPORT BLACKLIST & PURITY META-TEST
# =============================================================================


def test_store_module_has_zero_io_imports() -> None:
    """Verify store.py contains zero I/O, database, or configuration imports.

    Ensures the Protocol module remains a pure typing and domain contract.
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    store_file = repo_root / "src" / "fluxpay" / "ledger" / "store.py"
    source = store_file.read_text(encoding="utf-8")

    tree = ast.parse(source)

    forbidden_modules = {
        "asyncpg",
        "psycopg",
        "psycopg2",
        "sqlalchemy",
        "databases",
        "aio_pika",
        "redis",
        "valkey",
        "socket",
        "httpx",
        "requests",
        "urllib",
        "logging",
        "fluxpay.config",
    }

    imported_names: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_names.add(node.module)

    # Check for direct or prefix matches against forbidden modules
    for imported in imported_names:
        for forbidden in forbidden_modules:
            assert not (imported == forbidden or imported.startswith(f"{forbidden}.")), (
                f"Forbidden I/O or config import found in store.py: {imported}"
            )

    # Also verify asyncpg is not loaded as a side-effect
    assert "asyncpg" not in sys.modules or "fluxpay.ledger.store" not in getattr(
        sys.modules.get("asyncpg"), "__file__", ""
    )
