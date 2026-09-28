"""Unit tests for payments fee calculation and mathematical policy contract.

Validates:
1. Exact floor fee math table across critical boundaries (1000 -> 10, 10M -> 100K, 10^15 -> 10^13).
2. Minimum payment boundary enforcement (999 rejected).
3. Maximum payment sanity ceiling enforcement (10^15 + 1 rejected).
4. StrictInt monetary discipline (bool rejected, non-int rejected).
5. Currency grammar validation (Task 12 regex mirror).
6. Total identity property test (1000 deterministic seeded cases: total == amount + fee).
7. Zero-fee impossibility proof (MIN_PAYMENT guarantees fee >= 10 >= 1).
8. FeeQuote immutability and slots enforcement.
9. Pure-leaf meta-test: fees.py imports NOTHING from fluxpay.
"""

import ast
import random
from dataclasses import FrozenInstanceError, is_dataclass
from pathlib import Path
from typing import Any

import pytest

from fluxpay.payments.fees import (
    FEE_BPS,
    MAX_PAYMENT_MINOR,
    MIN_PAYMENT_MINOR,
    FeeQuote,
    quote,
)

pytestmark = pytest.mark.unit


# ==============================================================================
# 1. Exact Floor Math Table & Boundary Checks
# ==============================================================================


@pytest.mark.parametrize(
    ("amount_minor", "expected_fee", "expected_total"),
    [
        (1_000, 10, 1_010),
        (1_001, 10, 1_011),  # 10.01 floored to 10 (platform never takes unearned minor unit)
        (1_099, 10, 1_109),  # 10.99 floored to 10
        (1_100, 11, 1_111),  # 11.00 exact
        (10_000_000, 100_000, 10_100_000),  # $10.00 at 6-dec minor -> 100K fee ($0.10)
        (
            1_000_000_000_000_000,
            10_000_000_000_000,
            1_010_000_000_000_000,
        ),  # 10^15 (1 trillion USDC) -> 10^13 fee
    ],
)
def test_quote_exact_floor_table(
    amount_minor: int,
    expected_fee: int,
    expected_total: int,
) -> None:
    """Validate exact fee table confirming floor rounding and total identity."""
    result = quote(amount_minor=amount_minor, currency="USDC")
    assert result.amount_minor == amount_minor
    assert result.fee_minor == expected_fee
    assert result.total_minor == expected_total
    assert result.currency == "USDC"
    # Arithmetic identity
    assert result.total_minor == result.amount_minor + result.fee_minor


def test_quote_default_currency_is_usdc() -> None:
    """Validate quote defaults to USDC when currency is omitted."""
    result = quote(1_000)
    assert result.currency == "USDC"


# ==============================================================================
# 2. StrictInt & Type Rejections
# ==============================================================================


def test_quote_rejects_boolean_amounts() -> None:
    """Validate that booleans are strictly rejected under StrictInt philosophy.

    In Python, isinstance(True, int) is True and isinstance(False, int) is True.
    Financial code must explicitly reject booleans to prevent True becoming 1 minor unit.
    """
    with pytest.raises(ValueError, match="bool rejected"):
        quote(True)

    with pytest.raises(ValueError, match="bool rejected"):
        quote(False)


@pytest.mark.parametrize("invalid_amount", [1000.5, "1000", None, [1000], {"amount": 1000}])
def test_quote_rejects_non_integer_amounts(invalid_amount: Any) -> None:
    """Validate rejection of floats, strings, and other non-integers."""
    with pytest.raises(ValueError, match="must be an integer"):
        quote(invalid_amount)


# ==============================================================================
# 3. Operational Bounds (MIN and MAX)
# ==============================================================================


def test_quote_rejects_below_minimum_payment() -> None:
    """Validate that amounts strictly below MIN_PAYMENT_MINOR (1,000) are rejected."""
    # 999: would mathematically floor to 9 minor units fee, but MIN blocks it
    with pytest.raises(ValueError, match=r"below minimum allowed payment"):
        quote(999)

    with pytest.raises(ValueError, match=r"below minimum allowed payment"):
        quote(MIN_PAYMENT_MINOR - 1)

    with pytest.raises(ValueError, match=r"below minimum allowed payment"):
        quote(0)

    with pytest.raises(ValueError, match=r"below minimum allowed payment"):
        quote(-1)

    with pytest.raises(ValueError, match=r"below minimum allowed payment"):
        quote(-1_000)


def test_quote_rejects_above_maximum_payment() -> None:
    """Validate that amounts exceeding MAX_PAYMENT_MINOR (10^15) are rejected."""
    with pytest.raises(ValueError, match=r"exceeds maximum allowed payment"):
        quote(MAX_PAYMENT_MINOR + 1)

    with pytest.raises(ValueError, match=r"exceeds maximum allowed payment"):
        quote(10**16)


def test_quote_accepts_exact_boundary_payments() -> None:
    """Validate that exact MIN_PAYMENT_MINOR and MAX_PAYMENT_MINOR pass."""
    min_q = quote(MIN_PAYMENT_MINOR)
    assert min_q.amount_minor == MIN_PAYMENT_MINOR
    assert min_q.fee_minor == 10
    assert min_q.total_minor == 1010

    max_q = quote(MAX_PAYMENT_MINOR)
    assert max_q.amount_minor == MAX_PAYMENT_MINOR
    assert max_q.fee_minor == 10_000_000_000_000
    assert max_q.total_minor == 1_010_000_000_000_000


# ==============================================================================
# 4. Currency Grammar Validation (Task 12 L1 Mirror)
# ==============================================================================


@pytest.mark.parametrize(
    "valid_currency",
    [
        "USDC",
        "USD",
        "EUR",
        "BTC",
        "ETH",
        "USDT",
        "A123456789",  # 10 chars max uppercase alphanumeric
        "AB",  # 2 chars min
    ],
)
def test_quote_accepts_valid_currency_grammar(valid_currency: str) -> None:
    """Validate currencies conforming to ^[A-Z0-9]{2,10}$ are accepted."""
    q = quote(1_000, currency=valid_currency)
    assert q.currency == valid_currency


@pytest.mark.parametrize(
    "invalid_currency",
    [
        "",  # Empty
        "U",  # 1 char (min 2)
        "TOOLONGCURRENCY",  # >10 chars
        "usdc",  # Lowercase forbidden
        "USDC!",  # Special chars forbidden
        "USD C",  # Spaces forbidden
        "US_DC",  # Underscores forbidden
    ],
)
def test_quote_rejects_invalid_currency_grammar(invalid_currency: str) -> None:
    """Validate non-conforming currency tickers raise ValueError."""
    with pytest.raises(ValueError, match="currency: must match regex"):
        quote(1_000, currency=invalid_currency)


def test_quote_rejects_non_string_currency() -> None:
    """Validate non-string currency types raise ValueError."""
    with pytest.raises(ValueError, match="currency: must match regex"):
        quote(1_000, currency=123)  # type: ignore[arg-type]


# ==============================================================================
# 5. Total Identity Property Test (1,000 Deterministic Cases)
# ==============================================================================


def test_total_identity_property_randomized_1000_cases() -> None:
    """Property test: total == amount + fee EXACTLY with zero dust loss across 1,000 cases.

    Deterministic PRNG seeded with 42 (no hypothesis dependency).
    Guarantees:
    - total_minor == amount_minor + fee_minor identically.
    - fee_minor == (amount_minor * 100) // 10_000 == amount_minor // 100.
    """
    rng = random.Random(42)  # noqa: S311

    for _ in range(1_000):
        # Sample across orders of magnitude from MIN to MAX
        # Mix uniform sampling and log-scale sampling for broad coverage
        if rng.random() < 0.5:
            amount = rng.randint(MIN_PAYMENT_MINOR, 10_000_000)
        else:
            amount = rng.randint(MIN_PAYMENT_MINOR, MAX_PAYMENT_MINOR)

        q = quote(amount_minor=amount, currency="USDC")

        # 1. Total identity (the double-entry balance invariant)
        assert q.total_minor == q.amount_minor + q.fee_minor

        # 2. Exact integer floor math identity
        assert q.fee_minor == amount // 100
        assert q.fee_minor == (amount * FEE_BPS) // 10_000

        # 3. Principal preservation
        assert q.amount_minor == amount

        # 4. Strictly positive fee (never zero)
        assert q.fee_minor >= 10


# ==============================================================================
# 6. Zero-Fee Path Impossibility (The Interplay)
# ==============================================================================


def test_zero_fee_path_impossible_due_to_min_payment_interplay() -> None:
    """Verify that zero-fee payments are physically impossible through quote().

    Interplay Proof:
    - Floor math: fee = amount // 100.
    - fee would be 0 IF AND ONLY IF amount < 100.
    - BUT quote() enforces amount >= MIN_PAYMENT_MINOR = 1,000.
    - Since 1,000 // 100 = 10, the minimum possible fee across all valid quotes is 10.
    - 10 >= 1: zero-fee transactions cannot exist.
    """
    # 1. Boundary check: absolute minimum payment produces fee = 10 >= 1
    min_quote = quote(MIN_PAYMENT_MINOR)
    assert min_quote.fee_minor == 10
    assert min_quote.fee_minor >= 1

    # 2. Check all integers from 1000 to 1100: all have fee >= 10
    for amt in range(MIN_PAYMENT_MINOR, MIN_PAYMENT_MINOR + 100):
        q = quote(amt)
        assert q.fee_minor >= 10


# ==============================================================================
# 7. FeeQuote Immutability & Slots
# ==============================================================================


def test_feequote_is_frozen_slots_dataclass() -> None:
    """Validate FeeQuote is an immutable frozen dataclass with slots."""
    assert is_dataclass(FeeQuote)
    assert hasattr(FeeQuote, "__slots__")

    q = quote(1_000)
    with pytest.raises(FrozenInstanceError):
        q.amount_minor = 2_000  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        q.fee_minor = 50  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        q.total_minor = 2_050  # type: ignore[misc]


def test_feequote_direct_construction_validates_invariants() -> None:
    """Validate FeeQuote.__post_init__ catches direct instantiation invariant violations."""
    # Broken total identity
    with pytest.raises(ValueError, match=r"total_minor .* must exactly equal"):
        FeeQuote(amount_minor=1000, fee_minor=10, total_minor=1020, currency="USDC")

    # Boolean amount
    with pytest.raises(ValueError, match="bool rejected"):
        FeeQuote(amount_minor=True, fee_minor=10, total_minor=11, currency="USDC")

    # Non-int amount
    with pytest.raises(ValueError, match="amount_minor: must be an integer"):
        FeeQuote(amount_minor="1000", fee_minor=10, total_minor=1010, currency="USDC")  # type: ignore[arg-type]

    # Boolean fee_minor
    with pytest.raises(ValueError, match="bool rejected"):
        FeeQuote(amount_minor=1000, fee_minor=True, total_minor=1001, currency="USDC")

    # Non-int fee_minor
    with pytest.raises(ValueError, match="fee_minor: must be an integer"):
        FeeQuote(amount_minor=1000, fee_minor="10", total_minor=1010, currency="USDC")  # type: ignore[arg-type]

    # Boolean total_minor
    with pytest.raises(ValueError, match="bool rejected"):
        FeeQuote(amount_minor=1000, fee_minor=10, total_minor=True, currency="USDC")

    # Non-int total_minor
    with pytest.raises(ValueError, match="total_minor: must be an integer"):
        FeeQuote(amount_minor=1000, fee_minor=10, total_minor="1010", currency="USDC")  # type: ignore[arg-type]

    # Negative amount
    with pytest.raises(ValueError, match="non-negative"):
        FeeQuote(amount_minor=-1000, fee_minor=10, total_minor=-990, currency="USDC")

    # Negative fee
    with pytest.raises(ValueError, match="non-negative"):
        FeeQuote(amount_minor=1000, fee_minor=-10, total_minor=990, currency="USDC")

    # Invalid currency
    with pytest.raises(ValueError, match="currency: must match regex"):
        FeeQuote(amount_minor=1000, fee_minor=10, total_minor=1010, currency="invalid")


# ==============================================================================
# 8. Pure Leaf Meta-Test (Import Blacklist)
# ==============================================================================


def test_fees_is_pure_leaf_with_no_fluxpay_imports() -> None:
    """Contract enforcement: fees.py must NOT import anything from fluxpay.

    Pure leaf module law (Task 12 discipline):
    - Currency grammar is mirrored, not imported.
    - No dependencies on ledger, contracts, or shared errors.
    """
    fees_path = Path(__file__).resolve().parents[2] / "src" / "fluxpay" / "payments" / "fees.py"
    assert fees_path.is_file(), f"fees.py not found at {fees_path}"

    tree = ast.parse(fees_path.read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("fluxpay"), (
                    f"fees.py violates pure leaf law: imports '{alias.name}'"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert not node.module.startswith("fluxpay"), (
                    f"fees.py violates pure leaf law: imports from '{node.module}'"
                )
