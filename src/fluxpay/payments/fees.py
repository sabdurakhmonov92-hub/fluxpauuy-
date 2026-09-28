"""Payments foundation: exact fee calculation and mathematical policy.

Module Policy & Audit-Facing Fee Contract
==========================================

1. Mathematical Specification
-----------------------------
The platform processing fee is computed strictly in minor units as a flat 1% of the
payment principal:
    fee_minor = (amount_minor * FEE_BPS) // 10_000
where FEE_BPS = 100 (100 basis points = 1.00%).
Since FEE_BPS == 100, this integer floor calculation is exact and equivalent to:
    fee_minor = amount_minor // 100

2. Rounding Direction: Why Floor Rounding is Mandated (The Trust Contract)
--------------------------------------------------------------------------
In integer financial ledger math, non-integral minor units cannot exist on a balance sheet.
A definitive rounding direction must be chosen:
    - Floor:  fee = amount // 100
    - Ceil:   fee = (amount + 99) // 100
    - Half:   fee = (amount + 50) // 100

WHY FLOOR (Conservative-to-Payer):
- Fee Taker Invariant: The fee taker (platform) MUST NEVER gain an unearned minor unit
  through upward rounding. An agent sending 1,001 minor units at 1% generates a theoretical
  fee of 10.01 minor units. Under ceiling rounding, the agent would be assessed 11 minor units
  (effective rate 1.0989% > 1.0000%). Charging the payer for a fractional cent that never
  occurred violates the advertised 1% fee contract.
- Autonomous Agent Predictability: Autonomous agents execute algorithmic budgeting and
  pre-flight balance checks against strict allowances. Overcharging by even 1 minor unit
  creates spurious pre-flight rejections, reconciliation friction, and failed payment loops.
- Fiduciary Transparency: Conservative-to-payer rounding preserves trust as an absolute
  differentiator for high-throughput machine-to-machine commerce.
- Why Ceiling was REJECTED: Ceiling rounding is platform-favorable. It silently siphons
  micro-cents from payers, introducing regulatory audit exposure regarding deceptive fee
  disclosure and unearned revenue accrual.

3. Payment Amount Boundaries
----------------------------
- Minimum Payment: amount_minor >= MIN_PAYMENT_MINOR (1,000 minor units).
  In standard 6-decimal tokens (e.g. USDC, where 1 minor unit = 10^-6 = $0.000001):
    * 100 minor units = 0.000100 USDC = $0.0001 (one-hundredth of a cent).
    * 1,000 minor units = 0.001000 USDC = $0.001 (one-tenth of a cent / 1 mill).
  DECISION: MIN_PAYMENT_MINOR is set to 1,000 ($0.001). Sub-milli payments represent dust
  that bloats double-entry ledger journals, pollutes database b-tree indexes, and triggers
  needless webhook ingestion overhead without viable economic utility. Configurable
  per-tenant minimum thresholds belong to Phase 2.
- Maximum Payment: amount_minor <= MAX_PAYMENT_MINOR (10^15 minor units = 1 trillion USDC).
  PostgreSQL signed 64-bit BIGINT has an upper bound of 2^63 - 1 ≈ 9.22 * 10^18.
  At amount = 10^15, fee = 10^13, total = 1.01 * 10^15 minor units.
  This sanity ceiling ensures amount + fee fits comfortably in a BIGINT column with massive
  headroom for aggregate balance sums, preventing integer overflow in storage or accumulator math.

4. Zero-Fee Path Impossibility (The Interplay)
---------------------------------------------
Mathematically, for any amount_minor < 100, floor(amount_minor / 100) evaluates to 0.
DECISION: While the floor formula mathematically permits fee = 0 for inputs < 100, the
operational minimum payment boundary (1,000 minor units) makes zero-fee payments impossible
in practice:
    MIN_PAYMENT_MINOR = 1,000
    fee_minor = 1,000 // 100 = 10 >= 1
Because MIN_PAYMENT_MINOR (1,000) >> 100, any transaction admissible to quote() guarantees
fee_minor >= 10. Consequently, no zero-fee transaction can ever pass the platform boundary.

5. Three-Entry Ledger Invariant (Zero Dust Loss)
------------------------------------------------
Task 31 service orchestration decomposes a FeeQuote into three atomic double-entry legs:
    1. Agent Account DEBIT:         total_minor = amount_minor + fee_minor
    2. Merchant Account CREDIT:      amount_minor
    3. Platform Fees Account CREDIT: fee_minor
The arithmetic identity:
    total_minor == amount_minor + fee_minor
holds identically and unconditionally for all FeeQuote instances.
The double-entry sum:
    Debits - Credits = total_minor - (amount_minor + fee_minor) == 0
guarantees exactly zero dust loss across the entire integer minor unit domain.

6. Tuning Knob
--------------
FEE_BPS = 100 (100 basis points = 1.00%).
This is the single tuning knob for fee calculation in Phase 1.
Phase 2 will introduce tenant-specific basis points and fee tiers.
Changing FEE_BPS in the future affects only newly quoted transactions; historical ledger
records remain permanently immutable.
"""

import re
from dataclasses import dataclass
from typing import Final

# -----------------------------------------------------------------------------
# CONSTANTS & CONFIGURATION
# -----------------------------------------------------------------------------

# Single tuning knob: 1% flat fee = 100 basis points (100 bps = 1.00%).
# Phase 2 introduces per-tenant basis points; changing bps affects NEW quotes only.
FEE_BPS: Final[int] = 100

# Minimum payment: 1,000 minor units ($0.001 in 6-decimal USDC).
# Sub-milli payments are dust that pollutes ledger history and webhook queues.
MIN_PAYMENT_MINOR: Final[int] = 1_000

# Maximum payment: 10^15 minor units (1 trillion USDC in 6-decimal minor units).
# Sanity ceiling ensuring amount + fee fits comfortably in PostgreSQL signed BIGINT.
MAX_PAYMENT_MINOR: Final[int] = 1_000_000_000_000_000  # 10^15

# Task 12 L1 mirror: Currency grammar regex (2 to 10 uppercase alphanumeric characters).
# Pure leaf discipline: mirrored rather than imported from fluxpay.contracts / fluxpay.ledger.
_CURRENCY_REGEX: Final[re.Pattern[str]] = re.compile(r"^[A-Z0-9]{2,10}$")


# -----------------------------------------------------------------------------
# DOMAIN MODELS
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FeeQuote:
    """Immutable quote capturing fee breakdown and total debit for a payment.

    Attributes:
        amount_minor: Principal payment amount credited to merchant (minor units).
        fee_minor: Platform fee credited to fees account (minor units).
        total_minor: Full debit amount charged to paying agent (minor units).
        currency: Asset currency code conforming to ^[A-Z0-9]{2,10}$.
    """

    amount_minor: int
    fee_minor: int
    total_minor: int
    currency: str

    def __post_init__(self) -> None:
        """Enforce domain invariants upon quote instantiation."""
        # StrictInt discipline: in Python, bool is a subclass of int. Reject booleans.
        if type(self.amount_minor) is bool or not isinstance(self.amount_minor, int):
            raise ValueError("amount_minor: must be an integer (bool rejected)")
        if type(self.fee_minor) is bool or not isinstance(self.fee_minor, int):
            raise ValueError("fee_minor: must be an integer (bool rejected)")
        if type(self.total_minor) is bool or not isinstance(self.total_minor, int):
            raise ValueError("total_minor: must be an integer (bool rejected)")
        if self.amount_minor < 0 or self.fee_minor < 0:
            raise ValueError("amount_minor and fee_minor must be non-negative")
        # Three-entry balance identity: total must equal amount + fee with zero dust loss
        if self.total_minor != self.amount_minor + self.fee_minor:
            raise ValueError(
                f"total_minor ({self.total_minor}) must exactly equal "
                f"amount_minor ({self.amount_minor}) + fee_minor ({self.fee_minor})"
            )
        if not isinstance(self.currency, str) or not _CURRENCY_REGEX.fullmatch(self.currency):
            raise ValueError(
                f"currency: must match regex {_CURRENCY_REGEX.pattern} (e.g. 'USDC', 'USD')"
            )


# -----------------------------------------------------------------------------
# PURE API
# -----------------------------------------------------------------------------


def quote(amount_minor: int, currency: str = "USDC") -> FeeQuote:
    """Compute an exact, floored fee quote for a payment.

    Validates financial invariants, currency grammar, and operational bounds.

    Args:
        amount_minor: Principal amount in minor units to transfer to merchant.
        currency: Currency symbol (default 'USDC'). Must match ^[A-Z0-9]{2,10}$.

    Returns:
        FeeQuote containing amount_minor, fee_minor, total_minor, and currency.

    Raises:
        ValueError: If amount_minor is not an int (or is bool), if amount_minor is outside
            [MIN_PAYMENT_MINOR, MAX_PAYMENT_MINOR], or if currency fails grammar validation.
    """
    # 1. StrictInt validation: reject bool and non-int
    if type(amount_minor) is bool or not isinstance(amount_minor, int):
        raise ValueError(
            f"amount_minor: must be an integer, got {type(amount_minor).__name__} "
            "(bool rejected under StrictInt philosophy)"
        )

    # 2. Operational bounds validation
    if amount_minor < MIN_PAYMENT_MINOR:
        raise ValueError(
            f"amount_minor ({amount_minor}) is below minimum allowed payment "
            f"({MIN_PAYMENT_MINOR} minor units)"
        )
    if amount_minor > MAX_PAYMENT_MINOR:
        raise ValueError(
            f"amount_minor ({amount_minor}) exceeds maximum allowed payment "
            f"({MAX_PAYMENT_MINOR} minor units)"
        )

    # 3. Currency grammar validation (Task 12 L1 mirror)
    if not isinstance(currency, str) or not _CURRENCY_REGEX.fullmatch(currency):
        raise ValueError(
            f"currency: must match regex {_CURRENCY_REGEX.pattern} (e.g. 'USDC', 'USD')"
        )

    # 4. Exact floor fee calculation (1% = 100 bps)
    # Floor division ensures the platform never takes an unearned minor unit.
    fee_minor = (amount_minor * FEE_BPS) // 10_000
    total_minor = amount_minor + fee_minor

    return FeeQuote(
        amount_minor=amount_minor,
        fee_minor=fee_minor,
        total_minor=total_minor,
        currency=currency,
    )
