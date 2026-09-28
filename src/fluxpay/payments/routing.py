"""Payments foundation: settlement rail routing and execution decision models.

Rail Model Policy (Phase 1 Seam)
================================

Phase 1 Architecture: Internal Ledger Rail Only
-----------------------------------------------
In Phase 1, all agent-to-merchant payments settle internally across the FluxPay
immutable double-entry ledger. Settlement timing is immediate.

Phase 2 Evolution: Extensible Seam
----------------------------------
External settlement rails (such as Base L2 on-chain transfers via Task 50, Stripe
fiat payouts, or cross-border payment networks) will enter via the adapter pattern (Task 49).
When external rails are introduced:
    - Rail enum expands additively (e.g., BASE_L2 = "base_l2", STRIPE = "stripe").
    - Routing decision logic becomes dynamic (driven by merchant rail preferences,
      currency support, transaction size thresholds, and agent capabilities).
    - Settlement timing expands to include asynchronous finality (e.g., "wait_finality").

Why a Dedicated Function for a Constant Decision?
-------------------------------------------------
Today, route() always returns RailDecision(rail=Rail.INTERNAL, settle_at="immediate").
This 10-line function provides an indispensable architectural seam:
1. Callers (Task 31 service orchestration) are rail-agnostic from Day 1.
2. Callers NEVER contain inline if-branches checking `if rail == "internal"`.
3. The function signature is frozen now: `route(*, amount_minor, currency)`.
4. Upgrading routing in Phase 2 requires ZERO changes to payment orchestration callers.
Forward-compatibility as engineering discipline.
"""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal

# Task 12 L1 mirror: Currency grammar regex (2 to 10 uppercase alphanumeric characters).
# Pure leaf discipline: mirrored rather than imported from fluxpay.contracts / fluxpay.ledger.
_CURRENCY_REGEX: Final[re.Pattern[str]] = re.compile(r"^[A-Z0-9]{2,10}$")


# -----------------------------------------------------------------------------
# RAIL TYPES
# -----------------------------------------------------------------------------


class Rail(StrEnum):
    """Supported settlement rails for payment routing.

    Single member in Phase 1: INTERNAL.
    StrEnum is cleaner than raw strings or Literal types: it provides strict typing,
    natural JSON/string serialization, and additive enum member expansion in Phase 2
    without breaking existing consumers or schema validators.
    """

    INTERNAL = "internal"


@dataclass(frozen=True, slots=True)
class RailDecision:
    """Settlement rail execution decision produced by the routing engine.

    Attributes:
        rail: Selected settlement rail (Phase 1: Rail.INTERNAL).
        settle_at: Settlement timing guarantee (Phase 1: "immediate").
    """

    rail: Rail
    settle_at: Literal["immediate"] = "immediate"

    def __post_init__(self) -> None:
        """Enforce domain invariants upon rail decision instantiation."""
        raw_rail: object = self.rail
        if not isinstance(raw_rail, Rail):
            rail_cls = type(raw_rail).__name__
            raise ValueError(f"rail must be an instance of Rail enum, got {rail_cls}")
        if self.settle_at != "immediate":
            raise ValueError(f"settle_at must be 'immediate' in Phase 1, got {self.settle_at!r}")


# -----------------------------------------------------------------------------
# PURE ROUTING API
# -----------------------------------------------------------------------------


def route(*, amount_minor: int, currency: str) -> RailDecision:
    """Determine settlement rail and timing for a payment transaction.

    Keyword-only parameters ensure caller signatures remain explicit and robust
    against future parameter additions (e.g. merchant_id, destination_rail, tenant_id).

    Args:
        amount_minor: Payment principal in minor units (must be positive integer).
        currency: Asset currency code matching ^[A-Z0-9]{2,10}$.

    Returns:
        RailDecision with rail=Rail.INTERNAL and settle_at="immediate".

    Raises:
        ValueError: If amount_minor is not a positive int (or is bool), or if currency
            fails grammar validation.
    """
    # StrictInt validation
    if type(amount_minor) is bool or not isinstance(amount_minor, int) or amount_minor <= 0:
        raise ValueError(
            f"amount_minor: must be a positive integer > 0, got {amount_minor!r} "
            "(bool rejected under StrictInt philosophy)"
        )

    # Currency grammar validation (Task 12 L1 mirror)
    if not isinstance(currency, str) or not _CURRENCY_REGEX.fullmatch(currency):
        raise ValueError(
            f"currency: must match regex {_CURRENCY_REGEX.pattern} (e.g. 'USDC', 'USD')"
        )

    # Phase 1: Always route to internal ledger with immediate settlement
    return RailDecision(rail=Rail.INTERNAL, settle_at="immediate")
