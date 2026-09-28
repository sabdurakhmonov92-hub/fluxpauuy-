"""Payments map: fees.py (THIS) + routing.py (THIS) → service.py (Task 31).

Imports downward only. Provides the pure foundation for fee calculation
and rail routing decisions consumed by payment service orchestration.
"""

from fluxpay.payments.fees import (
    FEE_BPS,
    MAX_PAYMENT_MINOR,
    MIN_PAYMENT_MINOR,
    FeeQuote,
    quote,
)
from fluxpay.payments.routing import (
    Rail,
    RailDecision,
    route,
)

# Phase 1 single-currency default anchor (Task 12 single-source law).
PRIMARY_CURRENCY: str = "USDC"

__all__ = [
    "FEE_BPS",
    "MAX_PAYMENT_MINOR",
    "MIN_PAYMENT_MINOR",
    "PRIMARY_CURRENCY",
    "FeeQuote",
    "Rail",
    "RailDecision",
    "quote",
    "route",
]
