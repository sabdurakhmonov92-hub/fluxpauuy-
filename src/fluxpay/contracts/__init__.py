"""Contracts map: wire models (schemas.py) and merchant-facing event contract (webhook.schema.json).

Import Law:
Contracts import NOTHING from fluxpay — this is the leaf-est module in the repository.
Domain error shapes (from fluxpay.shared.errors) are mirrored STRUCTURALLY without direct
imports.

WHY:
errors.py is a leaf module for server-side domain failures, but contracts must remain strictly
independent and importable by external SDKs, worker runtimes, and client agents without pulling
in the server codebase, database drivers, or cryptographic dependencies. The contract-lock test
suite (tests/unit/test_contracts.py) imports both sides and enforces byte-for-byte semantic
equality via automated roundtrip tests — code, not prose.
"""

from .schemas import (
    CURRENCY_PATTERN,
    IDEMPOTENCY_KEY_PATTERN,
    MERCHANT_ID_PATTERN,
    BalanceResponse,
    ErrorBody,
    ErrorEnvelope,
    PaymentDetail,
    PaymentRequest,
    PaymentResponse,
)

__all__ = [
    "CURRENCY_PATTERN",
    "IDEMPOTENCY_KEY_PATTERN",
    "MERCHANT_ID_PATTERN",
    "BalanceResponse",
    "ErrorBody",
    "ErrorEnvelope",
    "PaymentDetail",
    "PaymentRequest",
    "PaymentResponse",
]
