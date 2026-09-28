"""KYC integration package (Block J, Task 55).

Contains KYC provider protocol, adapters for Sumsub, Trulioo, and Manual mode.
"""

from __future__ import annotations

from .manual import ManualProvider
from .protocol import KycProvider, KycState, VerificationStart
from .sumsub import FORMULA_DOC, SUMSUB_STATUS_MAP, SumsubProvider
from .trulioo import TRULIOO_STATUS_MAP, TruliooProvider

__all__ = [
    "FORMULA_DOC",
    "SUMSUB_STATUS_MAP",
    "TRULIOO_STATUS_MAP",
    "KycProvider",
    "KycState",
    "ManualProvider",
    "SumsubProvider",
    "TruliooProvider",
    "VerificationStart",
]
