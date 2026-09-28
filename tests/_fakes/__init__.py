"""In-memory test fakes for FluxPay components.

WHY in tests/, not src/:
These are test oracles designed for fast, isolated unit testing without external
databases or services. Keeping them in tests/ prevents accidental production dependency.
"""

from .ledger import FakeLedgerStore

__all__ = ["FakeLedgerStore"]
