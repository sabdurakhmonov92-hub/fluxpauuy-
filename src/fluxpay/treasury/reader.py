"""Blockchain observation seam: OnChainReader Protocol and transaction status.

Task 50 Seam:
This module defines the typing protocol for querying on-chain custody balances
and transaction status from external networks (e.g. Base L2 RPC).

DESIGN DECISIONS & INVARIANTS:
1. PURE OBSERVATION SEAM:
   The reader is the ONLY touchpoint between the treasury subsystem and the
   blockchain. It exposes read-only methods for hot wallet balances, cold vault
   balances, and transaction confirmations. It has zero capability to generate,
   sign, or submit transactions.

2. FAIL-OPEN ON OBSERVATION:
   Underlying RPC adapters raise native network exceptions (e.g. httpx, asyncio,
   or connection errors). The monitor catches all reader exceptions and marks
   `sync_status='reader_error'` in `wallet_state`. Fail-open on observation is
   strictly safe because no money moves during an observation pass.
   A degraded RPC node must not spam durable notification failure records;
   instead, the staleness alarm triggers if observations remain interrupted
   beyond 30 minutes.

3. SCRIPTABLE FAKE FOR TESTS:
   `FakeReader` provides an in-memory implementation enabling both unit and
   integration tests to simulate healthy syncs, top-up triggers, surplus sweeps,
   and network RPC outages without connecting to live EVM nodes.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

__all__ = [
    "FakeReader",
    "OnChainReader",
    "TxStatus",
]


from fluxpay.integrations.base_l2 import TxStatus


@runtime_checkable
class OnChainReader(Protocol):
    """Protocol for reading on-chain balance and transaction confirmations.

    Task 50 implements this protocol against the Base L2 RPC provider.
    """

    async def read_hot_balance(self, rail: str) -> int:
        """Fetch current on-chain balance of the rail hot wallet in minor units."""
        ...

    async def read_cold_balance(self, rail: str) -> int:
        """Fetch current on-chain balance of the rail cold vault in minor units."""
        ...

    async def get_tx_status(self, rail: str, tx_hash: str) -> TxStatus:
        """Query confirmation status for an on-chain transaction hash."""
        ...


class FakeReader:
    """Scriptable in-memory reader for testing threshold math and sync failure modes."""

    def __init__(
        self,
        hot: int = 150_000_000_000,
        cold: int = 1000_000_000_000,
        *,
        error: Exception | None = None,
        tx_status: TxStatus | None = None,
    ) -> None:
        self.hot = hot
        self.cold = cold
        self.error = error
        self.tx_status = tx_status or TxStatus(confirmed=True, confirmations=10)

    async def read_hot_balance(self, rail: str) -> int:
        """Return scripted hot balance or raise scripted error."""
        if self.error is not None:
            raise self.error
        return self.hot

    async def read_cold_balance(self, rail: str) -> int:
        """Return scripted cold balance or raise scripted error."""
        if self.error is not None:
            raise self.error
        return self.cold

    async def get_tx_status(self, rail: str, tx_hash: str) -> TxStatus:
        """Return scripted transaction status or raise scripted error."""
        if self.error is not None:
            raise self.error
        return self.tx_status
