"""Unit tests for Blockchain Reconciliation Worker (Task 1.5).

Validates reconciliation calculations, hashchain link audit, and metric updates.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from fluxpay.config import Settings
from fluxpay.workers.blockchain_reconciliation import (
    BlockchainReconciler,
    BlockchainReconciliationReport,
)

pytestmark = pytest.mark.unit


def _mock_settings() -> Settings:
    s = MagicMock(spec=Settings)
    s.base_chain_id = 8453
    s.base_usdc_address = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    return s


@pytest.mark.asyncio
async def test_blockchain_reconciler_balanced() -> None:
    """Validate reconciliation when on-chain confirmed deposits balance ledger obligations."""
    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_pool.acquire.return_value.__aenter__.return_value = mock_conn

    # 1. Total ledger minor = 100_000_000
    # 2. Total indexed deposits = 100_000_000
    mock_conn.fetchval = AsyncMock(side_effect=[100_000_000, 100_000_000])
    # 3. Orphaned deposits = []
    # 4. Orphaned withdrawals = []
    # 5. Recent entries = []
    mock_conn.fetch = AsyncMock(side_effect=[[], [], []])

    reconciler = BlockchainReconciler(mock_pool, settings=_mock_settings())
    report = await reconciler.reconcile()

    assert isinstance(report, BlockchainReconciliationReport)
    assert report.healthy is True
    assert report.imbalance_minor == 0
    assert report.total_ledger_balance_minor == 100_000_000
    assert report.on_chain_reserve_minor == 100_000_000
    assert report.orphaned_deposits_count == 0
    assert report.orphaned_withdrawals_count == 0


@pytest.mark.asyncio
async def test_blockchain_reconciler_imbalance_detected() -> None:
    """Validate reconciliation detects imbalance when ledger liabilities exceed reserves."""
    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_pool.acquire.return_value.__aenter__.return_value = mock_conn

    # 1. Total ledger minor = 150_000_000
    # 2. Total indexed deposits = 100_000_000
    mock_conn.fetchval = AsyncMock(side_effect=[150_000_000, 100_000_000])
    mock_conn.fetch = AsyncMock(side_effect=[[], [], []])

    reconciler = BlockchainReconciler(mock_pool, settings=_mock_settings())
    report = await reconciler.reconcile()

    assert report.healthy is False
    assert report.imbalance_minor == -50_000_000
