"""Live integration test against Base Sepolia testnet.

Exercises the real EVM pipeline against Base Sepolia (chain_id=84532):
- AsyncWeb3 HTTP provider connection
- Gas estimation and EIP-1559 transaction construction
- Local / KMS / HSM signer abstraction
- Mempool broadcast and receipt polling with confirmations

This test suite requires external network access and funded testnet accounts.
It is marked @pytest.mark.integration and skipped by default in local and CI
environments unless both `BASE_SEPOLIA_RPC_URL` and `BASE_SEPOLIA_PRIVATE_KEY`
environment variables are explicitly provided.
"""

from __future__ import annotations

import os
from decimal import Decimal

import pytest
from web3 import AsyncHTTPProvider, AsyncWeb3

from fluxpay.integrations.base_l2_writer import (
    BASE_SEPOLIA_CHAIN_ID,
    BASE_SEPOLIA_USDC_CONTRACT,
    BaseL2Writer,
    LocalDevSigner,
    TransferReceipt,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.getenv("BASE_SEPOLIA_RPC_URL") or not os.getenv("BASE_SEPOLIA_PRIVATE_KEY"),
        reason=(
            "Base Sepolia live integration tests require BASE_SEPOLIA_RPC_URL and "
            "BASE_SEPOLIA_PRIVATE_KEY"
        ),
    ),
]


def _get_live_writer() -> BaseL2Writer:
    """Build live BaseL2Writer connected to Base Sepolia testnet."""
    rpc_url = os.environ["BASE_SEPOLIA_RPC_URL"]
    private_key = os.environ["BASE_SEPOLIA_PRIVATE_KEY"]
    usdc_contract = os.getenv("BASE_SEPOLIA_USDC_CONTRACT", BASE_SEPOLIA_USDC_CONTRACT)

    w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url))
    signer = LocalDevSigner(private_key)

    return BaseL2Writer(
        signer=signer,
        w3=w3,
        chain_id=BASE_SEPOLIA_CHAIN_ID,
        usdc_address=usdc_contract,
        min_gas_threshold=Decimal("0.0001"),  # Lower threshold for Sepolia testnet
        default_confirmations=1,
        poll_interval_s=2.0,
    )


@pytest.mark.asyncio
async def test_live_base_sepolia_probe() -> None:
    """Verify live connectivity and chain ID validation on Base Sepolia."""
    writer = _get_live_writer()
    chain_id = await writer.probe()
    assert chain_id == BASE_SEPOLIA_CHAIN_ID


@pytest.mark.asyncio
async def test_live_base_sepolia_preflight_checks() -> None:
    """Verify pre-flight native ETH and ERC-20 token balance queries on live network."""
    writer = _get_live_writer()
    await writer.probe()

    # Hot wallet must have some ETH for gas
    eth_bal = await writer.preflight_gas_check()
    assert eth_bal >= Decimal("0.0001")

    # Check USDC balance reading (minor units)
    usdc_minor = await writer.preflight_usdc_check(1)
    assert usdc_minor >= 0


@pytest.mark.asyncio
async def test_live_base_sepolia_usdc_transfer() -> None:
    """Execute live outbound USDC transfer on Base Sepolia and verify receipt."""
    recipient = os.getenv("BASE_SEPOLIA_RECIPIENT")
    if not recipient:
        pytest.skip("BASE_SEPOLIA_RECIPIENT not set; skipping live transfer execution")

    writer = _get_live_writer()
    # Micro-transfer: 0.000001 USDC (1 minor unit)
    amount = Decimal("0.000001")

    receipt = await writer.transfer_usdc(
        to=recipient,
        amount=amount,
        confirmations=1,
        timeout_s=120.0,
    )

    assert isinstance(receipt, TransferReceipt)
    assert receipt.tx_hash.startswith("0x")
    assert len(receipt.tx_hash) == 66
    assert receipt.to_address.lower() == recipient.lower()
    assert receipt.amount_usdc == amount
    assert receipt.amount_minor == 1
    assert receipt.confirmations >= 1
    assert receipt.gas_used > 0
    assert receipt.block_number > 0
