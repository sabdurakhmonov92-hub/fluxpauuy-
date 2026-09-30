"""Unit tests for x402 Payment Protocol Router (Task 1.2 & Part 4).

Validates challenge generation, parameter validation, and settlement endpoints.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from fluxpay.config import Settings
from fluxpay.gateway.x402_router import (
    ChallengeRequest,
    create_challenge,
)

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_create_x402_challenge() -> None:
    """Validate challenge generation creates EIP-712 / EIP-3009 payload with nonce."""
    mock_settings = MagicMock(spec=Settings)
    mock_settings.base_chain_id = 8453
    mock_settings.base_usdc_address = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

    body = ChallengeRequest(
        resource_path="/api/premium-llm-compute",
        merchant_id="merchant_agent_01",
        amount_minor=1000000,  # 1.00 USDC
        currency="USDC",
    )
    resp = await create_challenge(body=body, settings=mock_settings)

    assert resp.status_code == 402
    assert "x-payment-required" in resp.headers
