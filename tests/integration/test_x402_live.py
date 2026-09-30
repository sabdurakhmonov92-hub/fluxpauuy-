"""Integration tests for x402 payment protocol against Base Sepolia configuration.

Exercises full agent payment lifecycle:
1. Agent requests protected resource -> 402 Payment Required
2. Agent signs EIP-3009 transfer authorization targeting Base Sepolia (chain_id=84532)
3. Middleware verifies signature against Base Sepolia USDC contract
4. Facilitator simulates/executes on-chain settlement
5. Double-entry ledger records debit/credit legs
6. Settlement receipt attached in X-PAYMENT-RESPONSE
7. Idempotent retry verifies exactly-once settlement invariant
"""

from __future__ import annotations

import base64
import json
from decimal import Decimal
from typing import Any
from uuid import UUID

import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from web3 import Web3

from fluxpay.gateway.x402 import (
    InMemoryReconciliationQueue,
    X402Middleware,
)
from fluxpay.gateway.x402_config import X402Config
from fluxpay.gateway.x402_eip3009 import (
    TRANSFER_WITH_AUTHORIZATION_TYPES,
    build_eip712_domain,
    normalize_nonce,
)
from fluxpay.gateway.x402_facilitator import SelfHostedFacilitator
from fluxpay.gateway.x402_types import (
    PaymentPayload,
    SettleResult,
)

pytestmark = pytest.mark.integration

# Base Sepolia Network Parameters
BASE_SEPOLIA_CHAIN_ID = 84532
BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
MERCHANT_SEPOLIA_ADDR = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"


class IntegrationLedgerStore:
    """Mock integration double-entry ledger conforming to LedgerClient."""

    def __init__(self) -> None:
        self.transactions: list[dict[str, Any]] = []

    async def record_payment(
        self,
        *,
        agent_id: str,
        merchant_id: str,
        amount_minor: int,
        currency: str,
        idempotency_key: str,
        agent_account_id: UUID | None = None,
        merchant_account_id: UUID | None = None,
    ) -> None:
        self.transactions.append(
            {
                "agent_id": agent_id,
                "merchant_id": merchant_id,
                "amount_minor": amount_minor,
                "currency": currency,
                "idempotency_key": idempotency_key,
                "agent_account_id": agent_account_id,
                "merchant_account_id": merchant_account_id,
            }
        )


@pytest.mark.asyncio
async def test_base_sepolia_full_payment_lifecycle() -> None:
    """End-to-end integration flow on Base Sepolia."""
    # 1. Setup Base Sepolia configuration
    config = X402Config(
        network="base-sepolia",
        chain_id=BASE_SEPOLIA_CHAIN_ID,
        asset=BASE_SEPOLIA_USDC,
        pay_to=MERCHANT_SEPOLIA_ADDR,
        protected_routes={
            "/api/v1/agent-resource": Decimal("0.25"),  # 0.25 USDC
        },
    )

    ledger = IntegrationLedgerStore()
    queue = InMemoryReconciliationQueue()

    # Simulated balance checker and settler
    async def mock_sepolia_balance(address: str) -> int:
        return 10_000_000  # 10 USDC

    async def mock_sepolia_settler(payment: PaymentPayload) -> SettleResult:
        return SettleResult(
            success=True,
            tx_hash="0x5f1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            block_number=14_250_800,
        )

    facilitator = SelfHostedFacilitator(
        config=config,
        balance_checker=mock_sepolia_balance,
        settler_fn=mock_sepolia_settler,
    )

    async def protected_endpoint(request: Request) -> JSONResponse:
        return JSONResponse({"status": "access_granted", "tier": "premium_agent"})

    app = Starlette(routes=[Route("/api/v1/agent-resource", protected_endpoint)])
    app.add_middleware(
        X402Middleware,
        config=config,
        facilitator=facilitator,
        ledger=ledger,
        reconciliation_queue=queue,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Step 1: Agent requests without payment -> Receives 402 challenge
        initial_resp = await client.get("/api/v1/agent-resource")
        assert initial_resp.status_code == 402
        assert "PAYMENT-REQUIRED" in initial_resp.headers

        challenge_data = json.loads(initial_resp.headers["PAYMENT-REQUIRED"])
        assert challenge_data["network"] == "base-sepolia"
        assert challenge_data["asset"] == BASE_SEPOLIA_USDC
        assert challenge_data["amount"] == "250000"  # 0.25 USDC
        assert challenge_data["payTo"] == MERCHANT_SEPOLIA_ADDR

        # Step 2: Autonomous Agent generates and signs EIP-3009 authorization
        agent_account = Account.create()
        norm_nonce = normalize_nonce("0x" + "22" * 32)
        domain = build_eip712_domain(
            name=config.token_name,
            version=config.token_version,
            chain_id=BASE_SEPOLIA_CHAIN_ID,
            verifying_contract=BASE_SEPOLIA_USDC,
        )
        msg_data = {
            "from": Web3.to_checksum_address(agent_account.address),
            "to": Web3.to_checksum_address(MERCHANT_SEPOLIA_ADDR),
            "value": 250_000,
            "validAfter": 0,
            "validBefore": 2_000_000_000,
            "nonce": norm_nonce,
        }
        encoded = encode_typed_data(
            domain_data=domain,
            message_types=TRANSFER_WITH_AUTHORIZATION_TYPES,
            message_data=msg_data,
        )
        signature = agent_account.sign_message(encoded)

        payload_dict = {
            "from": agent_account.address,
            "to": MERCHANT_SEPOLIA_ADDR,
            "value": 250_000,
            "validAfter": 0,
            "validBefore": 2_000_000_000,
            "nonce": norm_nonce,
            "signature": "0x" + signature.signature.hex(),
        }
        x_payment_header = base64.b64encode(json.dumps(payload_dict).encode()).decode("ascii")

        # Step 3: Agent retries request with X-PAYMENT header
        paid_resp = await client.get(
            "/api/v1/agent-resource",
            headers={"X-PAYMENT": x_payment_header},
        )
        assert paid_resp.status_code == 200
        assert paid_resp.json()["status"] == "access_granted"
        assert "X-PAYMENT-RESPONSE" in paid_resp.headers

        # Step 4: Verify settlement receipt
        raw_receipt = base64.b64decode(paid_resp.headers["X-PAYMENT-RESPONSE"]).decode("utf-8")
        receipt = json.loads(raw_receipt)
        assert receipt["success"] is True
        assert receipt["network"] == "base-sepolia"
        assert receipt["amount"] == "250000"
        assert receipt["blockNumber"] == 14_250_800

        # Step 5: Verify double-entry ledger record
        assert len(ledger.transactions) == 1
        ledger_tx = ledger.transactions[0]
        assert ledger_tx["amount_minor"] == 250_000
        assert ledger_tx["currency"] == "USDC"
        assert ledger_tx["idempotency_key"] == f"x402:{norm_nonce}"

        # Step 6: Verify idempotent retry behavior
        retry_resp = await client.get(
            "/api/v1/agent-resource",
            headers={"X-PAYMENT": x_payment_header},
        )
        assert retry_resp.status_code == 200
        assert len(ledger.transactions) == 1  # No duplicate ledger write
