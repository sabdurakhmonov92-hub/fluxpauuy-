"""FastAPI Router for x402 Payment Protocol (RFC 7231 & EIP-3009).

Exposes payment challenge generation, gasless transfer authorization verification,
and facilitator settlement endpoints for autonomous AI agents.
"""

from __future__ import annotations

import time
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from fluxpay.config import Settings
from fluxpay.di import get_ledger_store, get_settings_dep
from fluxpay.gateway.x402_eip3009 import (
    build_eip712_domain,
    validate_authorization_timing,
    verify_eip3009_signature,
)
from fluxpay.gateway.x402_types import PaymentPayload, PaymentRequired
from fluxpay.integrations.base_indexer import BASE_MAINNET_CHAIN_ID, BASE_USDC_CONTRACT
from fluxpay.ledger.hashchain import Direction
from fluxpay.ledger.postgres import PostgresLedgerStore
from fluxpay.ledger.store import EntryDraft
from fluxpay.shared.logging import get_logger

logger = get_logger("fluxpay.gateway.x402_router")

router = APIRouter(prefix="/x402", tags=["x402 Payment Protocol"])


class ChallengeRequest(BaseModel):
    """Payload to request an x402 payment challenge for a protected resource."""

    resource_path: str = Field(..., min_length=1)
    merchant_id: str = Field(..., min_length=1)
    amount_minor: int = Field(..., gt=0)
    currency: str = Field(default="USDC")


class VerifyPayloadRequest(BaseModel):
    """Payload to verify an agent's EIP-3009 authorization signature."""

    payload: PaymentPayload
    merchant_address: str


class SettleRequest(BaseModel):
    """Payload to submit verified authorization for facilitator settlement."""

    payload: PaymentPayload
    merchant_address: str
    idempotency_key: str = Field(default_factory=lambda: str(uuid4()))


@router.post("/challenge", status_code=status.HTTP_402_PAYMENT_REQUIRED)
async def create_challenge(
    body: ChallengeRequest,
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> Response:
    """Generate RFC 7231 / x402 Payment Required response challenge."""
    pay_to = getattr(settings, "eth_usdc_address", "0x0000000000000000000000000000000000000000")
    challenge = PaymentRequired(
        asset=body.currency,
        amount=str(body.amount_minor),
        pay_to=pay_to,
    )
    return Response(
        content=challenge.model_dump_json(),
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        media_type="application/json",
        headers={"X-Payment-Required": challenge.model_dump_json()},
    )


@router.post("/verify", status_code=status.HTTP_200_OK)
async def verify_authorization(
    body: VerifyPayloadRequest,
) -> dict[str, Any]:
    """Verify an agent's EIP-3009 authorization signature using eth-account (no KMS needed)."""
    domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=BASE_MAINNET_CHAIN_ID,
        verifying_contract=BASE_USDC_CONTRACT,
    )
    now = int(time.time())
    timing_valid, timing_err = validate_authorization_timing(
        body.payload.valid_after,
        body.payload.valid_before,
        now,
    )
    if not timing_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=timing_err)

    is_valid, reason = verify_eip3009_signature(body.payload, domain)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=reason or "Cryptographic EIP-3009 signature verification failed.",
        )

    return {
        "verified": True,
        "payer": body.payload.from_address,
        "recipient": body.merchant_address,
        "amount_minor": body.payload.value_int,
        "nonce": body.payload.nonce,
    }


@router.post("/settle", status_code=status.HTTP_201_CREATED)
async def settle_payment(
    body: SettleRequest,
    ledger: Annotated[PostgresLedgerStore, Depends(get_ledger_store)],
) -> dict[str, Any]:
    """Settle an authorized x402 payment and post immutable transaction to ledger."""
    domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=BASE_MAINNET_CHAIN_ID,
        verifying_contract=BASE_USDC_CONTRACT,
    )
    is_valid, reason = verify_eip3009_signature(body.payload, domain)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=reason or "Signature verification failed prior to settlement.",
        )

    amount = body.payload.value_int
    tx_id = uuid4()
    payer_uuid = uuid4()
    merchant_uuid = uuid4()

    entries = (
        EntryDraft(
            account_id=payer_uuid,
            direction=Direction.DEBIT,
            amount=amount,
            currency="USDC",
            tx_id=tx_id,
        ),
        EntryDraft(
            account_id=merchant_uuid,
            direction=Direction.CREDIT,
            amount=amount,
            currency="USDC",
            tx_id=tx_id,
        ),
    )
    await ledger.post_transaction(entries)

    logger.info(
        "x402_settlement_posted",
        tx_id=str(tx_id),
        payer=body.payload.from_address,
        amount_minor=amount,
        nonce=body.payload.nonce,
    )

    return {
        "status": "settled",
        "tx_id": str(tx_id),
        "amount_minor": amount,
        "currency": "USDC",
        "payer": body.payload.from_address,
        "nonce": body.payload.nonce,
    }
