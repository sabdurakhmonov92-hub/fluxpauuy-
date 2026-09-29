"""Unified Single-Page Console Router for FluxPay.

Serves both the single-page HTML interface and the reactive JSON API endpoints.
Brings all domains (Agents, Payments, Ledger Hashchain, Risk Holds, Limits, Treasury, Audit)
together on one single unified page.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from fluxpay.console.engine import console_engine

TEMPLATES_DIR: Path = Path(__file__).resolve().parents[3] / "templates"
templates: Jinja2Templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter(tags=["unified_console"])


# -----------------------------------------------------------------------------
# Request Payloads
# -----------------------------------------------------------------------------


class PayRequest(BaseModel):
    agent_id: UUID
    to_merchant: str
    amount: float = Field(..., gt=0, description="Amount in USDC")


class CreateAgentRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    external_id: str = Field(..., min_length=2, max_length=64)
    initial_balance: float = Field(default=1000.0, ge=0)


class TopupAgentRequest(BaseModel):
    amount: float = Field(..., gt=0)


class CreateMerchantRequest(BaseModel):
    external_id: str = Field(..., min_length=2, max_length=64)
    name: str = Field(..., min_length=2, max_length=120)
    webhook_url: str = Field(default="")


class HoldActionRequest(BaseModel):
    action: str = Field(..., pattern="^(approve|reject)$")


class UpdateLimitsRequest(BaseModel):
    agent_id: UUID
    single_max: float = Field(..., ge=1)
    daily_max: float = Field(..., ge=1)
    velocity_count: int = Field(default=10, ge=1)
    velocity_window_s: int = Field(default=60, ge=1)


# -----------------------------------------------------------------------------
# Single Page View Route
# -----------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
@router.get("/console", response_class=HTMLResponse)
async def serve_unified_console(request: Request) -> HTMLResponse:
    """Render the state-of-the-art All-in-One FluxPay Single-Page Dashboard."""
    state = console_engine.get_full_state()
    return templates.TemplateResponse(
        name="unified_console.html",
        context={
            "request": request,
            "state": state,
        },
    )


# -----------------------------------------------------------------------------
# Interactive API Endpoints
# -----------------------------------------------------------------------------


@router.get("/api/console/state")
async def get_state() -> dict[str, Any]:
    """Retrieve atomic snapshot of all platform entities."""
    return console_engine.get_full_state()


class A2ARequest(BaseModel):
    from_agent_id: UUID = Field(..., description="Paying Agent UUID")
    to_agent: str = Field(..., description="Recipient Agent UUID or external_id")
    amount: float = Field(..., gt=0, description="Amount in USDC")


@router.post("/api/console/pay")
async def execute_payment(payload: PayRequest) -> dict[str, Any]:
    """Execute live payment between agent and merchant or recipient agent (A2A)."""
    amount_minor = round(payload.amount * 1_000_000)
    try:
        outcome = await console_engine.execute_payment(
            agent_id=payload.agent_id,
            to_merchant=payload.to_merchant,
            amount_minor=amount_minor,
        )
        return outcome
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {e}") from e


@router.post("/api/console/a2a")
async def execute_a2a_payment(payload: A2ARequest) -> dict[str, Any]:
    """Execute live autonomous Agent-to-Agent (A2A / M2M) machine transfer."""
    amount_minor = round(payload.amount * 1_000_000)
    try:
        outcome = await console_engine.execute_payment(
            agent_id=payload.from_agent_id,
            to_merchant=payload.to_agent,
            amount_minor=amount_minor,
        )
        return outcome
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {e}") from e


@router.post("/api/console/agents")
async def create_agent(payload: CreateAgentRequest) -> dict[str, Any]:
    """Create a new autonomous agent."""
    try:
        agent = await console_engine.create_agent(
            name=payload.name,
            external_id=payload.external_id,
            initial_balance_usdc=payload.initial_balance,
        )
        return agent
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/api/console/agents/{agent_id}/toggle")
async def toggle_agent(agent_id: UUID) -> dict[str, Any]:
    """Toggle agent status (active / suspended)."""
    try:
        is_active = await console_engine.toggle_agent(agent_id)
        return {"active": is_active}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


class DepositRequest(BaseModel):
    agent_id: UUID
    amount: float
    network: str = "SOLANA"
    tx_hash: str | None = None


@router.post("/api/console/agents/{agent_id}/topup")
async def topup_agent(agent_id: UUID, payload: TopupAgentRequest) -> dict[str, Any]:
    """Fund an agent account."""
    try:
        return await console_engine.topup_agent(agent_id, payload.amount)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/api/console/deposit")
async def deposit_funds(payload: DepositRequest) -> dict[str, Any]:
    """Confirm incoming crypto on-ramp deposit for an agent with real on-chain validation."""
    from fluxpay.integrations.blockchain_verifier import verify_solana_tx, verify_tron_tx

    verification_info = None

    # If TxHash is provided, verify against live Mainnet via Helius or TronGrid
    if payload.tx_hash and len(payload.tx_hash.strip()) > 10:
        net_upper = (payload.network or "SOLANA").upper()
        if "SOL" in net_upper:
            check = await verify_solana_tx(payload.tx_hash.strip(), payload.amount)
            if not check.verified:
                raise HTTPException(
                    status_code=400,
                    detail=f"Solana Mainnet Verification Failed (Helius RPC): {check.message}",
                )
            verification_info = check.to_dict()
        elif "TRON" in net_upper or "TRC" in net_upper:
            check = await verify_tron_tx(payload.tx_hash.strip(), payload.amount)
            if not check.verified:
                raise HTTPException(
                    status_code=400,
                    detail=f"TRON Mainnet Verification Failed (TronGrid API): {check.message}",
                )
            verification_info = check.to_dict()

    try:
        outcome = await console_engine.topup_agent(payload.agent_id, payload.amount)
        if verification_info:
            outcome["on_chain_verification"] = verification_info
        return outcome
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


class InspectTxRequest(BaseModel):
    network: str = "SOLANA"
    tx_hash: str


@router.post("/api/console/inspect-tx")
async def inspect_blockchain_tx(payload: InspectTxRequest) -> dict[str, Any]:
    """Inspect and decode on-chain transaction amount from Solana or TRON."""
    from fluxpay.integrations.blockchain_verifier import verify_solana_tx, verify_tron_tx

    tx = payload.tx_hash.strip()
    if not tx:
        raise HTTPException(status_code=400, detail="Transaction hash is required.")

    net_upper = payload.network.upper()
    if "SOL" in net_upper:
        res = await verify_solana_tx(tx)
    elif "TRON" in net_upper or "TRC" in net_upper:
        res = await verify_tron_tx(tx)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported network: {payload.network}")

    return res.to_dict()


@router.post("/api/console/merchants")
async def create_merchant(payload: CreateMerchantRequest) -> dict[str, Any]:
    """Register a new merchant."""
    try:
        return await console_engine.create_merchant(
            external_id=payload.external_id,
            name=payload.name,
            webhook_url=payload.webhook_url,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/api/console/holds/{hold_id}/action")
async def hold_action(hold_id: UUID, payload: HoldActionRequest) -> dict[str, Any]:
    """Approve or reject a quarantined payment."""
    try:
        return await console_engine.handle_hold_action(hold_id, payload.action)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/api/console/limits")
async def update_limits(payload: UpdateLimitsRequest) -> dict[str, Any]:
    """Update risk limits for an agent."""
    try:
        return await console_engine.update_limits(
            payload.agent_id,
            single_max_usdc=payload.single_max,
            daily_max_usdc=payload.daily_max,
            velocity_count=payload.velocity_count,
            velocity_window_s=payload.velocity_window_s,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.get("/api/console/verify-chain")
async def verify_chain() -> dict[str, Any]:
    """Perform mathematical verification of the SHA-256 ledger hashchain."""
    return console_engine.verify_hashchain()


@router.post("/api/console/reset")
async def reset_demo() -> dict[str, Any]:
    """Reset to clean initial zero state."""
    console_engine.reset_to_zero()
    return {"status": "ok", "message": "Platform reset to absolute clean zero state."}
