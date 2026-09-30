"""Administrative Emergency Control and Circuit Breaker Router (Task 1.5).

Provides high-privilege emergency controls for operations teams:
- POST /admin/freeze-agent: Instantly suspend an autonomous AI agent
- POST /admin/halt-withdrawals: Halt all on-chain payouts and treasury sweeps
- POST /admin/emergency-stop: Platform-wide ingress kill-switch
- GET /admin/system-status: Query operational circuit breaker flags and health
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from fluxpay.config import Settings
from fluxpay.di import get_agent_repo, get_redis_client, get_settings_dep
from fluxpay.registry.repo import AgentRepo
from fluxpay.shared.logging import get_logger

logger = get_logger("fluxpay.admin.emergency")

router = APIRouter(prefix="/admin", tags=["Admin Emergency Controls"])

# Key prefixes for Redis-backed distributed circuit breakers
KEY_EMERGENCY_STOP = "flx:circuit:emergency_stop"
KEY_HALT_WITHDRAWALS = "flx:circuit:halt_withdrawals"


class FreezeAgentRequest(BaseModel):
    """Payload to suspend an autonomous agent."""

    agent_id: UUID
    reason: str = Field(..., min_length=3, max_length=255)


class CircuitToggleRequest(BaseModel):
    """Payload to toggle platform-wide circuit breakers."""

    enabled: bool
    reason: str = Field(..., min_length=3, max_length=255)
    operator_id: str = Field(default="OPERATOR", min_length=1)


@router.post("/freeze-agent", status_code=status.HTTP_200_OK)
async def freeze_agent(
    body: FreezeAgentRequest,
    agent_repo: Annotated[AgentRepo, Depends(get_agent_repo)],
) -> dict[str, Any]:
    """Instantly suspend an autonomous agent's credentials and prevent new payments."""
    success = await agent_repo.suspend(body.agent_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent {body.agent_id} not found or already suspended.",
        )
    logger.warning("agent_emergency_frozen", agent_id=str(body.agent_id), reason=body.reason)
    return {
        "status": "frozen",
        "agent_id": str(body.agent_id),
        "reason": body.reason,
    }


@router.post("/halt-withdrawals", status_code=status.HTTP_200_OK)
async def halt_withdrawals(
    body: CircuitToggleRequest,
    valkey: Annotated[Any, Depends(get_redis_client)],
) -> dict[str, Any]:
    """Toggle circuit breaker halting all outbound treasury and agent withdrawals."""
    if body.enabled:
        await valkey.set(KEY_HALT_WITHDRAWALS, b"1")
        logger.critical(
            "withdrawals_circuit_halted",
            operator=body.operator_id,
            reason=body.reason,
        )
    else:
        await valkey.delete(KEY_HALT_WITHDRAWALS)
        logger.info(
            "withdrawals_circuit_resumed",
            operator=body.operator_id,
            reason=body.reason,
        )

    return {
        "halt_withdrawals": body.enabled,
        "operator": body.operator_id,
        "reason": body.reason,
    }


@router.post("/emergency-stop", status_code=status.HTTP_200_OK)
async def emergency_stop(
    body: CircuitToggleRequest,
    valkey: Annotated[Any, Depends(get_redis_client)],
) -> dict[str, Any]:
    """Platform-wide emergency stop. Rejects all payment ingress immediately."""
    if body.enabled:
        await valkey.set(KEY_EMERGENCY_STOP, b"1")
        logger.critical(
            "global_emergency_stop_engaged",
            operator=body.operator_id,
            reason=body.reason,
        )
    else:
        await valkey.delete(KEY_EMERGENCY_STOP)
        logger.info(
            "global_emergency_stop_disengaged",
            operator=body.operator_id,
            reason=body.reason,
        )

    return {
        "emergency_stop": body.enabled,
        "operator": body.operator_id,
        "reason": body.reason,
    }


@router.get("/system-status", status_code=status.HTTP_200_OK)
async def get_system_status(
    valkey: Annotated[Any, Depends(get_redis_client)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> dict[str, Any]:
    """Retrieve runtime state of platform circuit breakers and operating mode."""
    is_emergency_stopped = bool(await valkey.exists(KEY_EMERGENCY_STOP))
    is_withdrawals_halted = bool(await valkey.exists(KEY_HALT_WITHDRAWALS))

    return {
        "status": "emergency_halted" if is_emergency_stopped else "operational",
        "env": settings.env,
        "circuit_breakers": {
            "emergency_stop": is_emergency_stopped,
            "halt_withdrawals": is_withdrawals_halted,
        },
    }
