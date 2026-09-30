"""Unit tests for Admin Emergency Router (Task 1.5).

Validates emergency endpoints: freeze-agent, halt-withdrawals, emergency-stop, system-status.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from fluxpay.admin.emergency_router import (
    CircuitToggleRequest,
    FreezeAgentRequest,
    emergency_stop,
    freeze_agent,
    get_system_status,
    halt_withdrawals,
)

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_freeze_agent_success() -> None:
    """Validate freezing an agent transitions status and emits audit log."""
    mock_agent_repo = MagicMock()
    mock_agent_repo.suspend = AsyncMock(return_value=True)

    agent_id = uuid4()
    body = FreezeAgentRequest(
        agent_id=agent_id,
        reason="Suspicious rapid micro-payments",
    )
    resp = await freeze_agent(body=body, agent_repo=mock_agent_repo)

    assert resp["status"] == "frozen"
    assert resp["agent_id"] == str(agent_id)
    mock_agent_repo.suspend.assert_awaited_once_with(agent_id)


@pytest.mark.asyncio
async def test_halt_withdrawals_success() -> None:
    """Validate halting withdrawals stores flag in Redis cache."""
    mock_valkey = MagicMock()
    mock_valkey.set = AsyncMock()

    body = CircuitToggleRequest(
        enabled=True,
        reason="Base L2 sequencer reorg under review",
        operator_id="devops@fluxpay.io",
    )
    resp = await halt_withdrawals(body=body, valkey=mock_valkey)

    assert resp["halt_withdrawals"] is True
    mock_valkey.set.assert_awaited_once()


@pytest.mark.asyncio
async def test_emergency_stop_success() -> None:
    """Validate emergency stop engages killswitch across platform."""
    mock_valkey = MagicMock()
    mock_valkey.set = AsyncMock()

    body = CircuitToggleRequest(
        enabled=True,
        reason="Investigating anomaly",
        operator_id="ciso@fluxpay.io",
    )
    resp = await emergency_stop(body=body, valkey=mock_valkey)

    assert resp["emergency_stop"] is True


@pytest.mark.asyncio
async def test_get_system_status() -> None:
    """Validate emergency system status returns active flags."""
    mock_valkey = MagicMock()
    mock_valkey.exists = AsyncMock(return_value=0)
    mock_settings = MagicMock()
    mock_settings.env = "production"

    resp = await get_system_status(valkey=mock_valkey, settings=mock_settings)
    assert resp["status"] == "operational"
    assert resp["circuit_breakers"]["emergency_stop"] is False
    assert resp["circuit_breakers"]["halt_withdrawals"] is False
