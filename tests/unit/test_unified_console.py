"""Unit tests for the Unified Console Engine and Router (Pure Real Zero Baseline)."""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from fluxpay.console.engine import console_engine
from fluxpay.console.router import router as console_router

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_unified_console_pure_zero_flow() -> None:
    # Reset engine to pure 0
    console_engine.reset_to_zero()

    app = FastAPI()
    app.include_router(console_router)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Test GET / (HTML serves)
        res = await client.get("/")
        assert res.status_code == 200
        assert "FluxPay v3" in res.text
        assert "PURE 0 REAL ENGINE" in res.text

        # 2. Test Initial State starts at pure 0
        res = await client.get("/api/console/state")
        assert res.status_code == 200
        data = res.json()
        assert data["stats"]["settled_payments_count"] == 0
        assert data["stats"]["total_system_volume_minor"] == 0
        assert len(data["agents"]) == 0
        assert len(data["merchants"]) == 0
        assert len(data["holds"]) == 0
        assert data["stats"]["zero_sum_conserved"] is True

        # 3. Create Real Agent with initial deposit
        res = await client.post(
            "/api/console/agents",
            json={
                "name": "Real Alpha Agent",
                "external_id": "real_alpha_01",
                "initial_balance": 500.0,
            },
        )
        assert res.status_code == 200
        agent_data = res.json()
        agent_id = agent_data["id"]

        # 4. Create Real Merchant at 0 balance
        res = await client.post(
            "/api/console/merchants",
            json={
                "name": "Real Compute Provider",
                "external_id": "real_compute_inc",
                "webhook_url": "",
            },
        )
        assert res.status_code == 200
        merch_data = res.json()
        merchant_id = merch_data["external_id"]

        # 5. Verify State updated with 1 real agent, 1 merchant, real ledger blocks
        res = await client.get("/api/console/state")
        assert res.status_code == 200
        data = res.json()
        assert len(data["agents"]) == 1
        assert len(data["merchants"]) == 1
        assert (
            data["stats"]["ledger_blocks_count"] == 2
        )  # 2 double-entry blocks minted for funding!
        assert data["stats"]["zero_sum_conserved"] is True

        # 6. Execute Real Payment
        res = await client.post(
            "/api/console/pay",
            json={"agent_id": agent_id, "to_merchant": merchant_id, "amount": 50.0},
        )
        assert res.status_code == 200
        pay_data = res.json()
        assert pay_data["status"] == "settled"
        assert pay_data["chain_seq"] == 5  # 2 + 3 legs = block 5!

        # 7. Verify Real Settled Volume and Charts History
        res = await client.get("/api/console/state")
        assert res.status_code == 200
        data = res.json()
        assert data["stats"]["settled_payments_count"] == 2  # 1 agent funding tx + 1 payment tx
        assert data["stats"]["total_system_volume_minor"] == 50_000_000
        assert len(data["volume_history"]) == 1
        assert data["stats"]["zero_sum_conserved"] is True

        # 8. Cryptographic Hashchain Verification
        res = await client.get("/api/console/verify-chain")
        assert res.status_code == 200
        assert res.json()["valid"] is True


@pytest.mark.asyncio
async def test_unified_console_a2a_transfer() -> None:
    """Test autonomous Agent-to-Agent (A2A / M2M) direct transfers without merchants."""
    console_engine.reset_to_zero()

    app = FastAPI()
    app.include_router(console_router)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Create Agent Alpha with $1000
        res = await client.post(
            "/api/console/agents",
            json={
                "name": "Buyer Bot Alpha",
                "external_id": "buyer_bot_01",
                "initial_balance": 1000.0,
            },
        )
        assert res.status_code == 200
        agent_alpha_id = res.json()["id"]

        # 2. Create Agent Beta with $0 (worker bot)
        res = await client.post(
            "/api/console/agents",
            json={
                "name": "Worker Bot Beta",
                "external_id": "worker_bot_02",
                "initial_balance": 0.0,
            },
        )
        assert res.status_code == 200
        agent_beta_id = res.json()["id"]

        # 3. Prevent self-transfer (Agent Alpha -> Agent Alpha)
        res = await client.post(
            "/api/console/pay",
            json={"agent_id": agent_alpha_id, "to_merchant": agent_alpha_id, "amount": 25.0},
        )
        assert res.status_code == 400
        assert "cannot make an A2A transfer to itself" in res.json()["detail"]

        # 4. Execute direct A2A transfer from Agent Alpha to Agent Beta via /api/console/pay
        res = await client.post(
            "/api/console/pay",
            json={"agent_id": agent_alpha_id, "to_merchant": agent_beta_id, "amount": 100.0},
        )
        assert res.status_code == 200
        pay_res = res.json()
        assert pay_res["status"] == "settled"
        assert pay_res["is_a2a"] is True
        assert pay_res["payer_name"] == "Buyer Bot Alpha"
        assert pay_res["recipient_name"] == "Worker Bot Beta"

        # 5. Execute dedicated /api/console/a2a endpoint
        res = await client.post(
            "/api/console/a2a",
            json={"from_agent_id": agent_alpha_id, "to_agent": "worker_bot_02", "amount": 50.0},
        )
        assert res.status_code == 200
        a2a_res = res.json()
        assert a2a_res["status"] == "settled"
        assert a2a_res["is_a2a"] is True

        # 6. Verify balances:
        # Agent Alpha paid 100 + fee (1.00) + 50 + fee (0.50) = 151.50 deducted from 1000 -> 848.50
        # Agent Beta received 100 + 50 = 150.00
        res = await client.get("/api/console/state")
        assert res.status_code == 200
        state = res.json()
        agents = {a["id"]: a for a in state["agents"]}

        assert agents[agent_alpha_id]["balance_formatted"] == "848.500000"
        assert agents[agent_beta_id]["balance_formatted"] == "150.000000"
        assert state["stats"]["zero_sum_conserved"] is True

        # 7. Verify hashchain validity
        res = await client.get("/api/console/verify-chain")
        assert res.status_code == 200
        assert res.json()["valid"] is True
