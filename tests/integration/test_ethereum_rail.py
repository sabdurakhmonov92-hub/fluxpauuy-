"""Integration tests for Ethereum Rail: The Second Chain via Generalization.

TASK 51: ETHEREUM RAIL: THE SECOND CHAIN VIA GENERALIZATION (BLOCK J)
Proves:
1. Migration 0012: Widens wallet_state.rail CHECK constraint to ('base_usdc', 'ethereum_usdc'),
   seeds 'ethereum_usdc' row, and rejects un-whitelisted rails (e.g. 'solana_usdc').
2. Second Rail E2E: Task 44's HotWalletMonitor + generalized BaseL2Reader + seeded wallet_state
   -> runs across both rails -> independent caches updated via respective RPC providers and
   addresses resolved from wallet_state.
3. Task 45 Cold Payout Confirmation on Ethereum: Finality knob enforcement:
   - confirmations=0 (< min 1) -> stays 'executed'
   - confirmations=3 (>= min 1) -> advances to 'confirmed'
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import httpx
import pytest
import pytest_asyncio
from web3 import AsyncWeb3
from web3.providers.async_base import AsyncBaseProvider

from fluxpay.integrations.base_l2 import (
    BALANCE_OF_SELECTOR,
    DECIMALS_SELECTOR,
    BaseL2Reader,
)
from fluxpay.integrations.rails import RailConfig
from fluxpay.treasury.monitor import HotWalletMonitor
from fluxpay.treasury.payouts import PayoutService

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_0006_PATH = REPO_ROOT / "migrations" / "0006_audit.sql"
MIGRATION_0011_PATH = REPO_ROOT / "migrations" / "0011_treasury.sql"
MIGRATION_0012_PATH = REPO_ROOT / "migrations" / "0012_ethereum_rail.sql"

SCALE = 1_000_000_000  # 6 decimal places: 1,000,000 minor units = 1 USDC ($1,000 = 1,000,000,000)

BASE_HOT_ADDR = "0x1111111111111111111111111111111111111111"
BASE_COLD_ADDR = "0x2222222222222222222222222222222222222222"
BASE_USDC_CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

ETH_HOT_ADDR = "0x3333333333333333333333333333333333333333"
ETH_COLD_ADDR = "0x4444444444444444444444444444444444444444"
ETH_USDC_CONTRACT = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"


# -----------------------------------------------------------------------------
# Recording & Scriptable Web3 Async Provider
# -----------------------------------------------------------------------------


class MultiChainRecordingRpcProvider(AsyncBaseProvider):
    """Web3 AsyncBaseProvider that tracks calls and returns chain-specific responses."""

    def __init__(
        self,
        *,
        chain_id: int,
        balances: dict[str, int] | None = None,
        receipts: dict[str, dict[str, Any]] | None = None,
        block_number: int = 100,
    ) -> None:
        super().__init__()
        self.chain_id = chain_id
        self.balances = balances or {}
        self.receipts = receipts or {}
        self.block_number = block_number
        self.recorded_calls: list[dict[str, Any]] = []

    async def make_request(self, method: str, params: Any) -> Any:
        if method == "eth_chainId":
            return {"jsonrpc": "2.0", "id": 1, "result": hex(self.chain_id)}

        if method == "eth_blockNumber":
            return {"jsonrpc": "2.0", "id": 1, "result": hex(self.block_number)}

        if method == "eth_getTransactionReceipt":
            tx_hash = params[0].lower() if params else ""
            receipt = self.receipts.get(tx_hash)
            return {"jsonrpc": "2.0", "id": 1, "result": receipt}

        if method == "eth_call":
            call_obj = params[0]
            to_addr = call_obj.get("to")
            data = call_obj.get("data", "")
            self.recorded_calls.append({"to": to_addr, "data": data})

            # Selector: decimals()
            if data.startswith(DECIMALS_SELECTOR):
                return {"jsonrpc": "2.0", "id": 1, "result": "0x" + (6).to_bytes(32, "big").hex()}

            # Selector: balanceOf(address)
            if data.startswith(BALANCE_OF_SELECTOR):
                padded_target = data[10:]
                target_hex = "0x" + padded_target[24:]
                balance_val = self.balances.get(target_hex.lower(), 0)
                encoded_bal = "0x" + balance_val.to_bytes(32, "big").hex()
                return {"jsonrpc": "2.0", "id": 1, "result": encoded_bal}

            return {"jsonrpc": "2.0", "id": 1, "result": "0x0"}

        return {"jsonrpc": "2.0", "id": 1, "result": None}


# -----------------------------------------------------------------------------
# Database Fixtures
# -----------------------------------------------------------------------------


@pytest_asyncio.fixture
async def apply_treasury_schema(db_pool: asyncpg.Pool) -> None:
    """Execute migrations 0006, 0011, and 0012 idempotently."""
    async with db_pool.acquire() as conn:
        if MIGRATION_0006_PATH.exists():
            await conn.execute(MIGRATION_0006_PATH.read_text(encoding="utf-8"))
        await conn.execute(MIGRATION_0011_PATH.read_text(encoding="utf-8"))
        await conn.execute(MIGRATION_0012_PATH.read_text(encoding="utf-8"))


@pytest_asyncio.fixture(autouse=True)
async def clean_treasury_tables(
    db_pool: asyncpg.Pool,
    apply_treasury_schema: None,
) -> AsyncGenerator[None, None]:
    """Clean payouts and reset wallet_state for both rails."""
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM payout_approvals;")
        await conn.execute("DELETE FROM cold_payouts;")

        # Seed base_usdc
        await conn.execute(
            """
            INSERT INTO wallet_state (
                rail, hot_address, cold_address, hot_balance_minor, cold_balance_minor,
                low_water_minor, high_water_minor, sync_status
            ) VALUES ('base_usdc', $1, $2, 0, 0, $3, $4, 'never')
            ON CONFLICT (rail) DO UPDATE
            SET hot_address = EXCLUDED.hot_address,
                cold_address = EXCLUDED.cold_address,
                hot_balance_minor = 0,
                cold_balance_minor = 0,
                low_water_minor = EXCLUDED.low_water_minor,
                high_water_minor = EXCLUDED.high_water_minor,
                sync_status = 'never',
                last_synced_at = NULL;
            """,
            BASE_HOT_ADDR,
            BASE_COLD_ADDR,
            50 * SCALE,
            200 * SCALE,
        )

        # Seed ethereum_usdc
        await conn.execute(
            """
            INSERT INTO wallet_state (
                rail, hot_address, cold_address, hot_balance_minor, cold_balance_minor,
                low_water_minor, high_water_minor, sync_status
            ) VALUES ('ethereum_usdc', $1, $2, 0, 0, $3, $4, 'never')
            ON CONFLICT (rail) DO UPDATE
            SET hot_address = EXCLUDED.hot_address,
                cold_address = EXCLUDED.cold_address,
                hot_balance_minor = 0,
                cold_balance_minor = 0,
                low_water_minor = EXCLUDED.low_water_minor,
                high_water_minor = EXCLUDED.high_water_minor,
                sync_status = 'never',
                last_synced_at = NULL;
            """,
            ETH_HOT_ADDR,
            ETH_COLD_ADDR,
            100 * SCALE,
            500 * SCALE,
        )

    yield

    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM payout_approvals;")
        await conn.execute("DELETE FROM cold_payouts;")
        await conn.execute(
            """
            UPDATE wallet_state
            SET hot_address = '0x0000000000000000000000000000000000000000',
                cold_address = '0x0000000000000000000000000000000000000000',
                hot_balance_minor = 0,
                cold_balance_minor = 0,
                sync_status = 'never',
                last_synced_at = NULL;
            """
        )


def make_db_address_resolver(pool: asyncpg.Pool) -> Any:
    """Create an AddressResolver reading directly from the authoritative wallet_state table."""

    async def _resolve(rail: str) -> tuple[str, str]:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT hot_address, cold_address FROM wallet_state WHERE rail = $1;",
                rail,
            )
            if row is None:
                raise ValueError(f"No wallet_state entry for rail: {rail}")
            return (
                AsyncWeb3.to_checksum_address(row["hot_address"]),
                AsyncWeb3.to_checksum_address(row["cold_address"]),
            )

    return _resolve


# -----------------------------------------------------------------------------
# 1. MIGRATION 0012: WIDENED CHECK & SEEDING PROOF
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_migration_0012_rail_check_widened_and_seeded(db_pool: asyncpg.Pool) -> None:
    """Prove migration 0012 widened the CHECK constraint and seeded both rail rows."""
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT rail FROM wallet_state ORDER BY rail ASC;")
        rails = [r["rail"] for r in rows]
        assert "base_usdc" in rails
        assert "ethereum_usdc" in rails

        # Test inserting an unsupported rail violates the widened CHECK constraint
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                """
                INSERT INTO wallet_state (
                    rail, hot_address, cold_address, hot_balance_minor, cold_balance_minor,
                    low_water_minor, high_water_minor, sync_status
                ) VALUES (
                    'solana_usdc',
                    '0x0000000000000000000000000000000000000000',
                    '0x0000000000000000000000000000000000000000',
                    0, 0, 100, 500, 'never'
                );
                """
            )


# -----------------------------------------------------------------------------
# 2. SECOND RAIL E2E: MULTI-CHAIN MONITOR SYNC
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_second_rail_e2e_dual_monitor_sync(db_pool: asyncpg.Pool) -> None:
    """Prove Task 44 HotWalletMonitor + generalized BaseL2Reader syncs both chains independently."""
    base_hot_units = 150 * SCALE
    base_cold_units = 1000 * SCALE
    base_provider = MultiChainRecordingRpcProvider(
        chain_id=8453,
        balances={
            BASE_HOT_ADDR.lower(): base_hot_units,
            BASE_COLD_ADDR.lower(): base_cold_units,
        },
    )

    eth_hot_units = 350 * SCALE
    eth_cold_units = 2500 * SCALE
    eth_provider = MultiChainRecordingRpcProvider(
        chain_id=1,
        balances={
            ETH_HOT_ADDR.lower(): eth_hot_units,
            ETH_COLD_ADDR.lower(): eth_cold_units,
        },
    )

    w3_base = AsyncWeb3(base_provider)
    w3_eth = AsyncWeb3(eth_provider)

    registry = {
        "base_usdc": RailConfig(
            rail="base_usdc",
            chain_id=8453,
            usdc_address=BASE_USDC_CONTRACT,
            rpc_url="https://base.example.com",
            confirmations_min=1,
        ),
        "ethereum_usdc": RailConfig(
            rail="ethereum_usdc",
            chain_id=1,
            usdc_address=ETH_USDC_CONTRACT,
            rpc_url="https://eth.example.com",
            confirmations_min=1,
        ),
    }

    resolver = make_db_address_resolver(db_pool)

    async with httpx.AsyncClient() as http:
        reader = BaseL2Reader(
            resolver=resolver,
            w3={"base_usdc": w3_base, "ethereum_usdc": w3_eth},
            http=http,
            registry=registry,
        )

        alerts: list[str] = []

        async def _capture_alert(msg: str, rail: str = "unknown") -> None:
            alerts.append(f"{rail}: {msg}")

        fixed_now = datetime(2026, 9, 28, 12, 0, 0, tzinfo=UTC).timestamp()

        # Monitor run 1: Base rail
        monitor_base = HotWalletMonitor(
            pool=db_pool,
            reader=reader,  # type: ignore[arg-type]
            alert=_capture_alert,
            rail="base_usdc",
            now=lambda: fixed_now,
        )
        report_base = await monitor_base.run_once()
        assert report_base.synced is True
        assert report_base.hot_balance == base_hot_units
        assert report_base.cold_balance == base_cold_units

        # Monitor run 2: Ethereum rail
        monitor_eth = HotWalletMonitor(
            pool=db_pool,
            reader=reader,  # type: ignore[arg-type]
            alert=_capture_alert,
            rail="ethereum_usdc",
            now=lambda: fixed_now,
        )
        report_eth = await monitor_eth.run_once()
        assert report_eth.synced is True
        assert report_eth.hot_balance == eth_hot_units
        assert report_eth.cold_balance == eth_cold_units

    # Verify database state for both rails
    async with db_pool.acquire() as conn:
        row_base = await conn.fetchrow("SELECT * FROM wallet_state WHERE rail = 'base_usdc';")
        assert row_base is not None
        assert row_base["hot_balance_minor"] == base_hot_units
        assert row_base["cold_balance_minor"] == base_cold_units
        assert row_base["sync_status"] == "ok"
        assert row_base["last_synced_at"] is not None

        row_eth = await conn.fetchrow("SELECT * FROM wallet_state WHERE rail = 'ethereum_usdc';")
        assert row_eth is not None
        assert row_eth["hot_balance_minor"] == eth_hot_units
        assert row_eth["cold_balance_minor"] == eth_cold_units
        assert row_eth["sync_status"] == "ok"
        assert row_eth["last_synced_at"] is not None

    # Verify calldata target isolation: Base provider received Base USDC; Eth received Eth USDC
    base_calls = [
        c for c in base_provider.recorded_calls if c["data"].startswith(BALANCE_OF_SELECTOR)
    ]
    assert len(base_calls) == 2
    assert all(c["to"].lower() == BASE_USDC_CONTRACT.lower() for c in base_calls)

    eth_calls = [
        c for c in eth_provider.recorded_calls if c["data"].startswith(BALANCE_OF_SELECTOR)
    ]
    assert len(eth_calls) == 2
    assert all(c["to"].lower() == ETH_USDC_CONTRACT.lower() for c in eth_calls)


# -----------------------------------------------------------------------------
# 3. TASK 45 COLD PAYOUT CONFIRMATION WITH ETHEREUM FINALITY KNOB
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cold_payout_confirmation_ethereum_rail_finality_knob(
    db_pool: asyncpg.Pool,
) -> None:
    """Prove Task 45 PayoutService on ethereum_usdc respects per-rail confirmations_min."""
    tx_hash = "0x" + "7" * 64

    # Receipt with status=1, confirmations=0 (< min 1)
    eth_provider = MultiChainRecordingRpcProvider(
        chain_id=1,
        receipts={
            tx_hash.lower(): {"status": 1, "confirmations": 0},
        },
        block_number=100,
    )
    w3_eth = AsyncWeb3(eth_provider)

    registry = {
        "ethereum_usdc": RailConfig(
            rail="ethereum_usdc",
            chain_id=1,
            usdc_address=ETH_USDC_CONTRACT,
            rpc_url="https://eth.example.com",
            confirmations_min=1,
        ),
    }

    resolver = make_db_address_resolver(db_pool)

    async with httpx.AsyncClient() as http:
        reader = BaseL2Reader(
            resolver=resolver,
            w3={"ethereum_usdc": w3_eth},
            http=http,
            registry=registry,
        )
        alerts: list[str] = []

        async def _capture_alert(msg: str, rail: str = "unknown") -> None:
            alerts.append(f"{rail}: {msg}")

        service = PayoutService(pool=db_pool, reader=reader, alert=_capture_alert)  # type: ignore[arg-type]

        # 1. Request payout on ethereum_usdc
        payout = await service.request(
            rail="ethereum_usdc",
            to_address=ETH_COLD_ADDR,
            amount_minor=100 * SCALE,
            currency="USDC",
            reason="operational",
            requested_by_sub="system",
        )

        # 2. Vote 2-of-2 approval
        await service.vote(
            payout_id=payout.payout_id, voter_sub="admin_a", voter_role="admin", vote="approve"
        )
        await service.vote(
            payout_id=payout.payout_id, voter_sub="admin_b", voter_role="admin", vote="approve"
        )

        # 3. Record execution receipt
        await service.record_execution(
            payout_id=payout.payout_id,
            tx_hash=tx_hash,
            recorded_by_sub="admin_b",
        )

        # 4. Confirm when confirmations == 0 (< min 1) -> stays executed
        res_0 = await service.confirm_if_ready(payout_id=payout.payout_id)
        assert res_0 is None, "Payout must not confirm with 0 confirmations when min is 1"

        # Verify DB status remains executed
        async with db_pool.acquire() as conn:
            row_exec = await conn.fetchrow(
                "SELECT status FROM cold_payouts WHERE payout_id = $1;", payout.payout_id
            )
            assert row_exec is not None
            assert row_exec["status"] == "executed"

        # 5. Update receipt: status=1, confirmations=3 (>= min 1) -> advances to confirmed
        eth_provider.receipts[tx_hash.lower()] = {"status": 1, "confirmations": 3}

        res_confirmed = await service.confirm_if_ready(payout_id=payout.payout_id)
        assert res_confirmed is not None
        assert res_confirmed.status == "confirmed"

        # Verify DB status is now confirmed
        async with db_pool.acquire() as conn:
            row_conf = await conn.fetchrow(
                "SELECT status, confirmed_at FROM cold_payouts WHERE payout_id = $1;",
                payout.payout_id,
            )
            assert row_conf is not None
            assert row_conf["status"] == "confirmed"
            assert row_conf["confirmed_at"] is not None
