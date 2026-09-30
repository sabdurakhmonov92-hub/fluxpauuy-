"""Base L2 On-Chain Observation Reader (Block J, Part 2).

This module provides the on-chain observation adapter for Base L2 (EVM).
It connects the FluxPay treasury subsystem to the blockchain to read:
1. Hot wallet and cold vault USDC custody balances (for Task 44 HotWalletMonitor).
2. Transaction execution receipts and confirmation depth (for Task 45 confirm_if_ready).

DESIGN LAWS & INVARIANTS:
1. PURE OBSERVATION LAW:
   The server READS the blockchain and NEVER mutates or signs state. All execution
   lives strictly in human signers behind Gnosis Safe multisig contracts. This module
   contains zero cryptographic signing capabilities or credential material.

2. MINOR-UNITS IDENTITY LAW:
   Base native USDC has 6 decimal places. FluxPay internal accounting uses 6 decimal
   places for USD/USDC minor units (1 USDC = 1_000_000 minor units). Therefore,
   raw ERC-20 `balanceOf()` returns minor units 1:1. No conversion math is performed.
   If a future token with 18 decimals is introduced, conversion MUST happen at the
   adapter boundary, never inside the core ledger or treasury accounting models.

3. RUNTIME DECIMALS GUARD (THE 10^12 DEFENSE):
   Assumptions are bugs waiting to happen. The reader verifies `decimals() == 6` on
   the target token contract at runtime before accepting balance data. If a token
   returns 18 decimals (e.g. DAI or native ETH) or any value other than 6, an
   IntegrationError is raised immediately to prevent a catastrophic 10^12 balance error.

4. FAIL-OPEN ON OBSERVATION LAW:
   Observation failures (RPC outages, timeouts, transport errors) never halt money
   movement. The HotWalletMonitor catches reader exceptions, marks sync_status='reader_error',
   and triggers alerts after sustained staleness (>30m).

5. ADDRESS RESOLVER SEAM:
   The adapter is strictly decoupled from the database (enforcing the integrations
   isolation law). The composition root injects an AddressResolver callback that
   queries `wallet_state` to obtain authoritative, checksummed addresses.

6. REVERTED TRANSACTION RECEIPT MAPPING:
   An EVM transaction with receipt status == 0 is TERMINAL-FAILED (execution reverted).
   It is mapped to TxStatus(confirmed=False, confirmations=0). Task 45's classify_stuck
   alarms on executed transactions unconfirmed after 24h, triggering human operator triage.
"""

from __future__ import annotations

import asyncio
import random
import re
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

import httpx
from web3 import AsyncWeb3
from web3.exceptions import TransactionNotFound

from fluxpay.integrations.base import BaseClient, ProviderCall
from fluxpay.integrations.rails import RailConfig, build_registry
from fluxpay.shared.errors import IntegrationError
from fluxpay.shared.logging import get_logger

__all__ = [
    "BALANCE_OF_SELECTOR",
    "DECIMALS_SELECTOR",
    "ERC20_MIN_ABI",
    "AddressResolver",
    "BaseL2Reader",
    "NullReader",
    "RailConfig",
    "TxStatus",
    "build_registry",
]

# -----------------------------------------------------------------------------
# Module Constants: ERC-20 Minimal ABI & Selectors
# -----------------------------------------------------------------------------
# Minimal ABI containing ONLY the read methods necessary for custody observation.
# Keeping the ABI surface minimal eliminates attack surface and dead parsing logic.
ERC20_MIN_ABI: list[dict[str, Any]] = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    },
]

# Standard 4-byte ERC-20 function selectors (keccak256 hash prefixes)
BALANCE_OF_SELECTOR: str = "0x70a08231"  # bytes4(keccak256("balanceOf(address)"))
DECIMALS_SELECTOR: str = "0x313ce567"  # bytes4(keccak256("decimals()"))

# Regex for strict transaction hash validation (0x prefix followed by 64 hex chars)
TX_HASH_REGEX: re.Pattern[str] = re.compile(r"^0x[0-9a-fA-F]{64}$")


@dataclass(frozen=True, slots=True)
class TxStatus:
    """Confirmation status of an on-chain transaction.

    Mirrors Task 44's frozen TxStatus protocol definition.
    """

    confirmed: bool
    confirmations: int


# AddressResolver: Bridge between Task 44's wallet_state schema and the DB-free reader.
# Resolves (hot_address, cold_address) checksummed tuple for a given rail.
AddressResolver = Callable[[str], Coroutine[Any, Any, tuple[str, str]]]


class NullReader:
    """Disabled-mode stub implementing the OnChainReader protocol.

    When Base L2 RPC URL is unconfigured (FLX_BASE_RPC_URL is None or empty),
    the application composition root wires this null adapter. In accordance with
    Task 44's fail-open observation architecture, every method raises IntegrationError.
    HotWalletMonitor catches this and records sync_status='reader_error', ensuring
    unconfigured production infrastructure remains loudly visible rather than silently dead.
    """

    async def read_hot_balance(self, rail: str) -> int:
        """Raise IntegrationError indicating reader is not configured."""
        raise IntegrationError(
            message="reader not configured",
            details={"rail": rail, "phase": "unconfigured"},
        )

    async def read_cold_balance(self, rail: str) -> int:
        """Raise IntegrationError indicating reader is not configured."""
        raise IntegrationError(
            message="reader not configured",
            details={"rail": rail, "phase": "unconfigured"},
        )

    async def get_tx_status(self, rail: str, tx_hash: str) -> Any:
        """Raise IntegrationError indicating reader is not configured."""
        raise IntegrationError(
            message="reader not configured",
            details={"rail": rail, "phase": "unconfigured"},
        )


class BaseL2Reader(BaseClient):
    """Base L2 On-Chain Observation Reader.

    Implements the OnChainReader protocol against Base L2 JSON-RPC endpoints.
    Subclasses BaseClient to compose retry ladder backoff, timeout enforcement,
    and structured observability across all RPC interactions.
    """

    # IDEMPOTENCY: N/A for BaseL2Reader.
    # All operations executed by this adapter are read-only JSON-RPC queries
    # (eth_call, eth_chainId, eth_getTransactionReceipt, eth_blockNumber).
    # Reads never mutate on-chain state, so HTTP idempotency keys are not applicable.

    def __init__(
        self,
        *,
        resolver: AddressResolver,
        w3: Any,
        registry: dict[str, RailConfig] | None = None,
        http: httpx.AsyncClient | None = None,
        expected_chain_id: int = 8453,
        usdc_address: str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        provider_name: str = "base_l2",
        max_attempts: int = 3,
        backoff_base_s: float = 0.5,
        backoff_cap_s: float = 8.0,
        sleep: Callable[[float], Coroutine[Any, Any, Any]] = asyncio.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize BaseL2Reader with injected dependencies.

        # --- Task 51 refactor ---
        DEPRECATION SHIM & COMPATIBILITY LAW:
        If `registry` is None, this constructor builds a single-entry registry
        for 'base_usdc' using the legacy `expected_chain_id` and `usdc_address`
        kwargs. This guarantees that Task 50's test suite, composition roots,
        and scripts continue functioning without edits.
        In Phase 2, passing raw `expected_chain_id` or `usdc_address` directly
        will be deprecated in favor of injecting `registry: dict[str, RailConfig]`.

        Args:
            resolver: Async callable returning (hot_address, cold_address) for a rail.
            w3: Injected Web3 / AsyncWeb3 instance or duck-typed provider ({rail: w3} dict).
            registry: Optional multi-chain RailConfig dictionary (Task 51 registry pattern).
            http: Injected httpx.AsyncClient owned by composition root.
            expected_chain_id: Expected network chain ID (legacy compat for base_usdc).
            usdc_address: Target USDC token contract address on Base (legacy compat).
            provider_name: Identifier for BaseClient structured logging.
            max_attempts: Maximum retry attempts for transient RPC transport failures.
            backoff_base_s: Initial exponential backoff delay in seconds.
            backoff_cap_s: Maximum backoff delay cap in seconds.
            sleep: Injected sleep primitive for zero-sleep testing.
            now: Injected monotonic clock for deterministic latency measurement.
        """
        client_http = http if http is not None else httpx.AsyncClient()
        super().__init__(
            provider_name=provider_name,
            http=client_http,
            max_attempts=max_attempts,
            backoff_base_s=backoff_base_s,
            backoff_cap_s=backoff_cap_s,
            sleep=sleep,
            now=now,
        )
        self._resolver = resolver
        self._w3 = w3

        # Compatibility shim: build single-entry registry for base_usdc if omitted
        if registry is None:
            self._registry: dict[str, RailConfig] = {
                "base_usdc": RailConfig(
                    rail="base_usdc",
                    chain_id=expected_chain_id,
                    usdc_address=usdc_address,
                    rpc_url=None,
                    confirmations_min=1,
                )
            }
        else:
            self._registry = dict(registry)

        self.expected_chain_id = (
            self._registry["base_usdc"].chain_id
            if "base_usdc" in self._registry
            else expected_chain_id
        )
        self._usdc_address = (
            self._registry["base_usdc"].usdc_address
            if "base_usdc" in self._registry
            else usdc_address
        )
        # Per-rail probe cache: {(rail): bool}
        self._probed_rails: dict[str, bool] = {}
        self._logger = get_logger("fluxpay.integrations.base_l2").bind(provider=provider_name)

    @property
    def _probed(self) -> bool:
        """Backward-compatibility alias for base_usdc probed state."""
        return self._probed_rails.get("base_usdc", False)

    @_probed.setter
    def _probed(self, value: bool) -> None:
        self._probed_rails["base_usdc"] = value

    @property
    def registry(self) -> dict[str, RailConfig]:
        """Access the injected rail registry."""
        return self._registry

    def _get_w3(self, rail: str) -> Any:
        """Resolve Web3 instance for a rail (supports single or per-rail provider mapping)."""
        if isinstance(self._w3, dict):
            if rail not in self._w3:
                raise IntegrationError(
                    message=f"No Web3 provider instance for rail '{rail}'",
                    details={"phase": "w3_check", "rail": rail},
                )
            return self._w3[rail]
        return self._w3

    async def _execute_with_ladder[T](
        self,
        op: str,
        coro_factory: Callable[[], Coroutine[Any, Any, T]],
    ) -> T:
        """Execute an asynchronous RPC operation through the BaseClient retry ladder.

        Retries transient network transport drops and timeouts up to max_attempts
        with exponential backoff and jitter. Emits structured log events for attempts
        and final completion.
        """
        op_start = self._now()
        last_exc: Exception | None = None

        for attempt in range(1, self.max_attempts + 1):
            attempt_start = self._now()
            try:
                result = await coro_factory()
                attempt_duration_ms = int((self._now() - attempt_start) * 1000)
                self._logger.info(
                    "provider_call_attempt",
                    provider=self.provider_name,
                    op=op,
                    attempt=attempt,
                    status=200,
                    duration_ms=attempt_duration_ms,
                )
                total_duration_ms = int((self._now() - op_start) * 1000)
                call = ProviderCall(
                    provider=self.provider_name,
                    op=op,
                    status=200,
                    duration_ms=total_duration_ms,
                    ok=True,
                )
                self._logger.info(
                    "provider_call_completed",
                    provider=call.provider,
                    op=call.op,
                    attempt=attempt,
                    status=call.status,
                    duration_ms=call.duration_ms,
                    ok=call.ok,
                )
                return result
            except (
                httpx.TransportError,
                httpx.TimeoutException,
                ConnectionError,
                TimeoutError,
            ) as exc:
                last_exc = exc
                attempt_duration_ms = int((self._now() - attempt_start) * 1000)
                self._logger.info(
                    "provider_call_attempt",
                    provider=self.provider_name,
                    op=op,
                    attempt=attempt,
                    status=None,
                    duration_ms=attempt_duration_ms,
                )
                if attempt < self.max_attempts:
                    n = attempt - 1
                    nominal = self.backoff_base_s * (2**n)
                    jitter = nominal * random.uniform(0.0, 0.25)  # noqa: S311
                    sleep_duration = min(self.backoff_cap_s, nominal + jitter)
                    await self._sleep(sleep_duration)
                    continue

        total_duration_ms = int((self._now() - op_start) * 1000)
        call = ProviderCall(
            provider=self.provider_name,
            op=op,
            status=None,
            duration_ms=total_duration_ms,
            ok=False,
        )
        self._logger.info(
            "provider_call_completed",
            provider=call.provider,
            op=call.op,
            attempt=self.max_attempts,
            status=call.status,
            duration_ms=call.duration_ms,
            ok=call.ok,
        )
        raise IntegrationError(
            message=(
                f"Base L2 RPC operation '{op}' exhausted after "
                f"{self.max_attempts} attempts: {last_exc}"
            ),
            details={
                "provider": self.provider_name,
                "op": op,
                "attempts": str(self.max_attempts),
                "error": type(last_exc).__name__ if last_exc else "exhausted",
            },
        )

    async def probe(self, rail: str = "base_usdc") -> int:
        """Verify remote RPC node chain_id matches expected configured network for rail.

        # --- Task 51 refactor ---
        RUNTIME CHAIN-ID GUARD & PER-RAIL ISOLATION:
        Connecting to the wrong chain (e.g. testnet Sepolia with mainnet contracts)
        causes silent balance drift or false confirmation reads.
        If chain_id != expected_chain_id, raises IntegrationError with details:
        {"phase": "chain_id_mismatch", "expected": ..., "got": ..., "rail": ...}.

        SELF-HEALING PER-RAIL PROBE CACHE:
        Success caches `self._probed_rails[rail] = True` to avoid redundant eth_chainId calls.
        A failed probe is NOT cached: `self._probed_rails[rail] = False`.
        A failure on rail B never poisons rail A's cached state.
        """
        try:
            cfg = self._registry[rail]
        except KeyError as exc:
            raise IntegrationError(
                message=f"Unsupported rail for BaseL2Reader: '{rail}'. Unknown rail.",
                details={"phase": "rail_check", "rail": rail},
            ) from exc

        w3 = self._get_w3(rail)

        async def _fetch_chain_id() -> int:
            cid_attr = w3.eth.chain_id
            if callable(cid_attr):
                val = await cid_attr()
            elif hasattr(cid_attr, "__await__"):
                val = await cid_attr
            else:
                val = cid_attr
            return int(val)

        got_id = await self._execute_with_ladder("chain_id", _fetch_chain_id)
        if got_id != cfg.chain_id:
            self._probed_rails[rail] = False
            self._logger.error(
                "chain_id_mismatch",
                rail=rail,
                expected=cfg.chain_id,
                got=got_id,
            )
            raise IntegrationError(
                message=(f"Rail '{rail}' chain ID mismatch: expected {cfg.chain_id}, got {got_id}"),
                details={
                    "phase": "chain_id_mismatch",
                    "expected": str(cfg.chain_id),
                    "got": str(got_id),
                    "rail": rail,
                },
            )

        self._probed_rails[rail] = True
        return got_id

    async def healthcheck(self, rail: str = "base_usdc") -> bool:
        """Cheapest ping: probe chain ID and verify connectivity for rail."""
        try:
            cfg = self._registry[rail]
            chain_id = await self.probe(rail)
            return chain_id == cfg.chain_id
        except Exception:
            return False

    async def _read_balance(self, checksum_address: str, rail: str = "base_usdc") -> int:
        """Query contract balanceOf and enforce runtime decimals guard.

        # --- Task 51 refactor ---
        Lookups flow through cfg = self._registry[rail] to bind correct USDC address.
        Decimals guard verifies decimals == 6 per-rail at runtime directly on contract.
        """
        cfg = self._registry[rail]
        w3 = self._get_w3(rail)
        checksum_usdc = AsyncWeb3.to_checksum_address(cfg.usdc_address)
        contract = w3.eth.contract(address=checksum_usdc, abi=ERC20_MIN_ABI)

        # 1. RUNTIME DECIMALS GUARD (THE 10^12-ERROR DEFENSE):
        # We verify decimals == 6 at runtime directly on the contract instance.
        # If an incorrect token address was supplied (e.g. 18-decimal token),
        # this guard prevents interpreting 1 token as 10^12 minor units.
        async def _fetch_decimals() -> int:
            return int(await contract.functions.decimals().call())

        decimals = await self._execute_with_ladder("decimals", _fetch_decimals)
        if decimals != 6:
            self._logger.error(
                "usdc_decimals_mismatch",
                rail=rail,
                expected=6,
                got=decimals,
                token_address=checksum_usdc,
            )
            raise IntegrationError(
                message=(
                    f"USDC token contract decimals mismatch on rail '{rail}': "
                    f"expected 6, got {decimals}"
                ),
                details={
                    "phase": "decimals",
                    "expected": "6",
                    "got": str(decimals),
                    "rail": rail,
                },
            )

        # 2. MINOR-UNITS IDENTITY:
        # raw balanceOf uint256 is 1:1 with FluxPay minor units.
        async def _fetch_balance() -> int:
            return int(await contract.functions.balanceOf(checksum_address).call())

        raw_balance = await self._execute_with_ladder("balance_of", _fetch_balance)
        return raw_balance

    async def read_hot_balance(self, rail: str) -> int:
        """Fetch current on-chain balance of the rail hot wallet in minor units.

        # --- Task 51 refactor ---
        Enforces rail check against registry before any I/O, resolves hot address via
        AddressResolver, ensures chain ID is probed per-rail, and returns balanceOf raw uint256.
        """
        try:
            _ = self._registry[rail]
        except KeyError as exc:
            raise IntegrationError(
                message=f"Unsupported rail for BaseL2Reader: '{rail}'. Unknown rail.",
                details={"phase": "rail_check", "rail": rail},
            ) from exc

        (hot_addr, _) = await self._resolver(rail)
        if not self._probed_rails.get(rail, False):
            await self.probe(rail)

        checksum_hot = AsyncWeb3.to_checksum_address(hot_addr)
        return await self._read_balance(checksum_hot, rail=rail)

    async def read_cold_balance(self, rail: str) -> int:
        """Fetch current on-chain balance of the rail cold vault in minor units.

        # --- Task 51 refactor ---
        Mirrors read_hot_balance targeting the cold multisig vault address.
        """
        try:
            _ = self._registry[rail]
        except KeyError as exc:
            raise IntegrationError(
                message=f"Unsupported rail for BaseL2Reader: '{rail}'. Unknown rail.",
                details={"phase": "rail_check", "rail": rail},
            ) from exc

        (_, cold_addr) = await self._resolver(rail)
        if not self._probed_rails.get(rail, False):
            await self.probe(rail)

        checksum_cold = AsyncWeb3.to_checksum_address(cold_addr)
        return await self._read_balance(checksum_cold, rail=rail)

    async def get_tx_status(self, rail: str, tx_hash: str) -> TxStatus:
        """Query confirmation status for an on-chain transaction hash.

        # --- Task 51 refactor ---
        THE REVERTED MAPPING ESSAY & THE FINALITY KNOB:
        1. Lookups flow strictly through cfg = self._registry[rail] (KeyError -> IntegrationError).
        2. Status == 0 maps to TxStatus(confirmed=False, confirmations=0) permanently
           (terminal reverted execution; payout stays 'executed' until stuck alert fires).
        3. Status == 1 computes confirmation depth and applies the per-rail finality knob:
           `confirmed = (confirmations >= cfg.confirmations_min)`.
           If confirmations < cfg.confirmations_min, status remains unconfirmed (confirmed=False).
           Task 45's confirm_if_ready consumes TxStatus.confirmed transparently.
        """
        try:
            cfg = self._registry[rail]
        except KeyError as exc:
            raise IntegrationError(
                message=f"Unsupported rail for BaseL2Reader: '{rail}'. Unknown rail.",
                details={"phase": "rail_check", "rail": rail},
            ) from exc

        # Validate transaction hash: accept case-insensitively, must be 0x + 64 hex chars
        if not TX_HASH_REGEX.match(tx_hash):
            raise ValueError(
                f"Invalid transaction hash format: '{tx_hash}'. "
                "Must be a 64-hex-character string prefixed with '0x'."
            )

        normalized_hash = tx_hash.lower()

        if not self._probed_rails.get(rail, False):
            await self.probe(rail)

        w3 = self._get_w3(rail)

        async def _fetch_receipt() -> Any:
            try:
                return await w3.eth.get_transaction_receipt(normalized_hash)
            except TransactionNotFound:
                return None

        receipt = await self._execute_with_ladder("get_transaction_receipt", _fetch_receipt)

        if receipt is None:
            # Transaction is still pending in mempool or not yet mined
            return TxStatus(confirmed=False, confirmations=0)

        # Extract receipt status: 1 = success, 0 = reverted
        status_val = getattr(receipt, "status", None)
        if status_val is None and isinstance(receipt, dict):
            status_val = receipt.get("status")

        if status_val == 0:
            # Reverted execution -> terminal failure, confirmed=False forever
            return TxStatus(confirmed=False, confirmations=0)

        if status_val == 1:
            # Check for direct confirmations on receipt object or dictionary
            receipt_confs = getattr(receipt, "confirmations", None)
            if receipt_confs is None and isinstance(receipt, dict):
                receipt_confs = receipt.get("confirmations")

            if receipt_confs is not None:
                confirmations = int(receipt_confs)
            else:

                async def _fetch_block() -> int:
                    block_attr = w3.eth.block_number
                    if callable(block_attr):
                        return int(await block_attr())
                    elif hasattr(block_attr, "__await__"):
                        return int(await block_attr)
                    return int(block_attr)

                latest_block = await self._execute_with_ladder("block_number", _fetch_block)

                receipt_block = getattr(receipt, "blockNumber", None)
                if receipt_block is None and isinstance(receipt, dict):
                    receipt_block = receipt.get("blockNumber", receipt.get("block_number"))

                block_num = int(receipt_block) if receipt_block is not None else latest_block
                confirmations = max(0, latest_block - block_num + 1)

            is_confirmed = confirmations >= cfg.confirmations_min
            return TxStatus(confirmed=is_confirmed, confirmations=confirmations)

        # Unknown receipt format fallback
        return TxStatus(confirmed=False, confirmations=0)
