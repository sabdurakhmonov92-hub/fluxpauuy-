"""Base L2 On-Chain USDC Writer: Outbound Settlement Engine (Block J, Part 3).

This module provides the production-grade on-chain execution adapter for Base L2 (EVM).
It executes outbound USDC transfers to autonomous agents and external recipients with:
1. EIP-1559 Type-2 Dynamic Gas Pricing (baseFeePerGas + maxPriorityFeePerGas + 20% margin).
2. Pluggable Cloud and HSM Signers (AWS KMS, YubiHSM2, LocalDev) under strict memory hygiene.
3. Thread-Safe Nonce Management: per-hot-wallet asyncio.Lock with mempool synchronization.
4. Defense-in-Depth Pre-flight Checks (Native gas threshold, USDC liquidity, EIP-55 checksums).
5. Comprehensive Reorg and Drop Detection with deterministic confirmation tracking.
6. Unified Error Taxonomy and Prometheus Observability conforming to FluxPay platform invariants.

DESIGN LAWS & INVARIANTS:
1. THE ABSOLUTE KEY ISOLATION LAW:
   Private keys and raw signed/unsigned transaction payloads must NEVER be logged or leaked
   to exception strings, metric labels, or structlog contexts. Key lifetimes in process memory
   are kept to the bare minimum required to sign the RLP-encoded transaction digest.

2. MINOR-UNITS IDENTITY LAW:
   Base native USDC has 6 decimal places. All internal financial operations enforce exact
   Decimal representation at the boundary, scaling by 10^6 to raw integer minor units.
   Float inputs are rejected with TypeError to protect arithmetic integrity.

3. ATOMIC NONCE SERIALIZATION LAW:
   Every outbound transfer from a hot wallet acquires a dedicated asyncio.Lock for that address.
   The lock synchronizes reading the "pending" block tag from the node and updating the local
   monotonic nonce water-mark, eliminating concurrent nonce collisions under high agent concurrency.

4. 20% GAS SAFETY MARGIN:
   Base L2 gas consumption can fluctuate slightly across sequencer blocks. A mandatory 1.20x
   multiplier is applied to node-estimated gas limit to prevent out-of-gas reverts.

5. ERROR TAXONOMY MAPPING:
   All domain failures map deterministically to IntegrationError (or strongly typed subclasses)
   with immutable machine-readable error codes in the `details` dictionary:
   - INSUFFICIENT_GAS: Native ETH balance below operating threshold.
   - INSUFFICIENT_USDC: Token balance below payout amount.
   - NONCE_CONFLICT: Mempool collision or replacement underpriced.
   - TX_REVERTED: Terminal on-chain EVM revert with reason.
   - RPC_TIMEOUT: Transient confirmation or network timeout.
   - RPC_RATE_LIMIT: Upstream RPC HTTP 429 backoff with jitter.
"""

from __future__ import annotations

import asyncio
import random
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Final, Protocol, cast

import httpx
from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge, Histogram
from web3 import AsyncWeb3
from web3.exceptions import TransactionNotFound, Web3RPCError

from fluxpay.integrations.base import BaseClient, ProviderCall
from fluxpay.shared.errors import IntegrationError
from fluxpay.shared.logging import get_logger

__all__ = [
    "BASE_MAINNET_CHAIN_ID",
    "BASE_SEPOLIA_CHAIN_ID",
    "BASE_SEPOLIA_USDC_CONTRACT",
    "BASE_USDC_CONTRACT",
    "DEFAULT_CONFIRMATIONS",
    "DEFAULT_GAS_SAFETY_MARGIN",
    "DEFAULT_MAX_TRANSFER_AMOUNT",
    "DEFAULT_MIN_GAS_THRESHOLD",
    "ERC20_TRANSFER_ABI",
    "FLX_HOT_WALLET_ETH_BALANCE",
    "FLX_USDC_TRANSFERS_TOTAL",
    "FLX_USDC_TRANSFER_DURATION_SECONDS",
    "TRANSFER_SELECTOR",
    "USDC_DECIMALS",
    "USDC_SCALE",
    "ZERO_ADDRESS",
    "AwsKmsSigner",
    "BaseL2Writer",
    "BaseL2WriterError",
    "HsmSessionProtocol",
    "InsufficientGasError",
    "InsufficientUsdcError",
    "InvalidAddressError",
    "InvalidAmountError",
    "KmsClientProtocol",
    "LocalDevSigner",
    "NonceConflictError",
    "RpcRateLimitError",
    "RpcTimeoutError",
    "TransactionDroppedError",
    "TransactionRevertedError",
    "TransferReceipt",
    "TxSigner",
    "YubiHsmSigner",
]

# -----------------------------------------------------------------------------
# Module Constants: Chains, Selectors, and ERC-20 Transfer ABI
# -----------------------------------------------------------------------------
BASE_MAINNET_CHAIN_ID: Final[int] = 8453
BASE_SEPOLIA_CHAIN_ID: Final[int] = 84532
BASE_USDC_CONTRACT: Final[str] = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
BASE_SEPOLIA_USDC_CONTRACT: Final[str] = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

USDC_DECIMALS: Final[int] = 6
USDC_SCALE: Final[int] = 10**USDC_DECIMALS  # 1_000_000

TRANSFER_SELECTOR: Final[str] = "0xa9059cbb"  # bytes4(keccak256("transfer(address,uint256)"))
DEFAULT_MIN_GAS_THRESHOLD: Final[Decimal] = Decimal("0.005")  # 0.005 ETH
DEFAULT_MAX_TRANSFER_AMOUNT: Final[Decimal] = Decimal("100000")  # 100,000 USDC
DEFAULT_CONFIRMATIONS: Final[int] = 12
DEFAULT_GAS_SAFETY_MARGIN: Final[float] = 1.20  # 20% margin
ZERO_ADDRESS: Final[str] = "0x0000000000000000000000000000000000000000"

# SECP256k1 curve order constants for canonical low-s signature enforcement
SECP256K1_N: Final[int] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_N: Final[int] = SECP256K1_N // 2

# Standard ERC-20 Minimal ABI containing transfer, balanceOf, and decimals
ERC20_TRANSFER_ABI: Final[list[dict[str, Any]]] = [
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"},
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "payable": False,
        "stateMutability": "nonpayable",
        "type": "function",
    },
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

_EVM_ADDR_REGEX: Final[re.Pattern[str]] = re.compile(r"^0x[0-9a-fA-F]{40}$")


# -----------------------------------------------------------------------------
# Prometheus Telemetry Definitions
# -----------------------------------------------------------------------------
def _get_or_create_counter(
    name: str,
    documentation: str,
    labelnames: tuple[str, ...],
    registry: CollectorRegistry = REGISTRY,
) -> Counter:
    """Idempotently register or retrieve a Counter metric."""
    try:
        return Counter(name, documentation, labelnames=labelnames, registry=registry)
    except ValueError:
        collector = getattr(registry, "_names_to_collectors", {}).get(name)
        if isinstance(collector, Counter):
            return collector
        raise


def _get_or_create_gauge(
    name: str,
    documentation: str,
    labelnames: tuple[str, ...],
    registry: CollectorRegistry = REGISTRY,
) -> Gauge:
    """Idempotently register or retrieve a Gauge metric."""
    try:
        return Gauge(name, documentation, labelnames=labelnames, registry=registry)
    except ValueError:
        collector = getattr(registry, "_names_to_collectors", {}).get(name)
        if isinstance(collector, Gauge):
            return collector
        raise


def _get_or_create_histogram(
    name: str,
    documentation: str,
    labelnames: tuple[str, ...],
    buckets: tuple[float, ...],
    registry: CollectorRegistry = REGISTRY,
) -> Histogram:
    """Idempotently register or retrieve a Histogram metric."""
    try:
        return Histogram(
            name, documentation, labelnames=labelnames, buckets=buckets, registry=registry
        )
    except ValueError:
        collector = getattr(registry, "_names_to_collectors", {}).get(name)
        if isinstance(collector, Histogram):
            return collector
        raise


FLX_HOT_WALLET_ETH_BALANCE: Final[Gauge] = _get_or_create_gauge(
    "flx_hot_wallet_eth_balance",
    "Current hot wallet ETH balance for gas pre-flight monitoring",
    (),
)

FLX_USDC_TRANSFERS_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_usdc_transfers_total",
    "Total outbound USDC transfer attempts by terminal settlement outcome",
    ("outcome",),
)

FLX_USDC_TRANSFER_DURATION_SECONDS: Final[Histogram] = _get_or_create_histogram(
    "flx_usdc_transfer_duration_seconds",
    "End-to-end USDC transfer confirmation duration in seconds",
    (),
    buckets=(0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0, 300.0),
)


# -----------------------------------------------------------------------------
# Error Taxonomy: IntegrationError Subclasses
# -----------------------------------------------------------------------------
class BaseL2WriterError(IntegrationError):
    """Base error for all Base L2 settlement writer operations."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        details: dict[str, str] | None = None,
    ) -> None:
        merged_details = {"code": code}
        if details:
            merged_details.update(details)
        super().__init__(message=message, details=merged_details)


class InsufficientGasError(BaseL2WriterError):
    """Raised when hot wallet ETH balance is below minimum operating threshold."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="INSUFFICIENT_GAS", details=details)


class InsufficientUsdcError(BaseL2WriterError):
    """Raised when hot wallet USDC balance is insufficient for requested payout."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="INSUFFICIENT_USDC", details=details)


class NonceConflictError(BaseL2WriterError):
    """Raised when a nonce collision or underpriced replacement is rejected by the mempool."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="NONCE_CONFLICT", details=details)


class TransactionRevertedError(BaseL2WriterError):
    """Raised when on-chain execution reverts with receipt status=0."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="TX_REVERTED", details=details)


class RpcTimeoutError(BaseL2WriterError):
    """Raised when RPC communication or confirmation polling times out."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="RPC_TIMEOUT", details=details)


class RpcRateLimitError(BaseL2WriterError):
    """Raised when RPC provider rejects requests with HTTP 429 rate limit."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="RPC_RATE_LIMIT", details=details)


class InvalidAddressError(BaseL2WriterError):
    """Raised when destination address fails checksum or violates security policy."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="INVALID_ADDRESS", details=details)


class InvalidAmountError(BaseL2WriterError):
    """Raised when transfer amount violates positive, decimal, or ceiling constraints."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="INVALID_AMOUNT", details=details)


class TransactionDroppedError(BaseL2WriterError):
    """Raised when a transaction drops from the mempool or is reorged out."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="TX_DROPPED", details=details)


# -----------------------------------------------------------------------------
# Data Models: Transfer Receipt
# -----------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class TransferReceipt:
    """Immutable proof of confirmed outbound USDC transfer on Base L2."""

    tx_hash: str
    from_address: str
    to_address: str
    amount_usdc: Decimal
    amount_minor: int
    block_number: int
    confirmations: int
    gas_used: int
    effective_gas_price: int
    duration_ms: int


# -----------------------------------------------------------------------------
# Signer Protocols & Concrete Implementations
# -----------------------------------------------------------------------------
class KmsClientProtocol(Protocol):
    """Typing protocol for AWS KMS client sign method."""

    def sign(
        self,
        *,
        KeyId: str,  # noqa: N803
        Message: bytes,  # noqa: N803
        MessageType: str,  # noqa: N803
        SigningAlgorithm: str,  # noqa: N803
    ) -> dict[str, Any]:
        """Sign a message digest."""
        ...


class HsmSessionProtocol(Protocol):
    """Typing protocol for YubiHSM2 session sign method."""

    def sign_ecdsa_pkcs1v1_5(self, *, key_id: int, data: bytes) -> bytes:
        """Sign raw data digest."""
        ...


class TxSigner(ABC):
    """Abstract signing interface for EVM transactions.

    Adheres to the Secret Isolation Law:
    - Never log raw private keys, key material, or unsigned/signed transaction hex.
    - Keep key lifetimes in memory as minimal as possible.
    """

    @property
    @abstractmethod
    def address(self) -> str:
        """Checksummed EVM address corresponding to the signing key."""
        ...

    @abstractmethod
    async def sign_transaction(self, tx_dict: dict[str, int | str | bytes]) -> bytes:
        """Sign an EIP-1559 transaction dict and return raw serialized signed transaction bytes.

        Args:
            tx_dict: Unsigned EIP-1559 transaction dictionary.

        Returns:
            Raw signed transaction bytes ready for eth_sendRawTransaction.
        """
        ...


class LocalDevSigner(TxSigner):
    """Local private key signer for testing and development environments.

    Security Invariants:
    - Never logs private key material.
    - Zeroes key bytes when close() is invoked.
    - Excludes key material from __repr__ and __str__.
    """

    def __init__(self, private_key: str | bytes) -> None:
        from eth_account import Account
        from web3 import Web3

        if isinstance(private_key, str):
            clean = private_key.strip()
            if clean.startswith("0x"):
                clean = clean[2:]
            self._key_bytes: bytes = bytes.fromhex(clean)
        else:
            self._key_bytes = bytes(private_key)

        acct = Account.from_key(self._key_bytes)
        self._address: Final[str] = Web3.to_checksum_address(acct.address)

    @property
    def address(self) -> str:
        """Return the checksummed EVM address."""
        return self._address

    async def sign_transaction(self, tx_dict: dict[str, int | str | bytes]) -> bytes:
        """Sign transaction dictionary and return raw bytes."""
        from eth_account import Account

        signed = Account.sign_transaction(tx_dict, self._key_bytes)
        return bytes(signed.raw_transaction)

    def close(self) -> None:
        """Wipe key bytes from memory."""
        self._key_bytes = b"\x00" * len(self._key_bytes)

    def __repr__(self) -> str:
        return f"<LocalDevSigner address='{self._address}'>"

    def __str__(self) -> str:
        return f"LocalDevSigner({self._address})"


class AwsKmsSigner(TxSigner):
    """Hardware-backed cloud signer using AWS Key Management Service (secp256k1)."""

    def __init__(
        self,
        *,
        key_id: str,
        address: str,
        kms_client: KmsClientProtocol | None = None,
        sign_fn: Callable[[bytes], Coroutine[object, object, bytes]] | None = None,
    ) -> None:
        from web3 import Web3

        self._key_id = key_id
        self._address: Final[str] = Web3.to_checksum_address(address)
        self._kms_client = kms_client
        self._sign_fn = sign_fn

    @property
    def address(self) -> str:
        """Return the checksummed EVM address."""
        return self._address

    async def sign_transaction(self, tx_dict: dict[str, int | str | bytes]) -> bytes:
        """Sign transaction via AWS KMS and assemble canonical EIP-1559 signed transaction."""
        from eth_account import Account
        from eth_account._utils.signing import (  # type: ignore[attr-defined]
            encode_transaction,
            serializable_unsigned_transaction_from_dict,
        )

        clean_tx = {k: v for k, v in tx_dict.items() if k != "from"}
        unsigned_tx = serializable_unsigned_transaction_from_dict(cast(dict[str, Any], clean_tx))
        tx_hash = unsigned_tx.hash()

        if self._sign_fn is not None:
            raw_sig = await self._sign_fn(tx_hash)
            r, s = self._parse_signature(raw_sig)
        elif self._kms_client is not None:
            client = self._kms_client
            response = await asyncio.to_thread(
                client.sign,
                KeyId=self._key_id,
                Message=tx_hash,
                MessageType="DIGEST",
                SigningAlgorithm="ECDSA_SHA_256",
            )
            raw_sig = response["Signature"]
            r, s = self._parse_signature(raw_sig)
        else:
            raise BaseL2WriterError(
                message="AwsKmsSigner requires either kms_client or sign_fn to be configured",
                code="KMS_UNCONFIGURED",
                details={"key_id": self._key_id},
            )

        # Enforce canonical low-s (BIP-62 / EIP-2)
        if s > SECP256K1_HALF_N:
            s = SECP256K1_N - s

        # Recover correct v (0 or 1 for EIP-1559 Type 2)
        matched_v: int | None = None
        for candidate_v in (0, 1):
            try:
                recovered = Account._recover_hash(tx_hash, vrs=(candidate_v, r, s))
                if recovered.lower() == self._address.lower():
                    matched_v = candidate_v
                    break
            except (ValueError, TypeError):
                continue

        if matched_v is None:
            raise BaseL2WriterError(
                message="Failed to recover valid ECDSA v parameter matching KMS signer address",
                code="KMS_SIGNATURE_INVALID",
                details={"key_id": self._key_id},
            )

        signed_bytes = encode_transaction(unsigned_tx, vrs=(matched_v, r, s))
        return bytes(signed_bytes)

    @staticmethod
    def _parse_signature(sig_bytes: bytes) -> tuple[int, int]:
        """Parse DER ASN.1 or 64-byte raw (r, s) ECDSA signature."""
        if len(sig_bytes) == 64:
            return int.from_bytes(sig_bytes[:32], "big"), int.from_bytes(sig_bytes[32:], "big")
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        return decode_dss_signature(sig_bytes)

    def __repr__(self) -> str:
        return f"<AwsKmsSigner key_id='{self._key_id}' address='{self._address}'>"

    def __str__(self) -> str:
        return f"AwsKmsSigner({self._address})"


class YubiHsmSigner(TxSigner):
    """Hardware Security Module signer using YubiHSM2."""

    def __init__(
        self,
        *,
        key_id: int,
        address: str,
        connector_url: str = "http://localhost:12345",
        session: HsmSessionProtocol | None = None,
        sign_fn: Callable[[bytes], Coroutine[object, object, bytes]] | None = None,
    ) -> None:
        from web3 import Web3

        self._key_id = key_id
        self._address: Final[str] = Web3.to_checksum_address(address)
        self._connector_url = connector_url
        self._session = session
        self._sign_fn = sign_fn

    @property
    def address(self) -> str:
        """Return the checksummed EVM address."""
        return self._address

    async def sign_transaction(self, tx_dict: dict[str, int | str | bytes]) -> bytes:
        """Sign transaction via YubiHSM2 and assemble canonical EIP-1559 signed transaction."""
        from eth_account import Account
        from eth_account._utils.signing import (  # type: ignore[attr-defined]
            encode_transaction,
            serializable_unsigned_transaction_from_dict,
        )

        clean_tx = {k: v for k, v in tx_dict.items() if k != "from"}
        unsigned_tx = serializable_unsigned_transaction_from_dict(cast(dict[str, Any], clean_tx))
        tx_hash = unsigned_tx.hash()

        if self._sign_fn is not None:
            raw_sig = await self._sign_fn(tx_hash)
            r, s = self._parse_signature(raw_sig)
        elif self._session is not None:
            sess = self._session
            raw_sig = await asyncio.to_thread(
                sess.sign_ecdsa_pkcs1v1_5,
                key_id=self._key_id,
                data=tx_hash,
            )
            r, s = self._parse_signature(raw_sig)
        else:
            raise BaseL2WriterError(
                message="YubiHsmSigner requires either session or sign_fn to be configured",
                code="HSM_UNCONFIGURED",
                details={"key_id": str(self._key_id)},
            )

        if s > SECP256K1_HALF_N:
            s = SECP256K1_N - s

        matched_v: int | None = None
        for candidate_v in (0, 1):
            try:
                recovered = Account._recover_hash(tx_hash, vrs=(candidate_v, r, s))
                if recovered.lower() == self._address.lower():
                    matched_v = candidate_v
                    break
            except (ValueError, TypeError):
                continue

        if matched_v is None:
            raise BaseL2WriterError(
                message="Failed to recover valid ECDSA v parameter matching HSM signer address",
                code="HSM_SIGNATURE_INVALID",
                details={"key_id": str(self._key_id)},
            )

        signed_bytes = encode_transaction(unsigned_tx, vrs=(matched_v, r, s))
        return bytes(signed_bytes)

    @staticmethod
    def _parse_signature(sig_bytes: bytes) -> tuple[int, int]:
        """Parse DER ASN.1 or 64-byte raw (r, s) ECDSA signature."""
        if len(sig_bytes) == 64:
            return int.from_bytes(sig_bytes[:32], "big"), int.from_bytes(sig_bytes[32:], "big")
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        return decode_dss_signature(sig_bytes)

    def __repr__(self) -> str:
        return f"<YubiHsmSigner key_id={self._key_id} address='{self._address}'>"

    def __str__(self) -> str:
        return f"YubiHsmSigner({self._address})"


# -----------------------------------------------------------------------------
# Base L2 USDC Settlement Writer
# -----------------------------------------------------------------------------
class BaseL2Writer(BaseClient):
    """Production-grade Base L2 USDC settlement engine for outbound payments.

    Inherits from BaseClient to compose retry ladder backoff, timeout enforcement,
    and structured observability across all RPC interactions.
    """

    def __init__(
        self,
        *,
        signer: TxSigner,
        w3: AsyncWeb3[Any] | Any,
        chain_id: int = BASE_MAINNET_CHAIN_ID,
        usdc_address: str = BASE_USDC_CONTRACT,
        min_gas_threshold: Decimal = DEFAULT_MIN_GAS_THRESHOLD,
        max_transfer_amount: Decimal = DEFAULT_MAX_TRANSFER_AMOUNT,
        default_confirmations: int = DEFAULT_CONFIRMATIONS,
        gas_safety_margin: float = DEFAULT_GAS_SAFETY_MARGIN,
        poll_interval_s: float = 1.0,
        provider_name: str = "base_l2_writer",
        http: httpx.AsyncClient | None = None,
        max_attempts: int = 3,
        backoff_base_s: float = 0.5,
        backoff_cap_s: float = 8.0,
        sleep: Callable[[float], Coroutine[Any, Any, Any]] = asyncio.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize BaseL2Writer with injected dependencies.

        Args:
            signer: Injected transaction signer (LocalDevSigner, AwsKmsSigner, YubiHsmSigner).
            w3: Injected Web3 / AsyncWeb3 instance or duck-typed provider.
            chain_id: Expected network chain ID (Base Mainnet = 8453, Sepolia = 84532).
            usdc_address: Target USDC token contract address on Base L2.
            min_gas_threshold: Minimum hot wallet ETH balance required to process transfers.
            max_transfer_amount: Maximum allowed outbound USDC transfer per transaction.
            default_confirmations: Default block confirmation depth required for finality.
            gas_safety_margin: Gas limit safety multiplier (default 1.20 for 20% margin).
            poll_interval_s: Polling delay between receipt checks in seconds.
            provider_name: Identifier for BaseClient structured logging.
            http: Injected httpx.AsyncClient owned by composition root.
            max_attempts: Maximum retry attempts for transient RPC transport failures.
            backoff_base_s: Initial exponential backoff delay in seconds.
            backoff_cap_s: Maximum backoff delay cap in seconds.
            sleep: Injected sleep primitive for zero-sleep testing.
            now: Injected monotonic clock for deterministic latency measurement.
        """
        from web3 import Web3

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
        self.signer: Final[TxSigner] = signer
        self._w3: Final[Any] = w3
        self.chain_id: Final[int] = chain_id
        self.usdc_address: Final[str] = Web3.to_checksum_address(usdc_address)
        self.wallet_address: Final[str] = Web3.to_checksum_address(signer.address)
        self.min_gas_threshold: Final[Decimal] = min_gas_threshold
        self.max_transfer_amount: Final[Decimal] = max_transfer_amount
        self.default_confirmations: Final[int] = default_confirmations
        self.gas_safety_margin: Final[float] = gas_safety_margin
        self.poll_interval_s: Final[float] = poll_interval_s

        # Nonce tracking: serialized per hot wallet via asyncio.Lock
        self._wallet_locks: dict[str, asyncio.Lock] = {}
        self._next_nonces: dict[str, int] = {}
        self._probed: bool = False
        self._contract = self._w3.eth.contract(address=self.usdc_address, abi=ERC20_TRANSFER_ABI)
        self._logger = get_logger("fluxpay.integrations.base_l2_writer").bind(
            provider=provider_name,
            wallet=self.wallet_address,
        )

    def _get_wallet_lock(self, address: str) -> asyncio.Lock:
        """Retrieve or initialize the asyncio.Lock for the hot wallet address."""
        addr_lower = address.lower()
        if addr_lower not in self._wallet_locks:
            self._wallet_locks[addr_lower] = asyncio.Lock()
        return self._wallet_locks[addr_lower]

    async def _execute_with_ladder[T](
        self,
        op: str,
        coro_factory: Callable[[], Coroutine[Any, Any, T]],
    ) -> T:
        """Execute an asynchronous RPC operation through the BaseClient retry ladder.

        Retries transient network transport drops, timeouts, and rate limits up to
        max_attempts with exponential backoff and jitter.
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
            except TransactionNotFound:
                raise
            except (
                httpx.TransportError,
                httpx.TimeoutException,
                ConnectionError,
                TimeoutError,
                Web3RPCError,
            ) as exc:
                last_exc = exc
                err_str = str(exc).lower()

                # Handle HTTP 429 rate limit errors specifically
                is_rate_limit = "429" in err_str or "rate limit" in err_str
                status_code = 429 if is_rate_limit else None

                attempt_duration_ms = int((self._now() - attempt_start) * 1000)
                self._logger.info(
                    "provider_call_attempt",
                    provider=self.provider_name,
                    op=op,
                    attempt=attempt,
                    status=status_code,
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

        last_err_str = str(last_exc).lower() if last_exc else ""
        if "429" in last_err_str or "rate limit" in last_err_str:
            raise RpcRateLimitError(
                message=f"RPC operation '{op}' failed with rate limit 429: {last_exc}",
                details={"op": op, "error": str(last_exc)},
            )

        err_type = type(last_exc).__name__ if last_exc else "exhausted"
        raise RpcTimeoutError(
            message=(
                f"Base L2 RPC operation '{op}' exhausted after {self.max_attempts} "
                f"attempts: {last_exc}"
            ),
            details={"op": op, "error": err_type},
        )

    async def probe(self) -> int:
        """Verify remote RPC node chain_id matches expected configured network.

        Raises:
            BaseL2WriterError: If remote chain_id does not match configured chain_id.

        Returns:
            The verified chain_id.
        """

        async def _fetch_chain_id() -> int:
            return int(await self._w3.eth.chain_id)

        remote_chain_id = int(await self._execute_with_ladder("eth_chainId", _fetch_chain_id))
        if remote_chain_id != self.chain_id:
            self._probed = False
            raise BaseL2WriterError(
                message=(
                    f"Chain ID mismatch for Base L2 writer: "
                    f"expected {self.chain_id}, got {remote_chain_id}"
                ),
                code="CHAIN_ID_MISMATCH",
                details={
                    "expected": str(self.chain_id),
                    "got": str(remote_chain_id),
                },
            )
        self._probed = True
        return remote_chain_id

    def validate_destination_address(self, to: str) -> str:
        """Validate destination address format, checksum, and security constraints.

        Args:
            to: Recipient EVM address string.

        Returns:
            Valid checksummed address.

        Raises:
            InvalidAddressError: If address is invalid, not checksummed, zero, or self-transfer.
        """
        from web3 import Web3

        if not isinstance(to, str) or not _EVM_ADDR_REGEX.match(to):
            raise InvalidAddressError(
                message=f"Destination address '{to}' is not a valid 40-hex EVM address",
                details={"to": str(to)},
            )

        if not Web3.is_checksum_address(to):
            raise InvalidAddressError(
                message=f"Destination address '{to}' fails EIP-55 checksum validation",
                details={"to": to},
            )

        if to.lower() == ZERO_ADDRESS.lower():
            raise InvalidAddressError(
                message="Transfer to the zero address (0x00...00) is strictly rejected",
                details={"to": to},
            )

        if to.lower() == self.wallet_address.lower():
            raise InvalidAddressError(
                message="Self-transfer to hot wallet address is strictly rejected",
                details={"to": to},
            )

        return to

    def validate_amount(self, amount: Decimal) -> int:
        """Validate USDC transfer amount and convert to integer minor units.

        Args:
            amount: Transfer amount in USDC (e.g. Decimal("10.50")).

        Returns:
            Amount in minor units (e.g. 10_500_000).

        Raises:
            TypeError: If amount is float.
            InvalidAmountError: If amount <= 0, > max_transfer_amount, or has > 6 decimals.
        """
        if not isinstance(amount, Decimal):
            raise TypeError(f"Transfer amount must be Decimal, got {type(amount).__name__}")

        if amount <= Decimal("0"):
            raise InvalidAmountError(
                message=f"Transfer amount must be strictly positive, got {amount}",
                details={"amount": str(amount)},
            )

        if amount > self.max_transfer_amount:
            raise InvalidAmountError(
                message=(
                    f"Transfer amount {amount} USDC exceeds maximum configured ceiling "
                    f"of {self.max_transfer_amount} USDC"
                ),
                details={"amount": str(amount), "max": str(self.max_transfer_amount)},
            )

        minor_decimal = amount * Decimal(USDC_SCALE)
        if minor_decimal != minor_decimal.to_integral_value():
            raise InvalidAmountError(
                message=f"Transfer amount {amount} USDC has more than 6 decimal places",
                details={"amount": str(amount)},
            )

        return int(minor_decimal)

    async def preflight_gas_check(self) -> Decimal:
        """Verify hot wallet native ETH balance satisfies minimum gas threshold.

        Returns:
            Current hot wallet ETH balance.

        Raises:
            InsufficientGasError: If ETH balance < min_gas_threshold.
        """
        balance_wei = await self._execute_with_ladder(
            "eth_getBalance",
            lambda: self._w3.eth.get_balance(self.wallet_address),
        )
        balance_eth = Decimal(balance_wei) / Decimal(10**18)
        FLX_HOT_WALLET_ETH_BALANCE.set(float(balance_eth))

        if balance_eth < self.min_gas_threshold:
            raise InsufficientGasError(
                message=(
                    f"Hot wallet ETH balance ({balance_eth:.6f} ETH) is below safety "
                    f"threshold ({self.min_gas_threshold} ETH). Top up gas wallet at "
                    f"{self.wallet_address}."
                ),
                details={
                    "wallet": self.wallet_address,
                    "balance_eth": str(balance_eth),
                    "threshold_eth": str(self.min_gas_threshold),
                },
            )

        return balance_eth

    async def preflight_usdc_check(self, amount_minor: int) -> int:
        """Verify hot wallet has sufficient USDC balance for outbound transfer.

        Args:
            amount_minor: Required transfer amount in minor units.

        Returns:
            Current hot wallet USDC minor unit balance.

        Raises:
            InsufficientUsdcError: If hot wallet USDC balance < amount_minor.
        """
        balance_minor = await self._execute_with_ladder(
            "balanceOf",
            lambda: self._contract.functions.balanceOf(self.wallet_address).call(),
        )

        if balance_minor < amount_minor:
            raise InsufficientUsdcError(
                message=(
                    f"Hot wallet USDC balance ({balance_minor} minor units) is insufficient "
                    f"for requested payout ({amount_minor} minor units)."
                ),
                details={
                    "wallet": self.wallet_address,
                    "balance_minor": str(balance_minor),
                    "required_minor": str(amount_minor),
                },
            )

        return int(balance_minor)

    async def estimate_gas_parameters(
        self,
        *,
        to: str,
        amount_minor: int,
        call_data: bytes,
    ) -> tuple[int, int, int]:
        """Estimate EIP-1559 gas parameters with 20% safety margin.

        Args:
            to: Recipient address.
            amount_minor: Minor unit amount.
            call_data: Encoded ERC-20 transfer calldata.

        Returns:
            Tuple of (gas_limit, max_fee_per_gas, max_priority_fee_per_gas).
        """
        # Fetch latest block for baseFeePerGas
        latest_block = await self._execute_with_ladder(
            "eth_getBlockByNumber",
            lambda: self._w3.eth.get_block("latest"),
        )
        base_fee = latest_block.get("baseFeePerGas")
        if base_fee is None:
            gas_price = await self._execute_with_ladder(
                "eth_gasPrice",
                lambda: self._w3.eth.gas_price,
            )
            base_fee = gas_price

        # Fetch or estimate priority fee
        try:
            priority_fee = await self._execute_with_ladder(
                "eth_maxPriorityFeePerGas",
                lambda: self._w3.eth.max_priority_fee,
            )
        except Exception:
            priority_fee = 1_000_000  # Default 0.001 gwei on Base L2

        if priority_fee is None or priority_fee <= 0:
            priority_fee = 1_000_000

        max_fee_per_gas = int(base_fee * 2 + priority_fee)

        # Estimate gas with safety margin
        tx_for_estimate = {
            "from": self.wallet_address,
            "to": self.usdc_address,
            "data": call_data,
            "value": 0,
        }
        estimated_gas = await self._execute_with_ladder(
            "eth_estimateGas",
            lambda: self._w3.eth.estimate_gas(tx_for_estimate),
        )
        gas_limit = int(estimated_gas * self.gas_safety_margin)

        return gas_limit, max_fee_per_gas, priority_fee

    async def allocate_and_broadcast(
        self,
        *,
        call_data: bytes,
        gas_limit: int,
        max_fee_per_gas: int,
        max_priority_fee_per_gas: int,
    ) -> tuple[str, int]:
        """Atomically allocate sequential nonce and broadcast raw transaction under lock.

        Args:
            call_data: Encoded ERC-20 transfer calldata.
            gas_limit: Gas limit including safety margin.
            max_fee_per_gas: EIP-1559 max fee per gas.
            max_priority_fee_per_gas: EIP-1559 max priority fee per gas.

        Returns:
            Tuple of (tx_hash, nonce).

        Raises:
            NonceConflictError: On nonce too low or replacement underpriced.
            RpcRateLimitError: On HTTP 429.
            BaseL2WriterError: On unhandled broadcast failure.
        """
        lock = self._get_wallet_lock(self.wallet_address)

        async with lock:
            # Sync with pending mempool nonce
            pending_nonce = await self._execute_with_ladder(
                "eth_getTransactionCount",
                lambda: self._w3.eth.get_transaction_count(self.wallet_address, "pending"),
            )
            tracked_nonce = self._next_nonces.get(self.wallet_address, 0)
            nonce = max(pending_nonce, tracked_nonce)
            self._next_nonces[self.wallet_address] = nonce + 1

            tx_dict: dict[str, int | str | bytes] = {
                "chainId": self.chain_id,
                "from": self.wallet_address,
                "to": self.usdc_address,
                "value": 0,
                "nonce": nonce,
                "gas": gas_limit,
                "maxFeePerGas": max_fee_per_gas,
                "maxPriorityFeePerGas": max_priority_fee_per_gas,
                "data": call_data,
                "type": 2,
            }

            # Sign transaction via abstract signer interface (NEVER logged)
            signed_raw_bytes = await self.signer.sign_transaction(tx_dict)

            # Broadcast raw transaction
            try:
                tx_hash_result = await self._execute_with_ladder(
                    "eth_sendRawTransaction",
                    lambda: self._w3.eth.send_raw_transaction(signed_raw_bytes),
                )
                if isinstance(tx_hash_result, bytes):
                    tx_hash = "0x" + tx_hash_result.hex()
                elif isinstance(tx_hash_result, str):
                    tx_hash = (
                        tx_hash_result if tx_hash_result.startswith("0x") else "0x" + tx_hash_result
                    )
                else:
                    tx_hash = "0x" + bytes(tx_hash_result).hex()
                return tx_hash, nonce

            except Exception as exc:
                err_str = str(exc).lower()
                # Re-sync local nonce water-mark upon conflict
                if "nonce too low" in err_str or "replacement underpriced" in err_str:
                    fresh_nonce = await self._w3.eth.get_transaction_count(
                        self.wallet_address, "pending"
                    )
                    self._next_nonces[self.wallet_address] = fresh_nonce
                    raise NonceConflictError(
                        message=(
                            f"Mempool nonce conflict on wallet {self.wallet_address} "
                            f"at nonce {nonce}: {exc}"
                        ),
                        details={
                            "wallet": self.wallet_address,
                            "nonce": str(nonce),
                            "error": str(exc),
                        },
                    ) from exc

                if "429" in err_str or "rate limit" in err_str:
                    raise RpcRateLimitError(
                        message=f"RPC rate limit 429 encountered during broadcast: {exc}",
                        details={"wallet": self.wallet_address, "error": str(exc)},
                    ) from exc

                raise BaseL2WriterError(
                    message=f"Broadcast failed for wallet {self.wallet_address}: {exc}",
                    code="BROADCAST_FAILED",
                    details={"wallet": self.wallet_address, "error": str(exc)},
                ) from exc

    async def wait_for_confirmation(
        self,
        *,
        tx_hash: str,
        to: str,
        amount: Decimal,
        amount_minor: int,
        call_data: bytes,
        confirmations_required: int,
        timeout_s: float,
        start_time: float,
    ) -> TransferReceipt:
        """Poll transaction receipt and block depth until confirmed or reverted.

        Args:
            tx_hash: Transaction hash.
            to: Recipient address.
            amount: Human-readable Decimal amount.
            amount_minor: Integer minor units.
            call_data: Transfer calldata for revert decoding.
            confirmations_required: Target confirmation depth.
            timeout_s: Timeout in seconds.
            start_time: Monotonic start timestamp.

        Returns:
            TransferReceipt upon successful finality.

        Raises:
            TransactionRevertedError: On status=0 EVM execution revert.
            RpcTimeoutError: On confirmation timeout.
            TransactionDroppedError: If transaction drops from mempool/reorgs.
        """
        deadline = self._now() + timeout_s
        seen_mined: bool = False
        mined_block_hash: str | None = None

        while self._now() < deadline:
            try:
                receipt = await self._execute_with_ladder(
                    "eth_getTransactionReceipt",
                    lambda: self._w3.eth.get_transaction_receipt(tx_hash),
                )
            except TransactionNotFound:
                receipt = None

            if receipt is None:
                if seen_mined:
                    duration_ms = int((self._now() - start_time) * 1000)
                    self._logger.warning(
                        "usdc_transfer_reorg_detected",
                        tx_hash=tx_hash,
                        duration_ms=duration_ms,
                    )
                    FLX_USDC_TRANSFERS_TOTAL.labels(outcome="failed").inc()
                    raise TransactionDroppedError(
                        message=f"Transaction {tx_hash} was reorged out of the blockchain",
                        details={"tx_hash": tx_hash},
                    )

                # Check if still in mempool
                try:
                    tx_obj = await self._execute_with_ladder(
                        "eth_getTransactionByHash",
                        lambda: self._w3.eth.get_transaction(tx_hash),
                    )
                except TransactionNotFound:
                    tx_obj = None

                if tx_obj is None:
                    duration_ms = int((self._now() - start_time) * 1000)
                    self._logger.error(
                        "usdc_transfer_dropped",
                        tx_hash=tx_hash,
                        duration_ms=duration_ms,
                    )
                    FLX_USDC_TRANSFERS_TOTAL.labels(outcome="failed").inc()
                    raise TransactionDroppedError(
                        message=f"Transaction {tx_hash} dropped from mempool",
                        details={"tx_hash": tx_hash},
                    )

                await self._sleep(self.poll_interval_s)
                continue

            seen_mined = True
            raw_block_hash = receipt.get("blockHash")
            current_block_hash = (
                "0x" + raw_block_hash.hex()
                if isinstance(raw_block_hash, bytes)
                else str(raw_block_hash or "")
            )

            if mined_block_hash is None:
                mined_block_hash = str(current_block_hash)
            elif mined_block_hash != str(current_block_hash):
                self._logger.warning(
                    "usdc_transfer_block_reorg",
                    tx_hash=tx_hash,
                    prev_block_hash=mined_block_hash,
                    new_block_hash=str(current_block_hash),
                )
                mined_block_hash = str(current_block_hash)

            # Check EVM execution status (1 = Success, 0 = Revert)
            status = receipt.get("status")
            if status == 0:
                duration_ms = int((self._now() - start_time) * 1000)
                revert_reason = "execution reverted"
                try:
                    await self._w3.eth.call(
                        {
                            "from": self.wallet_address,
                            "to": self.usdc_address,
                            "data": call_data,
                            "value": 0,
                        },
                        receipt.get("blockNumber", "latest"),
                    )
                except Exception as call_exc:
                    revert_reason = str(call_exc)

                self._logger.error(
                    "usdc_transfer_failed",
                    tx_hash=tx_hash,
                    to=to,
                    amount=str(amount),
                    gas_used=int(receipt.get("gasUsed", 0)),
                    duration_ms=duration_ms,
                    error=revert_reason,
                    code="TX_REVERTED",
                )
                FLX_USDC_TRANSFERS_TOTAL.labels(outcome="reverted").inc()
                raise TransactionRevertedError(
                    message=f"Transaction {tx_hash} reverted on-chain: {revert_reason}",
                    details={
                        "tx_hash": tx_hash,
                        "revert_reason": revert_reason,
                        "block_number": str(receipt.get("blockNumber", 0)),
                    },
                )

            # Status == 1: Verify confirmation depth
            current_block = int(
                await self._execute_with_ladder(
                    "eth_blockNumber",
                    lambda: self._w3.eth.block_number,
                )
            )
            tx_block = int(receipt.get("blockNumber", 0))
            confirmations = max(0, current_block - tx_block + 1)

            if confirmations >= confirmations_required:
                total_duration_s = self._now() - start_time
                duration_ms = int(total_duration_s * 1000)
                gas_used = int(receipt.get("gasUsed", 0))
                effective_gas_price = int(receipt.get("effectiveGasPrice", 0))

                self._logger.info(
                    "usdc_transfer_confirmed",
                    tx_hash=tx_hash,
                    to=to,
                    amount=str(amount),
                    gas_used=gas_used,
                    duration_ms=duration_ms,
                )
                FLX_USDC_TRANSFERS_TOTAL.labels(outcome="ok").inc()
                FLX_USDC_TRANSFER_DURATION_SECONDS.observe(total_duration_s)

                return TransferReceipt(
                    tx_hash=tx_hash,
                    from_address=self.wallet_address,
                    to_address=to,
                    amount_usdc=amount,
                    amount_minor=amount_minor,
                    block_number=tx_block,
                    confirmations=confirmations,
                    gas_used=gas_used,
                    effective_gas_price=effective_gas_price,
                    duration_ms=duration_ms,
                )

            await self._sleep(self.poll_interval_s)

        total_duration_s = self._now() - start_time
        duration_ms = int(total_duration_s * 1000)
        self._logger.error(
            "usdc_transfer_failed",
            tx_hash=tx_hash,
            to=to,
            amount=str(amount),
            gas_used=0,
            duration_ms=duration_ms,
            error=f"Confirmation timeout after {timeout_s}s",
            code="RPC_TIMEOUT",
        )
        FLX_USDC_TRANSFERS_TOTAL.labels(outcome="failed").inc()
        raise RpcTimeoutError(
            message=(
                f"Transaction {tx_hash} timed out after {timeout_s}s "
                f"waiting for {confirmations_required} confirmations"
            ),
            details={"tx_hash": tx_hash, "timeout_s": str(timeout_s)},
        )

    async def transfer_usdc(
        self,
        *,
        to: str,
        amount: Decimal,
        confirmations: int | None = None,
        timeout_s: float = 180.0,
    ) -> TransferReceipt:
        """Execute an outbound USDC settlement transfer on Base L2.

        Enforces:
        1. EIP-55 checksum, non-zero, non-self recipient validation.
        2. Decimal amount validation and 6-decimal scaling to minor units.
        3. Native gas balance pre-flight check (ETH >= min_gas_threshold).
        4. USDC liquidity balance pre-flight check (USDC >= amount).
        5. EIP-1559 gas parameter estimation with 20% margin.
        6. Serialized nonce allocation and signing under per-hot-wallet lock.
        7. Raw transaction broadcast with nonce race detection.
        8. Polling confirmation with reorg protection and telemetry emission.

        Args:
            to: Recipient EVM address (must be valid EIP-55 checksummed).
            amount: Amount in USDC (e.g. Decimal("100.00")).
            confirmations: Required confirmation block depth (default: self.default_confirmations).
            timeout_s: Confirmation receipt timeout in seconds.

        Returns:
            TransferReceipt upon verified finality.

        Raises:
            InvalidAddressError: If recipient address is invalid or rejected by policy.
            InvalidAmountError: If amount is negative, zero, exceeds ceiling, or fractional.
            InsufficientGasError: If hot wallet ETH balance is below min_gas_threshold.
            InsufficientUsdcError: If hot wallet USDC balance is below transfer amount.
            NonceConflictError: If nonce collision or replacement underpriced occurs.
            TransactionRevertedError: If transaction reverts on-chain (status=0).
            RpcTimeoutError: If confirmation polling times out.
            RpcRateLimitError: If RPC provider rejects with HTTP 429.
            BaseL2WriterError: On other operational infrastructure failures.
        """
        start_time = self._now()
        target_confirmations = (
            confirmations if confirmations is not None else self.default_confirmations
        )

        # 1. Validate inputs
        to_addr = self.validate_destination_address(to)
        amount_minor = self.validate_amount(amount)

        # 2. Runtime decimals guard (10^12 defense)
        if not self._probed:
            await self.probe()

        # 3. Pre-flight checks: Gas ETH & Token USDC
        await self.preflight_gas_check()
        await self.preflight_usdc_check(amount_minor)

        # 4. ABI encoding: transfer(address,uint256)
        call_data = self._contract.encode_abi("transfer", [to_addr, amount_minor])
        if isinstance(call_data, str):
            call_data_bytes = bytes.fromhex(
                call_data[2:] if call_data.startswith("0x") else call_data
            )
        else:
            call_data_bytes = bytes(call_data)

        # 5. Gas parameters estimation (EIP-1559 + 20% margin)
        gas_limit, max_fee, priority_fee = await self.estimate_gas_parameters(
            to=to_addr,
            amount_minor=amount_minor,
            call_data=call_data_bytes,
        )

        # 6. Atomic nonce allocation & broadcast under per-wallet lock
        tx_hash, _ = await self.allocate_and_broadcast(
            call_data=call_data_bytes,
            gas_limit=gas_limit,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
        )

        # 7. Log broadcast
        broadcast_duration_ms = int((self._now() - start_time) * 1000)
        self._logger.info(
            "usdc_transfer_broadcast",
            tx_hash=tx_hash,
            to=to_addr,
            amount=str(amount),
            gas_used=gas_limit,
            duration_ms=broadcast_duration_ms,
        )

        # 8. Wait for receipt and target confirmations
        return await self.wait_for_confirmation(
            tx_hash=tx_hash,
            to=to_addr,
            amount=amount,
            amount_minor=amount_minor,
            call_data=call_data_bytes,
            confirmations_required=target_confirmations,
            timeout_s=timeout_s,
            start_time=start_time,
        )
