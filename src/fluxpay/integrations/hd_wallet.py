"""Production-grade BIP-39/BIP-32/BIP-44 HD Wallet Manager for Base L2 (EVM).

==============================================================================
STANDARDS COMPLIANCE & SPECIFICATION
==============================================================================
1. BIP-39 (Mnemonic generation and seed derivation):
   - PBKDF2-HMAC-SHA512 with 2048 iterations salted with "mnemonic" + passphrase.
   - Enforces word count in (12, 15, 18, 21, 24) and SHA-256 entropy checksum.
   - Rejects low-entropy/weak phrases (identical or sequential words).

2. BIP-32 (Hierarchical Deterministic key derivation):
   - HMAC-SHA512 master key derivation using secp256k1 curve parameters.
   - Child Key Derivation (CKD) supporting hardened and non-hardened child indices.
   - Extended public key (xpub) serialization with standard mainnet version bytes.

3. BIP-44 / SLIP-0044 (Multi-account hierarchy for deterministic wallets):
   - Canonical derivation path: m / 44' / 60' / {account_index}' / 0 / {address_index}
     * 44' = BIP-44 purpose (hardened)
     * 60' = Ethereum / Base L2 coin type (hardened)
     * {account_index}' = Organizational/tenant account partition (hardened)
     * 0 = External chain for public receiving/deposit addresses (non-hardened)
     * {address_index} = Autonomous AI agent deposit address index (non-hardened)

==============================================================================
SECURITY MODEL & CUSTODY INVARIANTS
==============================================================================
1. KEY ISOLATION & FAIL-CLOSED INITIALIZATION:
   - Master mnemonic is injected strictly via environment variables
     (FLUXPAY_MASTER_MNEMONIC) or strongly typed SecretStr wrappers.
   - If the mnemonic credential is missing or invalid, initialization fails immediately.
   - Private keys are NEVER emitted in plain text; they are returned strictly as
     Pydantic `SecretStr` instances and ONLY when `include_private_key=True` is explicit.

2. LOGGING & TELEMETRY REDACTION:
   - Mnemonics, seeds, intermediate private keys, and child private keys are NEVER logged.
   - `DerivedAddress.__repr__` and `__str__` redact the private key to prevent accidental leaks.
   - On initialization, only a truncated 4-byte SHA-256 mnemonic fingerprint is emitted
     for audit tracking (e.g. `fingerprint="a1b2c3d4"`).
   - No per-address derivation logs are written to uphold customer/agent privacy.

3. WATCH-ONLY OBSERVABILITY (XPUB DERIVATION):
   - Deposit monitoring nodes do NOT require spending authority.
   - The account-level or change-level extended public key (xpub) can be exported
     and loaded into watch-only `HDWalletManager` instances to derive deposit addresses
     using elliptic curve point multiplication (CKDpub) with zero access to private keys.

4. MEMORY SCRUBBING:
   - Intermediate master seed buffers are allocated as mutable bytearrays and
     explicitly zeroed out after master key instantiation (best effort in Python runtime).
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from bip_utils import (  # type: ignore[import-untyped]
    Bip32KeyError,
    Bip32Secp256k1,
    Bip39MnemonicValidator,
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
    Bip44Levels,
    EthAddr,
)
from bip_utils.base58.base58_ex import Base58ChecksumError  # type: ignore[import-untyped]
from bip_utils.utils.mnemonic.mnemonic_ex import (  # type: ignore[import-untyped]
    MnemonicChecksumError,
)
from mnemonic import Mnemonic
from prometheus_client import REGISTRY, CollectorRegistry, Gauge
from pydantic import SecretStr
from web3 import Web3

from fluxpay.integrations.hd_wallet_config import BIP32_MAX_INDEX, HDWalletConfig
from fluxpay.shared.errors import IntegrationError
from fluxpay.shared.logging import get_logger

__all__ = [
    "BASE_BIP44_COIN_TYPE",
    "BIP32_HARDENED_FLAG",
    "BIP32_MAX_INDEX",
    "BIP44_PURPOSE",
    "DEFAULT_MAX_ADDRESS_INDEX",
    "FLX_HD_WALLET_DERIVED_TOTAL",
    "KNOWN_BURN_ADDRESSES",
    "VALID_MNEMONIC_WORD_COUNTS",
    "ZERO_ADDRESS",
    "DerivedAddress",
    "HDWalletConfig",
    "HDWalletError",
    "HDWalletManager",
    "IndexOutOfBoundsError",
    "InvalidDerivedAddressError",
    "InvalidXpubError",
    "MnemonicValidationError",
    "PrivateKeyAccessForbiddenError",
    "WeakMnemonicError",
]

logger = get_logger("fluxpay.integrations.hd_wallet")

# BIP-44 and BIP-32 Specification Constants
BIP44_PURPOSE: Final[int] = 44
BASE_BIP44_COIN_TYPE: Final[int] = 60  # SLIP-0044 Ethereum coin type (applies to Base L2)
BIP32_HARDENED_FLAG: Final[int] = 1 << 31  # 0x80000000 (2,147,483,648)
DEFAULT_MAX_ADDRESS_INDEX: Final[int] = BIP32_MAX_INDEX  # 2^31 - 1
VALID_MNEMONIC_WORD_COUNTS: Final[frozenset[int]] = frozenset({12, 15, 18, 21, 24})

# EVM Well-Known Address Constants
ZERO_ADDRESS: Final[str] = "0x0000000000000000000000000000000000000000"
KNOWN_BURN_ADDRESSES: Final[frozenset[str]] = frozenset(
    {
        ZERO_ADDRESS.lower(),
        "0x000000000000000000000000000000000000dead",
        "0x0000000000000000000000000000000000000001",
        "0xffffffffffffffffffffffffffffffffffffffff",
    }
)


# -----------------------------------------------------------------------------
# Prometheus Telemetry Definitions
# -----------------------------------------------------------------------------
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


FLX_HD_WALLET_DERIVED_TOTAL: Final[Gauge] = _get_or_create_gauge(
    "flx_hd_wallet_derived_total",
    "Monotonic count of Base L2 HD wallet deposit addresses derived",
    (),
)


# -----------------------------------------------------------------------------
# Domain Exceptions
# -----------------------------------------------------------------------------
class HDWalletError(IntegrationError):
    """Base exception for all HD wallet operations in FluxPay."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "hd_wallet_error",
        details: dict[str, str] | None = None,
    ) -> None:
        merged_details = {"code": code}
        if details:
            merged_details.update(details)
        super().__init__(message=message, details=merged_details)


class MnemonicValidationError(HDWalletError):
    """Raised when a mnemonic phrase violates BIP-39 syntax, wordlist, or checksum."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="INVALID_MNEMONIC", details=details)


class WeakMnemonicError(MnemonicValidationError):
    """Raised when a mnemonic phrase exhibits trivial patterns or low entropy."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, details=details)
        self.details["code"] = "WEAK_MNEMONIC"


class IndexOutOfBoundsError(HDWalletError):
    """Raised when an address derivation index violates BIP-32 bounds [0, 2^31 - 1]."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="INDEX_OUT_OF_BOUNDS", details=details)


class InvalidXpubError(HDWalletError):
    """Raised when an extended public key (xpub) is malformed, invalid, or inappropriate."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="INVALID_XPUB", details=details)


class InvalidDerivedAddressError(HDWalletError):
    """Raised when a derived address violates EIP-55 or collides with reserved burn addresses."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="INVALID_DERIVED_ADDRESS", details=details)


class PrivateKeyAccessForbiddenError(HDWalletError):
    """Raised when private key extraction is attempted without authorization."""

    def __init__(self, message: str, *, details: dict[str, str] | None = None) -> None:
        super().__init__(message, code="PRIVATE_KEY_ACCESS_FORBIDDEN", details=details)


# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class DerivedAddress:
    """Immutable record representing a derived Base L2 EVM deposit address.

    Security Guarantee:
    `private_key` is encapsulated as `SecretStr | None` and is omitted unless
    `include_private_key=True` was explicitly requested. The custom `__repr__` and
    `__str__` implementations guarantee that raw private key bytes are NEVER exposed
    in terminal prints, logging pipelines, or traceback strings.
    """

    address: str
    index: int
    path: str
    public_key: str
    private_key: SecretStr | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __repr__(self) -> str:
        pk_repr = "SecretStr('**********')" if self.private_key is not None else "None"
        return (
            f"DerivedAddress(address={self.address!r}, index={self.index}, "
            f"path={self.path!r}, public_key={self.public_key!r}, "
            f"private_key={pk_repr}, created_at={self.created_at!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def to_dict(self, *, include_private_key: bool = False) -> dict[str, Any]:
        """Serialize address record to dictionary, redacting private key by default."""
        payload: dict[str, Any] = {
            "address": self.address,
            "index": self.index,
            "path": self.path,
            "public_key": self.public_key,
            "created_at": self.created_at.isoformat(),
        }
        if include_private_key and self.private_key is not None:
            payload["private_key"] = self.private_key.get_secret_value()
        return payload


# -----------------------------------------------------------------------------
# Memory Hygiene Helper
# -----------------------------------------------------------------------------
def _scrub_bytearray(buf: bytearray) -> None:
    """Best-effort in-memory zeroization of sensitive cryptographic buffers."""
    for i in range(len(buf)):
        buf[i] = 0


# -----------------------------------------------------------------------------
# HD Wallet Manager
# -----------------------------------------------------------------------------
class HDWalletManager:
    """Production BIP-32/BIP-39/BIP-44 Hierarchical Deterministic Wallet Manager.

    Derives deposit addresses for Base L2 autonomous agents. Supports full signing
    mode (master mnemonic) and watch-only mode (account/change xpub).
    """

    def __init__(
        self,
        config: HDWalletConfig | None = None,
        *,
        mnemonic: str | SecretStr | None = None,
        passphrase: str | SecretStr | None = None,
        account_index: int | None = None,
        max_address_index: int | None = None,
    ) -> None:
        """Initialize HDWalletManager in full signing mode.

        Args:
            config: Optional Pydantic HDWalletConfig instance. If None and mnemonic is None,
                loads automatically from environment variables.
            mnemonic: Explicit mnemonic phrase or SecretStr. Overrides config if provided.
            passphrase: Optional BIP-39 passphrase. Overrides config if provided.
            account_index: BIP-44 account index (defaults to 0).
            max_address_index: Maximum permissible address index (defaults to 2^31 - 1).

        Raises:
            MnemonicValidationError: If the mnemonic phrase is syntactically invalid.
            WeakMnemonicError: If the mnemonic phrase exhibits trivial patterns.
            IntegrationError: If fail-closed configuration resolution fails.
        """
        resolved_config = self._resolve_config(
            config=config,
            mnemonic=mnemonic,
            passphrase=passphrase,
            account_index=account_index,
            max_address_index=max_address_index,
        )

        self._account_index: int = resolved_config.account_index
        self._max_address_index: int = resolved_config.max_address_index
        self._is_watch_only: bool = False

        # Monotonic state tracking for safe sequential index allocation
        self._current_index: int = -1
        self._index_lock: asyncio.Lock = asyncio.Lock()

        # Validate mnemonic phrase and reject weak phrases
        clean_mnemonic = self._validate_mnemonic(resolved_config.mnemonic)
        raw_passphrase = (
            resolved_config.passphrase.get_secret_value()
            if resolved_config.passphrase is not None
            else ""
        )

        # Compute safe 4-byte audit fingerprint (SHA-256 of cleaned mnemonic)
        self._fingerprint: str = hashlib.sha256(clean_mnemonic.encode("utf-8")).hexdigest()[:8]

        # Generate BIP-39 seed: PBKDF2-HMAC-SHA512 (2048 rounds)
        seed_bytes = Bip39SeedGenerator(clean_mnemonic).Generate(raw_passphrase)
        seed_buf = bytearray(seed_bytes)

        try:
            # Instantiate BIP-44 master hierarchy
            bip44_mst = Bip44.FromSeed(bytes(seed_buf), Bip44Coins.ETHEREUM)
            bip44_acc = bip44_mst.Purpose().Coin().Account(self._account_index)
            self._bip44_chg = bip44_acc.Change(Bip44Changes.CHAIN_EXT)

            # Export serialized extended keys for this account and change node
            self._account_xpub: str = bip44_acc.PublicKey().ToExtended()
            self._change_xpub: str = self._bip44_chg.PublicKey().ToExtended()
            self._bip32_pub_node: Any = Bip32Secp256k1.FromExtendedKey(self._change_xpub)
        finally:
            # Best-effort zeroization of sensitive master seed buffer
            _scrub_bytearray(seed_buf)

        logger.info(
            "hd_wallet_initialized",
            fingerprint=self._fingerprint,
            account_index=self._account_index,
            mode="signing",
        )

    @classmethod
    def from_mnemonic(
        cls,
        mnemonic: str | SecretStr,
        *,
        passphrase: str | SecretStr | None = None,
        account_index: int = 0,
        max_address_index: int = BIP32_MAX_INDEX,
    ) -> HDWalletManager:
        """Construct an HDWalletManager directly from a mnemonic phrase."""
        cfg = HDWalletConfig(
            mnemonic=SecretStr(mnemonic) if isinstance(mnemonic, str) else mnemonic,
            passphrase=SecretStr(passphrase) if isinstance(passphrase, str) else passphrase,
            account_index=account_index,
            max_address_index=max_address_index,
        )
        return cls(config=cfg)

    @classmethod
    def from_xpub(
        cls,
        xpub: str,
        *,
        account_index: int = 0,
        max_address_index: int = BIP32_MAX_INDEX,
    ) -> HDWalletManager:
        """Construct a watch-only HDWalletManager from an extended public key (xpub).

        Enables deposit monitoring nodes to derive deterministic agent deposit addresses
        without possessing spending private keys.

        Args:
            xpub: Base58Check-encoded extended public key for the account or change chain.
            account_index: Logical account index (for metadata attribution).
            max_address_index: Maximum permissible address index.

        Raises:
            InvalidXpubError: If the xpub is malformed or invalid for secp256k1 derivation.
        """
        clean_xpub = xpub.strip()
        if not (clean_xpub.startswith("xpub") or clean_xpub.startswith("xprv")):
            raise InvalidXpubError(
                "Invalid xpub format: must start with standard mainnet prefix 'xpub'",
                details={"prefix": clean_xpub[:4]},
            )

        try:
            bip32_key = Bip32Secp256k1.FromExtendedKey(clean_xpub)
        except (Base58ChecksumError, Bip32KeyError, ValueError) as exc:
            raise InvalidXpubError(
                f"Failed to parse extended public key: {exc}",
                details={"reason": type(exc).__name__},
            ) from exc

        if not bip32_key.IsPublicOnly():
            raise InvalidXpubError(
                "Watch-only initialization requires a public key (xpub), received private key"
            )

        # Depth inspection:
        # Depth 3 = Account level (m/44'/60'/account'). Derive child 0 (external chain).
        # Depth 4 = Change level (m/44'/60'/account'/0). Ready for address derivation.
        node_depth = bip32_key.Depth().ToInt()
        if node_depth == Bip44Levels.ACCOUNT:
            # Derive external receiving chain (change = 0)
            pub_node = bip32_key.ChildKey(0)
            change_xpub = pub_node.PublicKey().ToExtended()
            account_xpub = clean_xpub
        elif node_depth == Bip44Levels.CHANGE:
            pub_node = bip32_key
            change_xpub = clean_xpub
            account_xpub = ""
        else:
            raise InvalidXpubError(
                f"Unsupported xpub hierarchy depth {node_depth}. Expected depth 3 (account) "
                "or depth 4 (change external chain)."
            )

        # Allocate empty instance bypass __init__
        instance = cls.__new__(cls)
        instance._account_index = account_index
        instance._max_address_index = max_address_index
        instance._is_watch_only = True
        instance._current_index = -1
        instance._index_lock = asyncio.Lock()
        instance._bip32_pub_node = pub_node
        instance._change_xpub = change_xpub
        instance._account_xpub = account_xpub
        instance._fingerprint = hashlib.sha256(clean_xpub.encode("utf-8")).hexdigest()[:8]

        logger.info(
            "hd_wallet_initialized",
            fingerprint=instance._fingerprint,
            account_index=account_index,
            mode="watch_only",
        )
        return instance

    @property
    def is_watch_only(self) -> bool:
        """Return True if wallet operates in watch-only mode without private keys."""
        return self._is_watch_only

    @property
    def account_index(self) -> int:
        """Return the configured BIP-44 account index."""
        return self._account_index

    @property
    def max_address_index(self) -> int:
        """Return the maximum non-hardened child address index allowed."""
        return self._max_address_index

    @property
    def fingerprint(self) -> str:
        """Return the 4-byte hex audit fingerprint of the root credential."""
        return self._fingerprint

    def export_xpub(self) -> str:
        """Export the receiving chain extended public key (m/44'/60'/{account}'/0).

        This xpub can be safely deployed to deposit observers to derive agent addresses.
        """
        return str(self._change_xpub)

    def export_account_xpub(self) -> str:
        """Export the account-level extended public key (m/44'/60'/{account}')."""
        if not self._account_xpub:
            raise InvalidXpubError(
                "Account-level xpub is unavailable when initialized from change-level xpub"
            )
        return str(self._account_xpub)

    def derive_address(
        self,
        index: int,
        *,
        include_private_key: bool = False,
    ) -> DerivedAddress:
        """Derive deposit address and metadata for a specific agent index (stateless).

        Args:
            index: Monotonic non-hardened child index [0, max_address_index].
            include_private_key: If True, populates `private_key` as SecretStr.
                Default is False to enforce principle of least privilege.

        Returns:
            DerivedAddress dataclass containing checksummed address and public key.

        Raises:
            IndexOutOfBoundsError: If index is negative or exceeds max_address_index.
            PrivateKeyAccessForbiddenError: If private key is requested in watch-only mode.
            InvalidDerivedAddressError: If derived address is zero or a known burn address.
        """
        self._validate_index_bounds(index)

        path = f"m/{BIP44_PURPOSE}'/{BASE_BIP44_COIN_TYPE}'/{self._account_index}'/0/{index}"

        if self._is_watch_only:
            if include_private_key:
                raise PrivateKeyAccessForbiddenError(
                    "Private key cannot be derived: wallet is operating in watch-only mode",
                    details={"index": str(index), "path": path},
                )
            # Public child key derivation (CKDpub)
            child_pub_key = self._bip32_pub_node.ChildKey(index)
            compressed_pubkey_hex = child_pub_key.PublicKey().RawCompressed().ToHex()
            raw_address = EthAddr.EncodeKey(child_pub_key.PublicKey().RawCompressed().ToBytes())
            private_key_secret: SecretStr | None = None
        else:
            if include_private_key:
                # Private derivation: returns address + private key
                child_priv = self._bip44_chg.AddressIndex(index)
                compressed_pubkey_hex = child_priv.PublicKey().RawCompressed().ToHex()
                raw_address = child_priv.PublicKey().ToAddress()
                privkey_hex = child_priv.PrivateKey().Raw().ToHex()
                private_key_secret = SecretStr(f"0x{privkey_hex}")
            else:
                # Public-only derivation from pre-computed public node
                child_pub = self._bip32_pub_node.ChildKey(index)
                compressed_pubkey_hex = child_pub.PublicKey().RawCompressed().ToHex()
                raw_address = EthAddr.EncodeKey(child_pub.PublicKey().RawCompressed().ToBytes())
                private_key_secret = None

        # Guarantee EIP-55 checksumming
        checksum_address = Web3.to_checksum_address(raw_address)

        # Enforce address safety: reject zero address and known burn contracts
        self._validate_derived_address(checksum_address)

        # Record monotonic telemetry
        FLX_HD_WALLET_DERIVED_TOTAL.inc()

        return DerivedAddress(
            address=checksum_address,
            index=index,
            path=path,
            public_key=str(compressed_pubkey_hex),
            private_key=private_key_secret,
        )

    def derive_public_only(self, index: int) -> str:
        """Derive address WITHOUT private key (optimized for deposit monitoring)."""
        return self.derive_address(index, include_private_key=False).address

    async def allocate_next_index(self) -> int:
        """Thread-safe monotonic index allocation guarded by asyncio.Lock.

        Returns:
            The next sequentially allocated index starting from 0.

        Raises:
            IndexOutOfBoundsError: If allocation exhausts the configured max index.
        """
        async with self._index_lock:
            next_idx = self._current_index + 1
            if next_idx > self._max_address_index:
                raise IndexOutOfBoundsError(
                    f"Index allocation exhausted maximum capacity of {self._max_address_index}",
                    details={"attempted_index": str(next_idx)},
                )
            self._current_index = next_idx
            return next_idx

    async def derive_next_address(
        self,
        *,
        include_private_key: bool = False,
    ) -> DerivedAddress:
        """Allocate the next sequential index and derive its address."""
        allocated_index = await self.allocate_next_index()
        return self.derive_address(allocated_index, include_private_key=include_private_key)

    # -------------------------------------------------------------------------
    # Internal Validation & Configuration Helpers
    # -------------------------------------------------------------------------
    @staticmethod
    def _resolve_config(
        *,
        config: HDWalletConfig | None,
        mnemonic: str | SecretStr | None,
        passphrase: str | SecretStr | None,
        account_index: int | None,
        max_address_index: int | None,
    ) -> HDWalletConfig:
        """Resolve effective configuration with priority: explicit args > config > env."""
        if mnemonic is not None:
            resolved_mnemonic = SecretStr(mnemonic) if isinstance(mnemonic, str) else mnemonic
            resolved_passphrase = (
                SecretStr(passphrase)
                if isinstance(passphrase, str)
                else passphrase
                if passphrase is not None
                else (config.passphrase if config else None)
            )
            return HDWalletConfig(
                mnemonic=resolved_mnemonic,
                passphrase=resolved_passphrase,
                account_index=account_index
                if account_index is not None
                else (config.account_index if config else 0),
                max_address_index=max_address_index
                if max_address_index is not None
                else (config.max_address_index if config else BIP32_MAX_INDEX),
            )

        if config is not None:
            return config

        # Fallback to twelve-factor environment configuration (fails closed if env missing)
        try:
            return HDWalletConfig()
        except Exception as exc:
            raise MnemonicValidationError(
                "Failed to initialize HD wallet: missing master mnemonic in configuration "
                "or environment (FLUXPAY_MASTER_MNEMONIC)",
                details={"error_type": type(exc).__name__},
            ) from exc

    @staticmethod
    def _validate_mnemonic(mnemonic_secret: SecretStr) -> str:
        """Validate mnemonic syntax, BIP-39 checksum, and entropy strength."""
        raw_phrase = mnemonic_secret.get_secret_value().strip()
        words = raw_phrase.split()

        if len(words) not in VALID_MNEMONIC_WORD_COUNTS:
            sorted_counts = sorted(VALID_MNEMONIC_WORD_COUNTS)
            raise MnemonicValidationError(
                f"Invalid mnemonic word count: got {len(words)}, expected one of {sorted_counts}",
                details={"word_count": str(len(words))},
            )

        # Check against reference BIP-39 English wordlist
        ref_bip39 = Mnemonic("english")
        wordlist_set = set(ref_bip39.wordlist)
        unknown_words = [w for w in words if w not in wordlist_set]
        if unknown_words:
            raise MnemonicValidationError(
                f"Mnemonic contains {len(unknown_words)} words not in the BIP-39 wordlist",
                details={"unknown_count": str(len(unknown_words))},
            )

        # Weak mnemonic detection: identical repeated words (e.g. 12x zoo or 12x abandon)
        if len(set(words)) == 1:
            raise WeakMnemonicError(
                "Weak mnemonic rejected: phrase consists entirely of identical repeated words",
                details={"unique_words": "1"},
            )

        # Weak mnemonic detection: consecutive sequence in wordlist
        indices = [ref_bip39.wordlist.index(w) for w in words]
        is_fwd_seq = all(indices[i] + 1 == indices[i + 1] for i in range(len(indices) - 1))
        is_rev_seq = all(indices[i] - 1 == indices[i + 1] for i in range(len(indices) - 1))
        if is_fwd_seq or is_rev_seq:
            raise WeakMnemonicError(
                "Weak mnemonic rejected: phrase contains sequential consecutive wordlist words",
                details={"pattern": "sequential_wordlist"},
            )

        # Validate BIP-39 SHA-256 checksum
        validator = Bip39MnemonicValidator()
        clean_phrase = " ".join(words)
        try:
            validator.Validate(clean_phrase)
        except (MnemonicChecksumError, ValueError) as exc:
            raise MnemonicValidationError(
                f"BIP-39 checksum validation failed: {exc}",
                details={"reason": type(exc).__name__},
            ) from exc

        return clean_phrase

    def _validate_index_bounds(self, index: int) -> None:
        """Validate that the address index conforms to BIP-32 non-hardened bounds."""
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError(f"Address index must be an integer, got {type(index).__name__}")

        if index < 0 or index > self._max_address_index:
            raise IndexOutOfBoundsError(
                f"Address index {index} is out of permissible range [0, {self._max_address_index}]",
                details={
                    "index": str(index),
                    "min": "0",
                    "max": str(self._max_address_index),
                },
            )

    @staticmethod
    def _validate_derived_address(address: str) -> None:
        """Ensure derived EVM address is not zero address or known burn destination."""
        addr_lower = address.lower()
        if addr_lower in KNOWN_BURN_ADDRESSES:
            raise InvalidDerivedAddressError(
                f"Security check failed: address {address} matches a known burn/null address",
                details={"address": address},
            )
