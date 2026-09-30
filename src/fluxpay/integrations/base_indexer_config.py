"""Configuration model for Base L2 Inbound USDC Deposit Indexer.

Implements twelve-factor environment configuration with strict Pydantic v2 validation.
Enforces validation rules for RPC transport endpoints, EIP-55 address checksumming,
confirmation depth boundaries, and reorg tracking windows.
"""

from __future__ import annotations

import re
from typing import Final
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from web3 import Web3

__all__ = ["IndexerConfig"]

DEFAULT_USDC_MAINNET: Final[str] = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
_EVM_ADDR_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^0x[0-9a-fA-F]{40}$")


class IndexerConfig(BaseSettings):
    """Configuration settings for the Base L2 deposit indexer."""

    rpc_http_url: SecretStr = Field(
        ...,
        description="HTTP/HTTPS JSON-RPC provider endpoint for Base L2.",
    )
    rpc_wss_url: SecretStr | None = Field(
        default=None,
        description=(
            "Optional WebSocket (ws/wss) provider endpoint for real-time log subscriptions."
        ),
    )
    chain_id: int = Field(
        default=8453,
        description="EVM Chain ID (8453 for Base Mainnet, 84532 for Base Sepolia).",
    )
    usdc_address: str = Field(
        default=DEFAULT_USDC_MAINNET,
        description="EIP-55 checksummed USDC ERC-20 contract address on Base L2.",
    )
    confirmations: int = Field(
        default=12,
        description="Required block confirmation depth before crediting ledger (1-100).",
    )
    start_block: int | str = Field(
        default=0,
        description="Start block number (int >= 0) or 'latest' for live head start.",
    )
    batch_size: int = Field(
        default=2000,
        description="Maximum blocks queried per eth_getLogs call during backfill.",
    )
    poll_interval_s: float = Field(
        default=2.0,
        description="Polling cadence in seconds for fallback/live block header queries.",
    )
    max_reorg_depth: int = Field(
        default=1000,
        description="Maximum blocks retained in ring buffer for reorg LCA resolution.",
    )
    address_refresh_blocks: int = Field(
        default=100,
        description="Interval in blocks between automatic deposit address registry syncs.",
    )

    model_config = SettingsConfigDict(
        env_prefix="FLUXPAY_INDEXER_",
        extra="ignore",
    )

    @field_validator("usdc_address")
    @classmethod
    def validate_usdc_address(cls, v: str) -> str:
        """Validate that the token address matches EVM format and EIP-55 checksum."""
        if not _EVM_ADDR_HEX_RE.fullmatch(v):
            raise ValueError(f"Invalid EVM address format: '{v}'")
        try:
            checksummed = Web3.to_checksum_address(v)
        except Exception as exc:
            raise ValueError(f"Invalid EVM address: {exc}") from exc
        if v != checksummed:
            raise ValueError(
                f"USDC address '{v}' is not EIP-55 checksummed (expected '{checksummed}')"
            )
        return v

    @field_validator("rpc_http_url")
    @classmethod
    def validate_rpc_http_url(cls, v: SecretStr) -> SecretStr:
        """Validate that HTTP RPC endpoint has a valid http/https scheme."""
        url_str = v.get_secret_value().strip()
        parsed = urlparse(url_str)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                "rpc_http_url must be a valid HTTP or HTTPS URL (e.g. 'https://mainnet.base.org')"
            )
        return v

    @field_validator("rpc_wss_url")
    @classmethod
    def validate_rpc_wss_url(cls, v: SecretStr | None) -> SecretStr | None:
        """Validate that WebSocket RPC endpoint has a valid ws/wss scheme if present."""
        if v is None:
            return None
        url_str = v.get_secret_value().strip()
        parsed = urlparse(url_str)
        if parsed.scheme not in ("ws", "wss") or not parsed.netloc:
            raise ValueError(
                "rpc_wss_url must be a valid WS or WSS URL (e.g. 'wss://base-mainnet.g.alchemy.com/v2/...')"
            )
        return v

    @field_validator("confirmations")
    @classmethod
    def validate_confirmations(cls, v: int) -> int:
        """Enforce confirmation depth bounds [1, 100]."""
        if v < 1 or v > 100:
            raise ValueError(f"confirmations must be between 1 and 100 blocks (got {v})")
        return v

    @field_validator("start_block")
    @classmethod
    def validate_start_block(cls, v: int | str) -> int | str:
        """Validate start block integer or 'latest' sentinel."""
        if isinstance(v, str):
            v_clean = v.strip().lower()
            if v_clean == "latest":
                return "latest"
            try:
                val = int(v_clean)
                if val < 0:
                    raise ValueError("start_block must be >= 0")
                return val
            except ValueError as exc:
                raise ValueError(
                    f"start_block must be a non-negative integer or 'latest', got '{v}'"
                ) from exc
        if v < 0:
            raise ValueError(f"start_block must be >= 0 (got {v})")
        return v

    @field_validator("batch_size")
    @classmethod
    def validate_batch_size(cls, v: int) -> int:
        """Enforce reasonable batch size bounds [1, 50000]."""
        if v < 1 or v > 50000:
            raise ValueError(f"batch_size must be between 1 and 50000 (got {v})")
        return v

    @field_validator("poll_interval_s")
    @classmethod
    def validate_poll_interval_s(cls, v: float) -> float:
        """Enforce strictly positive polling cadence."""
        if v <= 0.0:
            raise ValueError(f"poll_interval_s must be > 0.0 (got {v})")
        return v

    @field_validator("max_reorg_depth")
    @classmethod
    def validate_max_reorg_depth(cls, v: int) -> int:
        """Enforce valid reorg tracking depth window [1, 10000]."""
        if v < 1 or v > 10000:
            raise ValueError(f"max_reorg_depth must be between 1 and 10000 (got {v})")
        return v

    @field_validator("address_refresh_blocks")
    @classmethod
    def validate_address_refresh_blocks(cls, v: int) -> int:
        """Enforce valid address refresh frequency >= 1."""
        if v < 1:
            raise ValueError(f"address_refresh_blocks must be >= 1 (got {v})")
        return v
