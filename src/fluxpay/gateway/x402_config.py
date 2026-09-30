"""Configuration settings for the x402 payment gateway middleware.

Specifies route protections, merchant recipient address, USDC contract addresses on Base,
timeouts, and facilitator endpoints.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Coroutine
from decimal import Decimal
from typing import Any, Final

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.requests import Request
from web3 import Web3

__all__ = ["X402Config"]

_EVM_ADDR_REGEX: Final[re.Pattern[str]] = re.compile(r"^0x[a-fA-F0-9]{40}$")


class X402Config(BaseSettings):
    """Pydantic settings for configuring x402 HTTP payment authorization middleware."""

    enabled: bool = True
    network: str = "base"
    chain_id: int = 8453
    asset: str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    pay_to: str = "0x0000000000000000000000000000000000000001"
    merchant_id: str = "merchant_primary"
    protected_routes: dict[str, Decimal] = Field(
        default_factory=lambda: {
            "/api/premium": Decimal("1.00"),
            "/api/data": Decimal("0.10"),
        }
    )
    facilitator_url: str | None = None
    max_timeout_seconds: int = 300
    verify_cache_ttl_s: int = 60
    nonce_cache_ttl_s: int = 86400
    max_payload_bytes: int = 10240
    verify_timeout_s: float = 15.0
    settle_timeout_s: float = 60.0
    token_name: str = "USD Coin"  # noqa: S105
    token_version: str = "2"  # noqa: S105
    token_decimals: int = 6
    scheme: str = "exact"
    price_fn: Callable[[Request], Decimal | Coroutine[Any, Any, Decimal]] | None = None

    model_config = SettingsConfigDict(
        env_prefix="FLUXPAY_X402_",
        arbitrary_types_allowed=True,
        extra="ignore",
    )

    @field_validator("asset", "pay_to")
    @classmethod
    def _validate_address(cls, v: str) -> str:
        """Validate 20-byte EVM address and normalize to EIP-55 checksum format."""
        if not isinstance(v, str) or not _EVM_ADDR_REGEX.match(v):
            raise ValueError(f"Invalid EVM address format: {v!r}")
        return Web3.to_checksum_address(v)
