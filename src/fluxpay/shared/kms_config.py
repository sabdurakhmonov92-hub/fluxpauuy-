"""Configuration settings and validation for FluxPay Cryptographic Key Management (KMS).

Defines twelve-factor configuration models for abstract signer backends including
AWS KMS, GCP Cloud KMS, Azure Key Vault, YubiHSM 2, Fireblocks MPC, and LocalDev.

All configuration is loaded from environment variables prefixed with `FLUXPAY_KMS_`.
Sensitive parameters (API keys, secrets) are wrapped in `pydantic.SecretStr` to prevent
inadvertent logging or leakage in tracebacks.
"""

from __future__ import annotations

import re
from typing import Final, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from web3 import Web3

__all__ = ["KMSConfig"]

_EVM_ADDR_REGEX: Final[re.Pattern[str]] = re.compile(r"^0x[0-9a-fA-F]{40}$")


class KMSConfig(BaseSettings):
    """Immutable runtime configuration for KMS signing backends.

    Enforces cryptographic address invariants, backend selection, and provider endpoints.
    Sensitive credentials (e.g. Fireblocks API secrets) are protected via SecretStr.
    """

    backend: Literal["aws", "gcp", "azure", "yubihsm", "fireblocks", "local"] = "aws"
    primary_key_id: str = Field(
        ...,
        description="Primary signing key identifier, ARN, version name, or alias.",
    )
    region: str | None = Field(
        default=None,
        description="Cloud region for AWS KMS (e.g. 'us-east-1') or GCP KMS (e.g. 'global').",
    )
    vault_url: str | None = Field(
        default=None,
        description="Full Azure Key Vault URL (e.g. 'https://myvault.vault.azure.net').",
    )
    connector_path: str | None = Field(
        default=None,
        description="Filesystem path to YubiHSM connector socket or PKCS#11 module.",
    )
    fireblocks_api_key: SecretStr | None = Field(
        default=None,
        description="Fireblocks API user UUID credential.",
    )
    fireblocks_api_secret: SecretStr | None = Field(
        default=None,
        description="Fireblocks RSA private key PEM secret.",
    )
    expected_address: str = Field(
        ...,
        description="EIP-55 checksummed EVM address. Signatures are verified against this.",
    )
    secondary_key_ids: list[str] = Field(
        default_factory=list,
        description="Previous key IDs preserved for zero-downtime key rotation verification.",
    )

    model_config = SettingsConfigDict(
        env_prefix="FLUXPAY_KMS_",
        extra="ignore",
        frozen=True,
    )

    @field_validator("expected_address")
    @classmethod
    def validate_expected_address(cls, v: str) -> str:
        """Enforce strict EIP-55 checksum format to eliminate mixed-case address bugs.

        Args:
            v: Input address string.

        Returns:
            Validated EIP-55 checksummed address string.

        Raises:
            ValueError: If address is not 40 hex characters or fails EIP-55 checksum.
        """
        if not isinstance(v, str) or not _EVM_ADDR_REGEX.match(v):
            raise ValueError(f"Value '{v}' is not a valid 40-character hex EVM address")

        if not Web3.is_checksum_address(v):
            raise ValueError(
                f"Address '{v}' fails EIP-55 checksum validation. "
                f"Expected '{Web3.to_checksum_address(v)}'."
            )
        return v
