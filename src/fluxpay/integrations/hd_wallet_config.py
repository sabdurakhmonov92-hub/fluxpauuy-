"""Configuration model for Base L2 HD wallet derivation (BIP-39/BIP-32/BIP-44).

Implements twelve-factor environment configuration with strict Pydantic v2 validation.
Enforces fail-closed security invariants if master mnemonic credentials are missing
or malformed.
"""

from __future__ import annotations

from typing import Final

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

BIP32_MAX_INDEX: Final[int] = (1 << 31) - 1  # 2^31 - 1 = 2,147,483,647


class HDWalletConfig(BaseSettings):
    """Configuration settings for Base L2 HD Wallet address derivation.

    Security Policies:
    1. Sensitive values (mnemonic, passphrase) are typed strictly as `SecretStr`.
    2. Fail-closed: missing `mnemonic` causes immediate validation failure.
    3. Monotonic index bounds are restricted to the BIP-32 non-hardened domain [0, 2^31 - 1].
    """

    mnemonic: SecretStr = Field(
        ...,
        validation_alias=AliasChoices(
            "FLUXPAY_MASTER_MNEMONIC",
            "FLUXPAY_HD_WALLET_MNEMONIC",
            "mnemonic",
        ),
        description="BIP-39 master mnemonic phrase (12, 15, 18, 21, or 24 words).",
    )
    passphrase: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "FLUXPAY_PASSPHRASE",
            "FLUXPAY_HD_WALLET_PASSPHRASE",
            "passphrase",
        ),
        description="Optional BIP-39 passphrase ('25th word') for master seed salt.",
    )
    account_index: int = Field(
        default=0,
        ge=0,
        le=BIP32_MAX_INDEX,
        description="BIP-44 account index (m/44'/60'/{account_index}'/0/{index}).",
    )
    max_address_index: int = Field(
        default=BIP32_MAX_INDEX,
        ge=0,
        le=BIP32_MAX_INDEX,
        description="Maximum permissible non-hardened child address index.",
    )

    model_config = SettingsConfigDict(
        env_prefix="FLUXPAY_HD_WALLET_",
        extra="ignore",
    )
