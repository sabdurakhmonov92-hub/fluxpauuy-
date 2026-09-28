"""Multi-chain rail configuration registry for OnChainReader integrations.

Task 51: Ethereum Rail — The Second Chain via Generalization.

DESIGN LAWS & INVARIANTS:
1. THE REGISTRY AS DRIFT GUARD:
   A payment reader can never query an arbitrary or mistyped chain. Lookups flow
   strictly through `registry[rail]`. An invalid or unconfigured rail fails fast
   at the reader boundary with a typed IntegrationError before any network I/O.
2. DISABLED-MODE LAW:
   Rails with `rpc_url is None` (or empty string) are OMITTED from the registry.
   If neither rail is configured with an RPC endpoint, the registry is empty `{}`.
3. COMPATIBILITY SHIM & DEPRECATION PATH:
   `base_usdc` is sourced from `settings.base_*` configuration fields (base_rpc_url,
   base_chain_id, base_usdc_address). In Phase 2, per-rail nested configs will replace
   these flat fields. Existing environment files remain 100% functional without edits.
4. PER-RAIL FINALITY KNOB:
   Different chains possess radically different finality guarantees. While L2 rollups
   (Base) achieve safe receipt inclusion quickly, Ethereum L1 requires observing
   reorg depth and Casper FFG finality (~13 minutes / 2 epochs, 64-96 blocks) for
   treasury-scale decisions. `confirmations_min` configures this per-rail.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = [
    "RAIL_REGISTRY",
    "RailConfig",
    "build_registry",
]

EVM_ADDRESS_REGEX = re.compile(r"^0x[0-9a-fA-F]{40}$")


@dataclass(frozen=True, slots=True)
class RailConfig:
    """Immutable configuration for an on-chain payment rail."""

    rail: str
    chain_id: int
    usdc_address: str
    rpc_url: str | None
    confirmations_min: int

    def __post_init__(self) -> None:
        if not EVM_ADDRESS_REGEX.match(self.usdc_address):
            raise ValueError(
                f"Invalid USDC contract address for rail '{self.rail}': '{self.usdc_address}'. "
                "Must be a 40-hex-character EVM address prefixed with '0x'."
            )
        if self.chain_id <= 0:
            raise ValueError(
                f"Invalid chain_id for rail '{self.rail}': {self.chain_id}. Must be > 0."
            )
        if self.confirmations_min < 1:
            raise ValueError(
                f"Invalid confirmations_min for rail '{self.rail}': {self.confirmations_min}. "
                "Must be >= 1."
            )


def _extract_setting(settings: Any, field_name: str, default: Any = None) -> Any:
    """Helper to extract configuration field from Settings object or dict."""
    if isinstance(settings, dict):
        return settings.get(field_name, default)
    return getattr(settings, field_name, default)


def build_registry(settings: Any = None) -> dict[str, RailConfig]:
    """Build the active rail configuration registry from application settings.

    DISABLED-MODE LAW:
    Rails with `rpc_url is None` (or empty string) are OMITTED from the registry.
    If no rails are configured with RPC URLs, an empty dict is returned.

    COMPATIBILITY SHIM & DEPRECATION PATH:
    `base_usdc` values are mapped from `settings.base_*` fields into the registry.
    `ethereum_usdc` values are mapped from `settings.eth_*` fields into the registry.
    """
    if settings is None:
        try:
            import importlib

            cfg_mod = importlib.import_module("fluxpay.config")
            settings = cfg_mod.get_settings()
        except Exception:
            return {}

    registry: dict[str, RailConfig] = {}

    # 1. Base L2 (base_usdc) — mapped from base_* fields (compat shim)
    base_rpc = _extract_setting(settings, "base_rpc_url", None)
    if base_rpc is not None:
        base_rpc_str = str(base_rpc).strip()
        if base_rpc_str:
            base_chain_id = int(_extract_setting(settings, "base_chain_id", 8453))
            base_usdc_addr = str(
                _extract_setting(
                    settings,
                    "base_usdc_address",
                    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                )
            ).strip()
            # Base L2 confirmations default to 1
            registry["base_usdc"] = RailConfig(
                rail="base_usdc",
                chain_id=base_chain_id,
                usdc_address=base_usdc_addr,
                rpc_url=base_rpc_str,
                confirmations_min=1,
            )

    # 2. Ethereum L1 (ethereum_usdc) — mapped from eth_* fields
    eth_rpc = _extract_setting(settings, "eth_rpc_url", None)
    if eth_rpc is not None:
        eth_rpc_str = str(eth_rpc).strip()
        if eth_rpc_str:
            eth_chain_id = int(_extract_setting(settings, "eth_chain_id", 1))
            eth_usdc_addr = str(
                _extract_setting(
                    settings,
                    "eth_usdc_address",
                    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                )
            ).strip()
            eth_confs = int(_extract_setting(settings, "eth_confirmations_min", 1))
            registry["ethereum_usdc"] = RailConfig(
                rail="ethereum_usdc",
                chain_id=eth_chain_id,
                usdc_address=eth_usdc_addr,
                rpc_url=eth_rpc_str,
                confirmations_min=eth_confs,
            )

    return registry


# Module-level default registry built from environment settings
RAIL_REGISTRY: dict[str, RailConfig] = build_registry()
