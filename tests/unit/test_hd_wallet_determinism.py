"""Property-based determinism and collision resistance tests for Base L2 HD wallet.

Uses the Hypothesis testing framework to verify mathematical invariants:
1. Strict determinism: f(mnemonic, passphrase, index) is a pure function.
2. Collision resistance: 1,000 distinct indices map to 1,000 distinct addresses.
3. Reference cross-validation: derivation matches eth-account independently.
"""

from __future__ import annotations

import random
from typing import Final

import pytest
from eth_account import Account
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fluxpay.integrations.hd_wallet import BIP32_MAX_INDEX, HDWalletManager

pytestmark = pytest.mark.unit

Account.enable_unaudited_hdwallet_features()

CANONICAL_MNEMONIC: Final[str] = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)


@given(
    index=st.integers(min_value=0, max_value=BIP32_MAX_INDEX),
)
@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_property_derivation_determinism(index: int) -> None:
    """Mathematical Invariant: Address derivation is pure and strictly deterministic.

    Repeated calls with identical parameters MUST produce identical output.
    """
    wallet = HDWalletManager.from_mnemonic(CANONICAL_MNEMONIC)

    derived_1 = wallet.derive_address(index, include_private_key=True)
    derived_2 = wallet.derive_address(index, include_private_key=True)

    assert derived_1.address == derived_2.address
    assert derived_1.public_key == derived_2.public_key
    assert derived_1.path == derived_2.path
    assert (
        derived_1.private_key.get_secret_value()  # type: ignore[union-attr]
        == derived_2.private_key.get_secret_value()  # type: ignore[union-attr]
    )


def test_collision_resistance_1000_distinct_indices() -> None:
    """Security Invariant: 1,000 distinct indices must produce 1,000 unique addresses."""
    wallet = HDWalletManager.from_mnemonic(CANONICAL_MNEMONIC)

    # Deterministic seed for reproducible pseudorandom indices across test runs
    rng = random.Random(42)  # noqa: S311
    sample_indices = rng.sample(range(0, BIP32_MAX_INDEX), 1000)

    assert len(sample_indices) == 1000

    derived_addresses: set[str] = set()
    derived_pubkeys: set[str] = set()

    for idx in sample_indices:
        derived = wallet.derive_address(idx)
        derived_addresses.add(derived.address)
        derived_pubkeys.add(derived.public_key)

    # Mathematical certainty: zero collisions in 1,000 random derivations
    assert len(derived_addresses) == 1000, "Address collision detected in HD derivation!"
    assert len(derived_pubkeys) == 1000, "Public key collision detected in HD derivation!"


def test_determinism_property_1000_iterations() -> None:
    """Verify determinism across 1,000 sequential index evaluations."""
    wallet = HDWalletManager.from_mnemonic(CANONICAL_MNEMONIC)

    for i in range(1000):
        addr_1 = wallet.derive_public_only(i)
        addr_2 = wallet.derive_public_only(i)
        assert addr_1 == addr_2


def test_cross_check_reference_eth_account() -> None:
    """Verify derivation results match eth-account reference implementation exactly."""
    wallet = HDWalletManager.from_mnemonic(CANONICAL_MNEMONIC)

    test_indices = [0, 1, 2, 5, 10, 42, 100, 777, 9999]

    for idx in test_indices:
        derived = wallet.derive_address(idx, include_private_key=True)
        path = f"m/44'/60'/0'/0/{idx}"

        ref_acc = Account.from_mnemonic(CANONICAL_MNEMONIC, account_path=path)

        assert derived.address.lower() == ref_acc.address.lower()
        assert derived.address == ref_acc.address  # EIP-55 checksum match
        assert derived.private_key is not None
        assert derived.private_key.get_secret_value() == f"0x{ref_acc.key.hex()}"
