"""Integration test cross-checking Base L2 HD wallet derivation against eth-account.

Derives 100 sequential addresses and verifies:
1. Exact address checksum equality against eth-account reference.
2. Exact private key match and EIP-191 message signing signature verification.
3. Multi-account partitioning (account 0, 1, 2) isolation.
4. Watch-only xpub parity across all 100 derived agent addresses.
"""

from __future__ import annotations

from typing import Final

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from fluxpay.integrations.hd_wallet import HDWalletManager

pytestmark = pytest.mark.integration

Account.enable_unaudited_hdwallet_features()

TEST_MNEMONIC: Final[str] = (
    "legal winner thank year wave sausage worth useful legal winner thank yellow"
)


def test_derive_100_addresses_verify_eth_account() -> None:
    """Derive 100 sequential addresses and verify every address and private key with eth-account."""
    manager = HDWalletManager.from_mnemonic(TEST_MNEMONIC, account_index=0)
    change_xpub = manager.export_xpub()
    watch_wallet = HDWalletManager.from_xpub(change_xpub, account_index=0)

    for i in range(100):
        # Full signing derivation
        derived = manager.derive_address(i, include_private_key=True)
        # Watch-only derivation
        watch_derived = watch_wallet.derive_address(i)

        # Independent reference derivation via eth-account
        path = f"m/44'/60'/0'/0/{i}"
        ref_account = Account.from_mnemonic(TEST_MNEMONIC, account_path=path)

        # 1. Address matching
        assert derived.address == ref_account.address, f"Address mismatch at index {i}"
        assert watch_derived.address == ref_account.address, f"Watch-only address mismatch at {i}"

        # 2. Private key matching
        assert derived.private_key is not None
        assert derived.private_key.get_secret_value() == f"0x{ref_account.key.hex()}"

        # 3. Cryptographic signature verification using derived private key
        message = encode_defunct(text=f"FluxPay-Agent-Deposit-Auth-index-{i}")
        signed = Account.sign_message(message, private_key=derived.private_key.get_secret_value())
        recovered_address = Account.recover_message(message, signature=signed.signature)
        assert recovered_address == derived.address


@pytest.mark.parametrize("account_idx", [0, 1, 2, 5])
def test_multi_account_derivation_cross_check(account_idx: int) -> None:
    """Verify distinct BIP-44 account indices produce isolated deterministic address sets."""
    manager = HDWalletManager.from_mnemonic(TEST_MNEMONIC, account_index=account_idx)

    for i in range(5):
        derived = manager.derive_address(i, include_private_key=True)
        path = f"m/44'/60'/{account_idx}'/0/{i}"
        ref = Account.from_mnemonic(TEST_MNEMONIC, account_path=path)

        assert derived.address == ref.address
        assert derived.path == path
        assert derived.private_key is not None
        assert derived.private_key.get_secret_value() == f"0x{ref.key.hex()}"
