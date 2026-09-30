"""Unit tests verifying standards compliance and security invariants of Base L2 HD wallet.

Tests cover:
1. BIP-39 official test vectors (mnemonic -> seed).
2. BIP-32 official Bitcoin test vectors (master key and child key derivation).
3. BIP-44 Ethereum reference derivation vectors.
4. Mnemonic validation: invalid word counts, bad checksums, unknown words.
5. Weak mnemonic rejection: identical words, sequential words, low diversity.
6. Index boundary validation (0, 1, 2^31-1, 2^31, negative, non-integer).
7. Zero address and burn address rejection.
8. SecretStr encapsulation and leak prevention in __repr__, __str__, and capsys logging.
9. Watch-only xpub derivation parity with full signing wallet.
10. Stateful monotonic index allocation with concurrency safety.
11. Fail-closed behavior on missing configuration/environment.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import pytest
from bip_utils import (  # type: ignore[import-untyped]
    Bip32Secp256k1,
    Bip39SeedGenerator,
)
from pydantic import SecretStr

from fluxpay.integrations.hd_wallet import (
    BIP32_MAX_INDEX,
    FLX_HD_WALLET_DERIVED_TOTAL,
    HDWalletConfig,
    HDWalletManager,
    IndexOutOfBoundsError,
    InvalidDerivedAddressError,
    InvalidXpubError,
    MnemonicValidationError,
    PrivateKeyAccessForbiddenError,
    WeakMnemonicError,
)

pytestmark = pytest.mark.unit

# Official BIP-39 Test Vectors (Trezor spec)
BIP39_VECTORS: list[dict[str, str]] = [
    {
        "mnemonic": (
            "abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon about"
        ),
        "passphrase": "TREZOR",
        "expected_seed": (
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
            "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        ),
    },
    {
        "mnemonic": ("legal winner thank year wave sausage worth useful legal winner thank yellow"),
        "passphrase": "TREZOR",
        "expected_seed": (
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
            "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
        ),
    },
    {
        "mnemonic": (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon art"
        ),
        "passphrase": "TREZOR",
        "expected_seed": (
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
            "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
        ),
    },
]

# Official BIP-32 Test Vector 1 (Chain m and m/0')
BIP32_VECTOR_1 = {
    "seed_hex": "000102030405060708090a0b0c0d0e0f",
    "master_xpub": (
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjq"
        "JoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    ),
    "master_xprv": (
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKm"
        "PGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    ),
    "child_0h_xpub": (
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeN"
        "K1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
    ),
    "child_0h_xprv": (
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj"
        "6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    ),
}

# BIP-44 Base L2 / Ethereum Reference Derivation Vectors
TEST_MNEMONIC: str = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)

BIP44_ETH_VECTORS: list[dict[str, Any]] = [
    {
        "index": 0,
        "path": "m/44'/60'/0'/0/0",
        "address": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        "public_key": "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299",
        "private_key": "0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
    },
    {
        "index": 1,
        "path": "m/44'/60'/0'/0/1",
        "address": "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
        "public_key": "039fd0991d0222b4e1339c1a1a5b5f6d9f6a96672a3247b638ee6156d9ea877a2f",
    },
    {
        "index": 2,
        "path": "m/44'/60'/0'/0/2",
        "address": "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A",
        "public_key": "03880bcb4bf46b49bdb071e307e282b11b9166907d9708f8c706092c44743f3e67",
    },
    {
        "index": 3,
        "path": "m/44'/60'/0'/0/3",
        "address": "0xF3f50213C1d2e255e4B2bAD430F8A38EEF8D718E",
        "public_key": "0371fd9d361f19065cb8e7be22dfd2ff3f7f265dcaf01f45cfcc956e55dba8b124",
    },
]


def test_bip39_official_test_vectors() -> None:
    """Verify PBKDF2-HMAC-SHA512 seed derivation matches official BIP-39 vectors."""
    for vec in BIP39_VECTORS:
        seed = Bip39SeedGenerator(vec["mnemonic"]).Generate(vec["passphrase"])
        assert seed.hex() == vec["expected_seed"]


def test_bip32_official_test_vectors() -> None:
    """Verify secp256k1 master key and child derivation matches official BIP-32 spec."""
    seed_bytes = bytes.fromhex(BIP32_VECTOR_1["seed_hex"])
    master_key = Bip32Secp256k1.FromSeed(seed_bytes)

    assert master_key.PrivateKey().ToExtended() == BIP32_VECTOR_1["master_xprv"]
    assert master_key.PublicKey().ToExtended() == BIP32_VECTOR_1["master_xpub"]

    # Child derivation: m/0' (hardened)
    child_0h = master_key.ChildKey(0 | (1 << 31))
    assert child_0h.PrivateKey().ToExtended() == BIP32_VECTOR_1["child_0h_xprv"]
    assert child_0h.PublicKey().ToExtended() == BIP32_VECTOR_1["child_0h_xpub"]


def test_bip44_ethereum_derivation_vectors() -> None:
    """Verify canonical m/44'/60'/0'/0/{index} derivation matches EVM reference."""
    manager = HDWalletManager.from_mnemonic(TEST_MNEMONIC)

    for vec in BIP44_ETH_VECTORS:
        idx = int(vec["index"])
        derived = manager.derive_address(idx, include_private_key=True)

        assert derived.index == idx
        assert derived.path == vec["path"]
        assert derived.address == vec["address"]
        assert derived.public_key == vec["public_key"]
        assert isinstance(derived.created_at, datetime)

        if "private_key" in vec:
            assert derived.private_key is not None
            assert derived.private_key.get_secret_value() == vec["private_key"]


def test_public_only_derivation_omits_private_key() -> None:
    """derive_public_only returns solely the EIP-55 address string."""
    manager = HDWalletManager.from_mnemonic(TEST_MNEMONIC)
    addr = manager.derive_public_only(0)
    assert addr == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

    # Default derive_address must omit private_key
    derived_default = manager.derive_address(0)
    assert derived_default.private_key is None


def test_invalid_mnemonic_word_count() -> None:
    """Reject mnemonics with invalid word counts (e.g. 11 or 13 words)."""
    # 11 words
    words_11 = "abandon " * 10 + "about"
    with pytest.raises(MnemonicValidationError) as exc:
        HDWalletManager.from_mnemonic(words_11)
    assert "word count" in str(exc.value).lower()

    # 13 words
    words_13 = "abandon " * 12 + "about"
    with pytest.raises(MnemonicValidationError) as exc:
        HDWalletManager.from_mnemonic(words_13)
    assert "word count" in str(exc.value).lower()


def test_invalid_mnemonic_unknown_word() -> None:
    """Reject mnemonics containing words not in the BIP-39 wordlist."""
    bad_phrase = "abandon " * 11 + "foobarword"
    with pytest.raises(MnemonicValidationError) as exc:
        HDWalletManager.from_mnemonic(bad_phrase)
    assert "not in the bip-39 wordlist" in str(exc.value).lower()


def test_invalid_mnemonic_checksum_error() -> None:
    """Reject mnemonics with invalid SHA-256 entropy checksum."""
    bad_checksum = "legal winner thank year wave sausage worth useful legal winner thank abandon"
    with pytest.raises(MnemonicValidationError) as exc:
        HDWalletManager.from_mnemonic(bad_checksum)
    assert "checksum validation failed" in str(exc.value).lower()


def test_weak_mnemonic_identical_words() -> None:
    """Reject weak mnemonics where all words are identical."""
    with pytest.raises(WeakMnemonicError) as exc:
        HDWalletManager._validate_mnemonic(SecretStr("abandon " * 11 + "abandon"))
    assert "identical repeated words" in str(exc.value).lower()

    with pytest.raises(WeakMnemonicError):
        HDWalletManager._validate_mnemonic(SecretStr("zoo " * 11 + "zoo"))


def test_weak_mnemonic_sequential_wordlist() -> None:
    """Reject phrases consisting of sequential consecutive wordlist entries."""
    from mnemonic import Mnemonic

    ref = Mnemonic("english")
    seq_words = ref.wordlist[10:22]
    phrase = " ".join(seq_words)
    with pytest.raises(WeakMnemonicError) as exc:
        HDWalletManager._validate_mnemonic(SecretStr(phrase))
    assert "sequential consecutive wordlist words" in str(exc.value).lower()


def test_index_boundary_validation() -> None:
    """Verify strict BIP-32 bounds: [0, 2^31 - 1]."""
    manager = HDWalletManager.from_mnemonic(TEST_MNEMONIC)

    # Valid boundaries
    assert manager.derive_address(0).index == 0
    assert manager.derive_address(1).index == 1
    assert manager.derive_address(BIP32_MAX_INDEX).index == BIP32_MAX_INDEX

    # Invalid: negative
    with pytest.raises(IndexOutOfBoundsError):
        manager.derive_address(-1)

    # Invalid: >= 2^31
    with pytest.raises(IndexOutOfBoundsError):
        manager.derive_address(BIP32_MAX_INDEX + 1)

    with pytest.raises(IndexOutOfBoundsError):
        manager.derive_address(2**32)

    # Invalid: non-integer types
    with pytest.raises(TypeError):
        manager.derive_address("0")  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        manager.derive_address(True)


def test_custom_max_address_index_limit() -> None:
    """Verify manager enforces configured max_address_index."""
    manager = HDWalletManager.from_mnemonic(TEST_MNEMONIC, max_address_index=50)
    assert manager.derive_address(50).index == 50

    with pytest.raises(IndexOutOfBoundsError):
        manager.derive_address(51)


def test_security_private_key_never_in_repr_or_str() -> None:
    """DerivedAddress repr and str MUST redact private keys unconditionally."""
    manager = HDWalletManager.from_mnemonic(TEST_MNEMONIC)
    derived = manager.derive_address(0, include_private_key=True)

    assert derived.private_key is not None
    raw_pk = derived.private_key.get_secret_value()
    assert raw_pk.startswith("0x")

    repr_str = repr(derived)
    str_val = str(derived)

    assert raw_pk not in repr_str
    assert raw_pk not in str_val
    assert "SecretStr('**********')" in repr_str
    assert "SecretStr('**********')" in str_val


def test_security_to_dict_redaction() -> None:
    """to_dict omits private key unless explicitly permitted."""
    manager = HDWalletManager.from_mnemonic(TEST_MNEMONIC)
    derived = manager.derive_address(0, include_private_key=True)

    redacted_dict = derived.to_dict(include_private_key=False)
    assert "private_key" not in redacted_dict

    full_dict = derived.to_dict(include_private_key=True)
    assert full_dict["private_key"] == derived.private_key.get_secret_value()  # type: ignore[union-attr]


def test_security_no_private_keys_in_logs(capsys: Any) -> None:
    """Verify initialization and derivation never write sensitive keys to stdout/stderr."""
    manager = HDWalletManager.from_mnemonic(TEST_MNEMONIC)
    derived = manager.derive_address(0, include_private_key=True)

    captured = capsys.readouterr()
    raw_pk = derived.private_key.get_secret_value()  # type: ignore[union-attr]
    assert raw_pk not in captured.out
    assert raw_pk not in captured.err
    assert TEST_MNEMONIC not in captured.out
    assert TEST_MNEMONIC not in captured.err


def test_watch_only_xpub_derivation_parity() -> None:
    """Addresses derived via watch-only xpub MUST match private derivation exactly."""
    full_wallet = HDWalletManager.from_mnemonic(TEST_MNEMONIC)
    change_xpub = full_wallet.export_xpub()
    account_xpub = full_wallet.export_account_xpub()

    # Initialize watch-only wallet from change xpub
    watch_wallet_chg = HDWalletManager.from_xpub(change_xpub)
    assert watch_wallet_chg.is_watch_only is True

    # Initialize watch-only wallet from account xpub
    watch_wallet_acc = HDWalletManager.from_xpub(account_xpub)
    assert watch_wallet_acc.is_watch_only is True

    for i in range(10):
        expected = full_wallet.derive_address(i, include_private_key=False)
        from_chg = watch_wallet_chg.derive_address(i)
        from_acc = watch_wallet_acc.derive_address(i)

        assert from_chg.address == expected.address
        assert from_chg.public_key == expected.public_key
        assert from_chg.private_key is None

        assert from_acc.address == expected.address
        assert from_acc.public_key == expected.public_key
        assert from_acc.private_key is None


def test_watch_only_rejects_private_key_request() -> None:
    """Requesting private key in watch-only mode raises PrivateKeyAccessForbiddenError."""
    full_wallet = HDWalletManager.from_mnemonic(TEST_MNEMONIC)
    watch_wallet = HDWalletManager.from_xpub(full_wallet.export_xpub())

    with pytest.raises(PrivateKeyAccessForbiddenError) as exc:
        watch_wallet.derive_address(0, include_private_key=True)
    assert "watch-only mode" in str(exc.value)


def test_invalid_xpub_rejection() -> None:
    """Invalid xpub formats, prefixes, private keys, and checksums must be rejected."""
    # Private key passed to from_xpub
    with pytest.raises(InvalidXpubError) as exc:
        HDWalletManager.from_xpub(BIP32_VECTOR_1["master_xprv"])
    assert "received private key" in str(exc.value)

    # Non-xpub valid prefix (e.g. testnet tpub)
    valid_tpub = (
        "tpubD6NzVbkrYhZ4Was8nwnZi7eiWUNJq2LFpPSCMQLioUfUtT1e72GkRbmVeRAZc26j5"
        "MRUz2hRLsaVHJfs6L7ppNfLUrm9btQTuaEsLrT7D87"
    )
    with pytest.raises(InvalidXpubError) as exc:
        HDWalletManager.from_xpub(valid_tpub)
    assert "prefix 'xpub'" in str(exc.value)

    # Checksum failure
    with pytest.raises(InvalidXpubError):
        HDWalletManager.from_xpub("xpubBadChecksum1234567890")

    # Unsupported depth (master xpub depth 0)
    with pytest.raises(InvalidXpubError):
        HDWalletManager.from_xpub(BIP32_VECTOR_1["master_xpub"])


def test_burn_address_safety_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """Synthetically derived burn/zero addresses are rejected with InvalidDerivedAddressError."""
    manager = HDWalletManager.from_mnemonic(TEST_MNEMONIC)

    # Mock Web3.to_checksum_address to return dead burn address
    monkeypatch.setattr(
        "fluxpay.integrations.hd_wallet.Web3.to_checksum_address",
        lambda _: "0x000000000000000000000000000000000000dEaD",
    )

    with pytest.raises(InvalidDerivedAddressError):
        manager.derive_address(0)


def test_fail_closed_missing_mnemonic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail-closed: initialization without config or env vars raises MnemonicValidationError."""
    monkeypatch.delenv("FLUXPAY_MASTER_MNEMONIC", raising=False)
    monkeypatch.delenv("FLUXPAY_HD_WALLET_MNEMONIC", raising=False)

    with pytest.raises(MnemonicValidationError):
        HDWalletManager()


@pytest.mark.asyncio
async def test_stateful_monotonic_allocation() -> None:
    """Verify thread-safe sequential index allocation with asyncio.Lock."""
    manager = HDWalletManager.from_mnemonic(TEST_MNEMONIC, max_address_index=10)

    # Sequential allocations
    idx0 = await manager.allocate_next_index()
    idx1 = await manager.allocate_next_index()
    assert idx0 == 0
    assert idx1 == 1

    addr2 = await manager.derive_next_address()
    assert addr2.index == 2

    # Concurrent allocations
    tasks = [manager.allocate_next_index() for _ in range(8)]
    allocated_indices = await asyncio.gather(*tasks)
    assert sorted(allocated_indices) == list(range(3, 11))

    # Next allocation exceeds max_address_index
    with pytest.raises(IndexOutOfBoundsError):
        await manager.allocate_next_index()


def test_observability_fingerprint_and_metrics() -> None:
    """Verify 4-byte audit fingerprint generation and Prometheus metric increments."""
    manager = HDWalletManager.from_mnemonic(TEST_MNEMONIC)
    assert len(manager.fingerprint) == 8  # 4 bytes hex = 8 chars

    initial_val = FLX_HD_WALLET_DERIVED_TOTAL._value.get()
    manager.derive_address(0)
    manager.derive_address(1)
    new_val = FLX_HD_WALLET_DERIVED_TOTAL._value.get()
    assert new_val == initial_val + 2


def test_gauge_registration_idempotency_and_mismatch() -> None:
    """_get_or_create_gauge returns existing gauge or raises on type collision."""
    from prometheus_client import CollectorRegistry, Counter

    from fluxpay.integrations.hd_wallet import _get_or_create_gauge

    test_reg = CollectorRegistry()
    g1 = _get_or_create_gauge("test_g", "doc", (), registry=test_reg)
    g2 = _get_or_create_gauge("test_g", "doc", (), registry=test_reg)
    assert g1 is g2

    Counter("test_counter", "doc", registry=test_reg)
    with pytest.raises(ValueError):
        _get_or_create_gauge("test_counter", "doc", (), registry=test_reg)


def test_properties_and_account_xpub_unavailability() -> None:
    """Verify accessors and InvalidXpubError on change-level xpub."""
    full = HDWalletManager.from_mnemonic(TEST_MNEMONIC, account_index=5, max_address_index=100)
    assert full.account_index == 5
    assert full.max_address_index == 100
    assert full.is_watch_only is False

    watch_chg = HDWalletManager.from_xpub(full.export_xpub())
    assert watch_chg.is_watch_only is True
    with pytest.raises(InvalidXpubError) as exc:
        watch_chg.export_account_xpub()
    assert "unavailable" in str(exc.value).lower()


def test_config_resolution_branches() -> None:
    """Verify all precedence combinations in _resolve_config."""
    cfg = HDWalletConfig(
        mnemonic=SecretStr(TEST_MNEMONIC),
        passphrase=SecretStr("pass1"),
        account_index=2,
        max_address_index=200,
    )
    # Direct config without explicit args
    m1 = HDWalletManager(config=cfg)
    assert m1.account_index == 2
    assert m1.max_address_index == 200

    # Explicit mnemonic with explicit string passphrase and indices
    m2 = HDWalletManager(
        mnemonic=TEST_MNEMONIC,
        passphrase="pass2",  # noqa: S106
        account_index=7,
        max_address_index=700,
    )
    assert m2.account_index == 7
    assert m2.max_address_index == 700

    # Explicit mnemonic overriding config
    m3 = HDWalletManager(mnemonic=TEST_MNEMONIC, config=cfg)
    assert m3.account_index == 2

    # Explicit SecretStr mnemonic without passphrase and without config
    m4 = HDWalletManager(mnemonic=SecretStr(TEST_MNEMONIC))
    assert m4.account_index == 0
    assert m4.max_address_index == BIP32_MAX_INDEX

    # Explicit SecretStr passphrase
    m5 = HDWalletManager(mnemonic=TEST_MNEMONIC, passphrase=SecretStr("pass3"))
    assert m5.account_index == 0
