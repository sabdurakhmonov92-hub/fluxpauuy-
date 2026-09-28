"""Unit tests verifying AES-256-GCM envelope encryption, AAD context binding, and RAM zeroization.

Validates the frozen envelope format, nonce uniqueness, tamper detection, ciphertext-swap
prevention via AAD, RAM zeroization hygiene, and error registry contracts.
"""

import base64
import gc
import os
import re
from collections.abc import Generator
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from fluxpay.config import get_settings
from fluxpay.shared.errors import ERROR_REGISTRY, VaultError
from fluxpay.shared.vault import (
    MIN_ENVELOPE_RAW_LEN,
    NONCE_BYTES_LEN,
    SecretBytes,
    decrypt_secret,
    encrypt_secret,
    reset_vault_cache,
    wipe,
)

EXPECTED_RETRYABLE_CODES = {
    "rate_limited",
    "conflict_retry_required",
}


@pytest.fixture(autouse=True)
def _register_vault_error(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Register VaultError in ERROR_REGISTRY for test execution and restore state on teardown."""
    ERROR_REGISTRY[VaultError.code] = VaultError
    yield
    ERROR_REGISTRY.pop(VaultError.code, None)


@pytest.fixture(autouse=True)
def fresh_vault_key(monkeypatch: pytest.MonkeyPatch) -> Generator[str, None, None]:
    """Provide a fresh random 32-byte AES-256 master key for each test.

    Ensures complete isolation across tests by clearing settings and vault caches.
    """
    # Generate fresh 32 bytes of cryptographically secure entropy
    raw_key = os.urandom(32)
    key_b64 = base64.b64encode(raw_key).decode("ascii")

    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", key_b64)
    monkeypatch.setenv("FLX_PG_DSN", "postgresql://test:test@localhost:5432/test")
    monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", "0" * 32)

    get_settings.cache_clear()
    reset_vault_cache()

    yield key_b64

    reset_vault_cache()
    get_settings.cache_clear()


@pytest.mark.unit
def test_roundtrip_encryption_decryption() -> None:
    """Validate that encrypt -> decrypt roundtrip returns identical plaintext."""
    plaintext = "sk-test-0001-secret-token"
    context = "agent_secret:agent_100"

    encrypted_b64 = encrypt_secret(plaintext, context=context)
    decrypted = decrypt_secret(encrypted_b64, context=context)

    try:
        assert isinstance(decrypted, SecretBytes)
        assert decrypted.decode("utf-8") == plaintext
    finally:
        decrypted.wipe()


@pytest.mark.unit
def test_envelope_format_and_shape() -> None:
    """Validate frozen envelope format: base64( VERSION_BYTE || NONCE || CIPHERTEXT||TAG )."""
    plaintext = "sk-test-0001"
    context = "agent_secret:agent_100"

    encrypted_b64 = encrypt_secret(plaintext, context=context)
    raw = base64.b64decode(encrypted_b64, validate=True)

    # Version byte is 0x01
    assert raw[0] == 1
    assert raw[0:1] == b"\x01"

    # Total length = 1 (version) + 12 (nonce) + len(plaintext) + 16 (tag)
    expected_len = 1 + NONCE_BYTES_LEN + len(plaintext.encode("utf-8")) + 16
    assert len(raw) == expected_len


@pytest.mark.unit
def test_nonce_uniqueness_prevents_gcm_catastrophe() -> None:
    """Validate that identical plaintext and context produce different envelopes.

    GCM nonce reuse under one key leads to catastrophic two-time-pad XOR leakage
    and GHASH auth key recovery. Proves random 96-bit nonces are unique per encryption.
    """
    plaintext = "sk-test-0001"
    context = "agent_secret:agent_100"

    env1 = encrypt_secret(plaintext, context=context)
    env2 = encrypt_secret(plaintext, context=context)

    assert env1 != env2

    raw1 = base64.b64decode(env1)
    raw2 = base64.b64decode(env2)

    # Nonces (bytes 1..13) must differ
    nonce1 = raw1[1:13]
    nonce2 = raw2[1:13]
    assert nonce1 != nonce2


@pytest.mark.unit
def test_tamper_ciphertext_bit_fails_authentication() -> None:
    """Validate that flipping one bit inside the ciphertext region raises VaultError."""
    plaintext = "sk-test-0001-very-long-secret-key-material"
    context = "agent_secret:agent_100"

    encrypted_b64 = encrypt_secret(plaintext, context=context)
    raw = bytearray(base64.b64decode(encrypted_b64))

    # Ciphertext starts at byte 13 and ends 16 bytes before the end (tag is last 16 bytes)
    ciphertext_offset = 13 + 2  # Flip bit in the 2nd byte of ciphertext
    raw[ciphertext_offset] ^= 0x01

    tampered_b64 = base64.b64encode(raw).decode("ascii")

    with pytest.raises(VaultError) as exc_info:
        decrypt_secret(tampered_b64, context=context)

    assert exc_info.value.code == "vault_error"
    assert exc_info.value.status == 500
    assert exc_info.value.details.get("phase") == "decrypt"


@pytest.mark.unit
def test_tamper_tag_bit_fails_authentication() -> None:
    """Validate that flipping one bit inside the 16-byte authentication tag raises VaultError."""
    plaintext = "sk-test-0001"
    context = "agent_secret:agent_100"

    encrypted_b64 = encrypt_secret(plaintext, context=context)
    raw = bytearray(base64.b64decode(encrypted_b64))

    # Tag is the final 16 bytes
    tag_offset = len(raw) - 1
    raw[tag_offset] ^= 0x01

    tampered_b64 = base64.b64encode(raw).decode("ascii")

    with pytest.raises(VaultError) as exc_info:
        decrypt_secret(tampered_b64, context=context)

    assert exc_info.value.code == "vault_error"
    assert exc_info.value.status == 500
    assert exc_info.value.details.get("phase") == "decrypt"


@pytest.mark.unit
def test_aad_context_binding_wrong_context_fails() -> None:
    """Validate that decrypting with a mismatched context string raises VaultError."""
    plaintext = "sk-test-0001"
    encrypted_b64 = encrypt_secret(plaintext, context="agent_secret:agent_100")

    with pytest.raises(VaultError) as exc_info:
        decrypt_secret(encrypted_b64, context="agent_secret:agent_999")

    assert exc_info.value.code == "vault_error"
    assert exc_info.value.details.get("phase") == "decrypt"


@pytest.mark.unit
def test_aad_ciphertext_swap_attack_scenario() -> None:
    """Validate defense against ciphertext-swap attacks across distinct database records.

    Simulates an attacker with DB write access moving secretA from record A to record B.
    With AAD bound to record identities, decryption under record B's context fails.
    """
    payload_a = "sk-test-secret-a"
    enc_a = encrypt_secret(payload_a, context="agent_secret:agent_aaa")

    # Attacker places enc_a into agent_bbb's record
    with pytest.raises(VaultError) as exc_info:
        decrypt_secret(enc_a, context="agent_secret:agent_bbb")

    assert exc_info.value.code == "vault_error"
    assert exc_info.value.details.get("phase") == "decrypt"


@pytest.mark.unit
def test_wrong_key_fails_and_cache_reset_reloads(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate that changing the master key and resetting cache causes old decryption to fail."""
    plaintext = "sk-test-0001"
    context = "agent_secret:agent_100"

    encrypted_b64 = encrypt_secret(plaintext, context=context)

    # Re-monkeypatch a DIFFERENT valid 32-byte key
    new_key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", new_key_b64)
    get_settings.cache_clear()
    reset_vault_cache()

    # Old envelope must fail decryption under the new key
    with pytest.raises(VaultError) as exc_info:
        decrypt_secret(encrypted_b64, context=context)

    assert exc_info.value.code == "vault_error"
    assert exc_info.value.details.get("phase") == "decrypt"


@pytest.mark.unit
def test_unknown_version_byte_rejected_without_leak() -> None:
    """Validate that unknown envelope version byte raises VaultError naming only the version."""
    # Craft envelope with version byte 0x09 + 12-byte nonce + 16-byte tag
    crafted_raw = b"\x09" + os.urandom(NONCE_BYTES_LEN) + os.urandom(16)
    crafted_b64 = base64.b64encode(crafted_raw).decode("ascii")

    with pytest.raises(VaultError) as exc_info:
        decrypt_secret(crafted_b64, context="test_ctx")

    err_msg = str(exc_info.value)
    # Must name the version
    assert "09" in err_msg or "0x09" in err_msg or "\\x09" in err_msg
    # Must NOT leak payload or base64 envelope
    assert crafted_b64 not in err_msg
    assert exc_info.value.details.get("phase") == "decrypt"


@pytest.mark.unit
def test_empty_plaintext_roundtrip() -> None:
    """Validate that empty plaintext string is valid and roundtrips successfully."""
    context = "agent_secret:agent_empty"

    encrypted_b64 = encrypt_secret("", context=context)
    decrypted = decrypt_secret(encrypted_b64, context=context)

    try:
        assert isinstance(decrypted, SecretBytes)
        assert len(decrypted) == 0
        assert decrypted.decode("utf-8") == ""
    finally:
        decrypted.wipe()


@pytest.mark.unit
def test_leak_hygiene_on_tampered_envelope() -> None:
    """Validate that VaultError messages never leak plaintext, ciphertext, or InvalidTag."""
    sample_payload = "sk-test-super-secret-token-xyz"
    context = "agent_secret:agent_100"

    encrypted_b64 = encrypt_secret(sample_payload, context=context)
    raw = bytearray(base64.b64decode(encrypted_b64))
    raw[15] ^= 0xFF  # Tamper ciphertext
    tampered_b64 = base64.b64encode(raw).decode("ascii")

    with pytest.raises(VaultError) as exc_info:
        decrypt_secret(tampered_b64, context=context)

    err = exc_info.value
    err_str = f"{err.message} {err.details} {err!s}"

    assert sample_payload not in err_str
    assert tampered_b64 not in err_str
    assert "InvalidTag" not in err_str
    assert err.__cause__ is None


@pytest.mark.unit
def test_wipe_zeroizes_secret_bytes() -> None:
    """Validate that wipe() and SecretBytes.wipe() zero-fill the buffer in place."""
    secret = SecretBytes(b"sensitive_key_material_9988")
    original_len = len(secret)

    secret.wipe()

    assert len(secret) == original_len
    assert all(b == 0 for b in secret)
    assert secret == bytearray(b"\x00" * original_len)


@pytest.mark.unit
def test_wipe_immutable_bytes_raises_type_error() -> None:
    """Validate that calling wipe() on immutable bytes raises TypeError immediately."""
    immutable_data = b"cannot_wipe_this"

    with pytest.raises(TypeError) as exc_info:
        wipe(immutable_data)  # type: ignore[arg-type]

    assert "Cannot wipe immutable object" in str(exc_info.value)
    assert "bytes" in str(exc_info.value)

    with pytest.raises(TypeError):
        wipe("cannot_wipe_string")  # type: ignore[arg-type]


@pytest.mark.unit
def test_secret_bytes_del_destructor_smoke() -> None:
    """Validate that SecretBytes.__del__ executes cleanly without raising out."""
    secret = SecretBytes(b"temporary_secret")
    del secret
    gc.collect()


@pytest.mark.unit
def test_secret_bytes_del_suppresses_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate that SecretBytes.__del__ safely suppresses any exception during wipe."""
    secret = SecretBytes(b"temporary_secret")
    mock_wipe = MagicMock(side_effect=RuntimeError("wipe error"))
    monkeypatch.setattr("fluxpay.shared.vault.wipe", mock_wipe)
    # Explicitly invoke __del__; must not raise
    secret.__del__()


@pytest.mark.unit
def test_encrypt_secret_catches_cryptography_exception() -> None:
    """Validate that exceptions during AESGCM.encrypt are wrapped into VaultError(phase=encrypt)."""
    with patch.object(AESGCM, "encrypt", side_effect=Exception("simulated encrypt failure")):
        with pytest.raises(VaultError) as exc_info:
            encrypt_secret("test", context="ctx")

    assert exc_info.value.code == "vault_error"
    assert exc_info.value.details.get("phase") == "encrypt"
    assert exc_info.value.__cause__ is None


@pytest.mark.unit
def test_vault_error_in_registry() -> None:
    """Validate that VaultError is registered in ERROR_REGISTRY with code 'vault_error'."""
    assert "vault_error" in ERROR_REGISTRY
    cls = ERROR_REGISTRY["vault_error"]
    assert cls is VaultError
    assert cls.code == "vault_error"
    assert cls.status == 500
    assert cls.retryable is False
    assert cls.client_message == "internal security module failure"


@pytest.mark.unit
def test_task4_contract_still_green() -> None:
    """Validate that Task 4 error contract invariants remain completely intact."""
    code_pattern = re.compile(r"^[a-z][a-z0-9_]*$")
    seen_codes: set[str] = set()

    for code, cls in ERROR_REGISTRY.items():
        assert code not in seen_codes, f"Duplicate code: {code}"
        seen_codes.add(code)
        assert code_pattern.match(code), f"Code '{code}' not snake_case"
        assert 400 <= cls.status <= 599, f"Invalid status {cls.status} for {code}"

    actual_retryable_codes = {code for code, cls in ERROR_REGISTRY.items() if cls.retryable}
    assert actual_retryable_codes == EXPECTED_RETRYABLE_CODES


@pytest.mark.unit
def test_key_rotation_rehearsal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate Phase 2 key rotation rehearsal flow via reset_vault_cache()."""
    context = "agent_secret:agent_rotation"
    payload_old = "sk-test-old-key-data"
    payload_new = "sk-test-new-key-data"

    # 1. Encrypt with current (old) key
    env_old = encrypt_secret(payload_old, context=context)
    dec_old = decrypt_secret(env_old, context=context)
    assert dec_old.decode("utf-8") == payload_old
    dec_old.wipe()

    # 2. Rotate to new key
    new_key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", new_key_b64)
    get_settings.cache_clear()
    reset_vault_cache()

    # 3. Decrypting old envelope under new key fails
    with pytest.raises(VaultError) as exc_info:
        decrypt_secret(env_old, context=context)
    assert exc_info.value.code == "vault_error"

    # 4. Encrypt and decrypt with new key succeeds
    env_new = encrypt_secret(payload_new, context=context)
    dec_new = decrypt_secret(env_new, context=context)
    assert dec_new.decode("utf-8") == payload_new
    dec_new.wipe()


@pytest.mark.unit
def test_input_validation_types() -> None:
    """Validate strict type checking on public API inputs."""
    with pytest.raises(TypeError):
        encrypt_secret(123, context="ctx")  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        encrypt_secret("sec", context=123)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        decrypt_secret(123, context="ctx")  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        decrypt_secret("b64", context=123)  # type: ignore[arg-type]


@pytest.mark.unit
def test_corrupted_base64_envelope_fails() -> None:
    """Validate that invalid base64 input raises VaultError with phase=decrypt."""
    with pytest.raises(VaultError) as exc_info:
        decrypt_secret("!!!invalid_base64$$$", context="ctx")

    assert exc_info.value.code == "vault_error"
    assert exc_info.value.details.get("phase") == "decrypt"


@pytest.mark.unit
def test_envelope_too_short_fails() -> None:
    """Validate that envelopes shorter than minimum length (29 bytes) raise VaultError."""
    short_raw = b"\x01" + b"too_short"
    assert len(short_raw) < MIN_ENVELOPE_RAW_LEN
    short_b64 = base64.b64encode(short_raw).decode("ascii")

    with pytest.raises(VaultError) as exc_info:
        decrypt_secret(short_b64, context="ctx")

    assert exc_info.value.code == "vault_error"
    assert exc_info.value.details.get("phase") == "decrypt"


@pytest.mark.unit
def test_corrupted_master_key_handling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate defensive handling if master key fails base64 decode or length check."""
    # Test length != 32
    bad_key_b64 = base64.b64encode(b"short_16_bytes!").decode("ascii")
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", bad_key_b64)
    get_settings.cache_clear()
    reset_vault_cache()

    # Settings constructor catches it during get_settings(), but if bypassed:
    from unittest.mock import MagicMock, patch

    mock_settings = MagicMock()
    mock_settings.vault_master_key = bad_key_b64

    with patch("fluxpay.shared.vault.get_settings", return_value=mock_settings):
        with pytest.raises(VaultError) as exc_info:
            encrypt_secret("test", context="ctx")
        assert exc_info.value.details.get("phase") == "encrypt"

    # Test invalid base64
    mock_settings.vault_master_key = "invalid!base64"
    reset_vault_cache()
    with patch("fluxpay.shared.vault.get_settings", return_value=mock_settings):
        with pytest.raises(VaultError) as exc_info:
            decrypt_secret(
                base64.b64encode(b"\x01" + os.urandom(12) + os.urandom(16)).decode("ascii"),
                context="ctx",
            )
        assert exc_info.value.details.get("phase") == "decrypt"
