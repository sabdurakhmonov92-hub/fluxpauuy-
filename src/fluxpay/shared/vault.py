"""AES-256-GCM Envelope Encryption and RAM Zeroization Vault for FluxPay.

Envelope Format (Frozen byte-exact specification):
    encrypted_b64 = base64( VERSION_BYTE || NONCE || CIPHERTEXT||TAG )
    - VERSION_BYTE: b"\\x01" (1 byte)
      Specifies the cipher scheme (AES-256-GCM) and envelope layout.
      Key rotation and algorithm upgrades become possible WITHOUT re-encrypting history:
      the version byte tells the decryptor which cryptographic scheme applies.
      Rotation mapping (key_id -> key material) is Phase 2; this envelope format
      is forward-compatible and explicitly supports it from day one.
    - NONCE: 12 random bytes (96 bits) generated via os.urandom.
      WHY 12 bytes / 96 bits: NIST SP 800-38D §5.2.1.1 recommends 96-bit nonces for GCM
      because they avoid the additional GHASH step required for non-96-bit nonces.
      GCM nonce reuse under a single key is catastrophic: it results in two-time-pad
      plaintext XOR leakage and allows mathematical recovery of the GHASH authenticator key.
      Under NIST guidelines, with random 96-bit nonces, the maximum safe invocation count
      is 2^32 messages per key to keep collision probability below 2^-32.
      Our volume (millions of agent records) is orders of magnitude below this 2^32 bound,
      making random 96-bit nonces safe and auditable.
    - CIPHERTEXT||TAG: AES-256-GCM output (variable-length ciphertext + 16-byte authentication tag).
      Produced directly by cryptography.hazmat.primitives.ciphers.aead.AESGCM.

AAD (Additional Authenticated Data) Context Binding:
    - Context string is encoded as byte-exact UTF-8 and passed to AESGCM as associated data.
    - PURPOSE: Prevents ciphertext-swap attacks. Without AAD, an attacker with database
      write access could copy an encrypted secret from record A to record B; both would
      decrypt successfully under the same master key, but assign the secret to the wrong record.
      With AAD bound to e.g. "agent_secret:{agent_external_id}", moving ciphertext between
      records causes GCM authentication verification to fail immediately.
    - CONTRACT: Callers MUST pass a stable, byte-exact context string. Context formats
      are frozen per record type. Changing the context format in the future breaks decryption
      of existing records (identical discipline to ledger hashchain field order).
      Context strings are never trimmed, normalized, or magically transformed.

Limits of RAM hygiene in CPython (Audit-facing documentation):
    (1) Immutable bytes/str copies created internally by Python (e.g. during str.encode,
        base64 decoding, or C-level OpenSSL allocations) cannot be reliably zeroized in place.
        We minimize their lifetime by converting immediately into mutable containers (SecretBytes)
        and allowing temporary references to drop out of scope for immediate garbage collection.
    (2) Swapped-out memory is outside application control. If the operating system pages
        process memory to swap disk, plaintext secrets may persist on physical storage.
        Production deployments must enforce encrypted swap or disable swap entirely via
        systemd unit configuration `MemorySwapMax=0` (Task 65 will enforce this).
    (3) Core dumps generated during unhandled process crashes can exfiltrate process memory
        containing sensitive keys. Production environments must disable core dumps via
        systemd `LimitCORE=0` and Linux sysctl `fs.suid_dumpable=0` (enforced in Task 65).

Module Silence Policy:
    Crypto modules stay strictly silent: silence cannot leak. This module does NOT import
    or use `logging` or `print()`. A log line in a cryptographic custody path is an
    inherent exfiltration vector. While sink-level redaction exists in FluxPay, complete
    absence of logging in cryptographic routines is an absolute guarantee that no key
    material or ciphertext fragments can ever be logged.
"""

import base64
import os
from typing import Final

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from fluxpay.config import get_settings
from fluxpay.shared.errors import VaultError

__all__ = [
    "SecretBytes",
    "decrypt_secret",
    "encrypt_secret",
    "reset_vault_cache",
    "wipe",
]

# Envelope format version 1: AES-256-GCM with 96-bit random nonce
VERSION_BYTE: Final[bytes] = b"\x01"
NONCE_BYTES_LEN: Final[int] = 12
TAG_BYTES_LEN: Final[int] = 16
MIN_ENVELOPE_RAW_LEN: Final[int] = 1 + NONCE_BYTES_LEN + TAG_BYTES_LEN  # 29 bytes


class SecretBytes(bytearray):
    """Wipeable bytearray container for sensitive secret data in RAM.

    Inherits from bytearray to allow in-place zeroization via slice assignment.
    Provides `.wipe()` for explicit cleanup and a best-effort `__del__` destructor.

    RAM Hygiene Caveat:
    `__del__` timing is NOT guaranteed by CPython (e.g. during interpreter shutdown,
    uncollected circular references, or deferred GC runs). It serves exclusively as
    defense-in-depth. Explicit invocation of `.wipe()` or `wipe(buf)` by the caller
    remains a mandatory operational discipline at all call sites.
    """

    def wipe(self) -> None:
        """Zero-fill the secret buffer in place."""
        wipe(self)

    def __del__(self) -> None:
        """Best-effort zeroization upon garbage collection.

        Destructors in Python must never raise exceptions into caller or interpreter space.
        """
        try:
            self.wipe()
        except Exception:  # noqa: S110
            # Destructors must never raise exceptions into caller or interpreter space.
            pass


def wipe(buf: bytearray | SecretBytes) -> None:
    """Zero-fill a mutable bytearray buffer in place.

    Accepts ONLY bytearray-family objects. Immutable `bytes` or `str` cannot be
    zeroized in Python; passing them raises a TypeError immediately to prevent
    a false sense of security.

    Args:
        buf: The mutable bytearray or SecretBytes instance to zero-fill.

    Raises:
        TypeError: If buf is not an instance of bytearray.
    """
    if not isinstance(buf, bytearray):
        raise TypeError(
            f"Cannot wipe immutable object of type '{type(buf).__name__}'. "
            "wipe() requires a mutable bytearray or SecretBytes instance."
        )
    # In-place slice assignment replaces all bytes with zeros without reallocating
    buf[:] = b"\x00" * len(buf)


# Module-level cached master key and AESGCM instance.
# Trade-off: Reloading and base64-decoding the master key per encrypt/decrypt call
# would repeatedly allocate immutable bytes and str copies in CPython memory,
# increasing the attack surface. Caching a single wipeable SecretBytes instance
# keeps key material in one controlled memory region.
# reset_vault_cache() provides the necessary hook for test isolation and Phase 2 key rotation.
_CACHED_MASTER_KEY: SecretBytes | None = None
_CACHED_AESGCM: AESGCM | None = None


def reset_vault_cache() -> None:
    """Reset and zero-fill the module-level cached master key and AESGCM cipher.

    Wipes the cached master key from RAM before releasing references.
    Mirrors the `get_settings.cache_clear()` pattern to support test isolation
    and key rotation rehearsals.
    """
    global _CACHED_MASTER_KEY, _CACHED_AESGCM
    if _CACHED_MASTER_KEY is not None:
        _CACHED_MASTER_KEY.wipe()
        _CACHED_MASTER_KEY = None
    _CACHED_AESGCM = None


def _get_aesgcm(phase: str) -> AESGCM:
    """Retrieve or initialize the cached AESGCM cipher instance.

    Loads the 32-byte master key from application settings.
    """
    global _CACHED_MASTER_KEY, _CACHED_AESGCM
    if _CACHED_AESGCM is None:
        settings = get_settings()
        try:
            raw_key = base64.b64decode(settings.vault_master_key, validate=True)
        except Exception:
            raise VaultError(
                message="Invalid vault master key: failed base64 decoding",
                details={"phase": phase},
            ) from None

        if len(raw_key) != 32:
            raise VaultError(
                message="Invalid vault master key: must decode to exactly 32 bytes",
                details={"phase": phase},
            )

        _CACHED_MASTER_KEY = SecretBytes(raw_key)
        _CACHED_AESGCM = AESGCM(bytes(_CACHED_MASTER_KEY))

    return _CACHED_AESGCM


def encrypt_secret(plaintext: str, *, context: str) -> str:
    """Encrypt a plaintext secret string using AES-256-GCM with context binding (AAD).

    Envelope Format:
        base64( VERSION_BYTE (1B) || NONCE (12B) || CIPHERTEXT||TAG (N+16B) )

    Args:
        plaintext: The secret string to encrypt (empty string "" is valid).
        context: Stable, byte-exact context string bound as AAD to prevent ciphertext swaps.

    Returns:
        Base64-encoded envelope string.

    Raises:
        TypeError: If plaintext or context is not a str.
        VaultError: If encryption fails.
    """
    if not isinstance(plaintext, str):
        raise TypeError(f"plaintext must be a str, got {type(plaintext).__name__}")
    if not isinstance(context, str):
        raise TypeError(f"context must be a str, got {type(context).__name__}")

    aesgcm = _get_aesgcm(phase="encrypt")

    # Generate fresh 96-bit nonce (NIST SP 800-38D requirement)
    nonce = os.urandom(NONCE_BYTES_LEN)
    plaintext_bytes = plaintext.encode("utf-8")
    aad = context.encode("utf-8")

    try:
        # AESGCM.encrypt appends 16-byte authentication tag to the ciphertext
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext_bytes, aad)
    except Exception:
        raise VaultError(
            message="Vault encryption failed",
            details={"phase": "encrypt"},
        ) from None

    # Construct envelope: VERSION_BYTE || NONCE || CIPHERTEXT||TAG
    envelope = VERSION_BYTE + nonce + ciphertext_and_tag
    return base64.b64encode(envelope).decode("ascii")


def decrypt_secret(encrypted_b64: str, *, context: str) -> SecretBytes:
    """Decrypt a base64-encoded vault envelope using AES-256-GCM and verify context binding.

    Args:
        encrypted_b64: Base64-encoded vault envelope string.
        context: Byte-exact context string bound as AAD during encryption.

    Returns:
        SecretBytes container holding the decrypted secret plaintext bytes.
        Callers MUST invoke `.wipe()` on the returned SecretBytes when done.

    Raises:
        TypeError: If encrypted_b64 or context is not a str.
        VaultError: If envelope decoding, version verification, or authentication fails.
            Never leaks plaintext, ciphertext, or internal exception strings.
    """
    if not isinstance(encrypted_b64, str):
        raise TypeError(f"encrypted_b64 must be a str, got {type(encrypted_b64).__name__}")
    if not isinstance(context, str):
        raise TypeError(f"context must be a str, got {type(context).__name__}")

    try:
        raw = base64.b64decode(encrypted_b64, validate=True)
    except Exception:
        raise VaultError(
            message="Invalid vault envelope: corrupted base64 encoding",
            details={"phase": "decrypt"},
        ) from None

    if len(raw) < MIN_ENVELOPE_RAW_LEN:
        raise VaultError(
            message="Invalid vault envelope: payload too short",
            details={"phase": "decrypt"},
        )

    version_byte = raw[0:1]
    if version_byte != VERSION_BYTE:
        # Report only the unrecognized version byte value; never leak envelope contents
        raise VaultError(
            message=(
                f"Unsupported vault envelope version: 0x{version_byte[0]:02x} ({version_byte!r})"
            ),
            details={"phase": "decrypt"},
        )

    nonce = raw[1 : 1 + NONCE_BYTES_LEN]
    ciphertext_and_tag = raw[1 + NONCE_BYTES_LEN :]
    aad = context.encode("utf-8")

    aesgcm = _get_aesgcm(phase="decrypt")

    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
    except Exception:
        # Cryptography InvalidTag or other decryption errors are mapped to VaultError.
        # The original exception text/tag NEVER propagates to avoid leaking ciphertext fragments.
        raise VaultError(
            message="Vault decryption failed: authentication or integrity check failed",
            details={"phase": "decrypt"},
        ) from None

    return SecretBytes(decrypted_bytes)
