"""=============================================================================
FLXP1 Canonical Request Signing Scheme — Python SDK Implementation
=============================================================================
Vendoring Law: This file is self-contained and imports Python standard library ONLY.
It contains zero internal server dependencies (no imports from fluxpay.*).

FLXP1 CANONICAL ENCODING SPECIFICATION (Byte-exact):
-----------------------------------------------------
    canonical = (
        "FLXP1"            || 0x0A ||
        METHOD_UPPER       || 0x0A ||
        PATH               || 0x0A ||
        TIMESTAMP_MS_DEC   || 0x0A ||
        NONCE              || 0x0A ||
        SHA256_HEX_LOWER(raw_body)
    )
    signature = lowercase_hex( HMAC-SHA256( agent_secret, canonical ) )

HEADERS CONTRACT:
-----------------
    Authorization: FLXP1 <agent_id>:<signature_hex>
    X-FLX-Timestamp: <epoch_ms_ascii_decimal>
    X-FLX-Nonce: <client_generated_nonce>
    X-FLX-Idempotency-Key: <opaque_client_key> (Required on POST writes; Task 21)

STOP-THE-LINE KAT NOTE:
-----------------------
The FROZEN_VECTORS defined below are the ground-truth contract between the FluxPay
server gateway and all client SDKs (Python, Node/TypeScript, Go, Rust). Any divergence
in canonical serialization, newline delimiters, hashing, or HMAC computation breaks
cross-language interoperability and is treated as a critical Sev1 defect.
=============================================================================
"""

import hashlib
import hmac
import re
from typing import Final, TypedDict

__all__ = [
    "FROZEN_VECTORS",
    "HEADER_AUTH",
    "HEADER_IDEMPOTENCY",
    "HEADER_NONCE",
    "HEADER_TIMESTAMP",
    "SCHEME",
    "SEPARATOR",
    "FrozenVector",
    "canonical_bytes",
    "get_frozen_vectors",
    "parse_authorization",
    "sha256_hex",
    "sign",
    "validate_idempotency_key",
    "validate_nonce",
    "validate_timestamp",
    "verify",
]

# Scheme protocol identifier
SCHEME: Final[str] = "FLXP1"

# Structural canonical line separator (ASCII 0x0A / newline)
SEPARATOR: Final[bytes] = b"\n"

# Header name constants
HEADER_AUTH: Final[str] = "Authorization"
HEADER_TIMESTAMP: Final[str] = "X-FLX-Timestamp"
HEADER_NONCE: Final[str] = "X-FLX-Nonce"
HEADER_IDEMPOTENCY: Final[str] = "X-FLX-Idempotency-Key"

# Pre-compiled strict validation regexes
_METHOD_REGEX: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z]+$")
_PATH_REGEX: Final[re.Pattern[str]] = re.compile(r"^/[A-Za-z0-9._~/-]*$")
_TIMESTAMP_REGEX: Final[re.Pattern[str]] = re.compile(r"^[0-9]{13}$")
_NONCE_REGEX: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9]{16,64}$")
_IDEMPOTENCY_KEY_REGEX: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9-]{16,128}$")
_UUID_REGEX: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_SIG_REGEX: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")


class FrozenVector(TypedDict):
    """Frozen Known Answer Test (KAT) vector definition for cross-language validation."""

    secret: bytes
    method: str
    path: str
    timestamp: str
    nonce: str
    body: bytes
    expected_canonical: bytes
    expected_signature: str


# =============================================================================
# FROZEN CONTRACT — DO NOT REGENERATE.
# Regeneration means the scheme changed; SDKs (Task 57/60) and the Node port
# validate against THESE vectors. A failing KAT is a protocol break.
# =============================================================================
FROZEN_VECTORS: Final[tuple[FrozenVector, ...]] = (
    # Vector 1: Empty body POST (proves empty payload hashing)
    {
        "secret": b"test-secret-key-32-bytes-long!!",
        "method": "POST",
        "path": "/v1/payments/empty",
        "timestamp": "1774472400000",
        "nonce": "abcdef0123456789",
        "body": b"",
        "expected_canonical": (
            b"FLXP1\n"
            b"POST\n"
            b"/v1/payments/empty\n"
            b"1774472400000\n"
            b"abcdef0123456789\n"
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        "expected_signature": "4f33eb63343aa8d19ac3adb785c5ee7d30e2a14bdee3bb48d23e19e90bde12c7",
    },
    # Vector 2: Typical JSON payment body (proves multi-field payload hashing)
    {
        "secret": b"test-secret-key-32-bytes-long!!",
        "method": "POST",
        "path": "/v1/payments",
        "timestamp": "1774472400000",
        "nonce": "fedcba9876543210",
        "body": (
            b'{"amount":10000,"currency":"USDC",'
            b'"recipient_id":"018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e"}'
        ),
        "expected_canonical": (
            b"FLXP1\n"
            b"POST\n"
            b"/v1/payments\n"
            b"1774472400000\n"
            b"fedcba9876543210\n"
            b"bb847548619233d487cce199b61cd1235c85925e63e5dec6108be1176fd87b52"
        ),
        "expected_signature": "3dc25e0205bba581b3acdadb09503d183bdda58a9f712594d1d3ad9f0cc5ad5d",
    },
    # Vector 3: GET request without body (proves zero-length body on read endpoint)
    {
        "secret": b"test-secret-key-32-bytes-long!!",
        "method": "GET",
        "path": "/v1/agents/me",
        "timestamp": "1774472400000",
        "nonce": "1234567890abcdef",
        "body": b"",
        "expected_canonical": (
            b"FLXP1\n"
            b"GET\n"
            b"/v1/agents/me\n"
            b"1774472400000\n"
            b"1234567890abcdef\n"
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        "expected_signature": "1564b8f509dd03b1ac17f99a9bdf6ac98c0cf564f0d305ac814c290167833f66",
    },
)


def get_frozen_vectors() -> tuple[FrozenVector, ...]:
    """Export frozen test vectors for cross-language SDK contract verification."""
    return FROZEN_VECTORS


def sha256_hex(body: bytes | bytearray) -> str:
    """Compute lowercase hex SHA-256 digest of raw request body bytes.

    BODY CONTRACT:
    The body is hashed strictly as raw bytes received on the wire.
    Never parses, canonicalizes, or re-serializes JSON payloads.
    Empty body b"" hashes to the standard SHA-256 empty digest.
    """
    if not isinstance(body, (bytes, bytearray)):
        raise ValueError("body: must be bytes-like")
    return hashlib.sha256(body).hexdigest().lower()


def validate_timestamp(ts: str) -> None:
    """Validate timestamp string format (epoch milliseconds decimal).

    Enforces ^[0-9]{13}$.
    """
    if not isinstance(ts, str):
        raise ValueError("timestamp: must be a string")
    if not _TIMESTAMP_REGEX.fullmatch(ts):
        raise ValueError("timestamp: must be exactly 13-digit epoch milliseconds decimal")


def validate_nonce(nonce: str) -> None:
    """Validate client-provided cryptographic nonce format.

    Enforces ^[A-Za-z0-9]{16,64}$.
    """
    if not isinstance(nonce, str):
        raise ValueError("nonce: must be a string")
    if not _NONCE_REGEX.fullmatch(nonce):
        raise ValueError("nonce: must be 16-64 alphanumeric characters [A-Za-z0-9]")


def validate_idempotency_key(key: str) -> None:
    """Validate client-provided idempotency key shape.

    Enforces ^[A-Za-z0-9-]{16,128}$.
    """
    if not isinstance(key, str):
        raise ValueError("idempotency_key: must be a string")
    if not _IDEMPOTENCY_KEY_REGEX.fullmatch(key):
        raise ValueError("idempotency_key: must be 16-128 characters matching [A-Za-z0-9-]")


def canonical_bytes(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    """Construct byte-exact canonical payload for signature computation.

    Format (newline-separated ASCII):
        canonical = "FLXP1"            || 0x0A
                  || METHOD_UPPER      || 0x0A
                  || PATH              || 0x0A
                  || TIMESTAMP_MS_DEC  || 0x0A
                  || NONCE             || 0x0A
                  || SHA256_HEX_LOWER(raw_body)
    """
    if not isinstance(method, str) or not _METHOD_REGEX.fullmatch(method):
        raise ValueError("method: must be valid alphabetic HTTP method token")
    method_upper = method.upper()

    if not isinstance(path, str):
        raise ValueError("path: must be a string")
    if "\n" in path:
        raise ValueError("path: must not contain newline")
    if "?" in path:
        raise ValueError("path: query strings forbidden; signed path must not contain '?'")
    if not path.startswith("/"):
        raise ValueError(f"path: must start with '/', got {path!r}")
    if not _PATH_REGEX.fullmatch(path):
        raise ValueError(f"path: invalid characters in path, got {path!r}")

    validate_timestamp(timestamp)
    validate_nonce(nonce)

    body_digest = sha256_hex(body)

    return SEPARATOR.join(
        [
            SCHEME.encode("ascii"),
            method_upper.encode("ascii"),
            path.encode("ascii"),
            timestamp.encode("ascii"),
            nonce.encode("ascii"),
            body_digest.encode("ascii"),
        ]
    )


def sign(
    secret: bytes | bytearray,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> str:
    """Compute HMAC-SHA256 signature for canonical request payload.

    Args:
        secret: Raw key material. Must be bytes-like (bytes or bytearray).
        method: HTTP method (e.g. 'POST', 'GET'). Case-insensitive, canonicalized to uppercase.
        path: Absolute request path starting with '/' and matching ^/[A-Za-z0-9._~/-]*$.
        timestamp: 13-digit decimal epoch milliseconds string.
        nonce: 16-64 character alphanumeric client nonce.
        body: Raw request body bytes.

    Returns:
        64-character lowercase hex HMAC-SHA256 signature.
    """
    if isinstance(secret, str):  # type: ignore[unreachable]
        raise TypeError("secret: strings are forbidden; key material must be bytes-like")
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError(f"secret: key material must be bytes-like, got {type(secret).__name__}")

    raw_canonical = canonical_bytes(
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    return hmac.new(secret, raw_canonical, hashlib.sha256).hexdigest().lower()


def verify(
    secret: bytes | bytearray,
    provided_sig: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bool:
    """Verify incoming request signature against recomputed HMAC-SHA256.

    ADVERSARIAL TOTALITY RULE:
    Malformed signatures (invalid length, non-hex, uppercase, empty, non-string)
    or malformed canonical fields from the client return False immediately.
    They NEVER raise exceptions into the caller.

    TIMING SAFETY:
    Comparison uses hmac.compare_digest to eliminate timing side channels.
    """
    if isinstance(secret, str):  # type: ignore[unreachable]
        raise TypeError("secret: strings are forbidden; key material must be bytes-like")
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError(f"secret: key material must be bytes-like, got {type(secret).__name__}")

    if not isinstance(provided_sig, str) or not _SIG_REGEX.fullmatch(provided_sig):
        return False

    try:
        expected_sig = sign(
            secret=secret,
            method=method,
            path=path,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
    except ValueError:
        return False

    return hmac.compare_digest(expected_sig, provided_sig)


def parse_authorization(header: str | None) -> tuple[str, str]:
    """Parse and validate incoming HTTP Authorization header.

    Expected Grammar:
        "FLXP1 <agent_id>:<signature_hex>"

    Returns:
        tuple[str, str]: (canonical_lowercase_uuid_agent_id, 64_hex_lowercase_signature)

    Raises:
        ValueError: If header is missing, empty, or violates strict grammar.
    """
    if header is None or not isinstance(header, str) or not header:
        raise ValueError("authorization header: missing or empty")

    scheme, sep, credentials = header.partition(" ")
    if sep != " ":
        raise ValueError("authorization header scheme: missing separator or credentials")
    if scheme != SCHEME:
        raise ValueError(f"authorization header scheme: must be '{SCHEME}'")
    if credentials.startswith(" "):
        raise ValueError("authorization header: unexpected whitespace after scheme")

    agent_id, colon, sig = credentials.partition(":")
    if colon != ":":
        raise ValueError("authorization header credentials: missing colon separator")

    if not _UUID_REGEX.fullmatch(agent_id):
        raise ValueError(
            "authorization header agent_id: must be canonical lowercase hyphenated UUID"
        )

    if not _SIG_REGEX.fullmatch(sig):
        raise ValueError("authorization header signature: must be 64-character lowercase hex")

    return agent_id, sig
