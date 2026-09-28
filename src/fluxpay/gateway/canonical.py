"""=============================================================================
FREEZE WARNING: PROTOCOL SPECIFICATION - DO NOT MODIFY
=============================================================================
FLXP1 Canonical Request Signing Scheme Protocol Specification.

THE ENCODING IS THE CONTRACT.
Changing any input field, field order, separator, casing rule, or hashing
primitive permanently breaks signature compatibility between the FluxPay
gateway and all client SDKs (Python, Node/TypeScript, Go).
This specification is FROZEN from inception. Future alterations require
a scheme version bump (e.g. FLXP2), never an in-place modification.

CANONICAL ENCODING SPECIFICATION (Byte-exact):
----------------------------------------------
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

=============================================================================
PROTOCOL DESIGN ESSAYS (WHY THE SCHEME IS BUILT THIS WAY)
=============================================================================

1. WHY RAW-BODY HASHING (Byte-Exact vs. Parsed JSON):
-----------------------------------------------------
JSON re-serialization is inherently non-deterministic across languages,
platforms, and serializer implementations. Key ordering (e.g. {"a":1,"b":2}
vs {"b":2,"a":1}), whitespace variations (compact vs formatted), floating-point
representation, and Unicode character escaping (e.g. \\u00e9 vs é) differ
widely between Python (json/orjson), Node.js (V8 JSON.stringify), Go, and Rust.
A request-signing scheme that parses JSON and then attempts to re-serialize it
creates extremely fragile signatures that break on serializer upgrades or minor
client environment differences.

Raw bytes received on the wire are the ONLY shared, unadulterated ground truth
between client and server. The client signs the exact byte sequence it puts into
the network socket; the server verifies the exact byte sequence read from the
socket. For requests with no payload (such as GET requests or empty-body POSTs),
the body is the empty byte sequence b"", whose SHA-256 digest is the known
constant e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.

2. WHY QUERY STRINGS ARE FORBIDDEN (Scheme Deletion vs. Canonicalization):
-------------------------------------------------------------------------
Query-string canonicalization is one of the most notorious bug farms in API
security. Handling parameter sorting, percent-encoding vs plus-encoding,
duplicate keys (e.g. ?tag=a&tag=b), nested array syntaxes (?ids[]=1), and
casing rules across diverse web servers and gateways has historically yielded
countless authentication bypasses and canonicalization mismatches.

The FluxPay agent gateway API (Blueprint §0) requires exactly 3 endpoints,
none of which require query parameters. Rather than specifying an intricate,
error-prone query canonicalization grammar that every language SDK would have to
reproduce byte-for-byte, the FLXP1 scheme deletes the problem entirely by
strictly forbidding query strings on signed routes.
Signed paths must match ^/[A-Za-z0-9._~/-]*$; any '?' character is rejected
outright by canonical_bytes with ValueError, and HTTP middleware (Task 21)
rejects any signed route request containing a query string.
FREEZE NOTE ON FLXP2: If future gateway endpoints ever require query strings,
that capability will be introduced via an explicit protocol version bump (FLXP2)
with formal query canonicalization rules, NEVER by a silent edit to FLXP1.

3. WHY AGENT_ID IS EXCLUDED FROM CANONICAL BYTES:
-------------------------------------------------
The Authorization header supplies agent_id (Authorization: FLXP1 <agent_id>:<sig>).
However, agent_id is NOT included in the canonical signed bytes.
Reviewers frequently ask why agent_id is omitted from the payload.
The reason is cryptographic: agent_id functions exclusively as a routing key
for the gateway to locate the corresponding secret key material in storage/vault.
If an attacker tampers with agent_id in transit, the gateway retrieves a
different secret (or fails lookup entirely); the HMAC-SHA256 verification then
fails immediately because the HMAC was computed with a different key.
Binding agent_id into the canonical byte sequence would add payload overhead
and provide a false sense of security, whereas the cryptographic binding is
already guaranteed by the symmetric key itself.

4. SEPARATOR RATIONALE (0x0A Newline):
--------------------------------------
0x0A (ASCII LF, newline) is chosen as the canonical field delimiter.
While Task 12 ledger fingerprinting uses 0x1F (ASCII Unit Separator), 0x0A is
selected here because every field in the FLXP1 canonical payload is guaranteed
to be NEWLINE-FREE by strict construction (path regex, method token, timestamp
decimal, nonce charset, sha256 hex). Furthermore, newline separators match
established HMAC canonicalization traditions familiar to systems engineers
(such as AWS SigV4 and GCS HMAC authentication).

5. CANONICAL-INJECTION GUARDS:
------------------------------
In newline-delimited protocols, if an adversary could smuggle a newline (\\n)
into any field (such as the HTTP path), they could forge additional canonical
lines or shift field positions (e.g. path "/x\\nFLXP1..."). Strict regex
whitelisting and explicit newline checks eliminate this entire vulnerability
class before hashing occurs.

6. FORMAT VS FRESHNESS SPLIT:
-----------------------------
This module validates structural format only (e.g. timestamp must be a 13-digit
decimal string). Freshness window checking (e.g. verifying that the timestamp
is within ±30s of gateway wall-clock time) is enforced by HTTP middleware
(Task 21) using runtime configuration. Keeping canonical.py clock-free
guarantees that this module is 100% deterministic, testable without mocking time,
and verifiable against timeless Known Answer Test vectors.

7. STRICT AUTHENTICATION HEADER PARSING:
----------------------------------------
Grammar is strictly "FLXP1 <agent_id>:<signature_hex>". Exactly one single
space is required between scheme and credentials. No multiple spaces, tabs,
or trailing whitespace are permitted. Lenient parsing in authentication headers
causes proxy/server interpretation discrepancies and parameter-confusion bugs.
On parse failure, ValueError is raised naming the defect class without echoing
the input string, adhering to strict log-injection hygiene.

8. ADVERSARIAL VERIFICATION TOTALITY:
-------------------------------------
The verify() function is total across all adversary-controlled inputs.
Malformed signatures (wrong length, non-hex, uppercase, empty, or non-string)
return False without raising exceptions. Comparison uses hmac.compare_digest
to eliminate timing side-channels.

9. SECRET MATERIAL TYPE SAFETY (TypeError on str):
--------------------------------------------------
Python str objects are immutable and cannot be safely zeroized or wiped in RAM.
Accepting str secrets encourages poor key custody. To enforce integration with
wipeable memory buffers (Task 7 SecretBytes / bytearray), passing a str secret
immediately raises TypeError.
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

# Header name constants consumed by Task 21 HTTP middleware
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
    """Export frozen test vectors for cross-language SDK contract verification.

    SDK test suites in Python (Task 57) import this function directly.
    TypeScript/Node SDK (Task 60) copies these hardcoded vectors verbatim.
    """
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

    WHY FORMAT ONLY (FORMAT vs FRESHNESS SPLIT):
    This module enforces structural syntax only. Freshness window verification
    (e.g. ±30s drift against gateway wall-clock time) is enforced in HTTP middleware
    (Task 21) using configurable runtime settings. Keeping canonical.py clock-free
    ensures 100% deterministic unit tests and enables timeless KAT verification.

    13-DIGIT BOUND:
    13 digits of milliseconds spans from 1000000000000 (Sun Sep 09 2001 01:46:40 UTC)
    to 9999999999999 (Sat Nov 20 2286 17:46:39 UTC). Sufficient for the next 260 years.
    """
    if not isinstance(ts, str):
        raise ValueError("timestamp: must be a string")
    if not _TIMESTAMP_REGEX.fullmatch(ts):
        raise ValueError("timestamp: must be exactly 13-digit epoch milliseconds decimal")


def validate_nonce(nonce: str) -> None:
    """Validate client-provided cryptographic nonce format.

    Enforces ^[A-Za-z0-9]{16,64}$.

    WHY:
    The nonce is incorporated directly into Redis replay-prevention keys (Task 20)
    and structured audit logs. Restricting character set to alphanumeric and bounding
    length (16 to 64 chars) eliminates memory-exhaustion vectors and log-injection
    vulnerabilities while providing at least 95 bits of entropy (at 16 chars).
    """
    if not isinstance(nonce, str):
        raise ValueError("nonce: must be a string")
    if not _NONCE_REGEX.fullmatch(nonce):
        raise ValueError("nonce: must be 16-64 alphanumeric characters [A-Za-z0-9]")


def validate_idempotency_key(key: str) -> None:
    """Validate client-provided idempotency key shape.

    Enforces ^[A-Za-z0-9-]{16,128}$.

    WHY:
    Idempotency keys are persisted in the database unique index (Task 11) and
    Valkey/Redis lock/cache keys (Task 21). Bounding length (16 to 128 characters)
    and restricting character set to alphanumeric and hyphen ([A-Za-z0-9-]) ensures
    keys are URL-safe, log-safe, index-friendly, and free of injection hazards.
    Underscores ('_') and special characters are intentionally excluded to enforce
    strict UUID-v4 or hyphenated opaque string hygiene.
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

    PUBLIC CONTRACT:
    Published to provide auditors, regulators, and SDK test suites the right
    to independently reconstruct exact hashed bytes from documented fields.
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
        secret: Raw key material. Must be bytes-like (bytes, bytearray, or SecretBytes).
                Strings are strictly rejected with TypeError to prevent unwipeable RAM residency.
        method: HTTP method (e.g. 'POST', 'GET'). Case-insensitive, canonicalized to uppercase.
        path: Absolute request path starting with '/' and matching ^/[A-Za-z0-9._~/-]*$.
        timestamp: 13-digit decimal epoch milliseconds string.
        nonce: 16-64 character alphanumeric client nonce.
        body: Raw request body bytes as received on the wire.

    Returns:
        64-character lowercase hex HMAC-SHA256 signature.

    Raises:
        TypeError: If secret is a string or non-bytes-like object.
        ValueError: If any input field violates canonical structural invariants.
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

    KEY MATERIAL SAFETY:
    Passing a str secret raises TypeError immediately to fail loud on caller/programmer error.
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

    STRICT GRAMMAR RULE:
    Requires exactly one ASCII space between scheme and credentials. No multiple
    spaces, tabs, or trailing whitespace are tolerated. Leniency in authentication
    header parsing is the root cause of proxy/origin parameter-confusion vulnerabilities.

    LOG-INJECTION HYGIENE:
    On failure, raises ValueError naming the defect class (scheme, whitespace,
    colon, agent_id, or signature). The malformed input string is NEVER echoed
    in the exception message to prevent log injection.

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
