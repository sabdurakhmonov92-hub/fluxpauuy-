"""Contract-lock verification suite for FluxPay Gateway Canonical Signing Scheme (FLXP1).

Pure unit test suite: zero I/O, zero network, zero clock access, zero randomness.
Validates protocol specification, injection defenses, Known Answer Tests (KAT),
and cross-language export contracts.
"""

import hashlib
import inspect
from typing import Final

import pytest

from fluxpay.gateway import canonical
from fluxpay.gateway.canonical import (
    FROZEN_VECTORS,
    HEADER_AUTH,
    HEADER_IDEMPOTENCY,
    HEADER_NONCE,
    HEADER_TIMESTAMP,
    SCHEME,
    SEPARATOR,
    canonical_bytes,
    get_frozen_vectors,
    parse_authorization,
    sha256_hex,
    sign,
    validate_idempotency_key,
    validate_nonce,
    validate_timestamp,
    verify,
)
from fluxpay.shared.vault import SecretBytes

pytestmark = pytest.mark.unit

_TEST_SECRET: Final[bytes] = b"test-secret-key-32-bytes-long!!"
_VALID_UUID: Final[str] = "018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e"
_VALID_TS: Final[str] = "1774472400000"
_VALID_NONCE: Final[str] = "abcdef0123456789"
_VALID_PATH: Final[str] = "/v1/payments"
_VALID_METHOD: Final[str] = "POST"
_VALID_BODY: Final[bytes] = b'{"amount":10000,"currency":"USDC"}'


# =============================================================================
# 1. KNOWN ANSWER TESTS (KAT) — FROZEN CONTRACT ENFORCEMENT
# =============================================================================


def test_frozen_vectors_kat_bidirectional() -> None:
    """Verify all frozen vectors against sign() and verify().

    FROZEN CONTRACT:
    A failing KAT means the wire signing format has drifted. This breaks
    all client SDKs and is a STOP-THE-LINE event.
    """
    vectors = get_frozen_vectors()
    assert len(vectors) == 3
    assert vectors is FROZEN_VECTORS

    for i, vec in enumerate(vectors):
        # 1. Canonical payload reconstruction against frozen canonical bytes
        actual_canonical = canonical_bytes(
            method=vec["method"],
            path=vec["path"],
            timestamp=vec["timestamp"],
            nonce=vec["nonce"],
            body=vec["body"],
        )
        assert actual_canonical == vec["expected_canonical"], (
            f"Vector {i}: canonical bytes mismatch"
        )

        # 2. Signature computation against frozen expected hex
        actual_sig = sign(
            secret=vec["secret"],
            method=vec["method"],
            path=vec["path"],
            timestamp=vec["timestamp"],
            nonce=vec["nonce"],
            body=vec["body"],
        )
        assert actual_sig == vec["expected_signature"], (
            f"Vector {i}: computed signature does not match frozen expected"
        )
        assert len(actual_sig) == 64
        assert actual_sig == actual_sig.lower()

        # 3. Verification succeeds with valid signature
        is_valid = verify(
            secret=vec["secret"],
            provided_sig=vec["expected_signature"],
            method=vec["method"],
            path=vec["path"],
            timestamp=vec["timestamp"],
            nonce=vec["nonce"],
            body=vec["body"],
        )
        assert is_valid is True, f"Vector {i}: verify() returned False for valid signature"


def test_empty_body_get_and_post_kat() -> None:
    """Prove empty-body payload hashes correctly on both POST and GET routes."""
    empty_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_hex(b"") == empty_digest

    # Vector 0 (empty POST) and Vector 2 (empty GET) must embed the empty body digest
    v_post_empty = FROZEN_VECTORS[0]
    v_get_empty = FROZEN_VECTORS[2]
    assert v_post_empty["body"] == b""
    assert v_get_empty["body"] == b""
    assert empty_digest.encode("ascii") in v_post_empty["expected_canonical"]
    assert empty_digest.encode("ascii") in v_get_empty["expected_canonical"]


# =============================================================================
# 2. INDEPENDENT CANONICAL RECONSTRUCTION (SPEC VS IMPLEMENTATION)
# =============================================================================


def test_independent_canonical_reconstruction() -> None:
    """Verify canonical_bytes matches hand-built b'\\n'.join of documented fields.

    Auditors and SDK authors must be able to independently reconstruct canonical
    bytes directly from the specification formula without proprietary code.
    """
    method = "POST"
    path = "/v1/transfers/agent"
    timestamp = "1774472400000"
    nonce = "0123456789abcdef"
    body = b'{"recipient":"agent_42","amount":500}'

    expected_hand_built = b"\n".join(
        [
            b"FLXP1",
            b"POST",
            b"/v1/transfers/agent",
            b"1774472400000",
            b"0123456789abcdef",
            hashlib.sha256(body).hexdigest().encode("ascii"),
        ]
    )

    actual_canonical = canonical_bytes(
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    assert actual_canonical == expected_hand_built


# =============================================================================
# 3. INPUT SENSITIVITY TABLE (EVERY FIELD PERTURBATION ALTERS SIGNATURE)
# =============================================================================


def test_input_sensitivity_table() -> None:
    """Prove that perturbing any single field produces an entirely different signature."""
    base_sig = sign(
        secret=_TEST_SECRET,
        method=_VALID_METHOD,
        path=_VALID_PATH,
        timestamp=_VALID_TS,
        nonce=_VALID_NONCE,
        body=_VALID_BODY,
    )

    # 1. Perturb path
    sig_diff_path = sign(
        secret=_TEST_SECRET,
        method=_VALID_METHOD,
        path="/v1/payments2",
        timestamp=_VALID_TS,
        nonce=_VALID_NONCE,
        body=_VALID_BODY,
    )
    assert sig_diff_path != base_sig

    # 2. Perturb timestamp
    sig_diff_ts = sign(
        secret=_TEST_SECRET,
        method=_VALID_METHOD,
        path=_VALID_PATH,
        timestamp="1774472400001",
        nonce=_VALID_NONCE,
        body=_VALID_BODY,
    )
    assert sig_diff_ts != base_sig

    # 3. Perturb nonce
    sig_diff_nonce = sign(
        secret=_TEST_SECRET,
        method=_VALID_METHOD,
        path=_VALID_PATH,
        timestamp=_VALID_TS,
        nonce="abcdef0123456780",
        body=_VALID_BODY,
    )
    assert sig_diff_nonce != base_sig

    # 4. Perturb body (single byte alteration)
    sig_diff_body = sign(
        secret=_TEST_SECRET,
        method=_VALID_METHOD,
        path=_VALID_PATH,
        timestamp=_VALID_TS,
        nonce=_VALID_NONCE,
        body=b'{"amount":10001,"currency":"USDC"}',
    )
    assert sig_diff_body != base_sig

    # 5. Perturb secret key
    sig_diff_key = sign(
        secret=b"different-secret-32-bytes-long!!",
        method=_VALID_METHOD,
        path=_VALID_PATH,
        timestamp=_VALID_TS,
        nonce=_VALID_NONCE,
        body=_VALID_BODY,
    )
    assert sig_diff_key != base_sig

    # 6. Perturb HTTP method
    sig_diff_method = sign(
        secret=_TEST_SECRET,
        method="PUT",
        path=_VALID_PATH,
        timestamp=_VALID_TS,
        nonce=_VALID_NONCE,
        body=_VALID_BODY,
    )
    assert sig_diff_method != base_sig


def test_method_case_normalization() -> None:
    """Prove that method casing is normalized to uppercase deterministically."""
    sig_upper = sign(
        secret=_TEST_SECRET,
        method="POST",
        path=_VALID_PATH,
        timestamp=_VALID_TS,
        nonce=_VALID_NONCE,
        body=_VALID_BODY,
    )
    sig_lower = sign(
        secret=_TEST_SECRET,
        method="post",
        path=_VALID_PATH,
        timestamp=_VALID_TS,
        nonce=_VALID_NONCE,
        body=_VALID_BODY,
    )
    sig_mixed = sign(
        secret=_TEST_SECRET,
        method="PoSt",
        path=_VALID_PATH,
        timestamp=_VALID_TS,
        nonce=_VALID_NONCE,
        body=_VALID_BODY,
    )
    assert sig_upper == sig_lower == sig_mixed


# =============================================================================
# 4. VERIFY TOTALITY AND TIMING-SAFE META-TEST
# =============================================================================


def test_verify_totality_malformed_signatures() -> None:
    """Adversarial totality: malformed signatures must return False and never raise."""
    malformed_signatures: list[object] = [
        "4f33eb63343aa8d19ac3adb785c5ee7d30e2a14bdee3bb48d23e19e90bde12c",  # 63 chars
        "4f33eb63343aa8d19ac3adb785c5ee7d30e2a14bdee3bb48d23e19e90bde12c78",  # 65 chars
        "4F33EB63343AA8D19AC3ADB785C5EE7D30E2A14BDEE3BB48D23E19E90BDE12C7",  # uppercase
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",  # non-hex
        "",  # empty
        "   ",  # whitespace
        None,
        123456,
    ]

    for bad_sig in malformed_signatures:
        result = verify(
            secret=_TEST_SECRET,
            provided_sig=bad_sig,  # type: ignore[arg-type]
            method=_VALID_METHOD,
            path=_VALID_PATH,
            timestamp=_VALID_TS,
            nonce=_VALID_NONCE,
            body=_VALID_BODY,
        )
        assert result is False


def test_verify_totality_invalid_canonical_fields() -> None:
    """Verify returns False rather than raising if client canonical fields are malformed."""
    valid_sig = sign(_TEST_SECRET, _VALID_METHOD, _VALID_PATH, _VALID_TS, _VALID_NONCE, _VALID_BODY)

    # Invalid path
    assert (
        verify(
            secret=_TEST_SECRET,
            provided_sig=valid_sig,
            method=_VALID_METHOD,
            path="x",
            timestamp=_VALID_TS,
            nonce=_VALID_NONCE,
            body=_VALID_BODY,
        )
        is False
    )

    # Invalid timestamp
    assert (
        verify(
            secret=_TEST_SECRET,
            provided_sig=valid_sig,
            method=_VALID_METHOD,
            path=_VALID_PATH,
            timestamp="123",
            nonce=_VALID_NONCE,
            body=_VALID_BODY,
        )
        is False
    )

    # Invalid nonce
    assert (
        verify(
            secret=_TEST_SECRET,
            provided_sig=valid_sig,
            method=_VALID_METHOD,
            path=_VALID_PATH,
            timestamp=_VALID_TS,
            nonce="short",
            body=_VALID_BODY,
        )
        is False
    )


def test_verify_valid_signature_mismatch_returns_false() -> None:
    """Valid 64-hex signature under different key returns False safely."""
    wrong_sig = "0000000000000000000000000000000000000000000000000000000000000000"
    assert (
        verify(
            secret=_TEST_SECRET,
            provided_sig=wrong_sig,
            method=_VALID_METHOD,
            path=_VALID_PATH,
            timestamp=_VALID_TS,
            nonce=_VALID_NONCE,
            body=_VALID_BODY,
        )
        is False
    )


def test_verify_meta_timing_safe_comparator() -> None:
    """Meta-test: inspect source of verify() to guarantee hmac.compare_digest is used."""
    source = inspect.getsource(canonical.verify)
    assert "compare_digest" in source, "verify() MUST use hmac.compare_digest for timing safety"


# =============================================================================
# 5. CANONICAL INJECTION & FIELD GUARDS
# =============================================================================


def test_guards_path() -> None:
    """Validate all path canonicalization and injection guards."""
    # 1. No leading slash
    with pytest.raises(ValueError, match="path: must start with '/'"):
        canonical_bytes("GET", "v1/payments", _VALID_TS, _VALID_NONCE, b"")

    with pytest.raises(ValueError, match="path: must start with '/'"):
        canonical_bytes("GET", "x", _VALID_TS, _VALID_NONCE, b"")

    # 2. Smuggled newline
    with pytest.raises(ValueError, match="path: must not contain newline"):
        canonical_bytes("GET", "/v1/payments\nFLXP1", _VALID_TS, _VALID_NONCE, b"")

    # 3. Query string attempt (forbidden by design)
    with pytest.raises(ValueError, match="path: query strings forbidden"):
        canonical_bytes("GET", "/v1/payments?page=1", _VALID_TS, _VALID_NONCE, b"")

    # 4. Spaces in path
    with pytest.raises(ValueError, match="path: invalid characters in path"):
        canonical_bytes("GET", "/v1/pay ments", _VALID_TS, _VALID_NONCE, b"")

    # 5. Non-string path
    with pytest.raises(ValueError, match="path: must be a string"):
        canonical_bytes("GET", 12345, _VALID_TS, _VALID_NONCE, b"")  # type: ignore[arg-type]


def test_guards_method() -> None:
    """Validate HTTP method tokens."""
    with pytest.raises(ValueError, match="method: must be valid alphabetic HTTP method token"):
        canonical_bytes("POST1", _VALID_PATH, _VALID_TS, _VALID_NONCE, b"")

    with pytest.raises(ValueError, match="method: must be valid alphabetic HTTP method token"):
        canonical_bytes("POST\nGET", _VALID_PATH, _VALID_TS, _VALID_NONCE, b"")

    with pytest.raises(ValueError, match="method: must be valid alphabetic HTTP method token"):
        canonical_bytes("", _VALID_PATH, _VALID_TS, _VALID_NONCE, b"")

    with pytest.raises(ValueError, match="method: must be valid alphabetic HTTP method token"):
        canonical_bytes(123, _VALID_PATH, _VALID_TS, _VALID_NONCE, b"")  # type: ignore[arg-type]


def test_guards_timestamp() -> None:
    """Validate 13-digit epoch milliseconds format."""
    # Valid
    validate_timestamp("1774472400000")

    # 12 digits
    with pytest.raises(ValueError, match="timestamp: must be exactly 13-digit"):
        validate_timestamp("177447240000")

    # 14 digits
    with pytest.raises(ValueError, match="timestamp: must be exactly 13-digit"):
        validate_timestamp("17744724000000")

    # Non-digit chars
    with pytest.raises(ValueError, match="timestamp: must be exactly 13-digit"):
        validate_timestamp("177447240000a")

    # Empty
    with pytest.raises(ValueError, match="timestamp: must be exactly 13-digit"):
        validate_timestamp("")

    # Non-string
    with pytest.raises(ValueError, match="timestamp: must be a string"):
        validate_timestamp(1774472400000)  # type: ignore[arg-type]


def test_guards_nonce() -> None:
    """Validate 16-64 character alphanumeric nonce."""
    # Valid bounds
    validate_nonce("a" * 16)
    validate_nonce("a" * 64)
    validate_nonce("AbCdEf0123456789")

    # Too short (15 chars)
    with pytest.raises(ValueError, match="nonce: must be 16-64 alphanumeric"):
        validate_nonce("a" * 15)

    # Too long (65 chars)
    with pytest.raises(ValueError, match="nonce: must be 16-64 alphanumeric"):
        validate_nonce("a" * 65)

    # Non-alphanumeric (hyphen, underscore, space)
    with pytest.raises(ValueError, match="nonce: must be 16-64 alphanumeric"):
        validate_nonce("ab-cd12345678901")

    with pytest.raises(ValueError, match="nonce: must be 16-64 alphanumeric"):
        validate_nonce("ab_cd12345678901")

    with pytest.raises(ValueError, match="nonce: must be 16-64 alphanumeric"):
        validate_nonce("")

    # Non-string
    with pytest.raises(ValueError, match="nonce: must be a string"):
        validate_nonce(1234567890123456)  # type: ignore[arg-type]


def test_guards_idempotency_key() -> None:
    """Validate 16-128 character [A-Za-z0-9-] idempotency key."""
    # Valid bounds
    validate_idempotency_key("a" * 16)
    validate_idempotency_key("a" * 128)
    validate_idempotency_key("018f2d5a-8b1e-7b2c-9d3e-4f5a6b7c8d9e")

    # Too short (15 chars)
    with pytest.raises(ValueError, match="idempotency_key: must be 16-128"):
        validate_idempotency_key("a" * 15)

    # Too long (129 chars)
    with pytest.raises(ValueError, match="idempotency_key: must be 16-128"):
        validate_idempotency_key("a" * 129)

    # Underscore is explicitly forbidden (enforces UUID/hyphenated hygiene)
    with pytest.raises(ValueError, match="idempotency_key: must be 16-128"):
        validate_idempotency_key("valid-prefix-16_key")

    with pytest.raises(ValueError, match="idempotency_key: must be 16-128"):
        validate_idempotency_key("")

    # Non-string
    with pytest.raises(ValueError, match="idempotency_key: must be a string"):
        validate_idempotency_key(1234567890123456)  # type: ignore[arg-type]


def test_guards_sha256_hex() -> None:
    """Validate sha256_hex input types."""
    assert sha256_hex(b"hello") == hashlib.sha256(b"hello").hexdigest()
    assert sha256_hex(bytearray(b"hello")) == hashlib.sha256(b"hello").hexdigest()

    with pytest.raises(ValueError, match="body: must be bytes-like"):
        sha256_hex("string-body")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="body: must be bytes-like"):
        sha256_hex(None)  # type: ignore[arg-type]


# =============================================================================
# 6. PARSE_AUTHORIZATION MATRIX AND LOG-INJECTION HYGIENE
# =============================================================================


def test_parse_authorization_valid() -> None:
    """Valid authorization header parses successfully into (agent_id, signature)."""
    valid_sig = "4f33eb63343aa8d19ac3adb785c5ee7d30e2a14bdee3bb48d23e19e90bde12c7"
    header = f"FLXP1 {_VALID_UUID}:{valid_sig}"

    agent_id, sig = parse_authorization(header)
    assert agent_id == _VALID_UUID
    assert sig == valid_sig


def test_parse_authorization_matrix_defects_and_no_echo() -> None:
    """Matrix of invalid headers; asserts defect classification and zero value echoing."""
    valid_sig = "4f33eb63343aa8d19ac3adb785c5ee7d30e2a14bdee3bb48d23e19e90bde12c7"

    test_cases: list[tuple[object, str, str]] = [
        # (header, expected_defect_in_message, malformed_payload_to_verify_not_echoed)
        (None, "missing or empty", "NONE_TOKEN"),
        ("", "missing or empty", "EMPTY_TOKEN"),
        ("Bearer some-token", "scheme", "some-token"),
        (f"flxp1 {_VALID_UUID}:{valid_sig}", "scheme", "flxp1"),
        (f" FLXP1 {_VALID_UUID}:{valid_sig}", "scheme", " FLXP1"),
        ("FLXP1", "separator or credentials", "FLXP1"),
        (f"FLXP1  {_VALID_UUID}:{valid_sig}", "unexpected whitespace", "  "),
        (f"FLXP1 {_VALID_UUID}", "missing colon", _VALID_UUID),
        (f"FLXP1 not-a-uuid-string:{valid_sig}", "agent_id", "not-a-uuid-string"),
        (
            f"FLXP1 {_VALID_UUID.upper()}:{valid_sig}",
            "agent_id",
            _VALID_UUID.upper(),
        ),
        (
            f"FLXP1 {_VALID_UUID}:{valid_sig.upper()}",
            "signature",
            valid_sig.upper(),
        ),
        (
            f"FLXP1 {_VALID_UUID}:{valid_sig[:-1]}",
            "signature",
            valid_sig[:-1],
        ),
        (
            12345,
            "missing or empty",
            "12345",
        ),
    ]

    for header, expected_defect, sensitive_fragment in test_cases:
        with pytest.raises(ValueError) as exc_info:
            parse_authorization(header)  # type: ignore[arg-type]

        err_msg = str(exc_info.value)
        # 1. Defect class is explicitly identified
        assert expected_defect in err_msg, (
            f"Expected defect '{expected_defect}' not found in message: '{err_msg}'"
        )

        # 2. Strict log-hygiene: sensitive malformed input string is NEVER echoed
        if sensitive_fragment not in ("NONE_TOKEN", "EMPTY_TOKEN", "FLXP1"):
            assert sensitive_fragment not in err_msg, (
                f"Malformed input '{sensitive_fragment}' was leaked in error message: '{err_msg}'"
            )


# =============================================================================
# 7. KEY MATERIAL HYGIENE (TYPEERROR ON STR & SECRETBYTES ACCEPTED)
# =============================================================================


def test_secret_as_str_raises_typeerror() -> None:
    """Passing a str secret raises TypeError loudly to prevent unwipeable RAM residency."""
    with pytest.raises(TypeError, match="strings are forbidden"):
        sign(
            secret="unwipeable-string-secret",  # type: ignore[arg-type] # noqa: S106
            method=_VALID_METHOD,
            path=_VALID_PATH,
            timestamp=_VALID_TS,
            nonce=_VALID_NONCE,
            body=_VALID_BODY,
        )

    with pytest.raises(TypeError, match="strings are forbidden"):
        verify(
            secret="unwipeable-string-secret",  # type: ignore[arg-type] # noqa: S106
            provided_sig="0" * 64,
            method=_VALID_METHOD,
            path=_VALID_PATH,
            timestamp=_VALID_TS,
            nonce=_VALID_NONCE,
            body=_VALID_BODY,
        )

    # Non-bytes-like object (e.g. int)
    with pytest.raises(TypeError, match="key material must be bytes-like"):
        sign(
            secret=12345,  # type: ignore[arg-type]
            method=_VALID_METHOD,
            path=_VALID_PATH,
            timestamp=_VALID_TS,
            nonce=_VALID_NONCE,
            body=_VALID_BODY,
        )

    with pytest.raises(TypeError, match="key material must be bytes-like"):
        verify(
            secret=12345,  # type: ignore[arg-type]
            provided_sig="0" * 64,
            method=_VALID_METHOD,
            path=_VALID_PATH,
            timestamp=_VALID_TS,
            nonce=_VALID_NONCE,
            body=_VALID_BODY,
        )


def test_secretbytes_key_accepted() -> None:
    """Verify that SecretBytes (Task 7 bytearray container) signs and verifies cleanly."""
    raw_key = b"vault-secret-key-32-bytes-long!!"
    vault_secret = SecretBytes(raw_key)

    sig = sign(
        secret=vault_secret,
        method=_VALID_METHOD,
        path=_VALID_PATH,
        timestamp=_VALID_TS,
        nonce=_VALID_NONCE,
        body=_VALID_BODY,
    )
    assert len(sig) == 64

    is_valid = verify(
        secret=vault_secret,
        provided_sig=sig,
        method=_VALID_METHOD,
        path=_VALID_PATH,
        timestamp=_VALID_TS,
        nonce=_VALID_NONCE,
        body=_VALID_BODY,
    )
    assert is_valid is True

    # Also bytearray directly
    ba_secret = bytearray(raw_key)
    assert (
        verify(
            secret=ba_secret,
            provided_sig=sig,
            method=_VALID_METHOD,
            path=_VALID_PATH,
            timestamp=_VALID_TS,
            nonce=_VALID_NONCE,
            body=_VALID_BODY,
        )
        is True
    )


# =============================================================================
# 8. CONSTANTS EXPORT INTEGRITY
# =============================================================================


def test_exported_header_constants() -> None:
    """Verify that header and protocol constants are exported as immutable contracts."""
    assert HEADER_AUTH == "Authorization"
    assert HEADER_TIMESTAMP == "X-FLX-Timestamp"
    assert HEADER_NONCE == "X-FLX-Nonce"
    assert HEADER_IDEMPOTENCY == "X-FLX-Idempotency-Key"
    assert SCHEME == "FLXP1"
    assert SEPARATOR == b"\n"
