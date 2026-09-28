"""Pure unit tests for dashboard authentication, PKCE, session cookies, and format_minor.

Verifies:
1. PKCE: verifier length law (43-128 chars), S256 challenge determinism and character set.
2. Signed OAuth State: roundtrip, tampering rejection, expiration rejection, secret isolation.
3. Stateless Session Cookies: roundtrip, timing-safe HMAC check, expiration, totality.
4. Cookie Flags Builder: Security KAT string asserting HttpOnly, Secure, SameSite=Strict.
5. Currency Exponent Formatter (format_minor): 1050->"10.50", 1->"0.000001", ceiling & negative.
6. Exchange Code: MockTransport token exchange with grant_type, code, PKCE verifier, etc.
"""

# ruff: noqa: S105, S106

from __future__ import annotations

import base64
import hashlib

import httpx
import pytest

from fluxpay.admin.keycloak import AdminPrincipal
from fluxpay.dashboard.auth import (
    MAX_AMOUNT_MINOR,
    DashboardSession,
    build_authorize_url,
    build_session_cookie_header,
    compute_code_challenge,
    create_oauth_state_cookie_value,
    create_session_cookie,
    exchange_code,
    format_minor,
    generate_code_verifier,
    generate_pkce,
    generate_signed_state,
    read_oauth_state_cookie_value,
    read_session_cookie,
    verify_signed_state,
)

pytestmark = pytest.mark.unit


# -----------------------------------------------------------------------------
# 1. PKCE INVARIANTS (RFC 7636)
# -----------------------------------------------------------------------------


def test_pkce_verifier_length_and_characters() -> None:
    """Validate code_verifier conforms to RFC 7636 length bounds [43, 128]."""
    for _ in range(20):
        verifier = generate_code_verifier()
        assert 43 <= len(verifier) <= 128
        valid_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_~.")
        assert all(c in valid_chars for c in verifier)


def test_pkce_challenge_determinism() -> None:
    """Validate S256 code challenge computation is strictly deterministic."""
    known_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    # Expected SHA-256 base64url-encoded challenge without padding
    digest = hashlib.sha256(known_verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    challenge = compute_code_challenge(known_verifier)
    assert challenge == expected
    assert "=" not in challenge

    # Successive calls on identical input return identical challenge
    assert compute_code_challenge(known_verifier) == challenge


def test_pkce_paired_generator() -> None:
    """Validate generate_pkce generates valid paired verifier and challenge."""
    verifier, challenge = generate_pkce()
    assert len(verifier) >= 43
    assert compute_code_challenge(verifier) == challenge


def test_build_authorize_url_pure() -> None:
    """Validate pure authorization URL construction with query parameters."""
    url = build_authorize_url(
        issuer="https://auth.fluxpay.local/realms/fluxpay",
        client_id="fluxpay-dashboard",
        redirect_uri="https://fluxpay.local/dashboard/callback",
        state="state123",
        nonce="nonce456",
        code_challenge="challenge789",
    )
    assert url.startswith("https://auth.fluxpay.local/realms/fluxpay/protocol/openid-connect/auth?")
    assert "response_type=code" in url
    assert "client_id=fluxpay-dashboard" in url
    assert "state=state123" in url
    assert "nonce=nonce456" in url
    assert "code_challenge=challenge789" in url
    assert "code_challenge_method=S256" in url


# -----------------------------------------------------------------------------
# 2. SIGNED OAUTH STATE
# -----------------------------------------------------------------------------


def test_signed_state_roundtrip() -> None:
    """Validate signed state generates and verifies cleanly within freshness window."""
    secret = "dashboard_secret_minimum_32_bytes_test"
    now = 1700000000.0

    state = generate_signed_state(secret=secret, now=now)
    assert isinstance(state, str)
    assert len(state) > 32

    verified = verify_signed_state(state, secret=secret, now=now + 5)
    assert verified is not None
    assert verified.startswith("1700000000:")


def test_signed_state_tamper_fails() -> None:
    """Validate modifying any character in signed state returns None."""
    secret = "dashboard_secret_minimum_32_bytes_test"
    now = 1700000000.0
    state = generate_signed_state(secret=secret, now=now)

    # Flip one character in the base64 string
    tampered = state[:-2] + ("A" if state[-2] != "A" else "B") + state[-1]
    assert verify_signed_state(tampered, secret=secret, now=now) is None


def test_signed_state_expired_fails() -> None:
    """Validate state older than max_age_s is rejected."""
    secret = "dashboard_secret_minimum_32_bytes_test"
    now = 1700000000.0
    state = generate_signed_state(secret=secret, now=now)

    # Verification 301s later with max_age_s=300 fails
    assert verify_signed_state(state, secret=secret, now=now + 301, max_age_s=300) is None


def test_signed_state_wrong_secret_fails() -> None:
    """Validate signed state verified under an alternate secret returns None."""
    secret = "dashboard_secret_minimum_32_bytes_test"
    wrong_secret = "dashboard_secret_alternate_32_bytes_00"
    now = 1700000000.0
    state = generate_signed_state(secret=secret, now=now)

    assert verify_signed_state(state, secret=wrong_secret, now=now) is None


def test_oauth_state_cookie_roundtrip_and_tamper() -> None:
    """Validate temporary OAuth state cookie stores state and code_verifier safely."""
    secret = "dashboard_secret_minimum_32_bytes_test"
    now = 1700000000.0
    cookie_val = create_oauth_state_cookie_value(
        state="state_xyz_123",
        code_verifier="pkce_verifier_abc_456",
        secret=secret,
        now=now,
    )

    result = read_oauth_state_cookie_value(cookie_val, secret=secret, now=now + 10)
    assert result == ("state_xyz_123", "pkce_verifier_abc_456")

    # Tampered cookie returns None
    tampered = cookie_val[:-4] + "zzzz"
    assert read_oauth_state_cookie_value(tampered, secret=secret, now=now + 10) is None


# -----------------------------------------------------------------------------
# 3. STATELESS SESSION COOKIES
# -----------------------------------------------------------------------------


def test_session_cookie_roundtrip() -> None:
    """Validate session cookie creation and parsing roundtrip."""
    secret = "dashboard_secret_minimum_32_bytes_test"
    now = 1700000000.0
    principal = AdminPrincipal(
        sub="kc_sub_admin_12345",
        role="admin",
        email="operator@fluxpay.local",
    )
    csrf_token = "csrf_token_hex_64_characters_long_0123456789abcdef"

    cookie_value = create_session_cookie(
        principal,
        secret=secret,
        now=now,
        max_age_s=28800,
        csrf_token=csrf_token,
    )

    session = read_session_cookie(cookie_value, secret=secret, now=now + 100)
    assert session is not None
    assert isinstance(session, DashboardSession)
    assert session.principal.sub == principal.sub
    assert session.principal.role == principal.role
    assert session.principal.email == principal.email
    assert session.csrf_token == csrf_token


def test_session_cookie_tampered_byte_fails() -> None:
    """Validate modifying any byte in session cookie returns None without raising."""
    secret = "dashboard_secret_minimum_32_bytes_test"
    now = 1700000000.0
    principal = AdminPrincipal(sub="kc_1", role="admin", email="a@b.com")
    cookie_value = create_session_cookie(principal, secret=secret, now=now)

    # Decode, flip one byte, re-encode
    raw = bytearray(base64.urlsafe_b64decode(cookie_value.encode("ascii")))
    raw[5] ^= 0xFF
    tampered_cookie = base64.urlsafe_b64encode(raw).decode("ascii")

    assert read_session_cookie(tampered_cookie, secret=secret, now=now) is None


def test_session_cookie_expired_fails() -> None:
    """Validate session cookie past its 8-hour max_age returns None."""
    secret = "dashboard_secret_minimum_32_bytes_test"
    now = 1700000000.0
    principal = AdminPrincipal(sub="kc_1", role="admin", email="a@b.com")
    cookie_value = create_session_cookie(principal, secret=secret, now=now, max_age_s=28800)

    # 28801 seconds later -> expired
    assert read_session_cookie(cookie_value, secret=secret, now=now + 28801) is None


def test_session_cookie_csrf_stability() -> None:
    """Validate CSRF token remains identical across multiple reads of the same cookie."""
    secret = "dashboard_secret_minimum_32_bytes_test"
    now = 1700000000.0
    principal = AdminPrincipal(sub="kc_1", role="admin", email="a@b.com")
    cookie_value = create_session_cookie(principal, secret=secret, now=now)

    s1 = read_session_cookie(cookie_value, secret=secret, now=now + 10)
    s2 = read_session_cookie(cookie_value, secret=secret, now=now + 20)
    assert s1 is not None and s2 is not None
    assert s1.csrf_token == s2.csrf_token
    assert len(s1.csrf_token) == 64


# -----------------------------------------------------------------------------
# 4. COOKIE FLAGS BUILDER (SECURITY KAT)
# -----------------------------------------------------------------------------


def test_cookie_flags_builder_security_kat() -> None:
    """Security Known-Answer Test: assert exact Set-Cookie flags string."""
    header = build_session_cookie_header(
        "flx_dash",
        "sample_session_value_xyz",
        max_age_s=28800,
        path="/dashboard",
        secure=True,
        httponly=True,
        samesite="Strict",
    )
    expected = (
        "flx_dash=sample_session_value_xyz; Path=/dashboard; "
        "Max-Age=28800; HttpOnly; Secure; SameSite=Strict"
    )
    assert header == expected
    assert "HttpOnly" in header
    assert "Secure" in header
    assert "SameSite=Strict" in header


# -----------------------------------------------------------------------------
# 5. CURRENCY EXPONENT FORMATTER (format_minor)
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("amount", "currency", "expected"),
    [
        (1050, "USD", "10.50"),
        (1050, "usd", "10.50"),
        (1, "USDC", "0.000001"),
        (100, "USDC", "0.000100"),
        (1_000_000, "USDC", "1.000000"),
        (0, "USDC", "0.000000"),
        (0, "USD", "0.00"),
        (50, "USD", "0.50"),
        (5, "EUR", "0.05"),
        (MAX_AMOUNT_MINOR, "USDC", "1000000000.000000"),
        (MAX_AMOUNT_MINOR, "USD", "10000000000000.00"),
    ],
)
def test_format_minor_table(amount: int, currency: str, expected: str) -> None:
    """Validate format_minor against the specified test vector table."""
    assert format_minor(amount, currency) == expected


def test_format_minor_negative_amount_rejected() -> None:
    """Validate negative amounts raise ValueError (negative impossible in ledger)."""
    with pytest.raises(ValueError, match="must be non-negative"):
        format_minor(-1, "USDC")

    with pytest.raises(ValueError, match="must be non-negative"):
        format_minor(-1050, "USD")


def test_format_minor_ceiling_exceeded_rejected() -> None:
    """Validate amounts exceeding 10^15 ceiling raise ValueError."""
    with pytest.raises(ValueError, match="exceeds maximum ceiling"):
        format_minor(MAX_AMOUNT_MINOR + 1, "USDC")


# -----------------------------------------------------------------------------
# 6. CODE EXCHANGE WITH INJECTED HTTPX CLIENT
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exchange_code_happy_path() -> None:
    """Validate authorization code exchange via MockTransport."""
    captured_request: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_request
        captured_request = request
        return httpx.Response(
            200,
            json={
                "access_token": "mock_access_token_123",
                "id_token": "mock_id_token_456",
                "expires_in": 300,
                "token_type": "Bearer",
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        tokens = await exchange_code(
            http_client=http_client,
            token_url="https://auth.fluxpay.local/protocol/openid-connect/token",
            code="auth_code_789",
            redirect_uri="https://fluxpay.local/dashboard/callback",
            code_verifier="pkce_verifier_abc",
            client_id="fluxpay-dashboard",
            client_secret="secret_abc",
        )

    assert tokens["access_token"] == "mock_access_token_123"
    assert tokens["id_token"] == "mock_id_token_456"
    assert tokens["expires_in"] == 300

    assert captured_request is not None
    body_str = captured_request.read().decode("utf-8")
    assert "grant_type=authorization_code" in body_str
    assert "code=auth_code_789" in body_str
    assert "code_verifier=pkce_verifier_abc" in body_str
    assert "client_id=fluxpay-dashboard" in body_str
    assert "client_secret=secret_abc" in body_str


def test_build_authorize_url_without_code_challenge() -> None:
    """Validate authorization URL construction when code_challenge is omitted."""
    url = build_authorize_url(
        issuer="https://auth.fluxpay.local/realms/fluxpay",
        client_id="fluxpay-dashboard",
        redirect_uri="https://fluxpay.local/dashboard/callback",
        state="state123",
        nonce="nonce456",
        code_challenge=None,
    )
    assert "code_challenge=" not in url
    assert "code_challenge_method=" not in url


@pytest.mark.asyncio
async def test_exchange_code_without_client_secret() -> None:
    """Validate authorization code exchange when client_secret is None."""
    captured_request: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_request
        captured_request = request
        return httpx.Response(200, json={"access_token": "tok"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        tokens = await exchange_code(
            http_client=http_client,
            token_url="https://auth.fluxpay.local/protocol/openid-connect/token",
            code="code1",
            redirect_uri="https://fluxpay.local/callback",
            code_verifier="verifier1",
            client_id="fluxpay-dashboard",
            client_secret=None,
        )
    assert tokens["access_token"] == "tok"
    assert captured_request is not None
    assert "client_secret" not in captured_request.read().decode("utf-8")


@pytest.mark.asyncio
async def test_exchange_code_invalid_payload_raises() -> None:
    """Validate exchange_code raises ValueError when IdP returns non-dict JSON."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["invalid", "array", "not", "dict"])

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        with pytest.raises(ValueError, match="Invalid token response: expected JSON dictionary"):
            await exchange_code(
                http_client=http_client,
                token_url="https://auth.fluxpay.local/protocol/openid-connect/token",
                code="code1",
                redirect_uri="https://fluxpay.local/callback",
                code_verifier="verifier1",
                client_id="fluxpay-dashboard",
            )


def test_verify_signed_state_boundary_cases() -> None:
    """Validate verify_signed_state edge cases: length < 33, bad sep, future skew, exceptions."""
    import hashlib
    import hmac

    secret = "dashboard_secret_minimum_32_bytes_test"
    now = 1700000000.0

    # Short string < 33 chars
    short_state = base64.urlsafe_b64encode(b"short").decode("ascii")
    assert verify_signed_state(short_state, secret=secret, now=now) is None

    # Separator not '.'
    raw_bad_sep = b"payload" + b"X" + (b"0" * 32)
    bad_sep_state = base64.urlsafe_b64encode(raw_bad_sep).decode("ascii")
    assert verify_signed_state(bad_sep_state, secret=secret, now=now) is None

    # Future timestamp > now + 30
    future_state = generate_signed_state(secret=secret, now=now + 35)
    assert verify_signed_state(future_state, secret=secret, now=now) is None

    # Malformed non-integer timestamp in payload with valid HMAC (triggers exception block)
    bad_payload = b"not_an_int:rnd"
    mac = hmac.new(secret.encode("utf-8"), bad_payload, hashlib.sha256).digest()
    bad_state = base64.urlsafe_b64encode(bad_payload + b"." + mac).decode("ascii")
    assert verify_signed_state(bad_state, secret=secret, now=now) is None

    # Invalid base64
    assert verify_signed_state("not-valid-base64!@#$%", secret=secret, now=now) is None


def test_read_oauth_state_cookie_boundary_cases() -> None:
    """Validate read_oauth_state_cookie_value edge cases: bad base64, missing dot, bad json."""
    import hashlib
    import hmac

    secret = "dashboard_secret_minimum_32_bytes_test"
    now = 1700000000.0

    # Invalid base64
    assert read_oauth_state_cookie_value("!@#$%", secret=secret, now=now) is None

    # Missing dot or wrong mac length
    no_dot = base64.urlsafe_b64encode(b"nodothere").decode("ascii")
    assert read_oauth_state_cookie_value(no_dot, secret=secret, now=now) is None

    # Wrong mac length
    bad_mac_len = base64.urlsafe_b64encode(b"payload.shortmac").decode("ascii")
    assert read_oauth_state_cookie_value(bad_mac_len, secret=secret, now=now) is None

    # Exact 32-byte MAC mismatch
    mismatch_mac = base64.urlsafe_b64encode(b"payload." + (b"x" * 32)).decode("ascii")
    assert read_oauth_state_cookie_value(mismatch_mac, secret=secret, now=now) is None

    # Future timestamp > now + 30
    future_cookie = create_oauth_state_cookie_value(
        state="s", code_verifier="v", secret=secret, now=now + 35
    )
    assert read_oauth_state_cookie_value(future_cookie, secret=secret, now=now) is None

    # Corrupted json in payload
    bad_json = b"not json"
    mac = hmac.new(secret.encode("utf-8"), bad_json, hashlib.sha256).digest()
    corrupt_cookie = base64.urlsafe_b64encode(bad_json + b"." + mac).decode("ascii")
    assert read_oauth_state_cookie_value(corrupt_cookie, secret=secret, now=now) is None


def test_read_session_cookie_boundary_cases() -> None:
    """Validate read_session_cookie edge cases: length < 33, bad sep, corrupted json."""
    import hashlib
    import hmac

    secret = "dashboard_secret_minimum_32_bytes_test"
    now = 1700000000.0

    # Short string < 33 chars
    short_cookie = base64.urlsafe_b64encode(b"short").decode("ascii")
    assert read_session_cookie(short_cookie, secret=secret, now=now) is None

    # Separator not '.'
    bad_sep = base64.urlsafe_b64encode(b"payload" + b"X" + (b"0" * 32)).decode("ascii")
    assert read_session_cookie(bad_sep, secret=secret, now=now) is None

    # Corrupt payload causing json error
    bad_json = b"bad payload"
    mac = hmac.new(secret.encode("utf-8"), bad_json, hashlib.sha256).digest()
    corrupt = base64.urlsafe_b64encode(bad_json + b"." + mac).decode("ascii")
    assert read_session_cookie(corrupt, secret=secret, now=now) is None

    # Invalid base64
    assert read_session_cookie("!@#$%", secret=secret, now=now) is None


def test_build_session_cookie_header_optional_flags() -> None:
    """Validate build_session_cookie_header with optional security flags disabled."""
    header = build_session_cookie_header(
        "flx_dash",
        "val",
        max_age_s=100,
        httponly=False,
        secure=False,
        samesite="",
    )
    assert "HttpOnly" not in header
    assert "Secure" not in header
    assert "SameSite" not in header
    assert header == "flx_dash=val; Path=/dashboard; Max-Age=100"


def test_format_minor_unregistered_currency_default() -> None:
    """Validate format_minor falls back to 2 decimal places for unlisted currency codes."""
    assert format_minor(1234, "UNKNOWN") == "12.34"


def test_three_lane_middleware_order_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate 3-lane middleware order: Gateway (outermost) -> Admin -> Dashboard (innermost)."""
    b64_vault_key = base64.b64encode(b"0" * 32).decode("ascii")
    monkeypatch.setenv("FLX_PG_DSN", "postgresql://test:test@localhost:5432/test")
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", b64_vault_key)
    monkeypatch.setenv(
        "FLX_WEBHOOK_SIGNING_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    monkeypatch.setenv(
        "FLX_DASHBOARD_SECRET", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    )

    from fluxpay.config import get_settings

    get_settings.cache_clear()

    from fluxpay.admin.middleware import AdminAuthMiddleware
    from fluxpay.dashboard.middleware import DashboardAuthMiddleware
    from fluxpay.gateway.middleware import GatewayMiddleware
    from fluxpay.main import create_app

    app = create_app()
    middleware_classes = [getattr(m, "cls", None) for m in app.user_middleware]

    # Task 33 contract: Gateway is outermost ingress gate
    assert middleware_classes[0] is GatewayMiddleware
    # Task 29 contract: Admin Bearer plane exists
    assert AdminAuthMiddleware in middleware_classes
    # Task 61 contract: Dashboard session cookie lane exists
    assert DashboardAuthMiddleware in middleware_classes

    gateway_idx = middleware_classes.index(GatewayMiddleware)
    admin_idx = middleware_classes.index(AdminAuthMiddleware)
    dashboard_idx = middleware_classes.index(DashboardAuthMiddleware)

    # Ingress execution: Gateway runs 1st, Admin runs 2nd, Dashboard runs 3rd
    assert gateway_idx < admin_idx
    assert admin_idx < dashboard_idx
