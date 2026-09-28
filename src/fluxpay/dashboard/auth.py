"""Cryptographic authentication, session management, and PKCE utilities for Dashboard Lane.

=============================================================================
SECURITY INVARIANTS & AUTHENTICATION DESIGN LAWS
=============================================================================

1. WHY PKCE FOR CONFIDENTIAL CLIENTS:
   Even though the backend dashboard holds a client_secret, PKCE (RFC 7636) with
   S256 is enforced for all authorization-code flows. PKCE binds the token request
   to the original authorization request cryptographically. If an authorization code
   is intercepted via browser history or TLS proxy logs, an attacker cannot exchange
   it without the high-entropy in-memory code_verifier.

2. WHY MANUAL OIDC FLOW (ZERO AUTHLIB / OAUTH PACKAGES):
   The authorization-code flow is ~100 lines of standard library code:
   - 1 URL constructor with standard query parameters.
   - 1 single-flight POST request to the token endpoint.
   Our KeycloakVerifier (Task 29) already verifies the minted RS256 JWTs against
   Keycloak's JWKS endpoint. Introducing a third-party OAuth package introduces
   unnecessary supply-chain risks, complex abstractions, and version upgrade friction
   for what is fundamentally boring math and standard HTTP.

3. STATELESS SIGNED COOKIES WITH ACTIVE DATABASE REVOCATION:
   Session state is self-contained and signed:
     base64(payload || "." || HMAC-SHA256(secret, payload))
   Storing a lightweight token payload (sub, role, email, exp, csrf) avoids a
   centralized session table during Phase 1. Immediate revocation is guaranteed by
   the local PostgreSQL user row check on EVERY authenticated request (the Task 29
   stale-token defense law). If an operator is deactivated or deleted locally, their
   session is rejected immediately regardless of cookie expiration.

4. THREE-LAYER CSRF DEFENSE:
   Browser session cookies require multi-layered defense against cross-site attacks:
   - Layer 1: SameSite=Strict on the session cookie.
   - Layer 2: Strict Origin/Referer header verification against the configured dashboard origin.
   - Layer 3: Mandatory HX-Request header and double-submit per-session CSRF token.
   State-changing GET requests are strictly forbidden by architectural design.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import urllib.parse
from dataclasses import dataclass
from typing import Any, Final

import httpx
import orjson

from fluxpay.admin.keycloak import AdminPrincipal

__all__ = [
    "CURRENCY_DECIMALS",
    "MAX_AMOUNT_MINOR",
    "DashboardSession",
    "build_authorize_url",
    "build_session_cookie_header",
    "compute_code_challenge",
    "create_oauth_state_cookie_value",
    "create_session_cookie",
    "exchange_code",
    "format_minor",
    "generate_code_verifier",
    "generate_pkce",
    "generate_signed_state",
    "read_oauth_state_cookie_value",
    "read_session_cookie",
    "verify_signed_state",
]

# ISO currency exponent mapping: minor units per major unit (10^decimals)
# USDC: 6 decimal places (1 USDC = 1_000_000 minor units)
# USD / EUR / GBP: 2 decimal places (1 USD = 100 cents)
CURRENCY_DECIMALS: Final[dict[str, int]] = {
    "USDC": 6,
    "USD": 2,
    "EUR": 2,
    "GBP": 2,
}

# Maximum allowed payment amount in minor units (1 trillion USDC / 10^15 minor units)
MAX_AMOUNT_MINOR: Final[int] = 10**15


@dataclass(frozen=True, slots=True)
class DashboardSession:
    """Authenticated operator session carrying the verified principal and CSRF token."""

    principal: AdminPrincipal
    csrf_token: str


# -----------------------------------------------------------------------------
# 1. PKCE (RFC 7636) HELPERS
# -----------------------------------------------------------------------------


def generate_code_verifier() -> str:
    """Generate a high-entropy cryptographic PKCE code verifier (43-128 chars).

    WHY token_urlsafe(32):
    Produces exactly 43 URL-safe ASCII characters containing ~256 bits of entropy,
    satisfying RFC 7636 §4.1 length and character constraints.
    """
    return secrets.token_urlsafe(32)


def compute_code_challenge(verifier: str) -> str:
    """Compute deterministic SHA-256 PKCE code challenge with URL-safe base64 encoding.

    In accordance with RFC 7636 §4.2, trailing '=' padding characters are stripped.
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def generate_pkce() -> tuple[str, str]:
    """Generate paired PKCE code_verifier and code_challenge."""
    verifier = generate_code_verifier()
    challenge = compute_code_challenge(verifier)
    return verifier, challenge


def build_authorize_url(
    *,
    issuer: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    nonce: str,
    code_challenge: str | None = None,
    code_challenge_method: str = "S256",
) -> str:
    """Build pure OIDC authorization-code redirect URL with PKCE parameters."""
    base_endpoint = f"{issuer.rstrip('/')}/protocol/openid-connect/auth"
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
    }
    if code_challenge is not None:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = code_challenge_method

    query_str = urllib.parse.urlencode(params)
    return f"{base_endpoint}?{query_str}"


async def exchange_code(
    *,
    http_client: httpx.AsyncClient,
    token_url: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    client_id: str,
    client_secret: str | None = None,
) -> dict[str, Any]:
    """Exchange authorization code and PKCE verifier for OIDC tokens.

    Posts to Keycloak's token endpoint with confidential client credentials.
    Returns token payload containing access_token, id_token, and expires_in.
    """
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "client_id": client_id,
    }
    if client_secret:
        data["client_secret"] = client_secret

    response = await http_client.post(
        token_url,
        data=data,
        headers={"Accept": "application/json"},
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("Invalid token response: expected JSON dictionary.")
    return payload


# -----------------------------------------------------------------------------
# 2. SIGNED OAUTH STATE (HMAC-SHA256)
# -----------------------------------------------------------------------------


def generate_signed_state(*, secret: str, now: float) -> str:
    """Generate an HMAC-SHA256 timestamped signed state parameter to prevent OAuth CSRF.

    Format: base64url(payload || "." || HMAC-SHA256(secret, payload))
    where payload = "{timestamp_int}:{random_hex}"
    """
    rnd = secrets.token_hex(16)
    payload_str = f"{int(now)}:{rnd}"
    payload_bytes = payload_str.encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    combined = payload_bytes + b"." + mac
    return base64.urlsafe_b64encode(combined).decode("ascii")


def verify_signed_state(
    state: str,
    *,
    secret: str,
    now: float,
    max_age_s: int = 300,
) -> str | None:
    """Verify signed state parameter with timing-safe comparison and expiration check.

    Returns the inner payload string if authentic and fresh; returns None on any defect.
    Totality rule: never raises exceptions on untrusted external input.
    """
    try:
        combined = base64.urlsafe_b64decode(state.encode("ascii"))
        if len(combined) < 33:
            return None
        mac = combined[-32:]
        sep = combined[-33:-32]
        payload_bytes = combined[:-33]
        if sep != b".":
            return None

        expected_mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            return None

        payload_str = payload_bytes.decode("utf-8")
        ts_str, _, _ = payload_str.partition(":")
        ts = int(ts_str)

        # Enforce freshness window with 30s future clock-skew tolerance
        if (now - ts > max_age_s) or (ts > now + 30):
            return None

        return payload_str
    except Exception:
        return None


def create_oauth_state_cookie_value(
    *,
    state: str,
    code_verifier: str,
    secret: str,
    now: float,
) -> str:
    """Store state and PKCE verifier securely in short-lived SameSite=Lax cookie."""
    data = {
        "state": state,
        "verifier": code_verifier,
        "ts": int(now),
    }
    payload = orjson.dumps(data)
    mac = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload + b"." + mac).decode("ascii")


def read_oauth_state_cookie_value(
    value: str,
    *,
    secret: str,
    now: float,
    max_age_s: int = 300,
) -> tuple[str, str] | None:
    """Read and verify temporary OAuth state cookie, returning (state, verifier) or None."""
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
        payload, sep, mac = raw.rpartition(b".")
        if sep != b"." or len(mac) != 32:
            return None

        expected_mac = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            return None

        data = orjson.loads(payload)
        ts = int(data["ts"])
        if (now - ts > max_age_s) or (ts > now + 30):
            return None

        return str(data["state"]), str(data["verifier"])
    except Exception:
        return None


# -----------------------------------------------------------------------------
# 3. STATELESS SIGNED SESSION COOKIES
# -----------------------------------------------------------------------------


def create_session_cookie(
    principal: AdminPrincipal,
    *,
    secret: str,
    now: float,
    max_age_s: int = 28800,
    csrf_token: str | None = None,
) -> str:
    """Create a self-contained HMAC-SHA256 signed session cookie value.

    Format: base64url(payload || "." || HMAC-SHA256(secret, payload))
    where payload = orjson({"sub", "role", "email", "exp", "csrf"})
    """
    token = csrf_token if csrf_token is not None else secrets.token_hex(32)
    payload_dict = {
        "sub": principal.sub,
        "role": principal.role,
        "email": principal.email,
        "exp": int(now + max_age_s),
        "csrf": token,
    }
    payload_bytes = orjson.dumps(payload_dict)
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    combined = payload_bytes + b"." + mac
    return base64.urlsafe_b64encode(combined).decode("ascii")


def read_session_cookie(
    value: str,
    *,
    secret: str,
    now: float,
) -> DashboardSession | None:
    """Parse, authenticate, and validate an incoming session cookie value.

    Guarantees:
    - Timing-safe HMAC verification via hmac.compare_digest.
    - Expiration check against injected now timestamp.
    - Totality: returns None on any defect, never raises.
    """
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
        if len(raw) < 33:
            return None
        mac = raw[-32:]
        sep = raw[-33:-32]
        payload_bytes = raw[:-33]
        if sep != b".":
            return None

        expected_mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            return None

        data = orjson.loads(payload_bytes)
        if now >= data["exp"]:
            return None

        principal = AdminPrincipal(
            sub=str(data["sub"]),
            role=str(data["role"]),
            email=str(data["email"]),
        )
        return DashboardSession(principal=principal, csrf_token=str(data["csrf"]))
    except Exception:
        return None


def build_session_cookie_header(
    name: str,
    value: str,
    *,
    max_age_s: int,
    path: str = "/dashboard",
    secure: bool = True,
    httponly: bool = True,
    samesite: str = "Strict",
) -> str:
    """Build exact Set-Cookie header string enforcing financial security flags (security KAT)."""
    parts = [f"{name}={value}", f"Path={path}", f"Max-Age={max_age_s}"]
    if httponly:
        parts.append("HttpOnly")
    if secure:
        parts.append("Secure")
    if samesite:
        parts.append(f"SameSite={samesite.capitalize()}")
    return "; ".join(parts)


# -----------------------------------------------------------------------------
# 4. CURRENCY FORMATTING (MINOR -> DECIMAL STRING)
# -----------------------------------------------------------------------------


def format_minor(amount: int, currency: str = "USDC") -> str:
    """Format minor monetary units into an exact decimal string without floating-point math.

    Examples:
        format_minor(1050, "USD") -> "10.50"
        format_minor(1, "USDC") -> "0.000001"
        format_minor(10**15, "USDC") -> "1000000000.000000"

    Invariants:
        - Negative values raise ValueError (impossible under schema law).
        - Value exceeding MAX_AMOUNT_MINOR (10^15) raises ValueError.
        - Fractional part is zero-padded to the exact currency exponent.
    """
    if amount < 0:
        raise ValueError(f"amount must be non-negative, got {amount}")
    if amount > MAX_AMOUNT_MINOR:
        raise ValueError(f"amount {amount} exceeds maximum ceiling of {MAX_AMOUNT_MINOR}")

    decimals = CURRENCY_DECIMALS.get(currency.upper(), 2)
    divisor = 10**decimals
    whole = amount // divisor
    frac = amount % divisor
    return f"{whole}.{frac:0{decimals}d}"
