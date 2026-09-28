"""Framework-free Keycloak OIDC JWT token verifier for FluxPay admin plane.

Blueprint §4 Keycloak identity broker, RBAC, MFA.

=============================================================================
SECURITY & VERIFICATION DESIGN DECISIONS (WHY THE SYSTEM IS BUILT THIS WAY)
=============================================================================

1. WHY STRICT RS256-ONLY (REJECT NONE & HS256):
------------------------------------------------
Algorithm-confusion is THE classic JWT vulnerability. In an algorithm-confusion attack,
an adversary signs a JWT using a symmetric HMAC (HS256) algorithm using the server's public
RSA key as the HMAC secret. If the verifier naively trusts the `alg` header or accepts
symmetric algorithms, the token verifies successfully because the public key is known.
We strictly require `alg == "RS256"`. Any token specifying `none`, `HS256`, or another
asymmetric algorithm is rejected at the header gate before key lookup or decoding.

2. WHY IN-PROCESS JWKS CACHE WITH ROTATION TOLERANCE:
------------------------------------------------------
Keycloak rotates signing keys periodically or during security incidents. An in-process
JWKS cache with TTL prevents pounding Keycloak's certs endpoint on every request.
However, when Keycloak rotates to a new key, tokens signed with the new key will arrive
before our cache TTL expires. If a token presents an unknown `kid`, we trigger an immediate
single refetch of the JWKS endpoint. If the `kid` is still absent after refetching, the
token is rejected. This provides zero-downtime key rotation tolerance without waiting for
cache TTL expiration.

3. WHY DEPENDENCY-INJECTED HTTP CLIENT & CLOCK:
-----------------------------------------------
The HTTP client (`httpx.AsyncClient`) and clock function (`Callable[[], float]`) are
injected at instantiation. Unit tests pass `httpx.MockTransport` and a deterministic clock,
guaranteeing 100% reproducible test scenarios without network dependencies, timing flakes,
or monkeypatching.

4. WHY DEFECT-CLASS-ONLY ERROR MESSAGES (NO LOG INJECTION):
----------------------------------------------------------
In alignment with Task 19's parsing philosophy and security standards, all verification
failures raise `ValueError` containing ONLY static defect class identifiers
("expired token", "bad signature", "unknown key", "missing role", etc.). Raw tokens,
header parameters, and payload claims are NEVER included in exception strings or logs,
preventing token leakage into SIEM logs, error envelopes, and terminal outputs.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

__all__ = [
    "AdminPrincipal",
    "KeycloakVerifier",
]

_ROLE_MAP: Final[dict[str, str]] = {
    "fluxpay-admin": "admin",
    "fluxpay-support": "support",
}


@dataclass(frozen=True, slots=True)
class AdminPrincipal:
    """Authenticated administrative principal carrying validated claims from Keycloak."""

    sub: str
    role: str  # "admin" | "support"
    email: str


class KeycloakVerifier:
    """Framework-free Keycloak OIDC JWT token verifier.

    Performs cryptographic signature verification against Keycloak's JWKS endpoint,
    validates standard claims (iss, aud, exp, iat, sub), and extracts mapped administrative roles.
    """

    def __init__(
        self,
        *,
        http_client: httpx.AsyncClient,
        jwks_url: str,
        issuer: str,
        audience: str,
        now: Callable[[], float] = time.time,
        leeway_s: int = 30,
        cache_ttl_s: int = 300,
    ) -> None:
        """Initialize KeycloakVerifier with injected dependencies and OIDC parameters."""
        self._http_client: httpx.AsyncClient = http_client
        self._jwks_url: str = jwks_url
        self._issuer: str = issuer
        self._audience: str = audience
        self._now: Callable[[], float] = now
        self._leeway_s: int = leeway_s
        self._cache_ttl_s: int = cache_ttl_s

        # In-process cache: kid -> (RSAPublicKey, expires_at_timestamp)
        self._key_cache: dict[str, tuple[Any, float]] = {}

    async def _fetch_jwks(self) -> None:
        """Fetch JWKS keys from Keycloak endpoint and populate the in-process cache.

        Failures fail closed (raise ValueError) — no fallback to insecure introspection.
        """
        try:
            resp = await self._http_client.get(self._jwks_url)
            if resp.status_code != 200:
                raise ValueError("jwks fetch failed")
            data = resp.json()
        except Exception as exc:
            raise ValueError("jwks fetch failed") from exc

        keys = data.get("keys", [])
        if not isinstance(keys, list):
            raise ValueError("jwks fetch failed")

        now_ts = self._now()
        expires_at = now_ts + self._cache_ttl_s

        for key_dict in keys:
            if not isinstance(key_dict, dict):
                continue
            kid = key_dict.get("kid")
            kty = key_dict.get("kty")
            if kid and kty == "RSA":
                try:
                    public_key = RSAAlgorithm.from_jwk(key_dict)
                    self._key_cache[kid] = (public_key, expires_at)
                except Exception:  # noqa: S112
                    continue

    async def verify(self, token: str) -> AdminPrincipal:
        """Cryptographically verify an admin JWT token and return the AdminPrincipal.

        Steps:
        1. Parse header: alg MUST be "RS256" (reject none/HS256). Ensure kid is present.
        2. Lookup RSA key in JWKS cache; if missing or expired, refetch JWKS once.
        3. Cryptographically decode token with PyJWT enforcing issuer, audience, and claims.
        4. Validate time bounds (exp, iat) against injected clock with leeway tolerance.
        5. Extract and map realm roles from realm_access.roles to 'admin' or 'support'.
        6. Validate subject is UUID-parseable.

        Raises:
            ValueError: On any validation failure with a static defect class description.
        """
        if not isinstance(token, str) or not token.strip():
            raise ValueError("invalid token")

        # 1. Parse header and enforce algorithm security
        try:
            headers = jwt.get_unverified_header(token)
        except Exception as exc:
            raise ValueError("invalid token") from exc

        # Algorithm-confusion defense: strictly reject anything other than RS256
        alg = headers.get("alg")
        if alg != "RS256":
            raise ValueError("invalid algorithm")

        kid = headers.get("kid")
        if not kid or not isinstance(kid, str):
            raise ValueError("missing kid")

        # 2. Key lookup with rotation tolerance (refetch on cache miss)
        now_ts = self._now()
        cached_entry = self._key_cache.get(kid)
        if cached_entry is not None:
            key, expires_at = cached_entry
            if now_ts >= expires_at:
                # Cache entry expired, refetch
                await self._fetch_jwks()
                cached_entry = self._key_cache.get(kid)
                if cached_entry is None:
                    raise ValueError("unknown key")
                key, _ = cached_entry
        else:
            # Unknown kid: refetch ONCE for key rotation tolerance without waiting for TTL
            await self._fetch_jwks()
            cached_entry = self._key_cache.get(kid)
            if cached_entry is None:
                raise ValueError("unknown key")
            key, _ = cached_entry

        # 3. Decode token enforcing RS256 signature, audience, and issuer
        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway_s,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub"],
                    "verify_exp": False,  # Evaluated deterministically below with self._now()
                    "verify_iat": False,  # Evaluated deterministically below with self._now()
                    "verify_iss": True,
                    "verify_aud": True,
                    "verify_signature": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise ValueError("expired token") from exc
        except jwt.InvalidSignatureError as exc:
            raise ValueError("bad signature") from exc
        except jwt.InvalidIssuerError as exc:
            raise ValueError("invalid issuer") from exc
        except jwt.InvalidAudienceError as exc:
            raise ValueError("invalid audience") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise ValueError("missing required claim") from exc
        except jwt.PyJWTError as exc:
            raise ValueError("invalid token") from exc

        # 4. Injected clock time validation (deterministic testing without monkeypatching)
        current_time = self._now()

        exp_val = payload.get("exp")
        if exp_val is None:
            raise ValueError("missing required claim")
        try:
            exp_float = float(exp_val)
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid token") from exc

        # Leeway boundary: token is valid if current_time <= exp + leeway_s
        if current_time > exp_float + self._leeway_s:
            raise ValueError("expired token")

        iat_val = payload.get("iat")
        if iat_val is None:
            raise ValueError("missing required claim")
        try:
            iat_float = float(iat_val)
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid token") from exc

        # Future token defense: iat cannot be in the future beyond leeway
        if iat_float > current_time + self._leeway_s:
            raise ValueError("invalid token")

        # 5. Extract and map Keycloak realm roles
        realm_access = payload.get("realm_access")
        if not isinstance(realm_access, dict):
            raise ValueError("missing role")

        raw_roles = realm_access.get("roles")
        if not isinstance(raw_roles, list):
            raise ValueError("missing role")

        roles_set = set(raw_roles)
        mapped_role: str | None = None
        if "fluxpay-admin" in roles_set:
            mapped_role = "admin"
        elif "fluxpay-support" in roles_set:
            mapped_role = "support"

        if mapped_role is None:
            raise ValueError("missing role")

        # 6. Validate subject is UUID-parseable canonical form
        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub.strip():
            raise ValueError("invalid subject")

        try:
            uuid.UUID(sub)
        except ValueError as exc:
            raise ValueError("invalid subject") from exc

        email = str(payload.get("email", ""))

        return AdminPrincipal(
            sub=sub,
            role=mapped_role,
            email=email,
        )
