"""Unit tests for the framework-free Keycloak OIDC JWT token verifier.

Tests verify cryptographic invariants, algorithm-confusion defense, claim boundaries,
leeway margins, JWKS key rotation, and defect class hygiene using httpx.MockTransport.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from fluxpay.admin.keycloak import AdminPrincipal, KeycloakVerifier

pytestmark = pytest.mark.unit

JWKS_URL = "https://auth.fluxpay.local/realms/fluxpay/protocol/openid-connect/certs"
ISSUER = "https://auth.fluxpay.local/realms/fluxpay"
AUDIENCE = "https://api.fluxpay.local"


@pytest.fixture(scope="session")
def rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate 2048-bit RSA keypair once for the test session."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


@pytest.fixture(scope="session")
def secondary_rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a second 2048-bit RSA keypair to test key rotation scenarios."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def build_jwks_response(keys: list[tuple[str, rsa.RSAPublicKey]]) -> dict[str, Any]:
    """Build a Keycloak-compatible JWKS JSON payload from (kid, public_key) pairs."""
    jwk_list: list[dict[str, Any]] = []
    for kid, pub_key in keys:
        jwk_dict = json.loads(RSAAlgorithm.to_jwk(pub_key))
        jwk_dict["kid"] = kid
        jwk_dict["alg"] = "RS256"
        jwk_dict["use"] = "sig"
        jwk_list.append(jwk_dict)
    return {"keys": jwk_list}


def mint_token(
    private_key: rsa.RSAPrivateKey | str | bytes,
    kid: str,
    *,
    sub: str | None = None,
    iss: str = ISSUER,
    aud: str = AUDIENCE,
    exp: float | None = None,
    iat: float | None = None,
    roles: list[str] | None = None,
    email: str = "admin@fluxpay.local",
    algorithm: str = "RS256",
    extra_headers: dict[str, Any] | None = None,
    omit_claims: list[str] | None = None,
) -> str:
    """Helper to mint JWT tokens with configurable claims, headers, and signatures."""
    now_ts = 1000.0
    payload: dict[str, Any] = {
        "sub": sub if sub is not None else str(uuid.uuid4()),
        "iss": iss,
        "aud": aud,
        "exp": exp if exp is not None else (now_ts + 300),
        "iat": iat if iat is not None else now_ts,
        "email": email,
        "realm_access": {"roles": roles if roles is not None else ["fluxpay-admin"]},
    }

    if omit_claims:
        for claim in omit_claims:
            payload.pop(claim, None)

    headers = {"kid": kid, "alg": algorithm}
    if extra_headers:
        headers.update(extra_headers)

    return jwt.encode(payload, private_key, algorithm=algorithm, headers=headers)


# ------------------------------------------------------------------------------
# 1. HAPPY PATH VERIFICATION TESTS
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_happy_path_admin_role(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Validate successful verification of token with fluxpay-admin mapped to admin."""
    private_key, public_key = rsa_keypair
    kid = "key-primary-1"
    sub_id = str(uuid.uuid4())
    token = mint_token(
        private_key,
        kid,
        sub=sub_id,
        roles=["fluxpay-admin", "offline_access"],
        email="ops-admin@fluxpay.local",
    )

    jwks_data = build_jwks_response([(kid, public_key)])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=jwks_data)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = KeycloakVerifier(
            http_client=http_client,
            jwks_url=JWKS_URL,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=lambda: 1000.0,
            leeway_s=30,
        )
        principal = await verifier.verify(token)

    assert isinstance(principal, AdminPrincipal)
    assert principal.sub == sub_id
    assert principal.role == "admin"
    assert principal.email == "ops-admin@fluxpay.local"


@pytest.mark.asyncio
async def test_verify_happy_path_support_role(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Validate successful verification of token with fluxpay-support mapped to support."""
    private_key, public_key = rsa_keypair
    kid = "key-primary-1"
    sub_id = str(uuid.uuid4())
    token = mint_token(
        private_key,
        kid,
        sub=sub_id,
        roles=["fluxpay-support"],
        email="tier1-support@fluxpay.local",
    )

    jwks_data = build_jwks_response([(kid, public_key)])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=jwks_data)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = KeycloakVerifier(
            http_client=http_client,
            jwks_url=JWKS_URL,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=lambda: 1000.0,
        )
        principal = await verifier.verify(token)

    assert principal.role == "support"
    assert principal.sub == sub_id
    assert principal.email == "tier1-support@fluxpay.local"


# ------------------------------------------------------------------------------
# 2. ADVERSARIAL & MATRIX FAILURE TESTS
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_rejects_expired_token(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Validate token beyond expiry + leeway is rejected with defect class 'expired token'."""
    private_key, public_key = rsa_keypair
    kid = "key-primary-1"
    now_ts = 1000.0
    leeway_s = 30
    # exp is set to now - leeway - 1 (1 second beyond allowed leeway)
    expired_time = now_ts - leeway_s - 1
    token = mint_token(private_key, kid, exp=expired_time, iat=expired_time - 60)

    jwks_data = build_jwks_response([(kid, public_key)])
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=jwks_data))

    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = KeycloakVerifier(
            http_client=http_client,
            jwks_url=JWKS_URL,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=lambda: now_ts,
            leeway_s=leeway_s,
        )
        with pytest.raises(ValueError) as exc_info:
            await verifier.verify(token)

    assert str(exc_info.value) == "expired token"
    # Security invariant: token content must never appear in exception string
    assert token not in str(exc_info.value)


@pytest.mark.asyncio
async def test_verify_leeway_exact_boundaries(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Boundary test: exp = now - 30 is accepted, exp = now - 31 is rejected as expired."""
    private_key, public_key = rsa_keypair
    kid = "key-primary-1"
    now_ts = 1000.0
    leeway_s = 30

    jwks_data = build_jwks_response([(kid, public_key)])
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=jwks_data))

    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = KeycloakVerifier(
            http_client=http_client,
            jwks_url=JWKS_URL,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=lambda: now_ts,
            leeway_s=leeway_s,
        )

        # 1. Boundary OK: exp = now - 30
        valid_token = mint_token(private_key, kid, exp=now_ts - 30, iat=now_ts - 60)
        principal = await verifier.verify(valid_token)
        assert principal is not None

        # 2. Boundary FAIL: exp = now - 31
        invalid_token = mint_token(private_key, kid, exp=now_ts - 31, iat=now_ts - 60)
        with pytest.raises(ValueError) as exc_info:
            await verifier.verify(invalid_token)
        assert str(exc_info.value) == "expired token"


@pytest.mark.asyncio
async def test_verify_rejects_wrong_issuer(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Validate token with mismatched issuer is rejected with 'invalid issuer'."""
    private_key, public_key = rsa_keypair
    kid = "key-primary-1"
    token = mint_token(private_key, kid, iss="https://rogue-idp.attacker.com/realms/evil")

    jwks_data = build_jwks_response([(kid, public_key)])
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=jwks_data))

    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = KeycloakVerifier(
            http_client=http_client,
            jwks_url=JWKS_URL,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=lambda: 1000.0,
        )
        with pytest.raises(ValueError) as exc_info:
            await verifier.verify(token)

    assert str(exc_info.value) == "invalid issuer"
    assert token not in str(exc_info.value)


@pytest.mark.asyncio
async def test_verify_rejects_wrong_audience(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Validate token with mismatched audience is rejected with 'invalid audience'."""
    private_key, public_key = rsa_keypair
    kid = "key-primary-1"
    token = mint_token(private_key, kid, aud="https://different-service.local")

    jwks_data = build_jwks_response([(kid, public_key)])
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=jwks_data))

    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = KeycloakVerifier(
            http_client=http_client,
            jwks_url=JWKS_URL,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=lambda: 1000.0,
        )
        with pytest.raises(ValueError) as exc_info:
            await verifier.verify(token)

    assert str(exc_info.value) == "invalid audience"


@pytest.mark.asyncio
async def test_verify_rejects_algorithm_confusion_hs256(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Validate the classic algorithm confusion attack (RS256 vs HS256) is strictly rejected.

    Attacker signs a JWT using HMAC-SHA256 (HS256) where the symmetric HMAC key is the
    PEM-encoded public RSA key of the server.
    The verifier MUST reject the token at the header gate with 'invalid algorithm'.
    """
    _, public_key = rsa_keypair
    kid = "key-primary-1"

    # Attacker mints token using HS256 and public key bytes (algorithm confusion)
    confusion_token = mint_token(
        private_key=b"0" * 32,
        kid=kid,
        algorithm="HS256",
    )

    jwks_data = build_jwks_response([(kid, public_key)])
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=jwks_data))

    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = KeycloakVerifier(
            http_client=http_client,
            jwks_url=JWKS_URL,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=lambda: 1000.0,
        )
        with pytest.raises(ValueError) as exc_info:
            await verifier.verify(confusion_token)

    assert str(exc_info.value) == "invalid algorithm"
    assert confusion_token not in str(exc_info.value)


@pytest.mark.asyncio
async def test_verify_rejects_missing_roles(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Validate token with no realm roles raises 'missing role'."""
    private_key, public_key = rsa_keypair
    kid = "key-primary-1"
    token = mint_token(private_key, kid, roles=[])

    jwks_data = build_jwks_response([(kid, public_key)])
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=jwks_data))

    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = KeycloakVerifier(
            http_client=http_client,
            jwks_url=JWKS_URL,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=lambda: 1000.0,
        )
        with pytest.raises(ValueError) as exc_info:
            await verifier.verify(token)

    assert str(exc_info.value) == "missing role"


@pytest.mark.asyncio
async def test_verify_rejects_foreign_role(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Validate token with unrelated realm roles (e.g. fluxpay-customer) raises 'missing role'."""
    private_key, public_key = rsa_keypair
    kid = "key-primary-1"
    token = mint_token(private_key, kid, roles=["fluxpay-customer", "uma_authorization"])

    jwks_data = build_jwks_response([(kid, public_key)])
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=jwks_data))

    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = KeycloakVerifier(
            http_client=http_client,
            jwks_url=JWKS_URL,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=lambda: 1000.0,
        )
        with pytest.raises(ValueError) as exc_info:
            await verifier.verify(token)

    assert str(exc_info.value) == "missing role"


@pytest.mark.asyncio
async def test_verify_rejects_bad_signature(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
    secondary_rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Validate token signed by an unknown key claiming to be kid1 fails with 'bad signature'."""
    _, public_key = rsa_keypair
    other_private, _ = secondary_rsa_keypair
    kid = "key-primary-1"

    # Token claims kid "key-primary-1", but is signed with a different private key
    bad_sig_token = mint_token(other_private, kid=kid)

    jwks_data = build_jwks_response([(kid, public_key)])
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=jwks_data))

    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = KeycloakVerifier(
            http_client=http_client,
            jwks_url=JWKS_URL,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=lambda: 1000.0,
        )
        with pytest.raises(ValueError) as exc_info:
            await verifier.verify(bad_sig_token)

    assert str(exc_info.value) == "bad signature"


@pytest.mark.asyncio
async def test_verify_rejects_unknown_kid_after_refetch(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Validate that token presenting a completely unknown kid raises 'unknown key'."""
    private_key, public_key = rsa_keypair
    kid = "key-primary-1"
    token = mint_token(private_key, kid="unknown-kid-999")

    # JWKS server only serves key-primary-1
    jwks_data = build_jwks_response([(kid, public_key)])
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=jwks_data))

    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = KeycloakVerifier(
            http_client=http_client,
            jwks_url=JWKS_URL,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=lambda: 1000.0,
        )
        with pytest.raises(ValueError) as exc_info:
            await verifier.verify(token)

    assert str(exc_info.value) == "unknown key"


@pytest.mark.asyncio
async def test_verify_handles_jwks_endpoint_500_fail_closed(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Validate that JWKS endpoint failure raises fail-closed 'jwks fetch failed'."""
    private_key, _ = rsa_keypair
    token = mint_token(private_key, kid="key-primary-1")

    transport = httpx.MockTransport(lambda req: httpx.Response(500, text="Internal Keycloak Error"))

    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = KeycloakVerifier(
            http_client=http_client,
            jwks_url=JWKS_URL,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=lambda: 1000.0,
        )
        with pytest.raises(ValueError) as exc_info:
            await verifier.verify(token)

    assert str(exc_info.value) == "jwks fetch failed"


# ------------------------------------------------------------------------------
# 3. JWKS ROTATION TOLERANCE TEST (Rotation without TTL Wait)
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_jwks_rotation_refetches_on_unknown_kid_without_ttl_wait(
    rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
    secondary_rsa_keypair: tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey],
) -> None:
    """Prove JWKS key rotation tolerance:

    1. Verifier verifies token with kid1 and caches it (cache_ttl_s = 3600).
    2. Keycloak rotates and mints token with kid2.
    3. Even though clock has NOT advanced (cache not expired for kid1), verifier sees
       kid2 is unknown, triggers an immediate refetch, discovers kid2, and verifies it.
    """
    priv1, pub1 = rsa_keypair
    priv2, pub2 = rsa_keypair_2 = secondary_rsa_keypair
    del rsa_keypair_2

    kid1 = "key-v1"
    kid2 = "key-v2"

    token1 = mint_token(priv1, kid=kid1)
    token2 = mint_token(priv2, kid=kid2)

    fetch_count = 0

    def jwks_endpoint_mock(request: httpx.Request) -> httpx.Response:
        nonlocal fetch_count
        fetch_count += 1
        # On first fetch, only kid1 exists
        if fetch_count == 1:
            return httpx.Response(200, json=build_jwks_response([(kid1, pub1)]))
        # After rotation, both kid1 and kid2 exist
        return httpx.Response(200, json=build_jwks_response([(kid1, pub1), (kid2, pub2)]))

    transport = httpx.MockTransport(jwks_endpoint_mock)
    now_ts = 1000.0

    async with httpx.AsyncClient(transport=transport) as http_client:
        verifier = KeycloakVerifier(
            http_client=http_client,
            jwks_url=JWKS_URL,
            issuer=ISSUER,
            audience=AUDIENCE,
            now=lambda: now_ts,
            cache_ttl_s=3600,  # 1 hour cache TTL
        )

        # 1. Verify token1 -> causes initial JWKS fetch (fetch_count = 1)
        p1 = await verifier.verify(token1)
        assert p1 is not None
        assert fetch_count == 1

        # 2. Verify token1 again -> cached hit, no fetch
        await verifier.verify(token1)
        assert fetch_count == 1

        # 3. Verify token2 (new kid2) -> unknown kid triggers refetch ONCE immediately
        # without waiting for the 3600s cache TTL!
        p2 = await verifier.verify(token2)
        assert p2 is not None
        assert fetch_count == 2
