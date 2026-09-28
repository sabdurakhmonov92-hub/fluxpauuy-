"""Pure unit tests for Stripe external rail integration adapter (Block J, Part 3).

TASK 52: STRIPE ADAPTER: SANDBOX-PROVEN FIAT UTILITIES
Verifies:
1. Signature KAT (the crown): Fixed secret, payload, and timestamp against hardcoded
   frozen HMAC hex with tolerance boundary checks (0, +299, +301, -299, -301).
2. Tamper matrix: Payload byte-flip, t garbled/missing, missing v1, multiple v1
   (one valid), and uppercase hex rejection (Stripe sends lowercase).
3. Valid-sig + malformed JSON: Returns None and logs WARNING ("stripe webhook:
   valid signature, invalid json").
4. Secret absence law: Neither secret_key nor webhook_secret leaks into logs or exceptions.
5. Link creation: Happy path, parameter mapping, Idempotency-Key capture,
   amount/currency validation, and provider contract drift guard (phase="parse").
6. Provider-error hook: 402 card_declined preserves machine code in details,
   while message is dropped from details and logs.
7. Healthcheck: GET /v1/balance returns True on 200, False on 401/500 (bool law, no raise).
8. Composed auth error: 401 through request raises IntegrationAuthError (500 non-retryable).
9. Isolation law meta-test: stripe.py imports strictly within allowlist.
10. Disabled-mode, config validators, and .env.example synchronization.
11. Anti-conversion law and EXPONENTS table verification.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
from pathlib import Path

import httpx
import orjson
import pytest
from pydantic import ValidationError

from fluxpay.config import Settings
from fluxpay.integrations.stripe import EXPONENTS, StripeClient, minor_to_major_str
from fluxpay.shared.errors import IntegrationAuthError, IntegrationError

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _setup_structlog_stdlib() -> None:
    """Ensure structlog routes through stdlib logging so caplog captures records."""
    import structlog

    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory())


# -----------------------------------------------------------------------------
# Test Helper: StripeClient Factory with MockTransport
# -----------------------------------------------------------------------------


def _make_stripe_client(
    transport: httpx.MockTransport,
    *,
    secret_key: str = "sk_test_mock_secret_key_12345",  # noqa: S107
    webhook_secret: str | None = "whsec_test_kat_000",  # noqa: S107
    webhook_tolerance_s: int = 300,
) -> tuple[StripeClient, list[float]]:
    """Create a StripeClient wired to MockTransport with zero-sleep recorder."""
    sleep_calls: list[float] = []

    async def _mock_sleep(duration: float) -> None:
        sleep_calls.append(duration)

    http = httpx.AsyncClient(transport=transport)
    client = StripeClient(
        secret_key=secret_key,
        webhook_secret=webhook_secret,
        webhook_tolerance_s=webhook_tolerance_s,
        http=http,
        sleep=_mock_sleep,
    )
    return client, sleep_calls


# -----------------------------------------------------------------------------
# 1. STOP-THE-LINE CONTRACT: SIGNATURE KNOWN-ANSWER TEST (KAT)
# -----------------------------------------------------------------------------
# DO NOT REGENERATE THIS VALUE UNDER ANY CIRCUMSTANCES.
# Fixed secret:  "whsec_test_kat_000"
# Fixed payload: b'{"id":"evt_1"}'
# Timestamp:     1700000000
# Expected v1:   9cacabc30255eb2da36dc4aaf50bbd4f8386987c9834a91ca3c3528d89af9e01
#
# If this test fails, STOP THE LINE. Do not update this constant.
# Regeneration means the webhook cryptographic signature verification contract
# was broken, introducing a catastrophic payment security incident.
# -----------------------------------------------------------------------------

KAT_SECRET = "whsec_test_kat_000"  # noqa: S105
KAT_PAYLOAD = b'{"id":"evt_1"}'
KAT_TIMESTAMP = 1700000000
KAT_EXPECTED_V1 = "9cacabc30255eb2da36dc4aaf50bbd4f8386987c9834a91ca3c3528d89af9e01"


def test_signature_kat_frozen_vector() -> None:
    """THE CROWN: Verify frozen signature KAT and exact tolerance boundaries."""
    client, _ = _make_stripe_client(
        httpx.MockTransport(lambda req: httpx.Response(200)),
        webhook_secret=KAT_SECRET,
        webhook_tolerance_s=300,
    )

    sig_header = f"t={KAT_TIMESTAMP},v1={KAT_EXPECTED_V1}"

    # Exact timestamp match (tolerance = 0)
    result_exact = client.verify_webhook(
        payload=KAT_PAYLOAD,
        sig_header=sig_header,
        now=KAT_TIMESTAMP,
    )
    assert result_exact == {"id": "evt_1"}

    # Within tolerance: now = t + 299s
    result_plus_299 = client.verify_webhook(
        payload=KAT_PAYLOAD,
        sig_header=sig_header,
        now=KAT_TIMESTAMP + 299,
    )
    assert result_plus_299 == {"id": "evt_1"}

    # Boundary: now = t + 300s (tolerance inclusive)
    result_plus_300 = client.verify_webhook(
        payload=KAT_PAYLOAD,
        sig_header=sig_header,
        now=KAT_TIMESTAMP + 300,
    )
    assert result_plus_300 == {"id": "evt_1"}

    # Outside tolerance: now = t + 301s (expired) -> None
    result_plus_301 = client.verify_webhook(
        payload=KAT_PAYLOAD,
        sig_header=sig_header,
        now=KAT_TIMESTAMP + 301,
    )
    assert result_plus_301 is None

    # Past boundary: now = t - 299s
    result_minus_299 = client.verify_webhook(
        payload=KAT_PAYLOAD,
        sig_header=sig_header,
        now=KAT_TIMESTAMP - 299,
    )
    assert result_minus_299 == {"id": "evt_1"}

    # Past outside tolerance: now = t - 301s -> None
    result_minus_301 = client.verify_webhook(
        payload=KAT_PAYLOAD,
        sig_header=sig_header,
        now=KAT_TIMESTAMP - 301,
    )
    assert result_minus_301 is None

    # Callable clock support (now as callable)
    result_callable = client.verify_webhook(
        payload=KAT_PAYLOAD,
        sig_header=sig_header,
        now=lambda: float(KAT_TIMESTAMP),
    )
    assert result_callable == {"id": "evt_1"}


# -----------------------------------------------------------------------------
# 2. TAMPER MATRIX TESTS
# -----------------------------------------------------------------------------


def test_verify_webhook_tamper_matrix() -> None:
    """Test cryptographic tamper resistance across all header and payload axes."""
    client, _ = _make_stripe_client(
        httpx.MockTransport(lambda req: httpx.Response(200)),
        webhook_secret=KAT_SECRET,
    )

    valid_header = f"t={KAT_TIMESTAMP},v1={KAT_EXPECTED_V1}"

    # Axis 1: Payload byte-flip
    tampered_payload = b'{"id":"evt_2"}'
    assert (
        client.verify_webhook(
            payload=tampered_payload,
            sig_header=valid_header,
            now=KAT_TIMESTAMP,
        )
        is None
    )

    # Axis 2: Garbled timestamp t
    assert (
        client.verify_webhook(
            payload=KAT_PAYLOAD,
            sig_header=f"t=not_a_number,v1={KAT_EXPECTED_V1}",
            now=KAT_TIMESTAMP,
        )
        is None
    )
    assert (
        client.verify_webhook(
            payload=KAT_PAYLOAD,
            sig_header=f"t=,v1={KAT_EXPECTED_V1}",
            now=KAT_TIMESTAMP,
        )
        is None
    )
    assert (
        client.verify_webhook(
            payload=KAT_PAYLOAD,
            sig_header=f"v1={KAT_EXPECTED_V1}",
            now=KAT_TIMESTAMP,
        )
        is None
    )

    # Axis 3: Missing v1 signature
    assert (
        client.verify_webhook(
            payload=KAT_PAYLOAD,
            sig_header=f"t={KAT_TIMESTAMP}",
            now=KAT_TIMESTAMP,
        )
        is None
    )
    assert (
        client.verify_webhook(
            payload=KAT_PAYLOAD,
            sig_header=f"t={KAT_TIMESTAMP},v2=some_other_signature",
            now=KAT_TIMESTAMP,
        )
        is None
    )

    # Axis 4: Multiple v1 signatures (Stripe spec: ANY valid signature wins)
    multi_v1_header = f"t={KAT_TIMESTAMP},v1=bad_sig_00000000000000,v1={KAT_EXPECTED_V1}"
    assert client.verify_webhook(
        payload=KAT_PAYLOAD,
        sig_header=multi_v1_header,
        now=KAT_TIMESTAMP,
    ) == {"id": "evt_1"}

    multi_v1_header_trailing = f"t={KAT_TIMESTAMP},v1={KAT_EXPECTED_V1},v1=another_bad_sig_0000"
    assert client.verify_webhook(
        payload=KAT_PAYLOAD,
        sig_header=multi_v1_header_trailing,
        now=KAT_TIMESTAMP,
    ) == {"id": "evt_1"}

    # Axis 5: Uppercase-hex signature rejection (Stripe sends lowercase hex; strict)
    uppercase_header = f"t={KAT_TIMESTAMP},v1={KAT_EXPECTED_V1.upper()}"
    assert (
        client.verify_webhook(
            payload=KAT_PAYLOAD,
            sig_header=uppercase_header,
            now=KAT_TIMESTAMP,
        )
        is None
    )

    # Axis 6: Empty, whitespace, or invalid headers
    assert client.verify_webhook(payload=KAT_PAYLOAD, sig_header="", now=KAT_TIMESTAMP) is None
    assert client.verify_webhook(payload=KAT_PAYLOAD, sig_header="   ", now=KAT_TIMESTAMP) is None
    assert (
        client.verify_webhook(
            payload=KAT_PAYLOAD, sig_header="invalid_header_format", now=KAT_TIMESTAMP
        )
        is None
    )


# -----------------------------------------------------------------------------
# 3. VALID-SIGNATURE + MALFORMED JSON (ATTACK SIGNAL FORENSICS)
# -----------------------------------------------------------------------------


def test_verify_webhook_valid_sig_malformed_json_warning(caplog: pytest.LogCaptureFixture) -> None:
    """Valid cryptographic signature with invalid JSON returns None and logs WARNING."""
    client, _ = _make_stripe_client(
        httpx.MockTransport(lambda req: httpx.Response(200)),
        webhook_secret=KAT_SECRET,
    )

    malformed_payload = b"not_valid_json_payload_at_all"
    signed_payload = f"{KAT_TIMESTAMP}.".encode() + malformed_payload
    valid_sig_for_garbage = hmac.new(
        KAT_SECRET.encode(),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    header = f"t={KAT_TIMESTAMP},v1={valid_sig_for_garbage}"

    with caplog.at_level("WARNING"):
        caplog.clear()
        result = client.verify_webhook(
            payload=malformed_payload,
            sig_header=header,
            now=KAT_TIMESTAMP,
        )

    # Must return None (reject event)
    assert result is None

    # Must log high-priority warning for SIEM / audit tracking
    assert "stripe webhook: valid signature, invalid json" in caplog.text


def test_verify_webhook_valid_sig_non_dict_json_warning(caplog: pytest.LogCaptureFixture) -> None:
    """Valid signature with valid JSON array/string returns None and logs WARNING."""
    client, _ = _make_stripe_client(
        httpx.MockTransport(lambda req: httpx.Response(200)),
        webhook_secret=KAT_SECRET,
    )

    non_dict_payload = b"[1, 2, 3]"
    signed_payload = f"{KAT_TIMESTAMP}.".encode() + non_dict_payload
    valid_sig = hmac.new(
        KAT_SECRET.encode(),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    header = f"t={KAT_TIMESTAMP},v1={valid_sig}"

    with caplog.at_level("WARNING"):
        caplog.clear()
        result = client.verify_webhook(
            payload=non_dict_payload,
            sig_header=header,
            now=KAT_TIMESTAMP,
        )

    assert result is None
    assert "stripe webhook: valid signature, invalid json" in caplog.text


# -----------------------------------------------------------------------------
# 4. SECRET ABSENCE LAW
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secret_absence_law_in_logs_and_errors(caplog: pytest.LogCaptureFixture) -> None:
    """Secrets must NEVER leak into log output or exception representations."""
    raw_secret = "sk_test_super_secret_canary_value_xyz987"  # noqa: S105
    raw_webhook_secret = "whsec_canary_webhook_secret_value_123"  # noqa: S105

    def error_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": {"code": "bad_request"}})

    client, _ = _make_stripe_client(
        httpx.MockTransport(error_handler),
        secret_key=raw_secret,
        webhook_secret=raw_webhook_secret,
    )

    with caplog.at_level("INFO"):
        caplog.clear()
        with pytest.raises(IntegrationError) as exc_info:
            await client.create_payment_link(
                amount_minor=1000,
                currency="usd",
                description="Test",
                idempotency_key="key_1",
            )

    exc_str = str(exc_info.value)
    details_str = str(exc_info.value.details)
    logs_str = caplog.text

    # Assert neither secret appears anywhere in exception details or logs
    assert raw_secret not in exc_str
    assert raw_secret not in details_str
    assert raw_secret not in logs_str
    assert raw_webhook_secret not in exc_str
    assert raw_webhook_secret not in details_str
    assert raw_webhook_secret not in logs_str


# -----------------------------------------------------------------------------
# 5. CREATE_PAYMENT_LINK TESTS
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_payment_link_happy_path() -> None:
    """Happy path: generates Stripe payment link, captures Idempotency-Key and payload."""
    captured_requests: list[httpx.Request] = []

    expected_url = "https://checkout.stripe.com/c/pay/cs_test_a1b2c3d4"

    def handler(req: httpx.Request) -> httpx.Response:
        captured_requests.append(req)
        return httpx.Response(200, json={"url": expected_url, "id": "plink_123"})

    client, _ = _make_stripe_client(
        httpx.MockTransport(handler),
        secret_key="sk_test_key_sample_555",  # noqa: S106
    )

    url = await client.create_payment_link(
        amount_minor=1050,
        currency="usd",
        description="Flux Platform On-Ramp 10.50",
        idempotency_key="flx_idem_link_001",
    )

    assert url == expected_url
    assert len(captured_requests) == 1
    req = captured_requests[0]

    assert req.method == "POST"
    assert str(req.url) == "https://api.stripe.com/v1/payment_links"
    assert req.headers["Authorization"] == "Bearer sk_test_key_sample_555"
    assert req.headers["Idempotency-Key"] == "flx_idem_link_001"
    assert client.IDEMPOTENCY_HEADER == "Idempotency-Key"

    # Verify JSON structure
    body = orjson.loads(req.content)
    line_item = body["line_items"][0]
    assert line_item["price_data"]["currency"] == "usd"
    assert line_item["price_data"]["unit_amount"] == 1050
    assert line_item["price_data"]["product_data"]["name"] == "Flux Platform On-Ramp 10.50"
    assert line_item["quantity"] == 1


@pytest.mark.asyncio
async def test_create_payment_link_amount_validation() -> None:
    """Non-positive amounts raise ValueError before issuing any HTTP request."""
    client, _ = _make_stripe_client(httpx.MockTransport(lambda req: httpx.Response(200)))

    with pytest.raises(ValueError, match="Amount must be strictly positive"):
        await client.create_payment_link(
            amount_minor=0,
            currency="usd",
            description="Zero amount test",
            idempotency_key="idem_0",
        )

    with pytest.raises(ValueError, match="Amount must be strictly positive"):
        await client.create_payment_link(
            amount_minor=-500,
            currency="usd",
            description="Negative amount test",
            idempotency_key="idem_neg",
        )


@pytest.mark.asyncio
async def test_create_payment_link_currency_validation() -> None:
    """Unsupported currency raises ValueError; supported currencies normalize case."""
    client, _ = _make_stripe_client(
        httpx.MockTransport(lambda req: httpx.Response(200, json={"url": "https://stripe.com/pay"}))
    )

    # GBP is not in EXPONENTS table -> ValueError
    with pytest.raises(ValueError, match="Unsupported currency: 'gbp'"):
        await client.create_payment_link(
            amount_minor=1000,
            currency="gbp",
            description="GBP test",
            idempotency_key="idem_gbp",
        )

    # Uppercase USD accepted and normalized
    url_usd = await client.create_payment_link(
        amount_minor=1000,
        currency="USD",
        description="Uppercase USD test",
        idempotency_key="idem_usd_upper",
    )
    assert url_usd == "https://stripe.com/pay"

    # JPY (0 decimal places) accepted
    url_jpy = await client.create_payment_link(
        amount_minor=500,
        currency="jpy",
        description="JPY test",
        idempotency_key="idem_jpy",
    )
    assert url_jpy == "https://stripe.com/pay"


@pytest.mark.asyncio
async def test_create_payment_link_provider_drift_guards() -> None:
    """2xx responses missing 'url' or malformed JSON raise IntegrationError with phase=parse."""
    # Case 1: 200 OK without 'url'
    client_missing_url, _ = _make_stripe_client(
        httpx.MockTransport(lambda req: httpx.Response(200, json={"id": "plink_no_url"}))
    )
    with pytest.raises(IntegrationError) as exc_info1:
        await client_missing_url.create_payment_link(
            amount_minor=1050,
            currency="usd",
            description="Test",
            idempotency_key="key_drift_1",
        )
    assert exc_info1.value.details["phase"] == "parse"
    assert exc_info1.value.details["error"] == "missing_url"

    # Case 2: 200 OK with empty or non-string 'url'
    client_empty_url, _ = _make_stripe_client(
        httpx.MockTransport(lambda req: httpx.Response(200, json={"url": ""}))
    )
    with pytest.raises(IntegrationError) as exc_info2:
        await client_empty_url.create_payment_link(
            amount_minor=1050,
            currency="usd",
            description="Test",
            idempotency_key="key_drift_2",
        )
    assert exc_info2.value.details["phase"] == "parse"

    # Case 3: 200 OK with non-JSON response body
    client_bad_json, _ = _make_stripe_client(
        httpx.MockTransport(
            lambda req: httpx.Response(200, content=b"<html>upstream proxy error</html>")
        )
    )
    with pytest.raises(IntegrationError) as exc_info3:
        await client_bad_json.create_payment_link(
            amount_minor=1050,
            currency="usd",
            description="Test",
            idempotency_key="key_drift_3",
        )
    assert exc_info3.value.details["phase"] == "parse"
    assert exc_info3.value.details["error"] == "invalid_json"


# -----------------------------------------------------------------------------
# 6. PROVIDER-ERROR HOOK & PII-FREE BEHAVIOR
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_extract_provider_error_code_preserved_message_dropped(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """402 card_declined preserves machine code in details; drops message from details and logs."""
    sensitive_message = "The card was declined because customer account 9999 is delinquent."

    def error_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            402,
            json={
                "error": {
                    "code": "card_declined",
                    "message": sensitive_message,
                    "type": "card_error",
                }
            },
        )

    client, _ = _make_stripe_client(httpx.MockTransport(error_handler))

    with caplog.at_level("INFO"):
        caplog.clear()
        with pytest.raises(IntegrationError) as exc_info:
            await client.create_payment_link(
                amount_minor=2000,
                currency="usd",
                description="Declined card test",
                idempotency_key="idem_decline",
            )

    details = exc_info.value.details
    assert details["provider_error"] == "card_declined"
    assert details["provider"] == "stripe"
    assert details["status"] == "402"

    # Message must be strictly absent from details, exception string, and logs
    assert "message" not in details
    assert sensitive_message not in str(exc_info.value)
    assert sensitive_message not in caplog.text


# -----------------------------------------------------------------------------
# 7. HEALTHCHECK TESTS (BOOL LAW — NO RAISE)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_healthcheck_bool_law() -> None:
    """healthcheck() returns True on 200, False on 401/500/network error without raising."""
    # 200 OK -> True
    client_ok, _ = _make_stripe_client(
        httpx.MockTransport(lambda req: httpx.Response(200, json={"object": "balance"}))
    )
    assert await client_ok.healthcheck() is True

    # 401 Unauthorized -> False (catches IntegrationAuthError, returns False)
    client_401, _ = _make_stripe_client(
        httpx.MockTransport(
            lambda req: httpx.Response(401, json={"error": {"code": "invalid_api_key"}})
        )
    )
    assert await client_401.healthcheck() is False

    # 500 Internal Error -> False (catches IntegrationError, returns False)
    client_500, _ = _make_stripe_client(httpx.MockTransport(lambda req: httpx.Response(500)))
    assert await client_500.healthcheck() is False

    # Transport drop -> False (catches transport error, returns False)
    def transport_error(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused by upstream", request=req)

    client_dropped, _ = _make_stripe_client(httpx.MockTransport(transport_error))
    assert await client_dropped.healthcheck() is False


# -----------------------------------------------------------------------------
# 8. 401 -> INTEGRATIONAUTHERROR COMPOSED CONTRACT
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_401_raises_integration_auth_error() -> None:
    """Direct operational requests returning 401/403 raise non-retryable IntegrationAuthError."""

    def auth_fail_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": {"code": "api_key_expired", "type": "invalid_request_error"}},
        )

    client, _ = _make_stripe_client(httpx.MockTransport(auth_fail_handler))

    with pytest.raises(IntegrationAuthError) as exc_info:
        await client.create_payment_link(
            amount_minor=1050,
            currency="usd",
            description="Auth test",
            idempotency_key="key_auth_fail",
        )

    err = exc_info.value
    assert err.code == "integration_auth_error"
    assert err.status == 500
    assert err.retryable is False
    assert err.details["provider"] == "stripe"
    assert err.details["status"] == "401"
    assert err.details["provider_error"] == "api_key_expired"


# -----------------------------------------------------------------------------
# 9. ISOLATION LAW META-TEST
# -----------------------------------------------------------------------------


def test_stripe_adapter_isolation_law() -> None:
    """Assert stripe.py imports strictly within the allowed external adapter boundary."""
    stripe_path = REPO_ROOT / "src" / "fluxpay" / "integrations" / "stripe.py"
    assert stripe_path.is_file(), f"stripe.py not found at {stripe_path}"

    with stripe_path.open("r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=str(stripe_path))

    allowed_prefixes = (
        "fluxpay.shared.errors",
        "fluxpay.shared.logging",
        "fluxpay.shared.vault",
        "fluxpay.integrations",
    )

    forbidden_business_core = (
        "fluxpay.ledger",
        "fluxpay.payments",
        "fluxpay.risk",
        "fluxpay.registry",
        "fluxpay.wallet",
        "fluxpay.treasury",
        "fluxpay.gateway",
        "fluxpay.admin",
        "fluxpay.approvals",
        "fluxpay.audit",
        "fluxpay.notifications",
        "fluxpay.workers",
    )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if name.startswith("fluxpay."):
                    assert any(name.startswith(p) for p in allowed_prefixes), (
                        f"ISOLATION VIOLATION: '{name}' in stripe.py"
                    )
                for forbidden in forbidden_business_core:
                    assert not name.startswith(forbidden), (
                        f"BUSINESS CORE LEAK: '{name}' in stripe.py"
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                mod = node.module
                if mod.startswith("fluxpay.") or mod == "fluxpay":
                    assert any(mod.startswith(p) for p in allowed_prefixes), (
                        f"ISOLATION VIOLATION: '{mod}' in stripe.py"
                    )
                for forbidden in forbidden_business_core:
                    assert not mod.startswith(forbidden), (
                        f"BUSINESS CORE LEAK: '{mod}' in stripe.py"
                    )


# -----------------------------------------------------------------------------
# 10. DISABLED-MODE & CONFIG VALIDATOR & .ENV SYNC TESTS
# -----------------------------------------------------------------------------


def test_stripe_config_validators(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate Settings fields and webhook secret length validator."""
    monkeypatch.setenv("FLX_PG_DSN", "postgresql://test:test@localhost:5432/test")
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", "a" * 32)
    monkeypatch.setenv("FLX_KEYCLOAK_JWKS_URL", "https://idp.local/jwks")
    monkeypatch.setenv("FLX_KEYCLOAK_ISSUER", "https://idp.local")
    monkeypatch.setenv("FLX_KEYCLOAK_AUDIENCE", "https://api.local")

    # Webhook secret < 16 chars -> ValidationError
    with pytest.raises(ValidationError, match="Stripe webhook secret must be at least 16"):
        Settings(stripe_webhook_secret="short_secret")  # noqa: S106

    # Valid secret length >= 16 -> accepted
    valid_settings = Settings(
        stripe_secret_key="sk_test_example_key",  # noqa: S106
        stripe_webhook_secret="whsec_1234567890abcdef",  # noqa: S106
    )
    assert valid_settings.stripe_secret_key == "sk_test_example_key"  # noqa: S105
    assert valid_settings.stripe_webhook_secret == "whsec_1234567890abcdef"  # noqa: S105
    assert valid_settings.stripe_api_base == "https://api.stripe.com"
    assert valid_settings.stripe_webhook_tolerance_s == 300

    # Empty string normalization to None
    empty_settings = Settings(stripe_secret_key="", stripe_webhook_secret="")
    assert empty_settings.stripe_secret_key is None
    assert empty_settings.stripe_webhook_secret is None


def test_env_example_contains_task_52_fields() -> None:
    """Verify all Task 52 Settings fields are declared in .env.example."""
    env_example_path = REPO_ROOT / ".env.example"
    assert env_example_path.is_file()

    content = env_example_path.read_text(encoding="utf-8")

    task_52_vars = [
        "FLX_STRIPE_SECRET_KEY",
        "FLX_STRIPE_WEBHOOK_SECRET",
        "FLX_STRIPE_API_BASE",
        "FLX_STRIPE_WEBHOOK_TOLERANCE_S",
    ]
    for var in task_52_vars:
        assert var in content, f"Missing {var} in .env.example"


# -----------------------------------------------------------------------------
# 11. ANTI-CONVERSION & EXPONENTS TABLE TESTS
# -----------------------------------------------------------------------------


def test_anti_conversion_and_exponents_identity() -> None:
    """Test EXPONENTS table lookup and minor_to_major_str identity formatting."""
    assert EXPONENTS["usd"] == 2
    assert EXPONENTS["eur"] == 2
    assert EXPONENTS["jpy"] == 0

    assert minor_to_major_str(1050, "usd") == "1050"
    assert minor_to_major_str(2000, "eur") == "2000"
    assert minor_to_major_str(500, "jpy") == "500"

    with pytest.raises(ValueError, match="Unsupported currency"):
        minor_to_major_str(100, "gbp")
