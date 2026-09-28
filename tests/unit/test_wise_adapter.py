"""Pure unit tests for Wise external rail integration adapter and fiat stubs (Task 53).

TASK 53: WISE ADAPTER + FIAT RAIL STUBS
Verifies:
1. Signature KAT (the crown): Fixed secret, payload, and hardcoded frozen Base64
   HMAC signature with tamper matrix and Base64-vs-Hex confusion rejection.
2. Valid-sig + malformed JSON: Returns None and logs WARNING ("wise webhook:
   valid signature, invalid json").
3. customerTransactionId enforcement: Transfers enforce non-empty reference before HTTP,
   and customerTransactionId matches reference in outbound JSON.
4. Quote / Recipient / Transfer flows: Happy path, parameter mapping, and provider
   contract drift guard (phase="parse", missing quote id).
5. Provider-error hook: Machine code parsed, human message dropped from details & logs.
6. Composed auth error: 401 raises IntegrationAuthError without retries.
7. Healthcheck & IDEMPOTENCY_HEADER bool law: Healthcheck returns True/False without
   raising; IDEMPOTENCY_HEADER is strictly None (honest absence contract).
8. Fiat Rail Stubs: SWIFT, SEPA, ACH stubs report dead (False), raise NotImplementedError
   with Phase roadmap pointers, and expose frozen RailCapabilities records.
9. Isolation law meta-test: wise.py and fiat_stubs.py import strictly within allowlist.
10. Disabled-mode & sandbox-default config guard: Prod-default guard proven, .env sync.
11. Anti-conversion law: CURRENCY_EXPONENTS table and minor_to_major_str identity.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
from dataclasses import FrozenInstanceError, is_dataclass
from pathlib import Path

import httpx
import orjson
import pytest
from pydantic import ValidationError

from fluxpay.config import Settings
from fluxpay.integrations.fiat_stubs import (
    ACHStub,
    FiatRailStub,
    RailCapabilities,
    SEPAStub,
    SWIFTStub,
)
from fluxpay.integrations.wise import (
    CURRENCY_EXPONENTS,
    EXPONENTS,
    WiseClient,
    minor_to_major_str,
)
from fluxpay.shared.errors import IntegrationAuthError, IntegrationError

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _setup_structlog_stdlib() -> None:
    """Ensure structlog routes through stdlib logging so caplog captures records."""
    import structlog

    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory())


# -----------------------------------------------------------------------------
# Test Helper: WiseClient Factory with MockTransport
# -----------------------------------------------------------------------------


def _make_wise_client(
    transport: httpx.MockTransport,
    *,
    api_key: str = "wise_mock_api_key_12345",
    api_base: str = "https://api.sandbox.transferwise.tech",
    webhook_secret: str | None = "wise_whsec_test_kat_000",  # noqa: S107
    webhook_tolerance_s: int = 300,
) -> tuple[WiseClient, list[float]]:
    """Create a WiseClient wired to MockTransport with zero-sleep recorder."""
    sleep_calls: list[float] = []

    async def _mock_sleep(duration: float) -> None:
        sleep_calls.append(duration)

    http = httpx.AsyncClient(transport=transport)
    client = WiseClient(
        api_key=api_key,
        api_base=api_base,
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
# Fixed secret:      "wise_whsec_test_kat_000"
# Fixed payload:     b'{"id":"evt_wise_1"}'
# Expected Base64:   Hpk3lIl0AvRfbclazGJv0rQUunchNeJxZ30dR79v6do=
# Expected Hex:      1e993794897402f45f6dc95acc626fd2b414ba772135e271677d1d47bf6fe9da
#
# If this test fails, STOP THE LINE. Do not update this constant.
# Regeneration means the webhook cryptographic signature verification contract
# was broken, introducing a catastrophic payment security incident.
# -----------------------------------------------------------------------------

KAT_SECRET = "wise_whsec_test_kat_000"  # noqa: S105
KAT_PAYLOAD = b'{"id":"evt_wise_1"}'
KAT_EXPECTED_B64 = "Hpk3lIl0AvRfbclazGJv0rQUunchNeJxZ30dR79v6do="
KAT_EXPECTED_HEX = "1e993794897402f45f6dc95acc626fd2b414ba772135e271677d1d47bf6fe9da"


def test_signature_kat_frozen() -> None:
    """STOP-THE-LINE KAT: assert HMAC-SHA256 Base64 digest matches frozen constant."""
    client, _ = _make_wise_client(
        httpx.MockTransport(lambda r: httpx.Response(200)),
        webhook_secret=KAT_SECRET,
    )

    # Valid signature -> successfully parsed payload dict
    parsed = client.verify_webhook(
        payload=KAT_PAYLOAD,
        sig_header=KAT_EXPECTED_B64,
    )
    assert parsed == {"id": "evt_wise_1"}


def test_signature_tamper_matrix() -> None:
    """Tamper matrix: flipped bytes, wrong secret, and garbled headers reject."""
    client, _ = _make_wise_client(
        httpx.MockTransport(lambda r: httpx.Response(200)),
        webhook_secret=KAT_SECRET,
    )

    # 1. Payload byte-flip
    tampered_payload = b'{"id":"evt_wise_2"}'
    assert client.verify_webhook(payload=tampered_payload, sig_header=KAT_EXPECTED_B64) is None

    # 2. Wrong secret
    assert (
        client.verify_webhook(
            payload=KAT_PAYLOAD,
            sig_header=KAT_EXPECTED_B64,
            webhook_secret="wrong_secret_123456",  # noqa: S106
        )
        is None
    )

    # 3. Empty or garbled signature header
    assert client.verify_webhook(payload=KAT_PAYLOAD, sig_header="") is None
    assert client.verify_webhook(payload=KAT_PAYLOAD, sig_header="not_base64_!@#$") is None


def test_base64_vs_hex_confusion_case() -> None:
    """Strict scheme enforcement: Hex digest in sig_header must return None."""
    client, _ = _make_wise_client(
        httpx.MockTransport(lambda r: httpx.Response(200)),
        webhook_secret=KAT_SECRET,
    )

    # Hex string instead of Base64 -> None
    assert client.verify_webhook(payload=KAT_PAYLOAD, sig_header=KAT_EXPECTED_HEX) is None


def test_valid_sig_malformed_json_logs_warning(caplog: pytest.LogCaptureFixture) -> None:
    """Valid signature with unparseable JSON payload returns None and logs WARNING."""
    client, _ = _make_wise_client(
        httpx.MockTransport(lambda r: httpx.Response(200)),
        webhook_secret=KAT_SECRET,
    )

    malformed_payload = b'{"invalid_json": broken...'
    raw_digest = hmac.new(KAT_SECRET.encode("utf-8"), malformed_payload, hashlib.sha256).digest()
    valid_sig = base64.b64encode(raw_digest).decode("ascii")

    caplog.clear()
    with caplog.at_level("WARNING"):
        result = client.verify_webhook(payload=malformed_payload, sig_header=valid_sig)

    assert result is None
    assert any(
        "wise webhook: valid signature, invalid json" in rec.message for rec in caplog.records
    )


def test_webhook_optional_timestamp_tolerance() -> None:
    """Optional payload timestamp: valid within tolerance, rejected outside tolerance."""
    client, _ = _make_wise_client(
        httpx.MockTransport(lambda r: httpx.Response(200)),
        webhook_secret=KAT_SECRET,
        webhook_tolerance_s=300,
    )

    base_time = 1700000000
    payload_dict = {"id": "evt_ts", "timestamp": base_time}
    payload_bytes = orjson.dumps(payload_dict)
    raw_digest = hmac.new(KAT_SECRET.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    sig = base64.b64encode(raw_digest).decode("ascii")

    # Within tolerance (now == base_time)
    assert (
        client.verify_webhook(payload=payload_bytes, sig_header=sig, now=base_time) == payload_dict
    )

    # Within tolerance (now == base_time + 299s)
    assert (
        client.verify_webhook(payload=payload_bytes, sig_header=sig, now=base_time + 299)
        == payload_dict
    )

    # Outside tolerance (now == base_time + 301s) -> None
    assert client.verify_webhook(payload=payload_bytes, sig_header=sig, now=base_time + 301) is None


# -----------------------------------------------------------------------------
# 2. CUSTOMER_TRANSACTION_ID & IDEMPOTENCY HANDLE LAW
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_transfer_enforces_reference_and_maps_idempotency_field() -> None:
    """create_transfer enforces non-empty reference and captures customerTransactionId."""
    captured_requests: list[httpx.Request] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        captured_requests.append(req)
        return httpx.Response(200, json={"id": 9901, "status": "incoming_payment_waiting"})

    client, _ = _make_wise_client(httpx.MockTransport(_handler))

    # Empty reference raises ValueError BEFORE any HTTP request
    with pytest.raises(ValueError, match=r"reference .* must be non-empty for idempotency"):
        await client.create_transfer(quote_id="quote_123", recipient_account_id=456, reference="")

    with pytest.raises(ValueError, match=r"reference .* must be non-empty for idempotency"):
        await client.create_transfer(
            quote_id="quote_123",
            recipient_account_id=456,
            reference="   ",
        )

    assert len(captured_requests) == 0

    # Happy path
    ref = "flx_tx_safe_dedup_001"
    res = await client.create_transfer(
        quote_id="quote_123",
        recipient_account_id=456,
        reference=ref,
    )
    assert res["id"] == 9901
    assert len(captured_requests) == 1

    req = captured_requests[0]
    assert req.method == "POST"
    assert req.url.path == "/v1/transfers"
    body = orjson.loads(req.content)
    assert body["customerTransactionId"] == ref
    assert body["targetAccount"] == 456
    assert body["quote"] == "quote_123"


# -----------------------------------------------------------------------------
# 3. QUOTE / RECIPIENT ACCOUNT / PROFILE FLOWS
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_quote_validations_and_drift_guard() -> None:
    """create_quote validates currencies, positive amounts, and missing id drift guard."""
    captured_requests: list[httpx.Request] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        captured_requests.append(req)
        body = orjson.loads(req.content)
        if body.get("amount") == 999999:
            # Simulate contract drift: 200 without 'id'
            return httpx.Response(200, json={"source": "usd", "target": "eur"})
        return httpx.Response(200, json={"id": "quote_guid_001", "rate": 0.92})

    client, _ = _make_wise_client(httpx.MockTransport(_handler))

    # Validation: unknown currency
    with pytest.raises(ValueError, match="Unsupported source currency: 'jpy'"):
        await client.create_quote(source_currency="jpy", target_currency="eur", amount_minor=1000)

    with pytest.raises(ValueError, match="Unsupported target currency: 'cad'"):
        await client.create_quote(source_currency="usd", target_currency="cad", amount_minor=1000)

    # Validation: non-positive amount
    with pytest.raises(ValueError, match="Amount must be strictly positive"):
        await client.create_quote(source_currency="usd", target_currency="eur", amount_minor=0)

    with pytest.raises(ValueError, match="Amount must be strictly positive"):
        await client.create_quote(source_currency="usd", target_currency="eur", amount_minor=-500)

    assert len(captured_requests) == 0

    # Happy path
    quote = await client.create_quote(
        source_currency="usd",
        target_currency="eur",
        amount_minor=1050,
    )
    assert quote["id"] == "quote_guid_001"

    # Contract drift guard: 200 without "id" raises IntegrationError phase=parse
    with pytest.raises(IntegrationError) as exc_info:
        await client.create_quote(source_currency="usd", target_currency="eur", amount_minor=999999)

    assert exc_info.value.details.get("phase") == "parse"
    assert exc_info.value.details.get("error") == "missing_id"


@pytest.mark.asyncio
async def test_get_profile_and_create_recipient_account() -> None:
    """Verify get_profile extracts personal profile and create_recipient passes through dict."""

    def _handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/profiles":
            return httpx.Response(
                200,
                json=[
                    {"id": 101, "type": "business", "details": {"name": "BizCorp"}},
                    {"id": 102, "type": "personal", "details": {"firstName": "Alice"}},
                ],
            )
        if req.url.path == "/v1/accounts":
            body = orjson.loads(req.content)
            return httpx.Response(200, json={"id": 7001, "accountHolderName": body.get("name")})
        return httpx.Response(404)

    client, _ = _make_wise_client(httpx.MockTransport(_handler))

    profile = await client.get_profile()
    assert profile["id"] == 102
    assert profile["type"] == "personal"

    recipient = await client.create_recipient_account(
        account_json={"currency": "EUR", "type": "iban", "name": "Bob Smith"}
    )
    assert recipient["id"] == 7001
    assert recipient["accountHolderName"] == "Bob Smith"


# -----------------------------------------------------------------------------
# 4. PROVIDER ERROR HOOK & AUTH ERROR COMPOSITION
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_provider_error_hook_code_extracted_message_dropped(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """extract_provider_error parses error code while dropping human message from details & logs."""
    sensitive_msg = "Account IBAN DE89370400440532013000 is frozen"

    def _handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={
                "code": "ACCOUNT_FROZEN",
                "message": sensitive_msg,
            },
        )

    client, _ = _make_wise_client(httpx.MockTransport(_handler))

    caplog.clear()
    with pytest.raises(IntegrationError) as exc_info:
        await client.create_quote(source_currency="usd", target_currency="eur", amount_minor=1000)

    details = exc_info.value.details
    assert details["provider_error"] == "ACCOUNT_FROZEN"
    assert details["provider"] == "wise"
    assert details["status"] == "422"

    # Sensitive message ABSENT from exception details
    assert "message" not in details
    assert sensitive_msg not in str(exc_info.value)

    # Sensitive message ABSENT from logs
    log_text = " ".join(rec.message for rec in caplog.records)
    assert sensitive_msg not in log_text


@pytest.mark.asyncio
async def test_401_maps_to_integration_auth_error() -> None:
    """401 responses raise IntegrationAuthError immediately without retrying."""
    attempts = 0

    def _handler(req: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(401, json={"code": "INVALID_TOKEN", "message": "Bad token"})

    client, sleep_calls = _make_wise_client(httpx.MockTransport(_handler))

    with pytest.raises(IntegrationAuthError):
        await client.get_profile()

    assert attempts == 1
    assert len(sleep_calls) == 0


# -----------------------------------------------------------------------------
# 5. HEALTHCHECK & IDEMPOTENCY_HEADER ABSENCE CONTRACT
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_healthcheck_bool_law() -> None:
    """Healthcheck returns True on 200, False on 401/500/network error without raising."""
    # 200 -> True
    c_ok, _ = _make_wise_client(httpx.MockTransport(lambda r: httpx.Response(200, json=[])))
    assert await c_ok.healthcheck() is True

    # 401 -> False
    c_auth, _ = _make_wise_client(httpx.MockTransport(lambda r: httpx.Response(401)))
    assert await c_auth.healthcheck() is False

    # 500 -> False
    c_err, _ = _make_wise_client(httpx.MockTransport(lambda r: httpx.Response(500)))
    assert await c_err.healthcheck() is False


def test_idempotency_header_is_none_meta_assert() -> None:
    """Honest absence contract: WiseClient.IDEMPOTENCY_HEADER is strictly None."""
    assert WiseClient.IDEMPOTENCY_HEADER is None
    client, _ = _make_wise_client(httpx.MockTransport(lambda r: httpx.Response(200)))
    assert client.IDEMPOTENCY_HEADER is None


# -----------------------------------------------------------------------------
# 6. FIAT RAIL STUBS
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fiat_rail_stubs_dead_law_and_not_implemented() -> None:
    """Stubs report dead on healthcheck and raise NotImplementedError with Phase pointers."""
    stubs: list[FiatRailStub] = [SWIFTStub(), SEPAStub(), ACHStub()]

    for stub in stubs:
        # Dead-alive law: healthcheck is unconditionally False
        assert await stub.healthcheck() is False

        # NotImplementedError carries Phase pointer
        with pytest.raises(NotImplementedError) as exc_info:
            await stub.initiate_transfer()

        err_msg = str(exc_info.value)
        assert f"Phase {stub.capabilities.phase}" in err_msg
        assert stub.capabilities.rail.upper() in err_msg


def test_rail_capabilities_frozen_and_valid() -> None:
    """Capabilities records are frozen dataclasses with exact roadmap attributes."""
    swift = SWIFTStub()
    sepa = SEPAStub()
    ach = ACHStub()

    assert is_dataclass(RailCapabilities)

    # SWIFT: Phase 3
    assert swift.capabilities.rail == "swift"
    assert swift.capabilities.implemented is False
    assert swift.capabilities.phase == 3
    assert "IBAN+BIC" in swift.capabilities.flow_summary

    # SEPA: Phase 2
    assert sepa.capabilities.rail == "sepa"
    assert sepa.capabilities.implemented is False
    assert sepa.capabilities.phase == 2
    assert "Wise" in sepa.capabilities.flow_summary

    # ACH: Phase 2
    assert ach.capabilities.rail == "ach"
    assert ach.capabilities.implemented is False
    assert ach.capabilities.phase == 2
    assert "NACHA" in ach.capabilities.flow_summary

    # Immutability
    with pytest.raises(FrozenInstanceError):
        swift.capabilities.implemented = True  # type: ignore[misc]


# -----------------------------------------------------------------------------
# 7. ISOLATION LAW META-TEST (WISE + STUBS)
# -----------------------------------------------------------------------------


def test_isolation_law_wise_and_stubs() -> None:
    """Assert wise.py and fiat_stubs.py import ONLY allowed dependencies."""
    target_files = [
        REPO_ROOT / "src" / "fluxpay" / "integrations" / "wise.py",
        REPO_ROOT / "src" / "fluxpay" / "integrations" / "fiat_stubs.py",
    ]

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

    for file_path in target_files:
        assert file_path.is_file(), f"Missing file: {file_path}"
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name
                    if name.startswith("fluxpay."):
                        assert any(name.startswith(p) for p in allowed_prefixes), (
                            f"ISOLATION VIOLATION: '{name}' in {file_path.name}"
                        )
                    for forbidden in forbidden_business_core:
                        assert not name.startswith(forbidden), (
                            f"BUSINESS CORE LEAK: '{name}' in {file_path.name}"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    mod = node.module
                    if mod.startswith("fluxpay.") or mod == "fluxpay":
                        assert any(mod.startswith(p) for p in allowed_prefixes), (
                            f"ISOLATION VIOLATION: '{mod}' in {file_path.name}"
                        )
                    for forbidden in forbidden_business_core:
                        assert not mod.startswith(forbidden), (
                            f"BUSINESS CORE LEAK: '{mod}' in {file_path.name}"
                        )


# -----------------------------------------------------------------------------
# 8. CONFIG VALIDATORS, SANDBOX DEFAULT GUARD, & .ENV SYNC
# -----------------------------------------------------------------------------


def test_wise_config_validators(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate Wise Settings fields, sandbox default guard, and https validator."""
    monkeypatch.setenv("FLX_PG_DSN", "postgresql://test:test@localhost:5432/test")
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", "a" * 32)
    monkeypatch.setenv("FLX_KEYCLOAK_JWKS_URL", "https://idp.local/jwks")
    monkeypatch.setenv("FLX_KEYCLOAK_ISSUER", "https://idp.local")
    monkeypatch.setenv("FLX_KEYCLOAK_AUDIENCE", "https://api.local")

    # Sandbox default guard: defaults to sandbox URL
    default_settings = Settings()
    assert default_settings.wise_api_base == "https://api.sandbox.transferwise.tech"
    assert default_settings.wise_api_key is None
    assert default_settings.wise_webhook_secret is None
    assert default_settings.wise_webhook_tolerance_s == 300

    # Non-https base URL -> ValidationError
    with pytest.raises(ValidationError, match="Wise API base URL must start with 'https://'"):
        Settings(wise_api_base="http://api.insecure.wise.local")

    # Empty string normalization to None
    empty_settings = Settings(wise_api_key="", wise_webhook_secret="")
    assert empty_settings.wise_api_key is None
    assert empty_settings.wise_webhook_secret is None


def test_env_example_contains_task_53_fields() -> None:
    """Verify all Task 53 Settings fields are declared in .env.example."""
    env_example_path = REPO_ROOT / ".env.example"
    assert env_example_path.is_file()

    content = env_example_path.read_text(encoding="utf-8")

    task_53_vars = [
        "FLX_WISE_API_KEY",
        "FLX_WISE_API_BASE",
        "FLX_WISE_WEBHOOK_SECRET",
        "FLX_WISE_WEBHOOK_TOLERANCE_S",
    ]
    for var in task_53_vars:
        assert var in content, f"Missing {var} in .env.example"


# -----------------------------------------------------------------------------
# 9. ANTI-CONVERSION LAW & CURRENCY_EXPONENTS TABLE
# -----------------------------------------------------------------------------


def test_anti_conversion_and_currency_exponents_identity() -> None:
    """Test CURRENCY_EXPONENTS table lookup and minor_to_major_str identity formatting."""
    assert CURRENCY_EXPONENTS["usd"] == 2
    assert CURRENCY_EXPONENTS["eur"] == 2
    assert CURRENCY_EXPONENTS["gbp"] == 2
    assert EXPONENTS is CURRENCY_EXPONENTS

    assert minor_to_major_str(1050, "usd") == "1050"
    assert minor_to_major_str(2500, "eur") == "2500"
    assert minor_to_major_str(750, "gbp") == "750"

    with pytest.raises(ValueError, match="Unsupported currency: 'jpy'"):
        minor_to_major_str(100, "jpy")
