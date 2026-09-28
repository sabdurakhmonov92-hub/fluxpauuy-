"""Pure unit tests for KYC provider integration adapters (Block J, Task 55).

==============================================================================
TASK 55 VERIFICATION SUITE
==============================================================================
1. SUMSUB SIGNATURE KAT:
   Fixed (ts, method, path, body, secret) -> hardcoded frozen HMAC hex.
   STOP-THE-LINE comment: formula drift = regenerate KAT = breaking change alarm.
   Header capture: X-App-Access-Ts == injected ts, X-App-Access-Sig == expected,
   X-App-Token == injected api_key.
2. SUMSUB WEBHOOK DIGEST KAT:
   Fixed (payload, secret) -> hardcoded frozen HMAC hex.
   Tamper matrix: byte-flip, missing header, wrong secret.
   Valid signature + malformed JSON -> returns None and logs WARNING.
3. STATUS MAPPING TABLES FROZEN:
   Sumsub: (reviewStatus, reviewAnswer) -> normalized status.
   Trulioo: RecordStatus -> normalized status.
   Unknown combos -> 'pending' safe default with raw carried.
4. MANUAL PROVIDER HONESTY:
   start_verification -> VerificationStart(ref=subject_ref, redirect_url=None).
   fetch_status -> KycState('pending', {}).
   verify_webhook -> None.
   healthcheck -> True.
5. TWILIO SMS STUB:
   healthcheck -> False.
   send -> NotImplementedError with A2P registration flow doc.
6. ISOLATION LAW META-TEST:
   AST check over src/fluxpay/integrations/kyc/*.py and sms.py.
7. CONFIG & DISABLED-MODE MAPPING:
   Default 'manual', invalid rejected, unconfigured omitted.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import logging
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from fluxpay.config import Settings
from fluxpay.integrations.kyc.manual import ManualProvider
from fluxpay.integrations.kyc.protocol import KycProvider, KycState, VerificationStart
from fluxpay.integrations.kyc.sumsub import FORMULA_DOC, SUMSUB_STATUS_MAP, SumsubProvider
from fluxpay.integrations.kyc.trulioo import TRULIOO_STATUS_MAP, TruliooProvider
from fluxpay.integrations.sms import TwilioSmsStub
from fluxpay.registry.kyc_service import KycOrchestrator
from fluxpay.shared.errors import ValidationError as FluxValidationError

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _setup_structlog_stdlib() -> None:
    """Ensure structlog routes through stdlib logging so caplog captures records."""
    import structlog

    structlog.configure(logger_factory=structlog.stdlib.LoggerFactory())


async def _noop_sleep(_seconds: float) -> None:
    """Zero-sleep coroutine for deterministic unit testing."""
    return None


def _fixed_clock() -> float:
    """Fixed monotonic clock."""
    return 1000.0


# -----------------------------------------------------------------------------
# 1. SUMSUB SIGNATURE KAT & HEADER CAPTURE
# -----------------------------------------------------------------------------


def test_sumsub_formula_doc_frozen() -> None:
    """Ensure the documented signature formula string is permanently frozen."""
    assert FORMULA_DOC == "ts + method.upper() + path_with_query + (body if body else '')"


def test_sumsub_request_signature_kat() -> None:
    """STOP-THE-LINE: Known Answer Test for Sumsub request signature.

    If Sumsub alters their App Access signature calculation, this test MUST fail.
    Formula: HMAC-SHA256(secret_key, ts + method.upper() + path_with_query + body)
    Confirmed against Sumsub official API documentation.
    """
    secret = "sbx_test_app_secret_67890"  # noqa: S105
    token = "sbx_test_app_token_12345"  # noqa: S105
    ts = 1700000000
    method = "POST"
    path = "/resources/applicants?levelName=basic-kyc-level"
    body = b'{"externalUserId":"test_subject_123"}'

    # The frozen KAT digest:
    # HMAC-SHA256(sbx_test_app_secret_67890,
    # 1700000000POST/resources/applicants?levelName=basic-kyc-level
    # {"externalUserId":"test_subject_123"})
    expected_hex = "997e2d464beb65367db1f62c5e82eaf8946e68c075a7c264dc09f557befa35af"

    provider = SumsubProvider(
        api_key=token,
        secret_key=secret,
        http=httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200))),
        ts_fn=lambda: ts,
    )

    headers = provider._auth_headers(method=method, path=path, body=body)

    assert headers["X-App-Token"] == token
    assert headers["X-App-Access-Ts"] == str(ts)
    assert headers["X-App-Access-Sig"] == expected_hex


# -----------------------------------------------------------------------------
# 2. SUMSUB WEBHOOK DIGEST KAT & TAMPER MATRIX
# -----------------------------------------------------------------------------


def test_sumsub_webhook_digest_kat_and_tamper_matrix(caplog: pytest.LogCaptureFixture) -> None:
    """STOP-THE-LINE: Known Answer Test for Sumsub webhook verification.

    Sumsub webhooks carry X-Payload-Digest = HEX(HMAC-SHA256(secret, payload)).
    """
    secret = "sbx_test_app_secret_67890"  # noqa: S105
    payload = (
        b'{"type":"applicantReviewed","applicantId":"app_123",'
        b'"reviewStatus":"completed","reviewResult":{"reviewAnswer":"GREEN"}}'
    )

    # The frozen KAT digest
    expected_hex = "5a5a516cf0bf954d72aa2e6adaf73218241b41c10470cdb7377e289e38667bf9"

    provider = SumsubProvider(
        api_key="token",
        secret_key=secret,
        http=httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200))),
    )

    # 1. Valid signature
    verified = provider.verify_webhook(
        payload=payload,
        headers={"X-Payload-Digest": expected_hex},
    )
    assert verified is not None
    assert verified["type"] == "applicantReviewed"
    assert verified["applicantId"] == "app_123"

    # 2. Case-insensitive header name matching
    verified_lower = provider.verify_webhook(
        payload=payload,
        headers={"x-payload-digest": expected_hex.upper()},
    )
    assert verified_lower is not None
    assert verified_lower["applicantId"] == "app_123"

    # 3. Tamper matrix: Byte-flip payload
    tampered_payload = (
        b'{"type":"applicantReviewed","applicantId":"app_999",'
        b'"reviewStatus":"completed","reviewResult":{"reviewAnswer":"GREEN"}}'
    )
    assert (
        provider.verify_webhook(
            payload=tampered_payload,
            headers={"X-Payload-Digest": expected_hex},
        )
        is None
    )

    # 4. Tamper matrix: Altered signature
    bad_sig = "a" * 64
    assert (
        provider.verify_webhook(
            payload=payload,
            headers={"X-Payload-Digest": bad_sig},
        )
        is None
    )

    # 5. Tamper matrix: Missing header
    assert provider.verify_webhook(payload=payload, headers={}) is None

    # 6. Valid signature + Malformed JSON -> None + WARNING log (Task 52 nuance)
    caplog.set_level(logging.WARNING)
    malformed_payload = b"not_valid_json_at_all"
    malformed_sig = hmac.new(secret.encode(), malformed_payload, hashlib.sha256).hexdigest().lower()

    bad_json_res = provider.verify_webhook(
        payload=malformed_payload,
        headers={"X-Payload-Digest": malformed_sig},
    )
    assert bad_json_res is None
    assert any(
        "sumsub_webhook_valid_signature_malformed_json" in rec.message for rec in caplog.records
    )


# -----------------------------------------------------------------------------
# 3. STATUS MAPPING TABLES FROZEN (SAFE DEFAULTS)
# -----------------------------------------------------------------------------


def test_sumsub_status_mapping_table_frozen() -> None:
    """Verify frozen Sumsub status mapping and safe default fallbacks."""
    # Frozen positive mappings
    assert SUMSUB_STATUS_MAP[("completed", "GREEN")] == "cleared"
    assert SUMSUB_STATUS_MAP[("completed", "RED")] == "declined"
    assert SUMSUB_STATUS_MAP[("completed", "YELLOW")] == "pending"
    assert SUMSUB_STATUS_MAP[("pending", None)] == "pending"
    assert SUMSUB_STATUS_MAP[("pending", "GREEN")] == "pending"
    assert SUMSUB_STATUS_MAP[("pending", "RED")] == "declined"
    assert SUMSUB_STATUS_MAP[("init", None)] == "pending"
    assert SUMSUB_STATUS_MAP[("prechecked", None)] == "pending"
    assert SUMSUB_STATUS_MAP[("queued", None)] == "pending"
    assert SUMSUB_STATUS_MAP[("onHold", None)] == "pending"


@pytest.mark.asyncio
async def test_sumsub_fetch_status_known_and_unknown_combos() -> None:
    """SumsubProvider.fetch_status maps statuses correctly and falls back to pending."""
    responses: list[dict[str, Any]] = [
        {"reviewStatus": "completed", "reviewResult": {"reviewAnswer": "GREEN"}},
        {"reviewStatus": "completed", "reviewResult": {"reviewAnswer": "RED"}},
        {"reviewStatus": "alienStatus", "reviewResult": {"reviewAnswer": "PURPLE"}},
    ]
    idx = 0

    def mock_transport(request: httpx.Request) -> httpx.Response:
        nonlocal idx
        res = responses[idx]
        idx += 1
        return httpx.Response(200, json=res)

    provider = SumsubProvider(
        api_key="token",
        secret_key="secret",  # noqa: S106
        http=httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)),
    )

    # 1. GREEN -> cleared
    state1 = await provider.fetch_status("app_1")
    assert state1.status == "cleared"
    assert state1.raw["reviewStatus"] == "completed"

    # 2. RED -> declined
    state2 = await provider.fetch_status("app_2")
    assert state2.status == "declined"

    # 3. Unknown combo -> pending + raw carried (safe default law)
    state3 = await provider.fetch_status("app_3")
    assert state3.status == "pending"
    assert state3.raw["reviewStatus"] == "alienStatus"


def test_trulioo_status_mapping_table_frozen() -> None:
    """Verify frozen Trulioo status mapping and safe defaults."""
    assert TRULIOO_STATUS_MAP["match"] == "cleared"
    assert TRULIOO_STATUS_MAP["nomatch"] == "declined"
    assert TRULIOO_STATUS_MAP["pending"] == "pending"
    assert TRULIOO_STATUS_MAP["completed"] == "cleared"
    assert TRULIOO_STATUS_MAP["fail"] == "declined"


@pytest.mark.asyncio
async def test_trulioo_fetch_status_known_and_unknown_combos() -> None:
    """TruliooProvider.fetch_status maps statuses correctly."""
    responses: list[dict[str, Any]] = [
        {"Record": {"RecordStatus": "match"}},
        {"Record": {"RecordStatus": "nomatch"}},
        {"Record": {"RecordStatus": "unknown_value"}},
    ]
    idx = 0

    def mock_transport(request: httpx.Request) -> httpx.Response:
        nonlocal idx
        res = responses[idx]
        idx += 1
        return httpx.Response(200, json=res)

    provider = TruliooProvider(
        api_key="key",
        http=httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)),
    )

    state1 = await provider.fetch_status("tx_1")
    assert state1.status == "cleared"

    state2 = await provider.fetch_status("tx_2")
    assert state2.status == "declined"

    state3 = await provider.fetch_status("tx_3")
    assert state3.status == "pending"
    assert state3.raw["Record"]["RecordStatus"] == "unknown_value"


# -----------------------------------------------------------------------------
# 4. MANUAL PROVIDER HONESTY
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_manual_provider_honest_methods_and_ref_roundtrip() -> None:
    """ManualProvider: zero I/O, pending status, None webhook, True healthcheck."""
    provider = ManualProvider()

    # Protocol conformance
    assert isinstance(provider, KycProvider)

    # 1. start_verification returns subject_ref as provider_ref
    subject_uuid = "12345678-1234-5678-1234-567812345678"
    start_res = await provider.start_verification(subject_ref=subject_uuid)
    assert isinstance(start_res, VerificationStart)
    assert start_res.ref == subject_uuid
    assert start_res.redirect_url is None

    # 2. fetch_status returns pending forever
    state = await provider.fetch_status(subject_uuid)
    assert isinstance(state, KycState)
    assert state.status == "pending"
    assert state.raw == {}

    # 3. verify_webhook returns None
    assert provider.verify_webhook(payload=b"test", headers={}) is None

    # 4. healthcheck returns True (admin is the engine)
    assert await provider.healthcheck() is True


# -----------------------------------------------------------------------------
# 5. TWILIO SMS STUB
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_twilio_sms_stub() -> None:
    """TwilioSmsStub: dead healthcheck, NotImplementedError with A2P flow doc."""
    stub = TwilioSmsStub(
        account_sid="AC123",
        auth_token="token",  # noqa: S106
        from_number="+15551234567",
    )

    assert await stub.healthcheck() is False

    with pytest.raises(NotImplementedError) as exc_info:
        await stub.send(to="+15559876543", body="Security code: 123456")

    msg = str(exc_info.value)
    assert "A2P 10DLC" in msg
    assert "The Campaign Registry" in msg
    assert "Task 43" in msg


# -----------------------------------------------------------------------------
# 6. PROVIDER START & HEALTHCHECK UNIT TESTS
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sumsub_start_verification_and_healthcheck() -> None:
    """SumsubProvider: start_verification handles applicant + token calls."""
    captured_requests: list[httpx.Request] = []

    def mock_transport(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        if "/resources/applicants?" in str(request.url):
            return httpx.Response(201, json={"id": "applicant_sumsub_123"})
        if "/resources/accessTokens?" in str(request.url):
            return httpx.Response(
                200,
                json={"token": "tok_xyz", "url": "https://cockpit.sumsub.com/hosted/tok_xyz"},
            )
        if "/resources/status/api" in str(request.url):
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404)

    provider = SumsubProvider(
        api_key="sbx_key",
        secret_key="sbx_sec",  # noqa: S106
        http=httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)),
    )

    assert isinstance(provider, KycProvider)

    # 1. start_verification
    res = await provider.start_verification(subject_ref="usr_001")
    assert res.ref == "applicant_sumsub_123"
    assert res.redirect_url == "https://cockpit.sumsub.com/hosted/tok_xyz"

    # 2. healthcheck
    assert await provider.healthcheck() is True

    # Check headers were attached
    req0 = captured_requests[0]
    assert "X-App-Token" in req0.headers
    assert "X-App-Access-Sig" in req0.headers
    assert "X-App-Access-Ts" in req0.headers


@pytest.mark.asyncio
async def test_trulioo_start_verification_and_healthcheck() -> None:
    """TruliooProvider: start_verification TestEntity call and healthcheck."""

    def mock_transport(request: httpx.Request) -> httpx.Response:
        if "/verifications/v1/verify" in str(request.url):
            return httpx.Response(200, json={"TransactionID": "tx_trulioo_456"})
        if "/connection/v1/sayhello/test-connection" in str(request.url):
            return httpx.Response(200, json={"status": "connected"})
        return httpx.Response(404)

    provider = TruliooProvider(
        api_key="trulioo_key",
        http=httpx.AsyncClient(transport=httpx.MockTransport(mock_transport)),
    )

    assert isinstance(provider, KycProvider)

    res = await provider.start_verification(subject_ref="subj_999")
    assert res.ref == "tx_trulioo_456"
    assert res.redirect_url is None

    assert await provider.healthcheck() is True
    assert provider.verify_webhook(payload=b"test", headers={}) is None


@pytest.mark.asyncio
async def test_provider_healthchecks_return_false_on_error() -> None:
    """Healthchecks return False on HTTP error or connection drops (never raise)."""

    def error_transport(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"})

    sumsub = SumsubProvider(
        api_key="key",
        secret_key="sec",  # noqa: S106
        http=httpx.AsyncClient(transport=httpx.MockTransport(error_transport)),
    )
    assert await sumsub.healthcheck() is False

    trulioo = TruliooProvider(
        api_key="key",
        http=httpx.AsyncClient(transport=httpx.MockTransport(error_transport)),
    )
    assert await trulioo.healthcheck() is False


def test_provider_error_code_extraction() -> None:
    """Verify provider error extraction isolates machine code and drops PII."""
    sumsub = SumsubProvider(
        api_key="k",
        secret_key="s",  # noqa: S106
        http=httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200))),
    )
    resp_sumsub = httpx.Response(
        400,
        json={"errorCode": 105, "message": "Applicant Jane Doe failed check"},
    )
    assert sumsub.extract_provider_error(resp_sumsub) == "105"

    trulioo = TruliooProvider(
        api_key="k",
        http=httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200))),
    )
    resp_trulioo = httpx.Response(
        400,
        json={"Code": "INVALID_NAME", "Message": "John Smith not found"},
    )
    assert trulioo.extract_provider_error(resp_trulioo) == "INVALID_NAME"


# -----------------------------------------------------------------------------
# 7. ISOLATION LAW META-TEST (ALLOWLIST)
# -----------------------------------------------------------------------------


def test_kyc_and_sms_isolation_law() -> None:
    """Assert kyc/ package and sms.py import strictly within allowed boundaries."""
    kyc_dir = REPO_ROOT / "src" / "fluxpay" / "integrations" / "kyc"
    sms_file = REPO_ROOT / "src" / "fluxpay" / "integrations" / "sms.py"

    target_files = [*list(kyc_dir.glob("*.py")), sms_file]
    assert len(target_files) >= 5, f"Expected at least 5 target files, found {len(target_files)}"

    allowed_prefixes = (
        "fluxpay.shared.errors",
        "fluxpay.shared.logging",
        "fluxpay.integrations.base",
        "fluxpay.integrations.kyc",
    )

    forbidden_domains = (
        "fluxpay.ledger",
        "fluxpay.payments",
        "fluxpay.risk",
        "fluxpay.registry",
        "fluxpay.wallet",
        "fluxpay.treasury",
        "fluxpay.gateway",
    )

    for py_file in target_files:
        with py_file.open("r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name
                    for forbidden in forbidden_domains:
                        assert not name.startswith(forbidden), (
                            f"{py_file.name} violates isolation law by importing '{name}'"
                        )
                    if name.startswith("fluxpay."):
                        assert any(name.startswith(p) for p in allowed_prefixes), (
                            f"{py_file.name} imports '{name}' outside allowed prefixes"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    # Allow relative imports within the kyc package (level > 0)
                    if node.level > 0:
                        continue
                    mod = node.module
                    for forbidden in forbidden_domains:
                        assert not mod.startswith(forbidden), (
                            f"{py_file.name} violates isolation law by importing from '{mod}'"
                        )
                    if mod.startswith("fluxpay."):
                        assert any(mod.startswith(p) for p in allowed_prefixes), (
                            f"{py_file.name} imports from '{mod}' outside allowed prefixes"
                        )


# -----------------------------------------------------------------------------
# 8. CONFIGURATION & COMPOSITION CONTRACT
# -----------------------------------------------------------------------------


def test_kyc_config_defaults_and_validation() -> None:
    """Verify default provider and validator reject invalid settings."""
    valid_vault_key = base64.b64encode(b"0" * 32).decode("ascii")
    settings = Settings(
        pg_dsn="postgresql://test:test@localhost/test",
        vault_master_key=valid_vault_key,
        webhook_signing_key="a" * 32,
        keycloak_jwks_url="https://auth.fluxpay.internal/jwks",
        keycloak_issuer="https://auth.fluxpay.internal",
        keycloak_audience="https://auth.fluxpay.internal",
    )
    assert settings.kyc_provider_default == "manual"
    assert settings.sumsub_api_key is None
    assert settings.trulioo_api_key is None

    # Invalid default raises ValidationError
    with pytest.raises(ValidationError):
        Settings(
            pg_dsn="postgresql://test:test@localhost/test",
            vault_master_key=valid_vault_key,
            webhook_signing_key="a" * 32,
            keycloak_jwks_url="https://auth.fluxpay.internal/jwks",
            keycloak_issuer="https://auth.fluxpay.internal",
            keycloak_audience="https://auth.fluxpay.internal",
            kyc_provider_default="unsupported_vendor",
        )


@pytest.mark.asyncio
async def test_disabled_mode_composition_contract() -> None:
    """When a provider is unconfigured, orchestrator raises ValidationError on start."""
    # Composition root builds providers dict omitting None-configured keys
    providers: dict[str, KycProvider] = {
        "manual": ManualProvider(),
    }
    # Sumsub and Trulioo were None in config, so not in providers dict
    dummy_pool: Any = None
    orchestrator = KycOrchestrator(
        pool=dummy_pool,
        providers=providers,
        default_provider="manual",
    )

    import uuid

    # Trying to start with unconfigured provider 'sumsub' must raise ValidationError
    with pytest.raises(FluxValidationError) as exc_info:
        await orchestrator.start(uuid.uuid4(), provider="sumsub")

    assert "Unknown or unconfigured KYC provider: 'sumsub'" in str(exc_info.value)
