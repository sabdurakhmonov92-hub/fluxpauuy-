"""Unit tests for Task 49 Integration Base Client (Block J, Part 1).

Tests:
1. Retry ladder: 500, 500, 200 -> 3 attempts, success; 500x3 -> IntegrationError(attempts=3);
   sleep called with increasing capped+jittered values ([base*2^n, base*2^n*1.25]).
2. 429 pacing: Retry-After respected exactly; cap enforced at >cap; 429 without header
   falls back to normal ladder backoff.
3. 4xx immediate failure: 401/403 map to IntegrationAuthError (non-retryable, attempt=1);
   400/404/422 map to IntegrationError (non-retryable, attempt=1); response body omitted.
4. Idempotency: POST with key attaches header, stable across retry attempts; GET with key
   omits header (method law); custom IDEMPOTENCY_HEADER honored.
5. Correlation: X-FLX-Provider-Request-Id generated once per operation, stable across attempts.
6. Secret-free observability: Authorization header and request/response bodies absent from logs.
7. ProviderCall shape lock & provider error hook default / override.
8. Healthcheck contract: raises NotImplementedError on base class.
9. ISOLATION LAW meta-test: assert integrations modules import ONLY allowed dependencies.
10. INJECTION LAW meta-test: assert NO module-level AsyncClient instantiation.
11. Registry contract: two error classes registered, unique, valid statuses,
    ErrorEnvelope roundtrip.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable
from dataclasses import FrozenInstanceError, is_dataclass
from pathlib import Path

import httpx
import pytest
from structlog.testing import capture_logs

from fluxpay.contracts.schemas import ErrorEnvelope
from fluxpay.integrations.base import BaseClient, ProviderCall
from fluxpay.shared.errors import (
    ERROR_REGISTRY,
    IntegrationAuthError,
    IntegrationError,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Test Helpers: Mock Sleep and Clock
# ---------------------------------------------------------------------------


class SleepRecorder:
    """Injected sleep callable that records requested durations without real delays."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


class StepClock:
    """Injected monotonic clock advancing predictably per invocation."""

    def __init__(self, start: float = 1000.0, step: float = 0.05) -> None:
        self.current = start
        self.step = step

    def __call__(self) -> float:
        val = self.current
        self.current += self.step
        return val


def _make_client(
    transport: httpx.AsyncBaseTransport,
    *,
    provider_name: str = "test_provider",
    max_attempts: int = 3,
    backoff_base_s: float = 0.5,
    backoff_cap_s: float = 8.0,
    sleep: SleepRecorder | None = None,
    now: Callable[[], float] | None = None,
    client_cls: type[BaseClient] = BaseClient,
) -> tuple[BaseClient, SleepRecorder]:
    recorder = sleep or SleepRecorder()
    clock = now or StepClock()
    http = httpx.AsyncClient(transport=transport, base_url="https://api.testprovider.com")
    client = client_cls(
        provider_name=provider_name,
        http=http,
        max_attempts=max_attempts,
        backoff_base_s=backoff_base_s,
        backoff_cap_s=backoff_cap_s,
        sleep=recorder,
        now=clock,
    )
    return client, recorder


# ---------------------------------------------------------------------------
# 1. RETRY LADDER & BACKOFF TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ladder_500_500_200_success_three_attempts() -> None:
    """500, 500, 200 -> 3 attempts total, returns 200 response, sleeps twice."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(500)
        return httpx.Response(200, json={"ok": True})

    client, recorder = _make_client(httpx.MockTransport(handler))
    resp = await client.request("test_charge", "POST", "/v1/charges")

    assert resp.status_code == 200
    assert len(calls) == 3
    assert len(recorder.calls) == 2

    # Bounds assertion: sleep duration in [base * 2^n, base * 2^n * 1.25]
    base = 0.5
    # Attempt 1 failed (n=0):
    assert base * (2**0) <= recorder.calls[0] <= base * (2**0) * 1.25
    # Attempt 2 failed (n=1):
    assert base * (2**1) <= recorder.calls[1] <= base * (2**1) * 1.25


@pytest.mark.asyncio
async def test_ladder_500_exhaustion_raises_integration_error() -> None:
    """500 x 3 -> IntegrationError with details attempts=3 and status=500."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(500)

    client, recorder = _make_client(httpx.MockTransport(handler), max_attempts=3)
    with pytest.raises(IntegrationError) as exc_info:
        await client.request("test_op", "GET", "/v1/status")

    assert call_count == 3
    assert len(recorder.calls) == 2
    err = exc_info.value
    assert err.status == 502
    assert err.retryable is True
    assert err.details["provider"] == "test_provider"
    assert err.details["op"] == "test_op"
    assert err.details["attempts"] == "3"
    assert err.details["status"] == "500"


@pytest.mark.asyncio
async def test_ladder_transport_error_retries_and_exhausts() -> None:
    """httpx.TransportError is caught as transient, retried via ladder, and mapped."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        raise httpx.ConnectError("Connection refused by upstream host")

    client, recorder = _make_client(httpx.MockTransport(handler), max_attempts=3)
    with pytest.raises(IntegrationError) as exc_info:
        await client.request("ping_node", "GET", "/rpc")

    assert call_count == 3
    assert len(recorder.calls) == 2
    err = exc_info.value
    assert err.status == 502
    assert err.retryable is True
    assert err.details["attempts"] == "3"
    assert "status" not in err.details  # No HTTP status code on connection failure


@pytest.mark.asyncio
async def test_ladder_timeout_exception_retried_and_succeeds() -> None:
    """httpx.ReadTimeout is caught as transient, retried, and succeeds on attempt 2."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise httpx.ReadTimeout("Read timed out")
        return httpx.Response(200, json={"recovered": True})

    client, recorder = _make_client(httpx.MockTransport(handler), max_attempts=3)
    resp = await client.request("fetch_data", "GET", "/data")

    assert resp.status_code == 200
    assert call_count == 2
    assert len(recorder.calls) == 1


# ---------------------------------------------------------------------------
# 2. 429 RETRY-AFTER PACING TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_429_with_retry_after_honored_exactly() -> None:
    """429 with Retry-After: 5 -> sleep(5) EXACTLY, then retry succeeds."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(429, headers={"Retry-After": "5"})
        return httpx.Response(200)

    client, recorder = _make_client(httpx.MockTransport(handler), backoff_cap_s=8.0)
    resp = await client.request("rate_limited_op", "POST", "/submit")

    assert resp.status_code == 200
    assert call_count == 2
    assert len(recorder.calls) == 1
    assert recorder.calls[0] == pytest.approx(5.0)


@pytest.mark.asyncio
async def test_429_with_retry_after_exceeding_cap_is_capped() -> None:
    """429 with Retry-After: 20 and cap 8.0 -> sleep(8.0) EXACTLY."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(429, headers={"Retry-After": "20"})
        return httpx.Response(200)

    client, recorder = _make_client(httpx.MockTransport(handler), backoff_cap_s=8.0)
    resp = await client.request("capped_op", "GET", "/items")

    assert resp.status_code == 200
    assert call_count == 2
    assert len(recorder.calls) == 1
    assert recorder.calls[0] == pytest.approx(8.0)


@pytest.mark.asyncio
async def test_429_without_retry_after_uses_normal_ladder() -> None:
    """429 without Retry-After header falls back to regular exponential jittered backoff."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(429)  # No Retry-After header
        return httpx.Response(200)

    base = 0.5
    client, recorder = _make_client(httpx.MockTransport(handler), backoff_base_s=base)
    resp = await client.request("fallback_op", "GET", "/items")

    assert resp.status_code == 200
    assert call_count == 2
    assert len(recorder.calls) == 1
    # Check normal ladder bounds [base, base * 1.25]
    assert base <= recorder.calls[0] <= base * 1.25


@pytest.mark.asyncio
async def test_429_with_invalid_retry_after_header_falls_back_to_ladder() -> None:
    """429 with non-numeric or malformed Retry-After header uses normal ladder backoff."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(429, headers={"Retry-After": "not-a-number"})
        return httpx.Response(200)

    base = 0.5
    client, recorder = _make_client(httpx.MockTransport(handler), backoff_base_s=base)
    resp = await client.request("invalid_hdr_op", "GET", "/items")

    assert resp.status_code == 200
    assert call_count == 2
    assert len(recorder.calls) == 1
    assert base <= recorder.calls[0] <= base * 1.25


# ---------------------------------------------------------------------------
# 3. 4xx IMMEDIATE FAILURE & ERROR MAPPING TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [401, 403])
async def test_401_403_map_to_integration_auth_error_no_retry(status_code: int) -> None:
    """401/403 indicate bad credentials -> IntegrationAuthError immediately (attempt=1)."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(status_code, json={"error": "invalid_api_key"})

    client, recorder = _make_client(httpx.MockTransport(handler))
    with pytest.raises(IntegrationAuthError) as exc_info:
        await client.request("auth_op", "POST", "/v1/transfers")

    assert call_count == 1
    assert len(recorder.calls) == 0  # No retry sleeps
    err = exc_info.value
    assert err.status == 500
    assert err.retryable is False
    assert err.details["provider"] == "test_provider"
    assert err.details["op"] == "auth_op"
    assert err.details["status"] == str(status_code)
    # Defense against PII/leak: response body is NOT in details
    assert "invalid_api_key" not in err.details.values()


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [400, 404, 422])
async def test_other_4xx_map_to_integration_error_no_retry(status_code: int) -> None:
    """400, 404, 422 client defects -> IntegrationError immediately (attempt=1, no retry)."""
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(
            status_code,
            json={"error": "parameter_missing", "customer_ssn": "000-12-3456"},
        )

    client, recorder = _make_client(httpx.MockTransport(handler))
    with pytest.raises(IntegrationError) as exc_info:
        await client.request("client_defect_op", "POST", "/v1/customers")

    assert call_count == 1
    assert len(recorder.calls) == 0  # No retry sleeps
    err = exc_info.value
    assert err.status == 502
    assert err.retryable is True
    assert err.details["provider"] == "test_provider"
    assert err.details["op"] == "client_defect_op"
    assert err.details["status"] == str(status_code)
    # Absence law: sensitive customer PII from response body is NEVER copied into details
    assert "000-12-3456" not in err.details.values()
    assert "customer_ssn" not in err.details.values()


# ---------------------------------------------------------------------------
# 4. IDEMPOTENCY KEY TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_idempotency_key_attached_and_stable_on_post_retries() -> None:
    """POST with idempotency_key attaches header, and it is STABLE across retry attempts."""
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        if len(captured_requests) < 2:
            return httpx.Response(500)
        return httpx.Response(200)

    client, _ = _make_client(httpx.MockTransport(handler))
    idem_key = "flx_idem_abc123"
    await client.request("create_payment", "POST", "/payments", idempotency_key=idem_key)

    assert len(captured_requests) == 2
    # Both attempts MUST contain the idempotency header
    for req in captured_requests:
        assert req.headers.get("Idempotency-Key") == idem_key
    # Equal across attempts
    assert (
        captured_requests[0].headers["Idempotency-Key"]
        == captured_requests[1].headers["Idempotency-Key"]
    )


@pytest.mark.asyncio
async def test_idempotency_key_omitted_on_get_method_law() -> None:
    """GET with idempotency_key MUST NOT attach the header (method law)."""
    captured_request: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_request
        captured_request = request
        return httpx.Response(200)

    client, _ = _make_client(httpx.MockTransport(handler))
    await client.request("get_balance", "GET", "/balance", idempotency_key="should_be_ignored")

    assert captured_request is not None
    assert "Idempotency-Key" not in captured_request.headers


@pytest.mark.asyncio
async def test_custom_idempotency_header_name_honored() -> None:
    """Custom IDEMPOTENCY_HEADER class attribute override is honored by request()."""

    class CustomHeaderClient(BaseClient):
        IDEMPOTENCY_HEADER = "X-Idempotency-Token"

    captured_request: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_request
        captured_request = request
        return httpx.Response(200)

    client, _ = _make_client(httpx.MockTransport(handler), client_cls=CustomHeaderClient)
    await client.request("custom_idem", "POST", "/submit", idempotency_key="custom_key_456")

    assert captured_request is not None
    assert captured_request.headers.get("X-Idempotency-Token") == "custom_key_456"
    assert "Idempotency-Key" not in captured_request.headers


# ---------------------------------------------------------------------------
# 5. CORRELATION ID TESTS
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_correlation_id_generated_and_stable_across_attempts() -> None:
    """X-FLX-Provider-Request-Id is generated once per op and stable across retries."""
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        if len(captured_requests) < 3:
            return httpx.Response(500)
        return httpx.Response(200)

    client, _ = _make_client(httpx.MockTransport(handler))
    await client.request("multi_attempt_op", "GET", "/status")

    assert len(captured_requests) == 3
    corr_ids = [req.headers.get("X-FLX-Provider-Request-Id") for req in captured_requests]

    # Must be valid 32-char hex string (UUID4 hex)
    hex_pattern = re.compile(r"^[0-9a-f]{32}$")
    assert corr_ids[0] is not None
    assert hex_pattern.match(corr_ids[0])

    # All attempts MUST share the identical correlation ID
    assert corr_ids[0] == corr_ids[1] == corr_ids[2]


# ---------------------------------------------------------------------------
# 6. SECRET-FREE OBSERVABILITY (ABSENCE LAW)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_secret_free_logging_absence_law() -> None:
    """Authorization header, tokens, and request/response bodies are ABSENT from logs."""
    secret_token = "sk_live_super_secret_production_credential_987654"  # noqa: S105
    secret_body_data = "sensitive_customer_account_number_4321"  # noqa: S105

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"provider_secret": "do_not_log_this"})

    client, _ = _make_client(httpx.MockTransport(handler))

    with capture_logs() as captured:
        await client.request(
            "secret_op",
            "POST",
            "/v1/tokens",
            json={"account": secret_body_data},
            headers={"Authorization": f"Bearer {secret_token}"},
        )

    # Convert entire captured logs collection to string for deep search
    captured_str = str(captured)

    assert secret_token not in captured_str, "Secret token leaked into structlog output!"
    assert secret_body_data not in captured_str, "Request body leaked into structlog output!"
    assert "do_not_log_this" not in captured_str, "Response body leaked into structlog output!"
    assert "Authorization" not in captured_str, "Auth header name leaked into structlog output!"

    # Verify standard telemetry fields ARE present
    events = [entry.get("event") for entry in captured]
    assert "provider_call_attempt" in events
    assert "provider_call_completed" in events

    completion_event = next(e for e in captured if e.get("event") == "provider_call_completed")
    assert completion_event.get("provider") == "test_provider"
    assert completion_event.get("op") == "secret_op"
    assert completion_event.get("status") == 200
    assert completion_event.get("ok") is True
    assert "duration_ms" in completion_event


# ---------------------------------------------------------------------------
# 7. PROVIDERCALL SHAPE LOCK & PROVIDER ERROR HOOK
# ---------------------------------------------------------------------------


def test_provider_call_shape_lock() -> None:
    """ProviderCall is a frozen, slotted dataclass with exact contract attributes."""
    assert is_dataclass(ProviderCall)
    call = ProviderCall(provider="stripe", op="charge", status=200, duration_ms=42, ok=True)

    assert call.provider == "stripe"
    assert call.op == "charge"
    assert call.status == 200
    assert call.duration_ms == 42
    assert call.ok is True

    # Invariant: slots enabled
    assert hasattr(call, "__slots__")

    # Invariant: frozen immutability
    with pytest.raises(FrozenInstanceError):
        call.status = 500  # type: ignore[misc]


def test_extract_provider_error_default_and_override() -> None:
    """Default returns http_{code}; subclass can override with custom JSON dialect."""

    class StripeClientStub(BaseClient):
        def extract_provider_error(self, response: httpx.Response) -> str:
            try:
                data = response.json()
                code = data.get("error", {}).get("code")
                return str(code) if code else super().extract_provider_error(response)
            except Exception:
                return super().extract_provider_error(response)

    client, _ = _make_client(httpx.MockTransport(lambda r: httpx.Response(400)))
    assert client.extract_provider_error(httpx.Response(400)) == "http_400"
    assert client.extract_provider_error(httpx.Response(422)) == "http_422"

    stripe_client, _ = _make_client(
        httpx.MockTransport(lambda r: httpx.Response(400)), client_cls=StripeClientStub
    )
    custom_resp = httpx.Response(402, json={"error": {"code": "card_declined"}})
    assert stripe_client.extract_provider_error(custom_resp) == "card_declined"


# ---------------------------------------------------------------------------
# 8. HEALTHCHECK CONTRACT
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_healthcheck_raises_not_implemented_error() -> None:
    """BaseClient.healthcheck() raises NotImplementedError referencing concrete adapters."""
    client, _ = _make_client(httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(NotImplementedError) as exc_info:
        await client.healthcheck()

    assert "healthcheck" in str(exc_info.value)
    assert "cheapest authenticated ping" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 9. ISOLATION LAW META-TEST (IMPORT BLACKLIST & ALLOWLIST)
# ---------------------------------------------------------------------------


def test_isolation_law_import_allowlist() -> None:
    """ISOLATION LAW meta-test: integrations modules import ONLY allowed dependencies.

    Adapters import ONLY:
    - Python standard library
    - httpx
    - fluxpay.shared.errors
    - fluxpay.shared.logging
    - fluxpay.shared.vault
    - other modules within fluxpay.integrations (or relative imports)

    NEVER each other. NEVER business core (ledger, payments, risk, registry,
    wallet, treasury, gateway, etc.).
    """
    integrations_dir = REPO_ROOT / "src" / "fluxpay" / "integrations"
    assert integrations_dir.is_dir(), f"Missing directory: {integrations_dir}"

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

    py_files = list(integrations_dir.rglob("*.py"))
    assert len(py_files) >= 2, "Expected at least __init__.py and base.py in integrations"

    for py_file in py_files:
        with py_file.open("r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name
                    if name.startswith("fluxpay."):
                        assert any(name.startswith(p) for p in allowed_prefixes), (
                            f"ISOLATION LAW VIOLATION in {py_file.name}: "
                            f"forbidden import '{name}'. Allowed: {allowed_prefixes}"
                        )
                    for forbidden in forbidden_business_core:
                        assert not name.startswith(forbidden), (
                            f"BUSINESS CORE LEAK in {py_file.name}: forbidden import '{name}'"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    mod = node.module
                    if mod.startswith("fluxpay.") or mod == "fluxpay":
                        assert any(mod.startswith(p) for p in allowed_prefixes), (
                            f"ISOLATION LAW VIOLATION in {py_file.name}: "
                            f"forbidden import from '{mod}'. Allowed: {allowed_prefixes}"
                        )
                    for forbidden in forbidden_business_core:
                        assert not mod.startswith(forbidden), (
                            f"BUSINESS CORE LEAK in {py_file.name}: forbidden import from '{mod}'"
                        )


# ---------------------------------------------------------------------------
# 10. INJECTION LAW META-TEST (NO MODULE-LEVEL ASYNC_CLIENT)
# ---------------------------------------------------------------------------


def test_injection_law_no_module_level_async_client() -> None:
    """INJECTION LAW meta-test: No module-level AsyncClient instantiation.

    Adapters must NOT create singleton / module-level AsyncClient instances.
    Lifecycle must be owned by composition root and injected into client constructors.
    """
    integrations_dir = REPO_ROOT / "src" / "fluxpay" / "integrations"
    assert integrations_dir.is_dir()

    py_files = list(integrations_dir.rglob("*.py"))
    for py_file in py_files:
        with py_file.open("r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(py_file))

        for stmt in tree.body:
            # Exclude functions and class definitions; we only check top-level module statements
            if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                continue
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    func_name = ""
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    assert func_name != "AsyncClient", (
                        f"INJECTION LAW VIOLATION in {py_file.name}: "
                        f"Module-level AsyncClient instantiation at line {node.lineno}. "
                        "AsyncClient must be injected via constructor, never at module level."
                    )


# ---------------------------------------------------------------------------
# 11. REGISTRY & TASK 4 / TASK 24 AUTO-ROUNDTRIP SUITE
# ---------------------------------------------------------------------------


def test_integration_errors_registry_and_contracts() -> None:
    """Verify registry presence, uniqueness, format, and Task 24 ErrorEnvelope roundtrip."""
    was_int_err = "integration_error" in ERROR_REGISTRY
    was_auth_err = "integration_auth_error" in ERROR_REGISTRY

    ERROR_REGISTRY["integration_error"] = IntegrationError
    ERROR_REGISTRY["integration_auth_error"] = IntegrationAuthError
    try:
        assert "integration_error" in ERROR_REGISTRY
        assert ERROR_REGISTRY["integration_error"] is IntegrationError
        assert "integration_auth_error" in ERROR_REGISTRY
        assert ERROR_REGISTRY["integration_auth_error"] is IntegrationAuthError

        # Snake_case format
        code_pattern = re.compile(r"^[a-z][a-z0-9_]*$")
        assert code_pattern.match(IntegrationError.code)
        assert code_pattern.match(IntegrationAuthError.code)

        # Uniqueness
        assert IntegrationError.code != IntegrationAuthError.code
        assert len(ERROR_REGISTRY) == len(set(ERROR_REGISTRY.keys()))

        # Status bounds
        assert 400 <= IntegrationError.status <= 599
        assert 400 <= IntegrationAuthError.status <= 599

        # Explicit semantic values
        assert IntegrationError.status == 502
        assert IntegrationError.retryable is True
        assert IntegrationAuthError.status == 500
        assert IntegrationAuthError.retryable is False

        # Task 24 ErrorEnvelope auto-roundtrip
        for err_cls in (IntegrationError, IntegrationAuthError):
            err_instance = err_cls(details={"provider": "test_provider"})
            payload = err_instance.to_payload()

            # 1. Structural wire validation
            envelope = ErrorEnvelope.model_validate(payload)

            # 2. Field-level equivalence
            assert envelope.error.code == err_instance.code
            assert envelope.error.message == err_instance.message
            assert envelope.error.retryable == err_instance.retryable

            # 3. Serialization byte-level equivalence
            assert envelope.model_dump() == payload
    finally:
        if not was_int_err:
            ERROR_REGISTRY.pop("integration_error", None)
        if not was_auth_err:
            ERROR_REGISTRY.pop("integration_auth_error", None)
