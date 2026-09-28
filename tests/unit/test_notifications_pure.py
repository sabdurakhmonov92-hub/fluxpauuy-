"""Unit tests for Task 43 notification adapters — pure, no real I/O.

Tests:
1. Formatter frozen shapes (KAT-style literal expected strings)
2. Config validator: token-without-chat_id -> ValidationError; both None -> fine
3. .env.example sync (auto-test; inherits from test_config.py logic)
4. Channel retry math via injected sleep (no real waits):
   - 5xx x 2 then 202 success -> 3 attempts, delivered
   - 4xx -> 1 attempt, immediate raise, defect-class only (no token)
   - 429 with Retry-After -> respected (sleep called with capped value)
   - TransportError ladder -> NotificationFailed after retry_max
   - Token absent from exception strings ALWAYS
"""

from __future__ import annotations

import base64
import re
from collections.abc import Generator
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest

from fluxpay.config import Settings
from fluxpay.notifications.channels import EmailChannel, NotificationFailed, TelegramChannel
from fluxpay.notifications.notifier import (
    LoggingStubNotifier,
    format_hold_pending,
    format_hold_rejected,
    format_hold_settled,
)
from fluxpay.risk.quarantine import HoldRecord

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# Test HoldRecord factory
# ---------------------------------------------------------------------------
from datetime import UTC, datetime  # noqa: E402


def _make_hold(
    *,
    hold_id: UUID | None = None,
    agent_id: UUID | None = None,
    amount_minor: int = 150_000_000,
    currency: str = "USDC",
    reason: str = "single_tx_ceiling",
) -> HoldRecord:
    return HoldRecord(
        hold_id=hold_id or uuid4(),
        agent_id=agent_id or uuid4(),
        idem_key="test-idem-key",
        amount_minor=amount_minor,
        currency=currency,
        reason=reason,
        status="pending",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# 1. FORMATTER FROZEN SHAPES (KAT-style literal expected strings)
# ---------------------------------------------------------------------------


def test_format_hold_pending_frozen_shape() -> None:
    """format_hold_pending output must match the exact frozen layout."""
    hold_id = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    agent_id = UUID("11111111-2222-3333-4444-555555555555")
    hold = _make_hold(hold_id=hold_id, agent_id=agent_id, amount_minor=150_000_000)

    result = format_hold_pending(hold)

    expected = (
        "🚨 HOLD pending approval\n"
        f"id: {hold_id}\n"
        f"agent: {agent_id}\n"
        "amount: 150000000 USDC\n"
        "reason: single_tx_ceiling\n"
        "Approve: dashboard → admin/holds (Task 62)"
    )
    assert result == expected, f"Formatter output does not match frozen shape:\nGot:\n{result!r}"


def test_format_hold_settled_frozen_shape() -> None:
    """format_hold_settled output must match the exact frozen layout."""
    hold_id = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    agent_id = UUID("11111111-2222-3333-4444-555555555555")
    hold = _make_hold(hold_id=hold_id, agent_id=agent_id, amount_minor=150_000_000)
    tx_id = UUID("99999999-aaaa-bbbb-cccc-dddddddddddd")

    result = format_hold_settled(hold, tx_id)

    expected = (
        f"✅ HOLD settled\nid: {hold_id}\nagent: {agent_id}\namount: 150000000 USDC\ntx_id: {tx_id}"
    )
    assert result == expected


def test_format_hold_rejected_frozen_shape() -> None:
    """format_hold_rejected output must match the exact frozen layout."""
    hold_id = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    agent_id = UUID("11111111-2222-3333-4444-555555555555")
    hold = _make_hold(hold_id=hold_id, agent_id=agent_id, reason="velocity")

    result = format_hold_rejected(hold)

    expected = (
        "❌ HOLD rejected\n"
        f"id: {hold_id}\n"
        f"agent: {agent_id}\n"
        "amount: 150000000 USDC\n"
        "reason: velocity"
    )
    assert result == expected


def test_format_hold_pending_includes_currency() -> None:
    """Amount formatting includes currency in the pending message."""
    hold = _make_hold(amount_minor=250_000, currency="EUR")
    result = format_hold_pending(hold)
    assert "250000 EUR" in result


def test_format_hold_settled_uses_tx_id_str() -> None:
    """format_hold_settled works with string tx_id (not only UUID)."""
    hold = _make_hold()
    result = format_hold_settled(hold, "tx-abc-123")
    assert "tx-abc-123" in result


def test_formatters_contain_no_secrets() -> None:
    """Verify formatters never include tokens or API keys — they use hold data only."""
    fake_token = "TESTTOKEN_7890ABCDEF"  # noqa: S105
    hold = _make_hold()
    for fn_result in [
        format_hold_pending(hold),
        format_hold_settled(hold, uuid4()),
        format_hold_rejected(hold),
    ]:
        assert fake_token not in fn_result, "Token leaked into formatter output"


# ---------------------------------------------------------------------------
# 2. CONFIG VALIDATOR TESTS
# ---------------------------------------------------------------------------


@pytest.fixture
def clean_env_base(monkeypatch: pytest.MonkeyPatch) -> Generator[dict[str, str], None, None]:
    """Strip FLX_ vars and set valid baseline (no notification vars)."""
    import os

    for key in list(os.environ.keys()):
        if key.startswith("FLX_"):
            monkeypatch.delenv(key, raising=False)

    from fluxpay.config import get_settings

    valid_vault_key = base64.b64encode(b"0" * 32).decode("ascii")
    baseline = {
        "FLX_PG_DSN": "postgresql://test:test@localhost:5432/test",
        "FLX_VAULT_MASTER_KEY": valid_vault_key,
        "FLX_WEBHOOK_SIGNING_KEY": "a" * 32,
        "FLX_KEYCLOAK_JWKS_URL": "https://auth.local/certs",
        "FLX_KEYCLOAK_ISSUER": "https://auth.local/realm",
        "FLX_KEYCLOAK_AUDIENCE": "https://api.local",
    }
    for k, v in baseline.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    yield baseline
    get_settings.cache_clear()


def test_telegram_token_without_chat_id_raises(
    clean_env_base: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Token set but chat_id absent → ValidationError (half-configured = misconfiguration)."""
    from pydantic import ValidationError as PydanticValidationError

    monkeypatch.setenv("FLX_TELEGRAM_BOT_TOKEN", "TESTTOKEN_1234567890")
    # telegram_admin_chat_id NOT set → defaults to None

    with pytest.raises(PydanticValidationError) as exc_info:
        Settings()

    error_msg = str(exc_info.value)
    assert "telegram_bot_token" in error_msg or "telegram_admin_chat_id" in error_msg
    # Ensure the token value itself is NOT in the error message
    assert "TESTTOKEN_1234567890" not in error_msg


def test_both_none_telegram_is_valid(clean_env_base: dict[str, str]) -> None:
    """Both token and chat_id absent → disabled mode; no ValidationError."""
    settings = Settings()
    assert settings.telegram_bot_token is None
    assert settings.telegram_admin_chat_id is None


def test_both_telegram_configured_is_valid(
    clean_env_base: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both token and chat_id set → valid fully-configured mode."""
    monkeypatch.setenv("FLX_TELEGRAM_BOT_TOKEN", "TESTTOKEN_1234567890")
    monkeypatch.setenv("FLX_TELEGRAM_ADMIN_CHAT_ID", "-100123456789")
    settings = Settings()
    assert settings.telegram_bot_token == "TESTTOKEN_1234567890"  # noqa: S105
    assert settings.telegram_admin_chat_id == "-100123456789"


def test_empty_string_telegram_token_becomes_none(
    clean_env_base: Generator[dict[str, str], None, None], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Empty-string FLX_TELEGRAM_BOT_TOKEN is normalized to None (disabled mode)."""
    monkeypatch.setenv("FLX_TELEGRAM_BOT_TOKEN", "")
    settings = Settings()
    assert settings.telegram_bot_token is None


def test_env_example_contains_all_notification_fields() -> None:
    """Task 43 fields must appear in .env.example (extends existing auto-sync test)."""
    env_example_path = REPO_ROOT / ".env.example"
    assert env_example_path.is_file()

    content = env_example_path.read_text(encoding="utf-8")
    declared_vars = set(re.findall(r"^(?:#\s*)?(FLX_[A-Z0-9_]+)=", content, re.MULTILINE))

    task43_fields = [
        "FLX_TELEGRAM_BOT_TOKEN",
        "FLX_TELEGRAM_ADMIN_CHAT_ID",
        "FLX_SENDGRID_API_KEY",
        "FLX_EMAIL_FROM",
        "FLX_NOTIFICATION_RETRY_MAX",
        "FLX_NOTIFICATION_BACKOFF_BASE_S",
    ]
    for var in task43_fields:
        assert var in declared_vars, (
            f"{var} not found in .env.example — Task 43 append may be missing"
        )


# ---------------------------------------------------------------------------
# 3. TELEGRAM CHANNEL RETRY MATH (injected sleep, no real waits)
# ---------------------------------------------------------------------------


class _SleepRecorder:
    """Records sleep calls for assertion."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, duration: float) -> None:
        self.calls.append(duration)


def _make_telegram_channel(
    transport: httpx.MockTransport,
    *,
    retry_max: int = 5,
    backoff_base_s: float = 2.0,
    sleep: _SleepRecorder | None = None,
) -> tuple[TelegramChannel, _SleepRecorder]:
    recorder = sleep or _SleepRecorder()
    client = httpx.AsyncClient(transport=transport)
    channel = TelegramChannel(
        client,
        bot_token="TESTTOKEN_FAKE",  # noqa: S106
        chat_id="-100123456",
        retry_max=retry_max,
        backoff_base_s=backoff_base_s,
        sleep=recorder,
    )
    return channel, recorder


@pytest.mark.asyncio
async def test_telegram_5xx_then_success_3_attempts() -> None:
    """5xx x 2 then 200-ish success -> 3 total call attempts, sleep called twice."""
    call_count = 0

    def _handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            return httpx.Response(500)
        return httpx.Response(200)

    channel, recorder = _make_telegram_channel(httpx.MockTransport(_handler))
    await channel.send("test message")

    assert call_count == 3
    assert len(recorder.calls) == 2  # slept after attempt 1 and attempt 2


@pytest.mark.asyncio
async def test_telegram_4xx_no_retry_immediate_raise() -> None:
    """4xx (non-429) → 1 attempt, immediate NotificationFailed, no sleep."""
    call_count = 0

    def _handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(401)

    channel, recorder = _make_telegram_channel(httpx.MockTransport(_handler))
    with pytest.raises(NotificationFailed) as exc_info:
        await channel.send("test message")

    assert call_count == 1
    assert len(recorder.calls) == 0
    # Defect-class check: message must not contain the token
    assert "TESTTOKEN_FAKE" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_telegram_token_not_in_exception_on_5xx_exhaustion() -> None:
    """Token must never appear in NotificationFailed exception string."""

    def _always_500(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    channel, _ = _make_telegram_channel(
        httpx.MockTransport(_always_500), retry_max=3, backoff_base_s=0.001
    )
    with pytest.raises(NotificationFailed) as exc_info:
        await channel.send("test")

    assert "TESTTOKEN_FAKE" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_telegram_429_retry_after_respected() -> None:
    """429 with Retry-After header → sleep called with capped Retry-After value."""
    call_count = 0

    def _handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(429, headers={"Retry-After": "3"})
        return httpx.Response(200)

    channel, recorder = _make_telegram_channel(httpx.MockTransport(_handler), backoff_base_s=10.0)
    await channel.send("rate-limited message")

    assert call_count == 2
    assert len(recorder.calls) == 1
    # Retry-After=3, backoff cap=10*2^0=10 → sleep value should be min(3, 10)=3
    assert recorder.calls[0] == pytest.approx(3.0)


@pytest.mark.asyncio
async def test_telegram_transport_error_ladder_then_failed() -> None:
    """TransportError on every attempt → NotificationFailed after retry_max."""

    def _always_transport_error(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated disconnect")

    channel, recorder = _make_telegram_channel(
        httpx.MockTransport(_always_transport_error), retry_max=3, backoff_base_s=1.0
    )
    with pytest.raises(NotificationFailed) as exc_info:
        await channel.send("test")

    assert len(recorder.calls) == 3  # slept after each of 3 attempts
    assert "TESTTOKEN_FAKE" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_telegram_success_on_first_attempt_no_sleep() -> None:
    """200 on first attempt → no sleep, no retry."""

    def _always_200(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    channel, recorder = _make_telegram_channel(httpx.MockTransport(_always_200))
    await channel.send("immediate success")

    assert len(recorder.calls) == 0


# ---------------------------------------------------------------------------
# 4. EMAIL CHANNEL RETRY MATH
# ---------------------------------------------------------------------------


def _make_email_channel(
    transport: httpx.MockTransport,
    *,
    retry_max: int = 5,
    backoff_base_s: float = 2.0,
    sleep: _SleepRecorder | None = None,
) -> tuple[EmailChannel, _SleepRecorder]:
    recorder = sleep or _SleepRecorder()
    client = httpx.AsyncClient(transport=transport)
    channel = EmailChannel(
        client,
        api_key="SG.TESTKEY_FAKE",
        from_addr="noreply@fluxpay.local",
        retry_max=retry_max,
        backoff_base_s=backoff_base_s,
        sleep=recorder,
    )
    return channel, recorder


@pytest.mark.asyncio
async def test_email_202_success_no_retry() -> None:
    """202 (SendGrid success) → no retry, no sleep."""

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202)

    channel, recorder = _make_email_channel(httpx.MockTransport(_handler))
    await channel.send(to_email="admin@test.com", subject="Test", body="Hello")
    assert len(recorder.calls) == 0


@pytest.mark.asyncio
async def test_email_4xx_no_retry_immediate_raise() -> None:
    """4xx → 1 attempt, immediate NotificationFailed, API key NOT in message."""

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403)

    channel, recorder = _make_email_channel(httpx.MockTransport(_handler))
    with pytest.raises(NotificationFailed) as exc_info:
        await channel.send(to_email="a@b.com", subject="Test", body="body")

    assert len(recorder.calls) == 0
    assert "SG.TESTKEY_FAKE" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_email_5xx_exhaustion_raises_notification_failed() -> None:
    """5xx every time → NotificationFailed after retry_max; API key absent from exc."""

    def _always_503(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    channel, _ = _make_email_channel(
        httpx.MockTransport(_always_503), retry_max=2, backoff_base_s=0.001
    )
    with pytest.raises(NotificationFailed) as exc_info:
        await channel.send(to_email="admin@test.com", subject="s", body="b")

    assert "SG.TESTKEY_FAKE" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# 5. LOGGING STUB NOTIFIER CONTRACT
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logging_stub_notifier_logs_pending() -> None:
    """LoggingStubNotifier.notify_hold_pending logs at INFO with hold_id."""
    import structlog

    hold = _make_hold()
    notifier = LoggingStubNotifier()
    with structlog.testing.capture_logs() as logs:
        await notifier.notify_hold_pending(hold)
    assert any(str(hold.hold_id) in str(entry) for entry in logs)
    assert any(entry.get("event") == "admin_notify_hold_pending" for entry in logs)


@pytest.mark.asyncio
async def test_logging_stub_notifier_logs_settled() -> None:
    """LoggingStubNotifier.notify_hold_settled logs at INFO."""
    import structlog

    hold = _make_hold()
    notifier = LoggingStubNotifier()
    with structlog.testing.capture_logs() as logs:
        await notifier.notify_hold_settled(hold, "test-outcome")
    assert any(str(hold.hold_id) in str(entry) for entry in logs)
    assert any(entry.get("event") == "admin_notify_hold_settled" for entry in logs)


@pytest.mark.asyncio
async def test_logging_stub_notifier_logs_rejected() -> None:
    """LoggingStubNotifier.notify_hold_rejected logs at INFO."""
    import structlog

    hold = _make_hold()
    notifier = LoggingStubNotifier()
    with structlog.testing.capture_logs() as logs:
        await notifier.notify_hold_rejected(hold, "rejected")
    assert any(str(hold.hold_id) in str(entry) for entry in logs)
    assert any(entry.get("event") == "admin_notify_hold_rejected" for entry in logs)
